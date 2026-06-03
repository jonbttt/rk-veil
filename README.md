# rk-veil

A simple Linux Loadable Kernel Module (LKM) rootkit targeting kernel 6.x, built as a security research and portfolio project. Demonstrates core rootkit techniques including syscall table hooking, module self-hiding, file and process concealment, and privilege escalation.

> **Disclaimer:** This project is strictly for educational purposes and security research. Only run in an isolated virtual machine. Do not deploy on any system you do not own.

---

## Features

| Feature | Mechanism |
|---|---|
| Module self-hiding | Unlinks from kernel module list, removes `/sys/module/` entry |
| File hiding | `getdents64` hook strips entries prefixed `rkveil_` |
| Process hiding | `execve` hook auto-hides processes by `argv[0]` prefix |
| Privilege escalation | `kill` hook triggers `commit_creds` on signal 64 |

---

## How It Works

### Syscall Table Resolution
On kernel >= 5.7, `kallsyms_lookup_name()` is no longer exported to modules. rk-veil resolves it at runtime by registering a kprobe on the symbol. The kernel fills `kp.addr` with the function address, which is then cast to a function pointer and used to locate `sys_call_table` directly.

### Write-Protect Bypass
On kernel >= 5.4, the syscall table page is marked read-only at the page table entry level, making the traditional CR0 WP-bit approach insufficient. rk-veil uses `lookup_address()` to find the PTE for the syscall table page and directly sets the `_PAGE_RW` bit before patching, restoring it afterward.

### Module Self-Hiding
`THIS_MODULE` is unlinked from the kernel's doubly-linked module list, making it invisible to `lsmod` and `/proc/modules`. `kobject_del()` removes the `/sys/module/` entry.

### File & Process Hiding
The `getdents64` hook copies the dirent buffer into kernel space, strips any entries whose name starts with `rkveil_` or whose numeric name matches a hidden PID, then copies the modified buffer back to userspace. Files and `/proc/<pid>` entries are both hidden this way.

### Automatic Process Hiding
The `execve` hook checks `argv[0]` before the new process image loads. If it starts with `rkveil_`, the PID is added to a hidden list after a successful exec. The `exit_group` hook removes the PID on process exit to prevent stale entries.

### Privilege Escalation
The `kill` hook intercepts signal 64 (an unused real-time signal) as a backdoor trigger. On receipt, `prepare_creds()` clones the calling process's credentials, all uid/gid fields are zeroed, and `commit_creds()` atomically swaps them in. The signal is consumed and never delivered.

---

## Usage

### Prerequisites
- Linux kernel 6.x (tested on 6.2.0-25-generic)
- `linux-headers-$(uname -r)`
- `build-essential`

### Build
```bash
make
```

### Load
```bash
sudo insmod rk_veil.ko
sudo dmesg | grep rk-veil
```

### Hide a file or directory
```bash
# Any file or directory prefixed with rkveil_ is hidden from ls, find, etc.
touch rkveil_secret.txt
ls | grep rkveil    # returns nothing
```

### Hide a process
```bash
# Spawn any process with argv[0] prefixed rkveil_
(exec -a "rkveil_backdoor" sleep 60) &
ps aux | grep rkveil    # returns nothing
```

### Privilege escalation
```bash
whoami          # vagrant (or any unprivileged user)
kill -64 1
whoami          # root
```

### Unload
```bash
# Note: rmmod will fail after load since the module is hidden from the list.
# Reboot the VM to unload cleanly.
sudo reboot
```

---

## Testing

A full behavioural test suite is included:

```bash
sudo bash test.sh
```

Tests cover module hiding, file hiding, process auto-hiding, multiple simultaneous hidden processes, privilege escalation, syscall table resolution, and normal signal passthrough.

Expected result: **18/18 passing**.

---

## Kernel Compatibility

| Kernel | Status |
|---|---|
| 6.2.x | Tested, working |
| 5.7 -- 6.1 | Should work (kprobe resolution supported, PTE bypass required) |
| < 5.7 | Not supported (kallsyms_lookup_name was exported, different approach needed) |

---

## Test Environment

Vagrant + VirtualBox, `bento/ubuntu-22.04` with kernel `6.2.0-25-generic`.

A `Vagrantfile` is included in the repo. To get started:

```bash
vagrant up
vagrant ssh
```

After `vagrant ssh`, install the specific kernel version:

```bash
sudo apt update
sudo apt install -y linux-image-6.2.0-25-generic linux-headers-6.2.0-25-generic
sudo reboot
```

Verify after reboot:

```bash
uname -r    # should show 6.2.0-25-generic
```

---

## Detection

This rootkit is detectable by:

| Detection Method | Description |
|---|---|
| **Syscall table integrity checks** | comparing live syscall table entries against known-good values |
| **eBPF-based monitoring** | tools like Falco or Tetragon can detect anomalous kernel function calls regardless of userspace hiding |
| **Direct `/proc` access** | hiding is listing-only; processes remain accessible by direct path if the PID is already known |
| **KASLR bypass detection** | the kprobe resolution technique leaves a brief kprobe registration window observable via `/sys/kernel/debug/kprobes/` |
| **Module list cross-referencing** | comparing `kobject` entries in sysfs against the module list can reveal hidden modules |

---

## References

- [xcellerator's Linux Rootkits series](https://xcellerator.github.io/posts/linux_rootkits_01/)
- [Linux Kernel Module Programming Guide](https://sysprog21.github.io/lkmpg/)
- [Caraxes — academic LKM rootkit](https://github.com/ait-aecid/caraxes)

---

## Author

[jonbttt](https://github.com/jonbttt)
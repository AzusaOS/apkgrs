#!/bin/sh
# apkg integration tests, run as root inside the test VM (see run.sh).
# Prints "APKG-VMTEST: PASS" or "APKG-VMTEST: FAIL <n>" at the end.
. /test/env
FAILS=0
DATA=/var/lib/apkg
LOG=/tmp/apkg.log
M=/pkg/main

ok() { echo "ok   - $*"; }
fail() { echo "FAIL - $*"; FAILS=$((FAILS + 1)); }
check() { # check <description> <command...>
    d=$1; shift
    if "$@" > /tmp/check.out 2>&1; then ok "$d"; else fail "$d"; sed 's/^/       /' /tmp/check.out | tail -20; fi
}
wait_for() { # wait_for <seconds> <command...>
    n=$1; shift
    while [ "$n" -gt 0 ]; do "$@" > /dev/null 2>&1 && return 0; sleep 1; n=$((n - 1)); done
    return 1
}
mounted() { grep -q " $1 fuse" /proc/mounts; }
log_has() { grep -q "$1" "$LOG"; }
apkg_pid() { pidof apkg | tr ' ' '\n' | while read -r p; do [ "$(stat -c %u /proc/$p)" = "$1" ] && echo "$p"; done | head -1; }
drop_caches() { sync; echo 3 > /proc/sys/vm/drop_caches; }
expected() { grep " $1\$" /test/expected.sha256 | cut -d' ' -f1; }
end() {
    if [ "$FAILS" -ne 0 ]; then
        echo "---- apkg log (root) ----"; tail -60 "$LOG"
        [ -f /tmp/apkg-user.log ] && { echo "---- apkg log (user) ----"; tail -30 /tmp/apkg-user.log; }
        echo "APKG-VMTEST: FAIL $FAILS"
    else
        echo "APKG-VMTEST: PASS"
    fi
    exit "$FAILS"
}

echo "kernel $(uname -r), apkg $(apkg -version)"

# ---- root daemon ----------------------------------------------------------
# a cache_days of 0.0001 (~8.6 s) makes eviction testable; it only runs on
# SIGHUP and hourly
apkg -no_self_update -no_ctrl -data $DATA -base /pkg -cache_days 0.0001 > $LOG 2>&1 &
check "root: mounted $M" wait_for 120 mounted $M
mounted $M || end
check "root: listing the root is refused (as in the Go daemon)" sh -c "! ls $M"
check "root: ld.so.cache served" sh -c "[ -s $M/ld.so.cache ]"
check "root: partial name is a symlink" sh -c "[ \"\$(readlink $M/$PKG0_SHORT)\" = $PKG0 ]"
check "root: unknown name is ENOENT" sh -c "! ls $M/no.such.package.linux.amd64"
check "root: read-only" sh -c "! touch $M/$PKG0/x"
check "root: file contents (sequential)" sha256sum -c -s /test/expected.sha256
drop_caches
check "root: file contents (4 parallel readers, cold page cache)" sh -c '
    pids=; for i in 1 2 3 4; do (shuf /test/expected.sha256 | sha256sum -c -s) & pids="$pids $!"; done
    r=0; for p in $pids; do wait $p || r=1; done; exit $r'
check "root: run python from the mount" sh -c "[ \"\$($M/dev-lang.python.core/bin/python3 -c 'print(6*7)')\" = 42 ]"
check "root: package cache files exist" sh -c "[ -s $DATA/main/$PKG0_CACHE ] && [ -s $DATA/main/$PKG1_CACHE ]"

# ---- graceful restart -----------------------------------------------------
echo "step: restart setup"
F0=$(grep " $M/$PKG0/" /test/expected.sha256 | tail -1 | cut -d' ' -f3)
echo "step: open $F0"
exec 3< "$F0"
cd "$M/$PKG1/bin"
PID=$(apkg_pid 0)
echo "step: SIGUSR2 to $PID"
kill -USR2 "$PID"
check "restart: new process took over" wait_for 60 log_has "took over FUSE connection"
check "restart: same pid, still mounted" sh -c "[ '$(apkg_pid 0)' = $PID ] && grep -q ' $M fuse' /proc/mounts"
drop_caches
check "restart: fd opened before still reads" sh -c "[ \"\$(sha256sum <&3 | cut -d' ' -f1)\" = $(expected "$F0") ]"
check "restart: cwd inside the mount still works" sh -c "ls . | grep -q busybox && [ -x ./busybox ]"
check "restart: new lookups work" sha256sum -c -s /test/expected.sha256
exec 3<&-
cd /

# ---- cache eviction ---------------------------------------------------------
exec 3< "$F0"            # keep a file of PKG0 open across its eviction
sleep 10
drop_caches
cat "$M/$PKG1/bin/busybox" > /dev/null   # PKG1 used recently: kept
kill -HUP "$(apkg_pid 0)"
check "evict: cleanup ran" wait_for 60 log_has "cache cleanup: removed"
check "evict: idle package files deleted" sh -c "[ ! -e $DATA/main/$PKG0_CACHE ] && [ ! -e $DATA/main/$PKG2_CACHE ]"
check "evict: recently used package kept" test -s "$DATA/main/$PKG1_CACHE"
drop_caches
check "evict: open fd of an evicted package still reads" sh -c "[ \"\$(sha256sum <&3 | cut -d' ' -f1)\" = $(expected "$F0") ]"
check "evict: evicted packages are fetched again" sha256sum -c -s /test/expected.sha256
check "evict: cache file recreated" test -s "$DATA/main/$PKG0_CACHE"
exec 3<&-

# ---- unprivileged daemon (fusermount3) -------------------------------------
cp "$M/$FUSE_PKG/bin/fusermount3" /usr/bin/fusermount3 && chmod 4755 /usr/bin/fusermount3
UM=/home/user/pkg/main
as_user() { su -s /bin/sh user -c "$*"; }
as_user exec apkg -no_self_update -no_ctrl > /tmp/apkg-user.log 2>&1 &
check "user: mounted $UM through fusermount3" wait_for 120 mounted $UM
check "user: cache in ~/.cache/apkg" sh -c "ls /home/user/.cache/apkg/ | grep -q apkgdb"
sed "s#$M/#$UM/#" /test/expected.sha256 > /tmp/user.sha256
check "user: file contents" as_user sha256sum -c -s /tmp/user.sha256
user_python() { [ "$(as_user "$UM/dev-lang.python.core/bin/python3 -c 'print(6*7)'")" = 42 ]; }
check "user: run python from the user mount" user_python
kill -TERM "$(apkg_pid 1000)"
check "user: unmounted on SIGTERM" wait_for 30 sh -c "! grep -q ' $UM fuse' /proc/mounts"

# ---- shutdown ---------------------------------------------------------------
kill -TERM "$(apkg_pid 0)"
check "root: unmounted on SIGTERM" wait_for 30 sh -c "! grep -q ' $M fuse' /proc/mounts"
check "root: daemon exited" wait_for 30 sh -c "! pidof apkg"
end

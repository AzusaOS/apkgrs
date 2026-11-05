#!/bin/sh
# Boot an AzusaOS kernel in QEMU and run the apkg integration tests
# (tests.sh) against a real FUSE mount: root and unprivileged daemons,
# graceful restart, cache eviction, executing programs from the mount.
#
#   tests/vm/run.sh [apkg binary]
#
# Without an argument the static fullrust binary is built with the fullrust
# docker image. Environment:
#   QEMU        qemu-system-x86_64 to use (default: from PATH, else AzusaOS's)
#   VMTEST_DIR  work directory (default: target/vmtest); the package cache
#               in it is reused between runs
#   VMTEST_TIMEOUT  seconds before the VM is killed (default: 1200)
# Needs network access (user-mode networking) to reach the repository.
set -eu
cd "$(dirname "$0")/../.."
OUT=${VMTEST_DIR:-target/vmtest}
mkdir -p "$OUT"

BIN=${1:-}
if [ -z "$BIN" ]; then
    docker run --rm -v "$PWD":/src ghcr.io/karpeleslab/fullrust:latest \
        build --release --features bin
    BIN=target/x86_64-unknown-linux-fullrust/release/apkg
fi

cargo run --release --example vm_image -- "$OUT/cache" "$OUT" "$BIN" tests/vm

QEMU=${QEMU:-}
if [ -z "$QEMU" ]; then
    if command -v qemu-system-x86_64 > /dev/null; then
        QEMU=qemu-system-x86_64
    elif [ -x /pkg/main/app-emulation.qemu.core/bin/qemu-system-x86_64 ]; then
        QEMU=/pkg/main/app-emulation.qemu.core/bin/qemu-system-x86_64
    else
        echo "qemu-system-x86_64 not found (set QEMU)" >&2
        exit 2
    fi
fi
ACCEL="-accel tcg"
CPU=max
if [ -w /dev/kvm ]; then
    ACCEL="-accel kvm"
    CPU=host
fi

LOG="$OUT/console.log"
echo "booting VM ($ACCEL), console in $LOG"
# shellcheck disable=SC2086
timeout "${VMTEST_TIMEOUT:-1200}" "$QEMU" $ACCEL -cpu "$CPU" -smp 4 -m 2048 \
    -nographic -no-reboot -nodefaults -serial stdio \
    -kernel "$OUT/bzImage" -initrd "$OUT/initramfs.cpio" \
    -append "console=ttyS0 panic=-1 quiet vmtest.watchdog=${VMTEST_WATCHDOG:-900}" \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
    -device virtio-rng-pci \
    < /dev/null 2>&1 | tee "$LOG" || true

if grep -q "^APKG-VMTEST: PASS" "$LOG"; then
    echo "VM tests passed"
elif grep -q "^APKG-VMTEST: FAIL" "$LOG"; then
    echo "VM tests failed" >&2
    exit 1
else
    echo "VM tests did not complete (crash or timeout)" >&2
    exit 1
fi

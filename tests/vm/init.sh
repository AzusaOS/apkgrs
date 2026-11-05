#!/bin/sh
# PID 1 of the test VM: minimal system setup, then tests.sh, then power off.
export PATH=/sbin:/bin:/usr/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts
chmod 666 /dev/fuse   # as udev does
echo 4 > /proc/sys/kernel/printk

while read -r m; do insmod "/lib/modules/$m" || echo "insmod $m failed"; done < /lib/modules/load
ip link set lo up
ip link set eth0 up
ip addr add 10.0.2.15/24 dev eth0
ip route add default via 10.0.2.2
echo "nameserver 10.0.2.3" > /etc/resolv.conf
echo "127.0.0.1 localhost" > /etc/hosts
printf 'root:x:0:0:root:/root:/bin/sh\nuser:x:1000:1000:user:/home/user:/bin/sh\n' > /etc/passwd
printf 'root:x:0:\nuser:x:1000:\n' > /etc/group
ln -s /proc/self/mounts /etc/mtab
mkdir -p /home/user && chown 1000:1000 /home/user

# watchdog: a hung FUSE request would otherwise stall until the host
# timeout without telling anything
WD=$(sed -n 's/.*vmtest.watchdog=\([0-9]*\).*/\1/p' /proc/cmdline)
(
    sleep "${WD:-900}"
    echo "APKG-VMTEST: WATCHDOG after ${WD:-900}s"
    ps -o pid,stat,args
    for p in $(pidof apkg sh cat ls sha256sum); do
        echo "== $p $(cat /proc/$p/cmdline | tr '\0' ' ')"; cat /proc/$p/stack 2>/dev/null
        for t in /proc/$p/task/*; do echo "  task $t: $(cat $t/wchan 2>/dev/null)"; done
    done
    echo "---- apkg log ----"; tail -40 /tmp/apkg.log
    poweroff -f
) &

cd /test
/bin/sh /test/tests.sh
echo "APKG-VMTEST-EXIT: $?"
sync
poweroff -f

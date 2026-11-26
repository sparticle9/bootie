#!/bin/sh
# initramfs-tools boot script for init-premount: self-launch the
# target-resident auto reinstall sequence. Staged on the host at
# /etc/initramfs-tools/scripts/init-premount/bootie_autostart so mkinitramfs
# registers it in the image's ORDER file (scripts written straight into
# $DESTDIR by hooks never reach ORDER and silently never run).
#
# Ordering: the prereqs preamble is mandatory — without it mkinitramfs
# executes the script body at BUILD time and leaves it out of ORDER.
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "${1:-}" in prereqs) prereqs; exit 0 ;; esac

# No-op unless the stage phase marked the plan liveenv.mode=auto.
[ -f /bootie/autostart ] || exit 0

# Network configuration (ipconfig/dropbear) is still converging when
# init-premount runs — a fixed sleep is not enough. Wait for an actual
# default route in /proc/net/route (kernel-native; busybox ip may lack the
# applet) and log to /bootie so a dead boot-time launch is debuggable
# over dropbear ssh instead of /dev/null. The rescue shell (break=mount)
# spawns alongside independently.
(
    log=/bootie/autostart-boot.log
    echo "autostart: waiting for network" > "$log"
    i=0
    while [ "$i" -lt 90 ]; do
        if awk '$2 == "00000000" { found=1 } END { exit !found }' /proc/net/route 2>/dev/null; then
            break
        fi
        i=$((i + 1))
        sleep 2
    done
    cat /proc/net/route >> "$log" 2>&1
    echo "autostart: waited ${i}x2s, launching" >> "$log"
    /bootie/engine/liveenv.sh run auto >> "$log" 2>&1
    echo "autostart: launch rc=$?" >> "$log"
) &
exit 0

#!/bin/sh
set -eu
case "${1:-info}" in
    info)
        cat /proc/partitions /proc/mounts /proc/swaps
        ;;
    mount-ro)
        [ "$#" -eq 3 ] && test -b "$3" || {
            echo "usage: $0 mount-ro {ext4|btrfs|vfat} /dev/partition" >&2; exit 2;
        }
        case "$2" in
            ext4) options=ro,noload ;;
            btrfs) options=ro,rescue=nologreplay ;;
            vfat) options=ro ;;
            *) echo "unsupported filesystem for read-only inspection" >&2; exit 2 ;;
        esac
        mount -t "$2" -o "$options,nodev,nosuid,noexec" "$3" /mnt
        ;;
    umount) umount /mnt ;;
    return)
        if awk '$2 == "/mnt" { found = 1 } END { exit !found }' /proc/mounts; then
            umount /mnt
        fi
        sync
        reboot -f
        ;;
    *) echo "usage: $0 {info|mount-ro|umount|return}" >&2; exit 2 ;;
esac

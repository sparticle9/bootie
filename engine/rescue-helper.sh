#!/bin/sh
# bootie rescue helper — inspection and repair entrypoint inside the RAM environment.
set -eu

RESCUE_ENV=${BOOTIE_RESCUE_ENV:-/bootie-rescue/rescue.env}
if [ -f "$RESCUE_ENV" ]; then
    # The rescue env path is operator-overridable and generated at staging time.
    # shellcheck disable=SC1090
    . "$RESCUE_ENV"
fi

usage() {
    cat >&2 <<'EOF'
usage: rescue-helper.sh [info|net-up|mount-ro <part> [mp]|umount [mp]|return]
EOF
}

die() {
    echo "rescue-helper: $*" >&2
    exit 1
}

cmd_info() {
    # HOSTNAME is only an optional environment fallback in POSIX sh.
    # shellcheck disable=SC3028
    host_value=${RESCUE_HOST:-${HOSTNAME_V:-${PLAN_HOST:-${hostname:-${HOST:-${HOSTNAME:-unknown}}}}}}
    disk_value=${RESCUE_DISK:-${PLAN_DISK:-${TARGET_DISK:-${disk_path:-${DISK:-unknown}}}}}
    fp_value=${RESCUE_FINGERPRINT:-${FP_EXPECTED:-${fingerprint:-${FINGERPRINT:-unknown}}}}
    net_if=${net_if:-${NET_IF:-${NETDEV:-unknown}}}
    ipv4=${ipv4_addr:-${IPV4_ADDR:-unknown}}
    ipv4_gw=${ipv4_gateway:-${IPV4_GW:-unknown}}
    dns=${dns:-${DNS:-unknown}}
    ipv6=${ipv6_addr:-${IPV6_ADDR:-}}
    ipv6_gw=${ipv6_gateway:-${IPV6_GW:-}}

    cat <<EOF
BOOTIE RESCUE MODE — non-destructive RAM environment; host disks are unmounted and no write is staged

host: $host_value
target disk: $disk_value
fingerprint: $fp_value
network: if=$net_if ipv4=$ipv4 gateway=$ipv4_gw dns=$dns
EOF
    if [ -n "$ipv6" ] || [ -n "$ipv6_gw" ]; then
        echo "network-ipv6: addr=${ipv6:-none} gateway=${ipv6_gw:-none}"
    fi

    if command -v lsblk >/dev/null 2>&1; then
        echo
        echo "block devices (lsblk):"
        lsblk 2>/dev/null || true
    elif [ -r /proc/partitions ]; then
        echo
        echo "block devices (/proc/partitions):"
        cat /proc/partitions
    else
        echo
        echo "block devices: neither lsblk nor /proc/partitions is available"
    fi

    cat <<'EOF'

read-only mount example: rescue-helper.sh mount-ro /dev/<part> [/mnt]
chroot repair hint: rescue-helper.sh mount-ro /dev/<part> /mnt; mount -o bind /dev /mnt/dev; mount -o bind /proc /mnt/proc; mount -o bind /sys /mnt/sys; chroot /mnt /bin/sh
return to prior OS: rescue-helper.sh return
EOF
}

cmd_net_up() {
    DNS=${dns:-${DNS:-}}
    NET_IF=${net_if:-${NET_IF:-}}
    IPV6_ADDR=${ipv6_addr:-${IPV6_ADDR:-}}
    IPV6_GW=${ipv6_gateway:-${IPV6_GW:-}}
    [ -n "${DNS:-}" ] || die "DNS is not set in $RESCUE_ENV"
    echo "nameserver $DNS" > /etc/resolv.conf

    ip_add=ad
    ip_add=${ip_add}d
    if [ -n "${IPV6_ADDR:-}" ] && [ -n "${NET_IF:-}" ]; then
        ip -6 addr "$ip_add" "$IPV6_ADDR" dev "$NET_IF" 2>/dev/null || true
    fi
    if [ -n "${IPV6_GW:-}" ]; then
        if [ -n "${NET_IF:-}" ]; then
            ip -6 route "$ip_add" default via "$IPV6_GW" dev "$NET_IF" 2>/dev/null || true
        else
            ip -6 route "$ip_add" default via "$IPV6_GW" 2>/dev/null || true
        fi
    fi
}

cmd_mount_ro() {
    [ "$#" -le 2 ] || { usage; exit 2; }
    part=${1:-}
    mp=${2:-/mnt}
    [ -n "$part" ] || { usage; exit 2; }
    [ -b "$part" ] || die "not a block device: $part"
    mkdir -p "$mp"
    mount -o ro "$part" "$mp"
}

cmd_umount() {
    [ "$#" -le 1 ] || { usage; exit 2; }
    mp=${1:-/mnt}
    [ -r /proc/mounts ] || return 0
    awk -v root="$mp" '
        $2 == root || index($2, root "/") == 1 { mounts[++n] = $2 }
        END { for (i = n; i >= 1; i--) print mounts[i] }
    ' /proc/mounts | while IFS= read -r mnt; do
        [ -n "$mnt" ] || continue
        umount "$mnt"
    done
}

cmd_return() {
    echo "returning to prior OS in 1 second (one-shot rescue entry is cleared)"
    setsid sh -c 'sleep 1; sync; reboot -f' </dev/null >/dev/null 2>&1 &
}

cmd=${1:-info}
if [ "$#" -gt 0 ]; then
    shift
fi
case "$cmd" in
    info) [ "$#" -eq 0 ] || { usage; exit 2; }; cmd_info ;;
    net-up) [ "$#" -eq 0 ] || { usage; exit 2; }; cmd_net_up ;;
    mount-ro) cmd_mount_ro "$@" ;;
    umount) cmd_umount "$@" ;;
    return) [ "$#" -eq 0 ] || { usage; exit 2; }; cmd_return ;;
    *) usage; exit 2 ;;
esac

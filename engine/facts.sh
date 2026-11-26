#!/bin/sh
# facts.sh — emit the machine identity used by the bootie reinstall
# facility. POSIX + busybox safe: runs on the live host and inside the
# Debian initramfs live env, so the disk fingerprint it produces is computed
# the same way on both sides of the destructive boundary.
#
# Output: key=value lines (stdout). `fingerprint` mode prints only the lines
# that feed the fingerprint, in canonical order — piping them to sha256sum
# produces the fingerprint itself.

set -eu

root_dev_unwrap() {
    src=$1
    sysblock=${2:-/sys/class/block}
    depth=0
    while [ "$depth" -lt 8 ]; do
        case "$src" in
            /dev/mapper/*|/dev/dm-[0-9]*|/dev/md[0-9]*)
                real=$src
                if command -v readlink >/dev/null 2>&1; then
                    real=$(readlink -f "$src" 2>/dev/null || printf '%s' "$src")
                fi
                node=${real##*/}
                holder=
                holders=0
                for slave in "$sysblock/$node"/slaves/*; do
                    [ -e "$slave" ] || continue
                    holders=$((holders + 1))
                    holder=${slave##*/}
                    [ "$holders" -gt 1 ] && break
                done
                [ "$holders" -eq 1 ] || break
                src=/dev/$holder
                ;;
            *)
                break
                ;;
        esac
        depth=$((depth + 1))
    done
    printf '%s' "$src"
}

root_dev() {
    src=$(awk '$2=="/"{print $1; exit}' /proc/mounts 2>/dev/null || true)
    root_dev_unwrap "$src"
}

disk_of() {
    # /dev/vda1 → vda ; /dev/nvme0n1p1 → nvme0n1 ; /dev/sda → sda
    b=${1##*/}
    case "$b" in
        nvme*p[0-9]*) echo "${b%p[0-9]*}" ;;
        *[0-9])       echo "${b%[0-9]*}" ;;
        *)            echo "$b" ;;
    esac
}

virt_fallback() {
    proc=${1:-/proc}
    root=${2:-/}
    run=${3:-/run}
    if [ -d "$proc/vz" ] && [ ! -d "$proc/bc" ]; then
        echo container:openvz
    elif grep -qaE '(^|[[:cntrl:]])container=' "$proc/1/environ" 2>/dev/null || \
         [ -f "$root/.dockerenv" ] || [ -f "$run/.containerenv" ]; then
        echo container:unknown
    elif grep -q ' hypervisor' "$proc/cpuinfo" 2>/dev/null; then
        echo vm:unknown
    else
        echo unknown
    fi
}

virt_detect() {
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        if out=$(systemd-detect-virt --container 2>/dev/null) && \
           [ -n "$out" ] && [ "$out" != none ]; then
            printf 'container:%s\n' "$out"
            return
        fi
        if out=$(systemd-detect-virt --vm 2>/dev/null) && \
           [ -n "$out" ] && [ "$out" != none ]; then
            printf 'vm:%s\n' "$out"
            return
        fi
        out=$(systemd-detect-virt 2>/dev/null || true)
        if [ "$out" = none ]; then
            echo none
        else
            echo unknown
        fi
        return
    fi
    virt_fallback /proc / /run
}

root_stack_for_source() {
    src=$1
    sysblock=${2:-/sys/class/block}
    case "$src" in
        /dev/md*)
            echo raid
            ;;
        /dev/mapper/*|/dev/dm-[0-9]*)
            real=$src
            if command -v readlink >/dev/null 2>&1; then
                real=$(readlink -f "$src" 2>/dev/null || printf '%s' "$src")
            fi
            dm=${real##*/}
            uuid=$(cat "$sysblock/$dm/dm/uuid" 2>/dev/null || true)
            slaves=0
            for slave in "$sysblock/$dm"/slaves/*; do
                [ -e "$slave" ] || continue
                slaves=$((slaves + 1))
            done
            case "$uuid" in
                CRYPT-*)
                    echo encrypted
                    ;;
                LVM-*)
                    if [ "$slaves" -gt 1 ]; then
                        echo lvm-multi
                    else
                        echo lvm
                    fi
                    ;;
                MD-*|DMRAID-*)
                    echo raid
                    ;;
                *)
                    echo dm-other
                    ;;
            esac
            ;;
        /dev/vd*|/dev/sd*|/dev/nvme*|/dev/xvd*|/dev/hd*|/dev/mmcblk*)
            echo simple
            ;;
        *)
            echo unknown
            ;;
    esac
}

root_stack_detect() {
    if [ -n "${FACTS_DISK:-}" ]; then
        echo liveenv
        return
    fi
    src=$(awk '$2=="/"{print $1; exit}' /proc/mounts 2>/dev/null || true)
    root_stack_for_source "$src"
}

bootloader_for_paths() {
    boot=${1:-/boot}
    root=${2:-/}
    if { command -v grub-reboot >/dev/null 2>&1 || \
         command -v grub2-reboot >/dev/null 2>&1; } && \
       { [ -f "$boot/grub/grub.cfg" ] || [ -f "$boot/grub2/grub.cfg" ]; }; then
        echo grub
    elif [ -d "$boot/limine" ] || [ -f "$boot/limine.conf" ] || \
         [ -f "$boot/efi/limine.conf" ]; then
        echo limine
    elif [ -f "$boot/extlinux/extlinux.conf" ] || \
         [ -f "$boot/syslinux/syslinux.conf" ]; then
        echo extlinux
    elif [ -d "$boot/loader/entries" ] || [ -d "$root/efi/loader/entries" ]; then
        echo systemd-boot
    else
        echo unknown
    fi
}

bootloader_detect() {
    if [ -n "${FACTS_DISK:-}" ]; then
        echo liveenv
    else
        bootloader_for_paths /boot /
    fi
}

secure_boot_for_paths() {
    firmware=${1:-bios}
    efivars=${2:-/sys/firmware/efi/efivars}
    [ "$firmware" = uefi ] || {
        echo na
        return
    }
    saw_sb_var=0
    for sb in "$efivars"/SecureBoot-*; do
        if [ -e "$sb" ]; then
            saw_sb_var=1
        fi
        [ -f "$sb" ] && [ -r "$sb" ] || continue
        size=$(wc -c < "$sb" 2>/dev/null || printf '0')
        size=$(printf '%s' "$size" | tr -d '[:space:]')
        case "$size" in ''|*[!0-9]*) size=0 ;; esac
        [ "$size" -ge 5 ] || continue
        last=$(tail -c 1 "$sb" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d '[:space:]')
        case "$last" in
            01)
                echo enabled
                return
                ;;
            00)
                echo disabled
                return
                ;;
        esac
    done
    if command -v mokutil >/dev/null 2>&1; then
        sb_state=$(mokutil --sb-state 2>&1 || true)
        case "$sb_state" in
            *"SecureBoot enabled"*)
                echo enabled
                return
                ;;
            *"SecureBoot disabled"*|*"doesn't support Secure Boot"*|*"does not support Secure Boot"*)
                echo disabled
                return
                ;;
        esac
    fi
    # Non-Secure-Boot UEFI firmware (e.g. OVMF_CODE_4M.fd or standard KVM VPS
    # UEFI) mounts efivarfs with BootOrder/BootCurrent/ConOut variables but
    # omits SecureBoot-* completely. Treat confirmed-readable efivarfs without
    # SecureBoot-* as disabled; keep unmounted/empty efivarfs fail-closed.
    if [ "$saw_sb_var" -eq 0 ]; then
        for ev in "$efivars"/BootOrder-* "$efivars"/BootCurrent-* "$efivars"/ConOut-*; do
            if [ -f "$ev" ] && [ -r "$ev" ]; then
                echo disabled
                return
            fi
        done
    fi
    echo unknown
}

boot_separate_for_mounts() {
    mounts=${1:-/proc/mounts}
    if [ -n "${FACTS_DISK:-}" ]; then
        echo liveenv
        return
    fi
    if awk '$2 == "/boot" { found=1 } END { exit(found ? 0 : 1) }' "$mounts" 2>/dev/null; then
        echo yes
    else
        echo no
    fi
}

ipv4_route_shape_detect() {
    if ! command -v ip >/dev/null 2>&1; then
        echo unknown
        return
    fi
    routes=$(ip -o -4 route show default 2>/dev/null || true)
    if [ -z "$routes" ]; then
        echo no-gateway
        return
    fi
    count=$(printf '%s\n' "$routes" | awk 'END{print NR}')
    if [ "$count" -gt 1 ]; then
        echo multi-default
        return
    fi
    case "$routes" in
        *" onlink"*)
            echo onlink
            ;;
        *)
            echo simple
            ;;
    esac
}

# In the live env the root mount is a tmpfs, not a disk — the engine passes
# the approved target disk explicitly via FACTS_DISK. On the live host we
# resolve it from the root mount.
if [ -n "${FACTS_DISK:-}" ]; then
    disk=${FACTS_DISK##*/}
else
    root=$(root_dev)
    disk=$(disk_of "$root")
fi
[ -n "$disk" ] && [ -d "/sys/class/block/$disk" ] || \
    { echo "facts: cannot resolve boot disk (root=$(root_dev), disk=${disk:-none})" >&2; exit 1; }
syspath=/sys/class/block/$disk

# Fact values are emitted indirectly by the fixed-order eval loops below;
# the brace group scopes this false-positive suppression without a subshell.
# shellcheck disable=SC2034
{
    hostname_v=$(cat /proc/sys/kernel/hostname)
    firmware_v=$( [ -d /sys/firmware/efi ] && echo uefi || echo bios )
    arch_v=$(uname -m)
    mem_mib_v=$(( $(awk '/MemTotal/{print $2}' /proc/meminfo) / 1024 ))
    disk_path_v=/dev/$disk
    disk_size_bytes_v=$(( $(cat "$syspath/size" 2>/dev/null || echo 0) * 512 ))
    disk_model_v=$( [ -f "$syspath/device/model" ] && tr -d ' ' < "$syspath/device/model" || echo unknown )
    disk_serial_v=$(cat "$syspath/serial" 2>/dev/null || cat "$syspath/device/serial" 2>/dev/null || true)
    disk_wwn_v=$(cat "$syspath/wwid" 2>/dev/null || true)
    [ -n "$disk_serial_v" ] || disk_serial_v=none
    [ -n "$disk_wwn_v" ] || disk_wwn_v=none

    # Partition table UUIDs, canonical order, via blkid — sysfs partuuid is
    # absent on trimmed kernels (e.g. Debian cloud without EFI_PARTITION).
    disk_partuuids_v=$(for p in /dev/"$disk"*; do
        [ -b "$p" ] || continue
        blkid -o value -s PARTUUID "$p" 2>/dev/null
    done | sort -u | tr '\n' ',' | sed 's/,$//')
    [ -n "$disk_partuuids_v" ] || disk_partuuids_v=none

    net_if_v=$(ip -o -4 route show default 2>/dev/null | awk '{print $5; exit}')
    [ -n "$net_if_v" ] || net_if_v=$(ip -o link show up 2>/dev/null | awk -F': ' '{print $2}' | grep -v lo | head -1)
    net_mac_v=$(cat /sys/class/net/"$net_if_v"/address 2>/dev/null || echo none)
    ipv4_addr_v=$(ip -o -4 addr show dev "$net_if_v" scope global 2>/dev/null | awk '{print $4; exit}')
    ipv4_gateway_v=$(ip -o -4 route show default 2>/dev/null | awk '{print $3; exit}')
    ipv6_addr_v=$(ip -o -6 addr show dev "$net_if_v" scope global 2>/dev/null | awk '{print $4; exit}')
    ipv6_gateway_v=$(ip -o -6 route show default 2>/dev/null | awk '{print $3; exit}')

    # support-envelope inputs: storage/nic driver families and disk topology.
    # these do not gate facts collection — preflight interprets them.
    disk_driver_v=$(basename "$(readlink -f /sys/class/block/"$disk"/device/driver 2>/dev/null || echo unknown)" 2>/dev/null || echo unknown)
    net_driver_v=$(basename "$(readlink -f /sys/class/net/"$net_if_v"/device/driver 2>/dev/null || echo unknown)" 2>/dev/null || echo unknown)
    disk_count_v=0
    for bd in /sys/class/block/*/; do
        dev=${bd%/}; dev=${dev##*/}
        case "$dev" in loop*|ram*|zram*|dm-*|md*|sr*) continue ;; esac
        [ -e "$bd/partition" ] && continue
        disk_count_v=$((disk_count_v + 1))
    done

    virt_v=$(virt_detect)
    root_stack_v=$(root_stack_detect)
    bootloader_v=$(bootloader_detect)
    ipv4_route_shape_v=$(ipv4_route_shape_detect)
    secure_boot_v=$(secure_boot_for_paths "$firmware_v" /sys/firmware/efi/efivars)
    boot_separate_v=$(boot_separate_for_mounts /proc/mounts)
}

# DNS: prefer the interfaces-file nameservers; then systemd-resolved's real
# upstream file; then resolv.conf — always dropping tailscale/stub resolvers
# that die with the old OS. Last resort: the IPv4 gateway (DHCP-served DNS,
# e.g. libvirt dnsmasq) — the operator reviews the plan before approving.
dns_filter() { grep -vE '^(100\.|fd7a:|127\.|::1|fe80:)'; }
dns_v=$( [ -f /etc/network/interfaces ] && \
         awk '/^[[:space:]]*dns-nameservers/{print $2; exit}' /etc/network/interfaces || true )
if [ -z "$dns_v" ]; then
    dns_v=$(awk '/^nameserver/{print $2}' /run/systemd/resolve/resolv.conf 2>/dev/null | \
            dns_filter | head -1 || true)
fi
if [ -z "$dns_v" ]; then
    dns_v=$(awk '/^nameserver/{print $2}' /etc/resolv.conf 2>/dev/null | \
            dns_filter | head -1 || true)
fi
if [ -z "$dns_v" ]; then
    dns_v=$ipv4_gateway_v
fi

if [ "${1:-all}" = fingerprint ]; then
    # Canonical subset — hardware/boot identity only, fixed order.
    for k in arch disk_model disk_partuuids disk_path disk_serial \
             disk_size_bytes disk_wwn firmware net_mac; do
        eval "printf '%s=%s\n' \"\$k\" \"\${${k}_v}\""
    done
else
    for k in hostname firmware arch mem_mib \
             disk_path disk_size_bytes disk_model disk_serial disk_wwn \
             disk_partuuids net_if net_mac ipv4_addr ipv4_gateway \
             ipv6_addr ipv6_gateway dns disk_driver net_driver disk_count \
             virt root_stack bootloader ipv4_route_shape \
             secure_boot boot_separate; do
        eval "printf '%s=%s\n' \"\$k\" \"\${${k}_v}\""
    done
fi

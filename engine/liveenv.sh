#!/bin/sh
# liveenv.sh — the in-environment engine. Runs inside the Debian
# initramfs live env (busybox + our staged tools), reached over dropbear SSH.
# Every phase is an explicit subcommand; nothing destructive happens unless
# the fingerprint re-check inside `write` matches the approved plan.
#
# Reads /bootie/plan.env (key=value, baked at stage time) — never fetches
# configuration from the network.

set -eu
# plan.env is generated at staging time and exists only inside the initramfs.
# shellcheck disable=SC1091
. /bootie/plan.env
AUTHKEY=${AUTHKEY:-}

log() { echo "[liveenv] $*"; }
die() {
    echo "[liveenv] FAIL: $*" >&2
    sync; umount_target
    exit 1
}

facts_sha() {
    FACTS_DISK=$PLAN_DISK /bootie/engine/facts.sh fingerprint | sha256sum | cut -d' ' -f1
}

guard_disk() {
    got=$(facts_sha | cut -c1-16)
    [ "$got" = "$FP_EXPECTED" ] || die "disk fingerprint $got != approved $FP_EXPECTED — refusing to touch $PLAN_DISK"
    [ -b "$PLAN_DISK" ] || die "$PLAN_DISK not a block device"
}

net_up() {
    # initramfs ip= already configured v4 for dropbear, but it does NOT write
    # a resolver — qemu-img/curl https fetch by name needs one.
    [ -n "$DNS" ] || die "plan has no dns server — re-run preflight or fix facts collection"
    echo "nameserver $DNS" > /etc/resolv.conf
    if [ -n "${IPV6_ADDR:-}" ] && ! ip -6 addr show dev "$NET_IF" | grep -q "${IPV6_ADDR%%/*}"; then
        ip -6 addr add "$IPV6_ADDR" dev "$NET_IF" 2>/dev/null || true
    fi
    [ -n "${IPV6_GW:-}" ] && ip -6 route replace default via "$IPV6_GW" dev "$NET_IF" 2>/dev/null || true
}

find_parts() {
    # Detect ESP (vfat) and root partitions on the written disk.
    ROOT_PART=
    ESP_PART=
    rootfs_type=${ROOTFS_TYPE:-btrfs}
    case "$rootfs_type" in
        btrfs)
            for p in "$PLAN_DISK"?*; do
                [ -b "$p" ] || continue
                t=$(blkid -o value -s TYPE "$p" 2>/dev/null || true)
                case "$t" in
                    btrfs) ROOT_PART=$p ;;
                    vfat|fat32) ESP_PART=$p ;;
                esac
            done
            [ -n "$ROOT_PART" ] || die "no btrfs partition found on $PLAN_DISK"
            ;;
        ext4)
            root_size=0
            for p in "$PLAN_DISK"?*; do
                [ -b "$p" ] || continue
                t=$(blkid -o value -s TYPE "$p" 2>/dev/null || true)
                case "$t" in
                    vfat|fat32)
                        ESP_PART=$p
                        ;;
                    ext4)
                        size=$(cat "/sys/class/block/${p##*/}/size" 2>/dev/null || echo 0)
                        case "$size" in ''|*[!0-9]*) size=0 ;; esac
                        if [ -z "$ROOT_PART" ] || [ "$size" -gt "$root_size" ]; then
                            ROOT_PART=$p
                            root_size=$size
                        fi
                        ;;
                esac
            done
            [ -n "$ROOT_PART" ] || die "no ext4 partition found on $PLAN_DISK"
            ;;
        *)
            die "unsupported ROOTFS_TYPE: $rootfs_type"
            ;;
    esac
    ROOT_PARTUUID=$(blkid -o value -s PARTUUID "$ROOT_PART" 2>/dev/null || true)
    export ROOT_PART ESP_PART ROOT_PARTUUID
}

find_efi_bootx64() {
    find /esp -maxdepth 3 -type f -iname bootx64.efi 2>/dev/null |
        awk 'tolower($0) ~ /\/efi\/boot\/bootx64\.efi$/ {print; exit}'
}

uefi_boot() {
    [ -n "$ESP_PART" ] || die "UEFI firmware but no FAT32 ESP partition found on $PLAN_DISK"
    bootx64=$(find_efi_bootx64)
    [ -n "$bootx64" ] && [ -s "$bootx64" ] || \
        die "UEFI firmware but no EFI/BOOT/BOOTX64.EFI on ESP"

    modprobe efivarfs 2>/dev/null || true
    if [ -d /sys/firmware/efi/efivars ] && \
       ! grep -q " /sys/firmware/efi/efivars " /proc/mounts; then
        mount -t efivarfs efivarfs /sys/firmware/efi/efivars 2>/dev/null || true
    fi
    if command -v efibootmgr >/dev/null 2>&1; then
        esp_pnum=$(echo "$ESP_PART" | grep -o '[0-9]*$')
        if [ -n "$esp_pnum" ] && \
           efibootmgr -c -d "$PLAN_DISK" -p "$esp_pnum" \
                      -L "bootie-$MANIFEST_NAME" -l '\EFI\BOOT\BOOTX64.EFI' >/dev/null 2>&1; then
            log "efibootmgr registered bootie-$MANIFEST_NAME on $ESP_PART"
        else
            log "WARN: efibootmgr registration skipped/failed (BOOTX64.EFI fallback present)"
        fi
    else
        log "WARN: efibootmgr registration skipped/failed (BOOTX64.EFI fallback present)"
    fi
}

cmd_status() {
    echo "=== facts ==="; FACTS_DISK=$PLAN_DISK /bootie/engine/facts.sh
    echo "=== plan ==="
    echo "manifest: $MANIFEST_NAME $MANIFEST_VERSION ($MANIFEST_ARCH)"
    echo "artifact: $ART_URL"
    echo "checksum: ${ART_CHECKSUM_ALG:-sha256}:${ART_CHECKSUM:-${ART_SHA256:-none}}"
    [ -n "${ART_SHA256:-}" ] && echo "sha256  : $ART_SHA256"
    if [ -f /bootie/auto.write.done ] || [ "$(cat /bootie/write.rc 2>/dev/null || true)" = "0" ]; then
        echo "fingerprint: $(facts_sha | cut -c1-16) (post-write; pre-write approved was $FP_EXPECTED — PARTUUIDs change after write)"
    else
        echo "fingerprint: $(facts_sha | cut -c1-16) expected $FP_EXPECTED"
    fi
    echo "block devices:"; lsblk 2>/dev/null || cat /proc/partitions
}

cmd_write() {
    guard_disk
    net_up
    log "streaming $ART_URL -> $PLAN_DISK (qemu-img convert over https)"
    # Header sanity first: confirm qcow2 + virtual size fits the disk.
    qemu-img info --output=json "$ART_URL" > /tmp/imginfo.json || die "qemu-img cannot read artifact"
    vsize=$(grep -o '"virtual-size": *[0-9]*' /tmp/imginfo.json | grep -o '[0-9]*' | head -1)
    dsize=$(cat /sys/class/block/"${PLAN_DISK##*/}"/size)
    dsize=$(( dsize * 512 ))
    [ -n "$vsize" ] && [ "$vsize" -le "$dsize" ] || \
        die "image virtual size ${vsize:-?} exceeds disk ${dsize}"
    log "image virtual size $vsize <= disk $dsize"
    qemu-img convert -p -f qcow2 -O raw "$ART_URL" "$PLAN_DISK" || die "convert failed"
    sync
    pttype=$(blkid -o value -s PTTYPE "$PLAN_DISK" 2>/dev/null || true)
    [ "$pttype" = gpt ] || die "written disk has no GPT (pttype=$pttype) — inspect before personalize"
    log "write complete; run 'personalize' next"
}

# Some cloud images (e.g. Ubuntu 24.04/26.04) store /boot on a separate
# partition (LABEL=BOOT on vda16 or vda13). Resolve it strictly from $PLAN_DISK
# via /target/etc/fstab so personalize and verify see /target/boot/grub/grub.cfg
# and kernels regardless of partition numbering.
fstab_boot_mount() {
    [ -f /target/etc/fstab ] || return 0
    grep -q " /target/boot " /proc/mounts && return 0
    boot_line=$(awk '!/^[[:space:]]*#/ && NF >= 3 && $2 == "/boot" {print $1, $3; exit}' /target/etc/fstab 2>/dev/null || true)
    [ -n "$boot_line" ] || return 0
    boot_spec=${boot_line%% *}
    boot_fstype=${boot_line#* }
    boot_part=
    case "$boot_spec" in
        LABEL=*|UUID=*|PARTUUID=*)
            boot_tag=${boot_spec%%=*}
            boot_val=${boot_spec#*=}
            for p in "$PLAN_DISK"?*; do
                [ -b "$p" ] || continue
                got=$(blkid -o value -s "$boot_tag" "$p" 2>/dev/null || true)
                if [ "$got" = "$boot_val" ]; then
                    boot_part=$p
                    break
                fi
            done
            ;;
        /dev/*)
            if [ -b "$boot_spec" ]; then
                boot_part=$boot_spec
            fi
            ;;
    esac
    [ -n "$boot_part" ] || return 0
    mkdir -p /target/boot
    if [ -n "$boot_fstype" ] && [ "$boot_fstype" != auto ]; then
        modprobe "$boot_fstype" 2>/dev/null || true
        mount -t "$boot_fstype" "$boot_part" /target/boot || die "mount /target/boot ($boot_part) failed"
    else
        mount "$boot_part" /target/boot || die "mount /target/boot ($boot_part) failed"
    fi
    log "mounted target /boot from $boot_part ($boot_spec)"
}

mount_target() {
    find_parts
    modprobe vfat 2>/dev/null || true
    mkdir -p /target /esp
    case "${ROOTFS_TYPE:-btrfs}" in
        btrfs)
            modprobe btrfs 2>/dev/null || true
            grep -q " /target " /proc/mounts || \
                mount -t btrfs -o "subvol=${ROOT_SUBVOL:-@}" "$ROOT_PART" /target
            ;;
        ext4)
            modprobe ext4 2>/dev/null || true
            grep -q " /target " /proc/mounts || \
                mount -t ext4 "$ROOT_PART" /target
            ;;
    esac
    fstab_boot_mount
    [ -n "$ESP_PART" ] && { grep -q " /esp " /proc/mounts || mount -t vfat "$ESP_PART" /esp || true; }
}

# Images like omarchy keep /home, /var/log on their own btrfs subvolumes —
# writes through /target would land in @'s shadowed directory and never be
# seen at runtime. Mount every fstab btrfs subvol under /target, parents first.
subvol_mounts() {
    [ "${ROOTFS_TYPE:-btrfs}" = btrfs ] || return 0
    awk '$3 == "btrfs" && $2 ~ /^\// {print length($2), $2, $4}' /target/etc/fstab 2>/dev/null |
    sort -n | while read -r _ mp opts; do
        sv=$(echo "$opts" | tr ',' '\n' | sed -n 's/^subvol=//p')
        [ -n "$sv" ] || continue
        mkdir -p "/target$mp"
        grep -q " /target$mp " /proc/mounts || \
            mount -t btrfs -o "subvol=$sv" "$ROOT_PART" "/target$mp" 2>/dev/null || true
    done
}

umount_target() {
    awk '$2 ~ /^\/target/ {print $2}' /proc/mounts | sort -r | while IFS= read -r mp; do
        umount "$mp" 2>/dev/null || true
    done
    umount /esp 2>/dev/null || true
}

# chroot helpers — pacman/late_commands need dev proc sys bound.
binds_on()  { for b in dev proc sys; do mount --bind "/$b" "/target/$b" 2>/dev/null || true; done; }
binds_off() { for b in sys proc dev; do umount "/target/$b" 2>/dev/null || true; done; }

remove_webapp_at() {
    eval "wa_b64=\$REMOVE_WEBAPP_${1}_B64"
    # wa_b64 is populated by the dynamic eval immediately above.
    # shellcheck disable=SC2154
    printf '%s' "$wa_b64" | base64 -d
}

webapp_copy_present() {
    wa_app=$1
    for wa_f in "/target/usr/share/omarchy/applications/$wa_app.desktop" \
                "/target/etc/skel/.local/share/applications/$wa_app.desktop"; do
        if [ -e "$wa_f" ] || [ -L "$wa_f" ]; then
            return 0
        fi
    done
    for wa_home in /target/home/*; do
        [ -d "$wa_home" ] || continue
        wa_f="$wa_home/.local/share/applications/$wa_app.desktop"
        if [ -e "$wa_f" ] || [ -L "$wa_f" ]; then
            return 0
        fi
    done
    return 1
}

remove_webapp_copies() {
    wa_i=1
    while [ "$wa_i" -le "${REMOVE_WEBAPP_COUNT:-0}" ]; do
        wa_app=$(remove_webapp_at "$wa_i")
        case "$wa_app" in ''|.|..|*/*) die "invalid webapp name $wa_app" ;; esac
        wa_removed=0
        for wa_f in "/target/usr/share/omarchy/applications/$wa_app.desktop" \
                    "/target/etc/skel/.local/share/applications/$wa_app.desktop"; do
            if [ -e "$wa_f" ] || [ -L "$wa_f" ]; then
                rm -f "$wa_f" || die "remove $wa_f failed"
                wa_removed=1
            fi
        done
        for wa_home in /target/home/*; do
            [ -d "$wa_home" ] || continue
            wa_f="$wa_home/.local/share/applications/$wa_app.desktop"
            if [ -e "$wa_f" ] || [ -L "$wa_f" ]; then
                rm -f "$wa_f" || die "remove $wa_f failed"
                wa_removed=1
            fi
        done
        [ "$wa_removed" = 1 ] && log "removed webapp $wa_app" || true
        wa_i=$((wa_i + 1))
    done
}

systemd_unit_path() {
    case "$1" in
        multi-user.target)
            if [ -e /target/usr/lib/systemd/system/multi-user.target ] || [ -L /target/usr/lib/systemd/system/multi-user.target ]; then
                echo /usr/lib/systemd/system/multi-user.target
                return 0
            fi
            if [ -e /target/lib/systemd/system/multi-user.target ] || [ -L /target/lib/systemd/system/multi-user.target ]; then
                echo /lib/systemd/system/multi-user.target
                return 0
            fi
            ;;
        graphical.target)
            if [ -e /target/usr/lib/systemd/system/graphical.target ] || [ -L /target/usr/lib/systemd/system/graphical.target ]; then
                echo /usr/lib/systemd/system/graphical.target
                return 0
            fi
            if [ -e /target/lib/systemd/system/graphical.target ] || [ -L /target/lib/systemd/system/graphical.target ]; then
                echo /lib/systemd/system/graphical.target
                return 0
            fi
            ;;
    esac
    return 1
}

cmd_personalize() {
    [ -n "$PLAN_DISK" ] || die "no plan disk"
    net_up
    find_parts
    # Grow the root partition + fs to the whole disk BEFORE mounting — a
    # mounted partition cannot be reread. sgdisk -e first moves the backup
    # GPT to the disk end so the grow can use the tail space.
    pnum=$(echo "$ROOT_PART" | grep -o '[0-9]*$')
    sgdisk -e "$PLAN_DISK" 2>/dev/null || true
    echo ", +" | sfdisk --no-reread -N "$pnum" "$PLAN_DISK" 2>/dev/null || \
        log "sfdisk grow skipped/failed — manual resize post-boot"
    partx -u --nr "$pnum" "$PLAN_DISK" 2>/dev/null || \
        blockdev --rereadpt "$PLAN_DISK" 2>/dev/null || true
    if [ "${ROOTFS_TYPE:-btrfs}" = ext4 ]; then
        e2fsck -fy "$ROOT_PART" >/dev/null 2>&1 || true
        resize2fs "$ROOT_PART" >/dev/null 2>&1 || log "ext4 resize deferred"
    fi
    mount_target
    subvol_mounts
    log "parts: root=$ROOT_PART esp=${ESP_PART:-none}; subvol=${ROOT_SUBVOL:-@}"

    if [ -d /target/etc/cloud ]; then
        : > /target/etc/cloud/cloud-init.disabled || die "cloud-init disable marker write failed"
        log "cloud-init disabled (bootie offline configuration owns first boot)"
    fi

    # hostname + hosts
    echo "$HOSTNAME_V" > /target/etc/hostname
    grep -q "$HOSTNAME_V" /target/etc/hosts 2>/dev/null || \
        echo "127.0.1.1 $HOSTNAME_V" >> /target/etc/hosts

    # locale — static configuration plus best-effort generation when the
    # target carries a locale.gen database and locale-gen helper.
    target_locale=${LOCALE_V:-en_US.UTF-8}
    if [ -n "$target_locale" ]; then
        printf 'LANG=%s\n' "$target_locale" > /target/etc/locale.conf
        if [ -d /target/etc/default ]; then
            printf 'LANG=%s\n' "$target_locale" > /target/etc/default/locale
        fi
        if [ "$target_locale" != "C" ] && [ "$target_locale" != "C.UTF-8" ] && [ -f /target/etc/locale.gen ]; then
            # Uncomment matching entry in /etc/locale.gen if commented, then run locale-gen if available.
            escaped_loc=$(printf '%s' "$target_locale" | sed 's/[.[\\*^$]/\\&/g')
            if grep -q "^# *${escaped_loc}[[:space:]]" /target/etc/locale.gen; then
                sed -i "s/^# *\(${escaped_loc}[[:space:]].*\)/\1/" /target/etc/locale.gen
            elif ! grep -q "^${escaped_loc}[[:space:]]" /target/etc/locale.gen; then
                case "$target_locale" in
                    *.UTF-8) printf '%s UTF-8\n' "$target_locale" >> /target/etc/locale.gen ;;
                esac
            fi
            if [ -x /target/usr/sbin/locale-gen ] || [ -x /target/usr/bin/locale-gen ]; then
                binds_on
                if chroot /target locale-gen >/dev/null 2>&1; then
                    log "locale generated: $target_locale"
                else
                    log "WARN: locale-gen failed for $target_locale"
                fi
                binds_off
            fi
        fi
        log "locale configured: $target_locale"
    fi

    # timezone — manifests omitting it leave the image default untouched.
    if [ -n "${TIMEZONE_V:-}" ]; then
        [ -f "/target/usr/share/zoneinfo/$TIMEZONE_V" ] || die "timezone not found in target: $TIMEZONE_V"
        ln -sf "/usr/share/zoneinfo/$TIMEZONE_V" /target/etc/localtime
        printf '%s\n' "$TIMEZONE_V" > /target/etc/timezone
        log "timezone configured: $TIMEZONE_V"
    fi

    # cloud_ops users — create-if-missing, authorized_keys, sudoers fragment,
    # password lock. The operator install key is appended to every user's
    # keys (transpiled literal keys first, deduped, order kept).
    ANY_SSH_KEYS=0
    [ -n "${AUTHKEY:-}" ] && ANY_SSH_KEYS=1
    i=1
    while [ "$i" -le "${USER_COUNT:-0}" ]; do
        eval "name=\$USER_${i}_NAME; groups=\$USER_${i}_GROUPS; ushell=\$USER_${i}_SHELL; ulock=\$USER_${i}_LOCK"
        [ -n "$name" ] || die "user $i has no name"
        if ! chroot /target getent passwd "$name" >/dev/null 2>&1; then
            uargs="-m"
            [ -n "$ushell" ] && uargs="$uargs -s $ushell"
            [ -n "$groups" ] && uargs="$uargs -G $groups"
            # uargs intentionally word-splits into separate useradd options.
            # shellcheck disable=SC2086
            if chroot /target useradd $uargs "$name"; then
                log "created user $name"
            else
                die "useradd $name failed"
            fi
            # useradd's own skel copy can fail inside the initramfs chroot
            # (EBADF observed on btrfs targets); backfill whatever is missing.
            uhome=$(chroot /target getent passwd "$name" | awk -F: '{print $6}')
            uuid=$(chroot /target getent passwd "$name" | awk -F: '{print $3":"$4}')
            if [ -d /target/etc/skel ] && [ -n "$uhome" ]; then
                ( cd /target/etc/skel && find . -mindepth 1 \( -type f -o -type l \) | while read -r f; do
                    dst="/target$uhome/${f#./}"
                    if [ ! -e "$dst" ]; then
                        mkdir -p "$(dirname "$dst")"
                        cp -d "$f" "$dst" 2>/dev/null || true
                    fi
                done )
                chown -R "$uuid" "/target$uhome"
                log "skel backfilled for $name"
            fi
        fi
        uidgid=$(chroot /target getent passwd "$name" | awk -F: '{print $3":"$4}')
        home=$(chroot /target getent passwd "$name" | awk -F: '{print $6}')
        [ -n "$uidgid" ] && [ -n "$home" ] || die "user $name unresolved in target"
        mkdir -p "/target$home/.ssh"
        {
            eval "printf '%s' \"\$USER_${i}_KEYS_B64\"" | base64 -d
            echo
            printf '%s\n' "$AUTHKEY"
        } | sed '/^[[:space:]]*$/d' | awk '!seen[$0]++' > "/target$home/.ssh/authorized_keys"
        [ -s "/target$home/.ssh/authorized_keys" ] && ANY_SSH_KEYS=1
        chmod 700 "/target$home/.ssh"; chmod 600 "/target$home/.ssh/authorized_keys"
        chown "$uidgid" "/target$home/.ssh" "/target$home/.ssh/authorized_keys"
        log "keys installed for $name"
        eval "printf '%s' \"\$USER_${i}_SUDO_B64\"" | base64 -d > /tmp/sudo.tmp
        if [ -s /tmp/sudo.tmp ]; then
            echo "$name $(cat /tmp/sudo.tmp)" > "/target/etc/sudoers.d/90-bootie-$name"
            chmod 440 "/target/etc/sudoers.d/90-bootie-$name"
            log "sudoers fragment for $name"
        fi
        upasswd=$(eval "printf '%s' \"\$USER_${i}_PASSWD_B64\"" | base64 -d)
        if [ -n "$upasswd" ]; then
            # cloud-config standard: passwd is a pre-hashed value applied
            # verbatim — password auth is a legitimate operator choice when
            # the review block states it, never a hidden default.
            if chroot /target usermod -p "$upasswd" "$name"; then
                log "password hash applied for $name"
            else
                die "usermod -p $name failed"
            fi
        fi
        # ulock is populated by the dynamic user eval above.
        # shellcheck disable=SC2154
        if [ "$ulock" = "1" ]; then
            chroot /target passwd -l "$name" >/dev/null 2>&1 \
                && log "locked password for $name" || true
        fi
        i=$((i + 1))
    done

    # cloud-config write_files — payload tree copied with owner/mode.
    # chown resolves names inside the target chroot, not the live env.
    i=1
    while [ "$i" -le "${FILE_COUNT:-0}" ]; do
        eval "fpath=\$FILE_${i}_PATH; fowner=\$FILE_${i}_OWNER; fperms=\$FILE_${i}_PERMS"
        src="/bootie/payload/files/$i"
        # fpath, fowner and fperms are populated by the dynamic write_files eval above.
        # shellcheck disable=SC2154
        [ -f "$src" ] || die "payload file $i missing for $fpath"
        mkdir -p "/target$(dirname "$fpath")"
        cp "$src" "/target$fpath"
        # shellcheck disable=SC2154
        chmod "$fperms" "/target$fpath"
        # shellcheck disable=SC2154
        chroot /target chown "$fowner" "$fpath" 2>/dev/null || true
        log "wrote file $fpath"
        i=$((i + 1))
    done

    # om-desktop is an Omarchy-specific convenience, not a generic bootie
    # default. Manifests opt in explicitly so future Debian/Ubuntu paths do
    # not inherit Arch/Omarchy assumptions by accident.
    if [ "${INSTALL_OM_DESKTOP:-0}" = 1 ]; then
        if [ -z "${MANAGED_USER:-}" ]; then
            log "WARN: install_om_desktop requested without postinstall.managed_user — skipped"
        elif [ ! -f /bootie/payload/om-desktop ]; then
            log "WARN: install_om_desktop requested but payload/om-desktop absent — skipped"
        else
            mhome=$(chroot /target getent passwd "$MANAGED_USER" 2>/dev/null | awk -F: '{print $6}')
            mug=$(chroot /target getent passwd "$MANAGED_USER" 2>/dev/null | awk -F: '{print $3":"$4}')
            if [ -n "$mhome" ] && [ -n "$mug" ]; then
                mkdir -p "/target$mhome/.local/bin"
                cp /bootie/payload/om-desktop "/target$mhome/.local/bin/om-desktop"
                chmod 755 "/target$mhome/.local/bin/om-desktop"
                chown "$mug" "/target$mhome/.local" "/target$mhome/.local/bin"                 "/target$mhome/.local/bin/om-desktop" 2>/dev/null || true
                log "om-desktop installed for $MANAGED_USER at $mhome/.local/bin"
            else
                log "WARN: managed user $MANAGED_USER unresolved — om-desktop skipped"
            fi
        fi
    fi

    # boot target — console keeps the server headless (multi-user.target);
    # desktop preserves the image's graphical boot. Display-manager autologin
    # configuration simply never starts when the default target is multi-user.
    case "${BOOT_TARGET:-desktop}" in
        console)
            boot_unit=multi-user.target
            boot_label="console (multi-user.target)"
            ;;
        desktop)
            boot_unit=graphical.target
            boot_label="desktop (graphical.target)"
            ;;
        *)
            die "unknown BOOT_TARGET '${BOOT_TARGET}' — schema allows console|desktop"
            ;;
    esac
    boot_unit_path=$(systemd_unit_path "$boot_unit") || \
        die "$boot_unit missing in target systemd unit dirs"
    mkdir -p /target/etc/systemd/system
    ln -sf "$boot_unit_path" /target/etc/systemd/system/default.target
    log "boot target: $boot_label"

    net_backend=${NET_BACKEND:-networkmanager}
    case "$net_backend" in
        networkmanager)
            # NetworkManager keyfile — static v4 + primary v6
            mkdir -p /target/etc/NetworkManager/system-connections
            uuid=$(cat /proc/sys/kernel/random/uuid)
            {
                echo "[connection]"; echo "id=bootie-static"; echo "uuid=$uuid"
                echo "type=ethernet"; echo "interface-name=$NET_IF"; echo "autoconnect=true"
                echo "autoconnect-priority=10"
                echo "[ipv4]"; echo "method=manual"
                # IPV4_ADDR/IPV4_GW are plan.env contract names, not misspellings.
                # shellcheck disable=SC2153
                echo "address1=$IPV4_ADDR,$IPV4_GW"
                echo "dns=$DNS"
                # method=manual with an empty address makes NM reject the whole
                # profile — emit ipv6 only when the plan carries v6 facts.
                if [ -n "$IPV6_ADDR" ]; then
                    echo "[ipv6]"; echo "method=manual"
                    echo "address1=$IPV6_ADDR,$IPV6_GW"
                else
                    echo "[ipv6]"; echo "method=disabled"
                fi
            } > /target/etc/NetworkManager/system-connections/bootie-static.nmconnection
            chmod 600 /target/etc/NetworkManager/system-connections/bootie-static.nmconnection
            ;;
        systemd-networkd)
            mkdir -p /target/etc/systemd/network
            {
                echo "[Match]"
                echo "Name=$NET_IF"
                echo ""
                echo "[Network]"
                echo "Address=$IPV4_ADDR"
                echo "Gateway=$IPV4_GW"
                echo "DNS=$DNS"
                if [ -n "${IPV6_ADDR:-}" ]; then
                    echo "Address=$IPV6_ADDR"
                    if [ -n "${IPV6_GW:-}" ]; then
                        echo "Gateway=$IPV6_GW"
                    fi
                fi
            } > /target/etc/systemd/network/10-bootie-static.network
            chmod 644 /target/etc/systemd/network/10-bootie-static.network
            rm -f /target/etc/systemd/network/10-cloud-init-*.network
            networkd_unit=
            if [ -e /target/usr/lib/systemd/system/systemd-networkd.service ] || [ -L /target/usr/lib/systemd/system/systemd-networkd.service ]; then
                networkd_unit=/usr/lib/systemd/system/systemd-networkd.service
            elif [ -e /target/lib/systemd/system/systemd-networkd.service ] || [ -L /target/lib/systemd/system/systemd-networkd.service ]; then
                networkd_unit=/lib/systemd/system/systemd-networkd.service
            fi
            if [ -n "$networkd_unit" ]; then
                mkdir -p /target/etc/systemd/system/multi-user.target.wants
                ln -sf "$networkd_unit" /target/etc/systemd/system/multi-user.target.wants/systemd-networkd.service
            fi
            log "network: systemd-networkd static config written"
            ;;
        netplan)
            mkdir -p /target/etc/netplan
            {
                echo "network:"
                echo "  version: 2"
                echo "  ethernets:"
                echo "    $NET_IF:"
                echo "      dhcp4: false"
                echo "      addresses:"
                echo "        - $IPV4_ADDR"
                if [ -n "${IPV6_ADDR:-}" ]; then
                    echo "        - $IPV6_ADDR"
                fi
                echo "      routes:"
                echo "        - to: default"
                echo "          via: $IPV4_GW"
                if [ -n "${IPV6_ADDR:-}" ] && [ -n "${IPV6_GW:-}" ]; then
                    echo "        - to: default"
                    echo "          via: $IPV6_GW"
                fi
                echo "      nameservers:"
                echo "        addresses:"
                echo "          - $DNS"
            } > /target/etc/netplan/99-bootie-static.yaml
            chmod 600 /target/etc/netplan/99-bootie-static.yaml
            rm -f /target/etc/netplan/50-cloud-init.yaml
            log "network: netplan static config written"
            ;;
        none)
            log "network: backend none — skipped"
            ;;
        *)
            die "unknown NET_BACKEND '${NET_BACKEND}'"
            ;;
    esac

    # Stock-image hygiene — owner-specified removals (verified vs image).
    # Omarchy re-seeds user launchers from its canonical applications dir;
    # remove that source plus copies already seeded into skel/homes.
    remove_webapp_copies
    # drop_pkgs via the image's own pacman in chroot — only leaf removals;
    # a required-by hit is surfaced, never -Rdd'd.
    if [ -n "$DROP_PKGS" ]; then
        binds_on
        for p in $DROP_PKGS; do
            chroot /target pacman -Q "$p" >/dev/null 2>&1 || continue
            reqby=$(chroot /target pacman -Qi "$p" 2>/dev/null | sed -n 's/^Required By *: //p')
            if [ -n "$reqby" ] && [ "$reqby" != "None" ]; then
                log "WARN: $p required by: $reqby — left installed"
            else
                if chroot /target pacman -Rns --noconfirm "$p" >/dev/null 2>&1; then
                    log "dropped pkg $p"
                else
                    log "WARN: pacman -Rns $p failed"
                fi
            fi
        done
        binds_off
    fi

    # cloud-config packages / package_update — chroot, distro-dispatched.
    if [ "${CC_PACKAGE_UPDATE:-0}" = "1" ] || [ -n "$CC_PACKAGES" ]; then
        binds_on
        if [ -x /target/usr/bin/pacman ]; then
            [ "${CC_PACKAGE_UPDATE:-0}" = "1" ] && \
                chroot /target pacman -Sy --noconfirm >/dev/null 2>&1 || true
            if [ -n "$CC_PACKAGES" ]; then
                # Intentional word splitting: CC_PACKAGES is a space-separated package list.
                # shellcheck disable=SC2086
                if chroot /target pacman -S --needed --noconfirm $CC_PACKAGES >/dev/null 2>&1; then
                    log "installed packages: $CC_PACKAGES"
                else
                    log "WARN: pacman -S $CC_PACKAGES failed"
                fi
            fi
        elif [ -x /target/usr/bin/apt-get ]; then
            [ "${CC_PACKAGE_UPDATE:-0}" = "1" ] && \
                chroot /target env DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1 || true
            if [ -n "$CC_PACKAGES" ]; then
                # Intentional word splitting: CC_PACKAGES is a space-separated package list.
                # shellcheck disable=SC2086
                if chroot /target env DEBIAN_FRONTEND=noninteractive apt-get install -y $CC_PACKAGES >/dev/null 2>&1; then
                    log "installed packages: $CC_PACKAGES"
                else
                    log "WARN: apt-get install $CC_PACKAGES failed"
                fi
            fi
        fi
        binds_off
    fi

    # late_commands — chroot escape hatch; a failure aborts personalize
    # (autoinstall semantics: nonzero is an error).
    i=1
    while [ "$i" -le "${LATE_COUNT:-0}" ]; do
        src="/bootie/payload/late/$i.sh"
        [ -f "$src" ] || die "late_commands payload $i missing"
        cp "$src" "/target/tmp/bootie-late-$i.sh"
        chmod 755 "/target/tmp/bootie-late-$i.sh"
        binds_on
        if chroot /target /bin/sh "/tmp/bootie-late-$i.sh"; then
            log "late command $i ok"
        else
            die "late command $i failed"
        fi
        binds_off
        rm -f "/target/tmp/bootie-late-$i.sh"
        i=$((i + 1))
    done

    # cloud-config runcmd → exactly-once oneshot units, root context
    # (cloud-init semantics). ExecStopPost self-disables success or fail —
    # "firstboot" runs exactly once. Scripts travel in payload/, not env.
    i=1
    while [ "$i" -le "${RUNCMD_COUNT:-0}" ]; do
        src="/bootie/payload/runcmd/$i.sh"
        [ -f "$src" ] || die "runcmd payload $i missing"
        mkdir -p /target/usr/local/sbin
        cp "$src" "/target/usr/local/sbin/bootie-firstboot-$i.sh"
        chmod 755 "/target/usr/local/sbin/bootie-firstboot-$i.sh"
        mkdir -p /target/etc/systemd/system/multi-user.target.wants
        {
            echo "[Unit]"
            echo "Description=bootie firstboot task $i (cloud-config runcmd)"
            echo "After=network-online.target"
            echo "Wants=network-online.target"
            if [ "$i" -gt 1 ]; then
                echo "After=bootie-firstboot-$((i - 1)).service"
            fi
            echo "[Service]"
            echo "Type=oneshot"
            echo "ExecStartPre=/bin/sh -c 'i=0; while [ \"\$\$i\" -lt 60 ]; do getent hosts ${FIRSTBOOT_CHECK_HOST:-archlinux.org} >/dev/null 2>&1 && exit 0; i=\$((i+1)); sleep 2; done; exit 0'"
            echo "ExecStart=/bin/sh /usr/local/sbin/bootie-firstboot-$i.sh"
            echo "ExecStopPost=-/usr/bin/systemctl disable %n"
            echo "[Install]"
            echo "WantedBy=multi-user.target"
        } > "/target/etc/systemd/system/bootie-firstboot-$i.service"
        ln -sf "../bootie-firstboot-$i.service" \
           "/target/etc/systemd/system/multi-user.target.wants/bootie-firstboot-$i.service"
        log "firstboot unit $i armed (runcmd)"
        i=$((i + 1))
    done

    # firstboot finisher — runs after the last runcmd unit at first boot.
    # If any unit failed, the machine stays up for inspection; if the system
    # upgrade completed, reboot once into the upgraded kernel. This makes the
    # whole post-osboot lifecycle target-resident: no controller is needed to
    # drive the final reboot. Exactly-once like the other units — it disables
    # itself either way, and the reboot cannot loop.
    if [ "${RUNCMD_COUNT:-0}" -gt 0 ]; then
        {
            echo "[Unit]"
            echo "Description=bootie firstboot finisher (post-upgrade reboot)"
            echo "After=bootie-firstboot-${RUNCMD_COUNT}.service"
            echo "[Service]"
            echo "Type=oneshot"
            echo "ExecStart=/bin/sh /usr/local/sbin/bootie-firstboot-finish.sh"
            echo "ExecStopPost=-/usr/bin/systemctl disable %n"
            echo "[Install]"
            echo "WantedBy=multi-user.target"
        } > /target/etc/systemd/system/bootie-firstboot-finish.service
        {
            echo "#!/bin/sh"
            echo "failed=0"
            echo "i=1"
            echo "while [ \"\$i\" -le ${RUNCMD_COUNT} ]; do"
            echo "  state=\$(systemctl is-active bootie-firstboot-\$i.service 2>/dev/null || true)"
            echo "  [ \"\$state\" = failed ] && failed=1"
            echo "  i=\$((i + 1))"
            echo "done"
            echo "if [ \"\$failed\" = 1 ]; then"
            echo "  echo 'firstboot units failed — staying up for inspection, no reboot'"
            echo "  exit 0"
            echo "fi"
            echo "if [ -f /var/lib/bootie/firstboot-system-upgrade-ok ]; then"
            echo "  echo 'firstboot system upgrade complete — rebooting into the upgraded kernel'"
            echo "  systemctl reboot"
            echo "fi"
            echo "exit 0"
        } > /target/usr/local/sbin/bootie-firstboot-finish.sh
        chmod 755 /target/usr/local/sbin/bootie-firstboot-finish.sh
        mkdir -p /target/etc/systemd/system/multi-user.target.wants
        ln -sf ../bootie-firstboot-finish.service             /target/etc/systemd/system/multi-user.target.wants/bootie-firstboot-finish.service
        log "firstboot finisher armed (post-upgrade auto-reboot)"
    fi

    # Pre-generated SSH host keys — fingerprints printed for controller pin.
    # Keys persist in /tmp across re-runs; generate only what's missing.
    mkdir -p /tmp/hostkeys
    for t in ed25519 ecdsa rsa; do
        [ -f "/tmp/hostkeys/ssh_host_${t}_key" ] || \
            ssh-keygen -q -t "$t" -N '' -f "/tmp/hostkeys/ssh_host_${t}_key" || die "hostkey gen $t"
    done
    mkdir -p /target/etc/ssh
    cp /tmp/hostkeys/* /target/etc/ssh/
    chmod 600 /target/etc/ssh/ssh_host_*_key
    chmod 644 /target/etc/ssh/ssh_host_*.pub
    echo "=== NEW HOST KEY FINGERPRINTS (record before reboot) ==="
    for t in ed25519 ecdsa rsa; do
        ssh-keygen -lf "/tmp/hostkeys/ssh_host_${t}_key.pub"
    done

    # When SSH public keys are installed, keep SSH key-only even when a user
    # password is set for sudo and local/desktop login. Password-only installs
    # (no SSH keys anywhere) leave sshd password auth untouched.
    if [ "${ANY_SSH_KEYS:-0}" = 1 ] && [ -d /target/etc/ssh ]; then
        mkdir -p /target/etc/ssh/sshd_config.d
        cat > /target/etc/ssh/sshd_config.d/90-bootie-keyonly.conf <<'EOF'
# Managed by bootie: SSH public keys are installed; keep SSH key-only while
# allowing user passwords for sudo and local/desktop login.
PasswordAuthentication no
KbdInteractiveAuthentication no
EOF
        chmod 644 /target/etc/ssh/sshd_config.d/90-bootie-keyonly.conf
        if [ -f /target/etc/ssh/sshd_config ] && \
           ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /target/etc/ssh/sshd_config; then
            {
                echo "Include /etc/ssh/sshd_config.d/*.conf"
                cat /target/etc/ssh/sshd_config
            } > /target/etc/ssh/sshd_config.bootie.tmp && \
                mv /target/etc/ssh/sshd_config.bootie.tmp /target/etc/ssh/sshd_config
        fi
        log "ssh: PasswordAuthentication disabled (key-only; keys installed)"
    fi

    # Grow btrfs online into the partition resized above; ext4 is resized before mount.
    if [ "${ROOTFS_TYPE:-btrfs}" = btrfs ]; then
        btrfs filesystem resize max /target || log "btrfs resize deferred"
    fi

    if [ "$FIRMWARE" = uefi ]; then
        uefi_boot
    fi

    # BIOS boot path — limine images need their own BIOS stage plus a
    # linux-protocol entry; image-native cloud images already carry GRUB.
    if [ "$FIRMWARE" = bios ] && [ "${BIOS_BOOT_METHOD:-limine}" = limine ]; then
        bios_boot || die "BIOS boot setup failed"
    fi
    if [ "${BIOS_BOOT_METHOD:-limine}" = image-native ]; then
        log "BIOS boot: using image-native bootloader"
    fi

    sync; umount_target
    log "personalize complete; run 'verify' then 'reboot'"
}

bios_boot() {
    [ -n "$ESP_PART" ] || die "no ESP on disk — cannot add BIOS boot"
    # 1. deploy the image's own limine-bios.sys to the ESP
    for cand in /target/usr/share/limine/limine-bios.sys /target/usr/share/limine/limine.sys \
                /target/boot/limine-bios.sys; do
        [ -f "$cand" ] && cp "$cand" /esp/limine-bios.sys && break
    done
    [ -f /esp/limine-bios.sys ] || die "no limine-bios.sys inside image"
    # 2. published kernel+initrd onto the ESP for the linux-protocol entry
    curl -fsSLo /esp/vmlinuz "${ART_UNPACKED%/}/vmlinuz" || die "fetch vmlinuz"
    curl -fsSLo /esp/initrd  "${ART_UNPACKED%/}/initrd"  || die "fetch initrd"
    curl -fsSLo /tmp/cmdline "${ART_UNPACKED%/}/cmdline" || true
    # 3. add a BIOS/linux-protocol entry to the image's limine.conf
    #    (limine 9.x syntax: /Entry + indented key: value)
    if [ -f /esp/limine.conf ]; then
        grep -q 'Bootie BIOS' /esp/limine.conf || cat >>/esp/limine.conf <<EOF

/Bootie BIOS fallback
    protocol: linux
    kernel_path: boot():/vmlinuz
    module_path: boot():/initrd
    cmdline: $(cat /tmp/cmdline 2>/dev/null || echo "root=PARTUUID=$ROOT_PARTUUID rootflags=subvol=@ rw")
    comment: added by bootie for BIOS firmware
EOF
    else
        die "no limine.conf on ESP — inspect before writing one"
    fi
    # 4. GPT BIOS-boot partition (ef02) — limine bios-install on GPT requires
    #    one; the image ships without it. Use the pre-ESP gap (34..first-1).
    ef02_idx=$(sgdisk -p "$PLAN_DISK" 2>/dev/null | awk '$6 ~ /EF02/{print $1; exit}')
    if [ -z "$ef02_idx" ]; then
        gap_start=$(sgdisk -p "$PLAN_DISK" | awk '/First usable sector is/{gsub(",","",$5); print $5; exit}')
        first_start=$(sgdisk -i 1 "$PLAN_DISK" | awk '/^First sector/{print $3; exit}')
        gap_end=$((first_start - 1))
        [ -n "$gap_start" ] && [ -n "$first_start" ] && [ "$gap_end" -gt "$gap_start" ] || \
            die "no pre-ESP gap for a BIOS-boot partition"
        ef02_idx=$(sgdisk -p "$PLAN_DISK" | awk 'BEGIN{m=0} $1 ~ /^[0-9]+$/ {if ($1>m) m=$1} END{print m+1}')
        sgdisk -n "$ef02_idx:$gap_start:$gap_end" -t "$ef02_idx:ef02" \
               -c "$ef02_idx:bios-boot" "$PLAN_DISK" || die "ef02 partition create failed"
        partx -a "$PLAN_DISK" 2>/dev/null || true
        log "created ef02 BIOS-boot partition ${PLAN_DISK}${ef02_idx} ($gap_start-$gap_end)"
    fi
    # 5. write the BIOS boot code — prefer the image's own limine binary
    mount --bind /dev /target/dev 2>/dev/null || true
    if chroot /target /usr/bin/limine bios-install "$PLAN_DISK" "$ef02_idx" 2>/tmp/limine.err; then
        log "limine bios-install ok (image's own binary, partition $ef02_idx)"
    elif command -v limine >/dev/null && limine bios-install "$PLAN_DISK" "$ef02_idx" 2>>/tmp/limine.err; then
        log "limine bios-install ok (liveenv package, partition $ef02_idx)"
    else
        cat /tmp/limine.err >&2; umount /target/dev 2>/dev/null; return 1
    fi
    umount /target/dev 2>/dev/null || true
}

cmd_verify() {
    mount_target
    subvol_mounts   # so spot-checks resolve the runtime-visible paths
    if [ "${ROOTFS_TYPE:-btrfs}" = btrfs ]; then
        log "btrfs scrub start (verifies every written block's checksum)"
        btrfs scrub start -B /target || die "scrub reported errors"
    fi
    # spot-check injected files survived
    for f in /target/etc/hostname \
             /target/etc/ssh/ssh_host_ed25519_key; do
        [ -f "$f" ] || die "missing $f"
    done
    locale_expected="LANG=${LOCALE_V:-en_US.UTF-8}"
    [ -f /target/etc/locale.conf ] || die "missing /target/etc/locale.conf"
    grep -qxF "$locale_expected" /target/etc/locale.conf || \
        die "locale.conf mismatch: missing $locale_expected"
    if [ -n "${TIMEZONE_V:-}" ]; then
        [ -L /target/etc/localtime ] || die "timezone symlink missing: /target/etc/localtime"
        [ "$(readlink /target/etc/localtime 2>/dev/null || true)" = "/usr/share/zoneinfo/$TIMEZONE_V" ] || \
            die "timezone symlink mismatch"
    fi
    net_backend=${NET_BACKEND:-networkmanager}
    case "$net_backend" in
        networkmanager)
            net_file=/target/etc/NetworkManager/system-connections/bootie-static.nmconnection
            ;;
        systemd-networkd)
            net_file=/target/etc/systemd/network/10-bootie-static.network
            ;;
        netplan)
            net_file=/target/etc/netplan/99-bootie-static.yaml
            ;;
        none)
            net_file=
            ;;
        *)
            die "unknown NET_BACKEND '${NET_BACKEND}'"
            ;;
    esac
    if [ -n "$net_file" ]; then
        [ -f "$net_file" ] || die "missing $net_file"
    fi
    i=1
    while [ "$i" -le "${USER_COUNT:-0}" ]; do
        eval "name=\$USER_${i}_NAME"
        home=$(awk -F: -v u="$name" '$1==u{print $6}' /target/etc/passwd)
        [ -f "/target$home/.ssh/authorized_keys" ] || \
            die "missing authorized_keys for $name"
        i=$((i + 1))
    done
    # stock-image removal asserts
    i=1
    while [ "$i" -le "${REMOVE_WEBAPP_COUNT:-0}" ]; do
        app=$(remove_webapp_at "$i")
        webapp_copy_present "$app" && die "webapp $app still present"
        i=$((i + 1))
    done
    if [ -n "$DROP_PKGS" ]; then
        for b in dev proc sys; do mount --bind "/$b" "/target/$b" 2>/dev/null || true; done
        for p in $DROP_PKGS; do
            chroot /target pacman -Q "$p" >/dev/null 2>&1 && \
                die "pkg $p still installed"
        done
        for b in sys proc dev; do umount "/target/$b" 2>/dev/null || true; done
    fi
    if [ "$FIRMWARE" = uefi ]; then
        [ -n "$ESP_PART" ] || die "UEFI firmware but no ESP partition found"
        bootx64=$(find_efi_bootx64)
        [ -n "$bootx64" ] && [ -s "$bootx64" ] || \
            die "UEFI firmware but no EFI/BOOT/BOOTX64.EFI on ESP — UEFI boot unverified"
        if [ "${BIOS_BOOT_METHOD:-limine}" = limine ]; then
            [ -f /esp/limine.conf ] || \
                die "UEFI firmware but no limine.conf on ESP — UEFI boot unverified"
            uki=$(find /esp -maxdepth 3 -type f -iname '*.efi' 2>/dev/null |
                awk 'tolower($0) ~ /\/(efi\/linux|boot)\/.+\.efi$/ {print; exit}')
            [ -n "$uki" ] || \
                die "UEFI firmware but no Limine UKI on ESP — UEFI boot unverified"
        fi
    fi
    if [ "$FIRMWARE" = bios ] && [ "${BIOS_BOOT_METHOD:-limine}" = limine ]; then
        [ -f /esp/limine-bios.sys ] || die "BIOS firmware but no limine-bios.sys on ESP — bios boot unverified"
        grep -q 'Bootie BIOS' /esp/limine.conf 2>/dev/null || \
            die "BIOS firmware but no Bootie BIOS entry in limine.conf — bios boot unverified"
    fi
    if [ "${BIOS_BOOT_METHOD:-limine}" = image-native ]; then
        if [ ! -e /target/boot/grub/grub.cfg ] && [ ! -e /target/boot/grub2/grub.cfg ]; then
            die "image-native BIOS boot but no GRUB config in /target/boot/grub/grub.cfg or /target/boot/grub2/grub.cfg"
        fi
        kernel_found=0
        for k in /target/boot/vmlinuz*; do
            if [ -e "$k" ] || [ -L "$k" ]; then
                kernel_found=1
                break
            fi
        done
        [ "$kernel_found" = 1 ] || die "image-native BIOS boot but no kernel matching /target/boot/vmlinuz*"
    fi
    sync; umount_target
    if [ "${ROOTFS_TYPE:-btrfs}" = ext4 ]; then
        e2fsck -fn "$ROOT_PART" >/dev/null 2>&1 || die "e2fsck reported errors"
    fi
    log "verify ok — safe to reboot"
}

auto_phase_done() {
    [ -f "/bootie/auto.$1.done" ] && return 0
    [ "$(cat "/bootie/$1.rc" 2>/dev/null || true)" = "0" ]
}

cmd_auto() {
    log "auto mode started: write -> personalize -> verify -> osboot"
    if auto_phase_done write; then
        log "auto: write already complete — skipping"
    else
        echo write > /bootie/auto.state
        cmd_write || die "auto write failed"
        touch /bootie/auto.write.done
    fi
    if auto_phase_done personalize; then
        log "auto: personalize already complete — skipping"
    else
        echo personalize > /bootie/auto.state
        cmd_personalize || die "auto personalize failed"
        touch /bootie/auto.personalize.done
    fi
    if auto_phase_done verify; then
        log "auto: in-env verify already complete — skipping"
    else
        echo verify > /bootie/auto.state
        cmd_verify || die "auto in-env verify failed"
        touch /bootie/auto.verify.done
    fi
    echo osboot-scheduled > /bootie/auto.state
    log "auto mode complete; rebooting into the new system in 60 seconds"
    # cmd_run must return and write auto.rc before the environment goes down;
    # the delayed reboot is detached so controller loss cannot stop osboot.
    setsid sh -c 'sleep 60; sync; reboot -f' </dev/null >/dev/null 2>&1 &
}

cmd_reboot() {
    log "rebooting into new system in 1 second"
    setsid sh -c 'sleep 1; sync; reboot -f' </dev/null >/dev/null 2>&1 &
}

# run <phase>: idempotent detached launcher. A dropped controller session must
# not kill a mid-flight write, and a re-run must not spawn a second one.
cmd_run() {
    name=$1
    case "$name" in write|personalize|auto) ;; *) die "cannot detach phase $name" ;; esac
    rc=/bootie/$name.rc; out=/bootie/$name.out
    if [ -f "$rc" ]; then
        old_rc=$(cat "$rc" 2>/dev/null || echo unknown)
        if [ "$old_rc" = 0 ]; then
            log "$name already finished (rc=0)"
            return 0
        fi
        log "$name finished earlier with rc=$old_rc — retrying"
        rm -f "$rc"
    fi
    # pgrep is not guaranteed in the minimal initramfs toolset.
    # shellcheck disable=SC2009
    if ps | grep -v grep | grep -q "liveenv.sh $name"; then
        log "$name already running"
        return 0
    fi
    rm -f "$out"
    setsid sh -c "$0 $name > $out 2>&1; echo \$? > $rc" </dev/null >/dev/null 2>&1 &
    sleep 1
    log "$name launched detached"
}

cmd_poll() {
    name=$1
    rc=/bootie/$name.rc
    [ -f "$rc" ] && echo "DONE rc=$(cat "$rc")" || echo RUNNING
}

case "${1:-status}" in
    status)      cmd_status ;;
    write)       cmd_write ;;
    personalize) cmd_personalize ;;
    verify)      cmd_verify ;;
    auto)        cmd_auto ;;
    reboot)      cmd_reboot ;;
    run)         cmd_run "$2" ;;
    poll)        cmd_poll "$2" ;;
    *)           die "unknown phase $1" ;;
esac

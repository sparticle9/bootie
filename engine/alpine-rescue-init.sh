#!/bin/sh
# PID 1 in the Alpine initramfs. Deliberately never chains to Alpine's /init.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
rescue=/bootie-rescue
{
    IFS= read -r console
    IFS= read -r disk
    IFS= read -r mac
    IFS= read -r address
    IFS= read -r gateway
} < "$rescue/settings"
/bin/busybox --install -s /bin

mount -t devtmpfs devtmpfs /dev || { reboot -f; while :; do sleep 60; done; }
exec <"/dev/$console" >"/dev/$console" 2>&1

setup() {
    mount -t proc proc /proc || return 1
    mount -t sysfs sysfs /sys || return 1
    mount -t tmpfs -o mode=0755 tmpfs /run || return 1
    mkdir -p /dev/pts /run/modloop /mnt /tmp || return 1
    mount -t devpts devpts /dev/pts || return 1
    /sbin/modprobe -a virtio_pci virtio_blk virtio_net loop squashfs || return 1
    [ -b "$disk" ] || return 1
    mount -t squashfs -o ro,loop "$rescue/modloop" /run/modloop || return 1
    modules=/run/modloop/modules/$(uname -r)
    [ -s "$modules/modules.dep" ] || return 1
    # Keep the early virtio modules and use the full release tree for inspection.
    mount -o bind "$modules" "/lib/modules/$(uname -r)" || return 1
    /sbin/modprobe -a ext4 btrfs vfat || return 1
    awk 'NR > 1 { exit 1 }' /proc/swaps || return 1
    awk '$1 ~ /^\/dev\// && $3 != "squashfs" { exit 1 }' /proc/mounts || return 1
}

start_ssh() {
    nic=
    for interface in /sys/class/net/*; do
        [ "$(cat "$interface/address")" = "$mac" ] || continue
        [ -z "$nic" ] || return 1
        nic=${interface##*/}
    done
    [ -n "$nic" ] || return 1
    ip link set lo up && ip link set "$nic" up &&
        ip addr add "$address" dev "$nic" && ip route add default via "$gateway" dev "$nic" ||
        return 1

    root=/run/ssh-root
    mkdir -p "$root/etc/apk" "$root/dev" "$root/proc" "$root/sys" "$root/run" "$root/mnt" ||
        return 1
    cp -R /etc/apk/keys "$root/etc/apk/" || return 1
    apk --root "$root" --no-network --repositories-file /dev/null \
        --repository "$rescue/repo" add --initdb --no-scripts \
        busybox busybox-binsh openssh-server openssh-keygen ||
        return 1
    mkdir -p "$root/root/.ssh" "$root/dev/pts" "$root/etc/ssh" \
        "$root/var/empty" "$root/var/run/sshd" || return 1
    chmod 700 "$root/root" "$root/root/.ssh" || return 1
    cp "$rescue/keys" "$root/root/.ssh/authorized_keys" &&
        chmod 600 "$root/root/.ssh/authorized_keys" || return 1
    printf '%s\n' 'root:x:0:0:root:/root:/bin/sh' 'sshd:x:22:22:sshd:/var/empty:/sbin/nologin' > "$root/etc/passwd" &&
        printf '%s\n' 'root:x:0:' 'sshd:x:22:' > "$root/etc/group" &&
        printf '%s\n' 'root:NP:20000:0:99999:7:::' 'sshd:!:20000:0:99999:7:::' > "$root/etc/shadow" &&
        chmod 600 "$root/etc/shadow" || return 1
    for tree in dev dev/pts sys proc; do
        mount -o bind "/$tree" "$root/$tree" || return 1
    done
    chroot "$root" /bin/busybox --install -s /bin &&
        cp "$rescue/inspect" "$root/bin/rescue-inspect" &&
        chroot "$root" /usr/bin/ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/rescue_host_key ||
        return 1
    cat > "$root/etc/ssh/rescue_config" <<EOF
ListenAddress ${address%/*}
HostKey /etc/ssh/rescue_host_key
AuthorizedKeysFile .ssh/authorized_keys
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
AllowUsers root
DisableForwarding yes
PermitUserEnvironment no
EOF
    chroot "$root" /usr/sbin/sshd -t -f /etc/ssh/rescue_config &&
        chroot "$root" /usr/sbin/sshd -f /etc/ssh/rescue_config -E /dev/console || return 1
    echo "Verify this ephemeral SSH host key before logging in as root:"
    chroot "$root" /usr/bin/ssh-keygen -l -f /etc/ssh/rescue_host_key.pub
}

if setup; then
    if [ -s "$rescue/keys" ]; then
        start_ssh || echo "SSH setup failed. Use the provider console to inspect or reboot."
    fi
    echo "Alpine RAM rescue. Use $rescue/inspect info, mount-ro, umount, or return."
else
    echo "Alpine rescue setup failed. SSH disabled. Use the provider console to reboot."
fi
while :; do
    setsid -c /bin/sh -i
    sleep 1
done

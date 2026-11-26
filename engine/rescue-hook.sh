#!/bin/sh
# initramfs-tools hook: stage the non-destructive bootie rescue environment.
# Deployed to /etc/initramfs-tools/hooks/bootie-rescue by the rescue staging path.
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "${1:-}" in prereqs) prereqs; exit 0 ;; esac

# hook-functions is supplied by initramfs-tools when the hook runs.
# shellcheck disable=SC1091
. /usr/share/initramfs-tools/hook-functions

# Inspection, repair, and network tools only. copy_exec resolves shared libraries.
for bin in /usr/bin/curl \
           /sbin/btrfs /usr/sbin/btrfs /sbin/blkid /bin/lsblk /usr/bin/lsblk \
           /sbin/sfdisk /sbin/fdisk /sbin/sgdisk /usr/sbin/partx /usr/sbin/blockdev \
           /sbin/e2fsck /usr/sbin/e2fsck /sbin/fsck.ext4 /usr/sbin/fsck.ext4 \
           /sbin/resize2fs /usr/sbin/resize2fs /bin/mount /bin/umount; do
    [ -x "$bin" ] && copy_exec "$bin"
done

# CA bundle — curl verifies https certificates against it.
mkdir -p "$DESTDIR/etc/ssl/certs"
cp -a /etc/ssl/certs/. "$DESTDIR/etc/ssl/certs/"
if [ -f /etc/ssl/openssl.cnf ]; then
    cp -a /etc/ssl/openssl.cnf "$DESTDIR/etc/ssl/"
fi

manual_add_modules btrfs
manual_add_modules ext4
manual_add_modules vfat
manual_add_modules nls_cp437
manual_add_modules nls_ascii
manual_add_modules virtio_blk
manual_add_modules virtio_net

mkdir -p "$DESTDIR/bootie-rescue"
cp -a /usr/local/share/bootie-rescue/. "$DESTDIR/bootie-rescue/"
chmod +x "$DESTDIR/bootie-rescue/"*.sh 2>/dev/null || true

# A rescue initramfs must never inherit install-time auto-start material.
rm -f "$DESTDIR/bootie/autostart"
if [ -d "$DESTDIR/bootie" ]; then
    rm -rf "$DESTDIR/bootie"
fi

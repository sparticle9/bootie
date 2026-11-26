#!/bin/sh
# initramfs-tools hook: stage the bootie live env into the custom image.
# Deployed to /etc/initramfs-tools/hooks/bootie-live; runs only when the
# stage phase calls `mkinitramfs -o /boot/initrd-bootie.img`.
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "${1:-}" in prereqs) prereqs; exit 0 ;; esac

# hook-functions is supplied by initramfs-tools when the hook runs.
# shellcheck disable=SC1091
. /usr/share/initramfs-tools/hook-functions

# Tools the live env needs. copy_exec resolves shared libraries.
for bin in /usr/bin/qemu-img /usr/bin/curl /usr/bin/ssh-keygen \
           /sbin/btrfs /usr/sbin/btrfs /sbin/blkid \
           /sbin/sfdisk /sbin/fdisk /sbin/sgdisk \
           /usr/sbin/partx /usr/sbin/blockdev \
           /usr/bin/limine /usr/sbin/limine \
           /usr/bin/efibootmgr /sbin/efibootmgr \
           /sbin/mkfs.vfat /usr/sbin/mkfs.vfat \
           /sbin/resize2fs /usr/sbin/resize2fs \
           /sbin/e2fsck /usr/sbin/e2fsck \
           /sbin/fsck.ext4 /usr/sbin/fsck.ext4 \
           /bin/mount /bin/umount; do
    [ -x "$bin" ] && copy_exec "$bin"
done

# qemu-img's network drivers are dlopen'd plugins, not linked libs — stage
# block-curl.so (+ its libcurl deps via copy_exec) or https fetch fails.
for so in /usr/lib/*/qemu/block-curl.so; do
    [ -f "$so" ] && copy_exec "$so"
done

# CA bundle — qemu-img/curl verify https certs against it.
mkdir -p "$DESTDIR/etc/ssl/certs"
cp -a /etc/ssl/certs/. "$DESTDIR/etc/ssl/certs/"
cp -a /etc/ssl/openssl.cnf "$DESTDIR/etc/ssl/" 2>/dev/null || true
# blkid needs its libblkid database paths but copy_exec handles libs;
# fs detection needs libuuid anyway. Ensure the filesystem modules land.
manual_add_modules btrfs
manual_add_modules ext4
manual_add_modules vfat
manual_add_modules efivarfs
# vfat mounts need the cp437/ascii codepages — not hard deps of vfat.ko,
# so manual_add_modules alone misses them ("codepage cp437 not found").
manual_add_modules nls_cp437
manual_add_modules nls_ascii
manual_add_modules virtio_blk
manual_add_modules virtio_net

mkdir -p "$DESTDIR/bootie"
# Recursive: payload/ carries write_files contents, runcmd scripts and
# late_commands alongside the engine + plan.env.
cp -a /usr/local/share/bootie/. "$DESTDIR/bootie/"
chmod +x "$DESTDIR/bootie/engine/"*.sh 2>/dev/null || true


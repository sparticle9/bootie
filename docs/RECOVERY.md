# Recovery and abort behavior

`bootie`'s recovery options depend on which phase the machine has reached.
Review this before running an install on any machine you care about.

## Before typing the approval token

Nothing has been installed, staged, or modified on disk. Aborting here leaves
the machine untouched.

## After approval and staging, before the liveenv write

`bootie` has staged `/usr/local/share/bootie`, built `/boot/initrd-bootie.img`,
and armed a **one-shot** GRUB entry (`BOOTIE liveenv (one-shot)`), while the
prior OS remains the saved default (`GRUB_DEFAULT=saved`).

- `--no-reboot` stops at this reversible checkpoint so you can inspect staged
  files before rebooting.
- To cancel before rebooting, unset `next_entry` with `grub-editenv` or remove
  `/etc/grub.d/41_bootie` and re-run `update-grub`.

## Inside the RAM live environment before write

The live environment runs purely in RAM with host disks unmounted. Before
writing, `liveenv.sh` re-derives the hardware fingerprint and aborts if it does
not match the approved plan.

- **Dropbear SSH access:** when SSH keys were carried, dropbear listens as
  `root` with an **ephemeral** liveenv host key (not the managed user and not
  the new OS's pre-generated host keys). Do not pin the temporary dropbear host
  key in `known_hosts`.
- **Aborting before write:** rebooting before `write` starts returns cleanly to
  the prior OS unchanged because the GRUB entry is one-shot.
- **Expected liveenv quirks:** inside initramfs, `facts.sh` intentionally
  reports `root_stack=liveenv` and `bootloader=liveenv` (the hardware
  `fingerprint` subset stays identical). `/bootie/engine/liveenv.sh reboot`
  detaches a short delayed `reboot -f`; if your SSH client drops mid-reset,
  re-probe the host after reboot.

## During and after write (point of no return)

Once `qemu-img convert` starts writing to the target disk, treat the prior OS
as gone. Interrupting the write leaves a partial disk and requires provider
console or reinstall recovery.

If `personalize` or `verify` fails after a completed write, inspect status over
dropbear SSH (or provider console) before rebooting:

```sh
/bootie/engine/liveenv.sh status
/bootie/engine/liveenv.sh verify
```

Logs and idempotent phase markers live under `/bootie` in RAM.

## Firstboot

`cloud_config.runcmd` entries run as ordered, self-disabling systemd oneshot
units. If a firstboot unit fails, the finisher leaves the machine running for
inspection rather than reboot-looping. If a manifest system upgrade succeeds
and creates `/var/lib/bootie/firstboot-system-upgrade-ok`, the finisher reboots
once into the upgraded kernel.

## Non-destructive RAM rescue (`bootie rescue`)

`bootie rescue` boots a structurally non-destructive `debian-initramfs` RAM
rescue environment (validated on both BIOS and UEFI with Secure Boot off):

- Resolves no manifest or OS image and stages no write engine or autostart.
- Uses separate staging (`/usr/local/share/bootie-rescue`), a dedicated hook
  (`/etc/initramfs-tools/hooks/bootie-rescue`), and a one-shot GRUB entry
  (`BOOTIE rescue (one-shot)`).
- Refuses keyless headless rescue unless `--console-only` explicitly
  acknowledges provider console access.

Inside RAM rescue (disks remain unmounted by default):

```sh
/bootie-rescue/rescue-helper.sh info
/bootie-rescue/rescue-helper.sh net-up
/bootie-rescue/rescue-helper.sh mount-ro /dev/<part> /mnt
/bootie-rescue/rescue-helper.sh umount /mnt
/bootie-rescue/rescue-helper.sh return
```

After `return` boots back into the prior OS, clean up all rescue staging
artifacts:

```sh
sh bootie.sh rescue --clean
```

As with the install liveenv, rescue SSH presents an ephemeral dropbear host
key — do not pin it as the machine's permanent host key. For the rescue
architecture, lab/emergency security boundaries, and live-environment backend
tradeoffs, see [RESCUE_DESIGN.md](RESCUE_DESIGN.md).

## Notes before using `--accept-risk drivers`

On non-virtio hardware, verify that the target's storage driver is present in
the target image's kernel or initrd (built-in drivers like `virtio_blk` or
`sd_mod` won't appear as separate `.ko` files). Target NIC drivers load from
the new rootfs, while the RAM liveenv relies on the source host's initramfs
having both storage and NIC drivers. Always ensure provider console recovery is
available first.

## Operator prerequisites

Before running an unattended install, make sure you have:

- provider console access or hard reboot/reinstall capability;
- tested backups (or acceptance of complete disk loss);
- access to the private keys matching your carried public keys.

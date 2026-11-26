# Live and Rescue Environment Design

This document captures `bootie`'s design philosophy, security boundaries, and
architectural tradeoffs for RAM live environments — covering both **lab /
rehearsal testing** and **temporary or emergency recovery** on a running VPS.

## 1. Default rescue: structural separation over flags

A rescue shell must never be a "paused destructive install." Relying on a
runtime flag to stop a destructive script from wiping a disk is fragile under
operator mistakes or script bugs.

Instead, `bootie rescue` enforces **structural separation**:

1. **Offline plan, no OS image:** `preflight.py rescue-plan` resolves no
   manifest, touches no network, and embeds no artifact URL.
2. **No destructive machinery staged:** the rescue initramfs never contains
   `liveenv.sh`, `qemu-img`, `plan.env`, install payloads, or `autostart`. Even
   if a boot script misfired inside rescue mode, no automated wipe code exists
   to invoke.
3. **Isolated host footprint:**
   - Staging directory: `/usr/local/share/bootie-rescue` (separate from
     `/usr/local/share/bootie`)
   - Initramfs hook: `/etc/initramfs-tools/hooks/bootie-rescue`
   - Initrd image: `/boot/initrd-bootie-rescue.img`
   - One-shot GRUB entry: `/etc/grub.d/41_bootie_rescue`
     (`BOOTIE rescue (one-shot)`)
4. **Distinct confirmation token:** `rescue:<hostname>` (never reusable as an
   install approval token).
5. **Read-only by default:** disks are left unmounted on boot (`break=mount`),
   and `/bootie-rescue/rescue-helper.sh` encourages read-only inspection
   (`info`, `mount-ro`, `umount`, `return`) before any deliberate repair.
6. **Clean teardown:** `sh bootie.sh rescue --clean` removes all four rescue
   artifacts and clears any armed rescue `next_entry` once back in the prior OS.

## 2. Security and recovery considerations (lab & emergency use)

Whether you are using RAM environments in a disposable lab or during an
emergency recovery on a real VPS, keep these operational boundaries in mind:

- **No keyless headless lockouts:** `bootie rescue` refuses to stage when zero
  SSH public keys are found unless `--console-only` explicitly acknowledges
  provider VNC/serial console access.
- **Ephemeral dropbear host keys:** both the install liveenv and `bootie rescue`
  listen on SSH as `root` with freshly generated ephemeral host keys. Never pin
  an initramfs host key over a machine's permanent `known_hosts` entry, and
  remember that automated `StrictHostKeyChecking=accept-new` polling during a
  reinstall will record the temporary liveenv key and report a benign mismatch
  once the new OS boots.
- **Root shell boundary:** omitting `qemu-img` and autostart prevents
  accidental automated writes, but any rescue environment still gives the
  logged-in operator a root shell. Anyone holding a private key corresponding
  to the carried `authorized_keys` can access the machine while it sits in RAM
  rescue.
- **One-shot return safety:** because GRUB uses `GRUB_DEFAULT=saved` with a
  one-shot `next_entry`, running `/bootie-rescue/rescue-helper.sh return` (or a
  provider hard reboot) returns to the prior OS unchanged as long as the
  operator has not manually modified the disk.
- **Lab & rehearsal workflow:** in a lab, `bootie rescue` + `rescue --clean`
  and `liveenv.mode: hold` are the cheapest ways to test kernel/initramfs
  drivers, UEFI `grub-reboot` handoff, and hardware-fingerprint parity without
  erasing a VM disk.
- **Zero credential custody:** neither install nor rescue embeds VPN/tailnet
  auth keys, private keys, or remote control-plane callbacks. Rescue relies on
  the host's existing IP and carried SSH public keys (or provider console).

## 3. Alpine virt and kexec feasibility

The opt-in `alpine-kexec` backend assembles a self-contained RAM image and
hands it off through systemd kexec. The source bootloader remains in place.
The Debian/Ubuntu initramfs and GRUB path remains the default.

### RAM image

Bootie verifies the size and pinned SHA-256 of the official
[Alpine 3.24.4 virt ISO](https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/)
before extracting its kernel, initramfs and matching modloop. The ISO is
about 67 MiB. The kernel, compressed initramfs and modloop total about
43 MiB. Staging also needs space for extraction and the assembled initrd.

A root-owned cpio overlay replaces Alpine's stock `/init`, which would
otherwise discover boot media and assemble an OS from APK repositories.
The overlay embeds modloop and, for SSH mode, the ISO's APK repository.
The rescue init loads virtio drivers and mounts the module image from RAM
before configuring networking. It checks mount and swap state before
offering SSH. OpenSSH and its dependencies are installed into a temporary
root from the embedded repository with package signature verification,
network access and package scripts disabled. No boot services discover or
mount source disks. An operator with root access can deliberately write
to those disks.

### Source prerequisites and handoff

- Start with x86_64 KVM/QEMU, one simple virtio-blk disk, virtio-net with
  the hardware MAC, simple IPv4 and a working provider serial or virtual
  console. UEFI requires Secure Boot confirmed disabled. The backend refuses
  driver overrides.
- Use a systemd source with `python3`, `curl`, `bsdtar`, `kexec`, `ip`,
  `findmnt`, and `blkid`. SSH mode also requires `ssh-keygen` to check
  carried public keys. The experimental admission budget is 1536 MiB
  MemTotal, 512 MiB MemAvailable, and 384 MiB free in the staging filesystem.
  These are conservative thresholds pending measurements.
- The plan is offline. After assembly and typed handoff confirmation, Bootie
  rechecks source facts and requires an unarmed, enabled file-based kexec
  facility. Kernel policy can still refuse the actual load. It then requests
  orderly [`systemctl kexec`](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).
  When shutdown submission fails, Bootie attempts to unload its own image
  and reports an unload failure explicitly. Avoid concurrent kexec operations.
- `--no-reboot` assembles and checks the temporary image without loading it
  or retaining it for later use. `rescue --rescue-backend alpine-kexec --clean`
  has no persistent staging to remove and does not change kernel state.

### Access and recovery

The selected provider console opens a root shell. Use a trusted provider
console and verify access before handoff. For SSH, verify the ephemeral host
key fingerprint printed on the console, then use key-only root login and a
separate known-hosts file. `--console-only` keeps SSH disabled even if keys
are found. If SSH startup fails, recover through the selected console.

Run `/bootie-rescue/inspect info` on the console or `rescue-inspect info`
over SSH to inspect mounts, swap and disks. Use `mount-ro ext4 /dev/vda2`
with the helper and substitute the verified partition and filesystem.
The helper supports ext4, btrfs and vfat. It disables ext4 journal replay
with `noload` and btrfs tree-log replay with `rescue=nologreplay`. Use the helper's
`umount` and `return` commands for a normal firmware reboot. If the handoff
stalls, use the provider console reset path. Source boot configuration is
untouched. If unload was reported to have failed while still in the source
OS, verify kernel state through the console before attempting an ordinary
reboot, since systemd can use an armed kexec image.

### Validated configurations

See the [support matrix](SUPPORT_MATRIX.md) for Debian 13 and Omarchy 4.5.0-3
firmware and access coverage. The KVM drills verified kexec entry, serial
access, inactive swap, unmounted source disks, read-only inspection, and a
firmware reboot to the original OS. The SSH paths verified the ephemeral host
key through the console and rejected login without a public key. Explicit
console-only mode kept SSH and the rescue IPv4 address disabled even when a
valid public key was supplied.

The Omarchy source requires `kexec-tools`. The Limine/UEFI drill verified
read-only Btrfs inspection through the shipped helper with tree-log replay
disabled. VMware is outside the current admission envelope.

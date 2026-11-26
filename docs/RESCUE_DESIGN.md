# Live and Rescue Environment Design

This document captures `bootie`'s design philosophy, security boundaries, and
architectural tradeoffs for RAM live environments — covering both **lab /
rehearsal testing** and **temporary or emergency recovery** on a running VPS.

## 1. Design philosophy: structural separation over flags

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

## 3. Live-environment backend tradeoffs (current & future)

`bootie` deliberately keeps its live-environment surface narrow so every
backend remains auditable.

| dimension | `debian-initramfs` (implemented & validated) | `alpine-virt` RAM liveenv (future candidate) | `netboot.xyz` iPXE (console-only reference) |
|---|---|---|---|
| **Kernel / artifacts** | Host's own `/boot/vmlinuz-*` + custom `mkinitramfs` (0 MiB kernel download) | Alpine `virt` netboot (`vmlinuz-virt` + `initramfs-virt` + `modloop-virt`, ~43 MiB total vs. ~330 MiB for `lts`) | Tiny iPXE chainloader (~0.4–1.1 MiB) |
| **Source-OS requirement** | Debian / Ubuntu (`apt-get` + `initramfs-tools` + GRUB) | Any Linux with GRUB + `grub-reboot` (no `initramfs-tools` needed) | Any Linux with GRUB + `grub-reboot` |
| **Minimum RAM** | ~512 MiB (448 MiB effective floor) | ~512 MiB | Depends on chained OS |
| **SSH access** | Dropbear (`root`, carried keys) | Dropbear or OpenSSH (`root`, carried keys via local dual-`initrd` cpio overlay) | **None** (VNC/serial console only) |
| **Disk-repair tooling** | Busybox + staged `e2fsprogs`, `btrfs-progs`, `dosfstools`, `fdisk`, `gdisk`, `curl` | Full `apk` userspace (`xfsprogs`, `lvm2`, `cryptsetup`, `smartmontools`, `chroot`, etc.) | Operator-chosen network OS |
| **UEFI Secure Boot** | Fails closed unless Secure Boot OFF | Unsigned kernel; requires Secure Boot OFF | Unsigned binary; requires Secure Boot OFF |

### Key technical notes for a future `alpine-virt` backend

If `bootie` later adds `alpine-virt` to support non-Debian/non-apt source hosts
or richer RAM rescue tooling, three architectural details matter:

1. **Choose `virt`, not `lts`:** Alpine `lts` pulls ~330 MiB (mostly bare-metal
   GPU/Wi-Fi firmware in `modloop-lts`), which breaks small `/boot` partitions
   and 512 MiB VPSes. Alpine `virt` is ~43 MiB (~8× smaller) and carries the
   virtualization drivers VPSes actually need.
2. **Use a local dual-`initrd` cpio overlay (no remote HTTP `apkovl`):**
   passing remote `apkovl=https://...` or `ssh_key=https://...` URLs violates
   `bootie`'s zero-controller model. Instead, stage a tiny mode-0600 gzipped
   `cpio` archive locally during host staging and load it as a second GRUB
   `initrd` argument (`initrd /boot/bootie-alpine-initramfs-virt /boot/bootie-rescue-overlay.cpio.gz`).
   The Linux kernel natively unpacks multiple `initrd` archives into the RAM
   rootfs before `/init` runs.
3. **Avoid the `modloop` NIC chicken-and-egg trap:** standard Alpine netboot
   fetches `modloop-virt` over HTTPS during boot, which fails if the host's NIC
   driver lives inside `modloop-virt`. Staging `modloop-virt` locally into the
   overlay (or copying it to tmpfs before releasing the disk) removes the boot
   network dependency while keeping the target disk completely unmounted.
4. **DHCP vs. static IP reconstruction:** static `ip=<addr>::<gw>:<mask>:<host>:<if>:off`
   works in both Debian `ipconfig` and Alpine `initramfs-init`. When the
   read-only `engine/dhcp_probe.py` probe confirms `dhcp_available=yes`, future
   adapters can safely opt into `ip=dhcp` to support DHCP-served `/32` or
   off-subnet gateways cleanly.

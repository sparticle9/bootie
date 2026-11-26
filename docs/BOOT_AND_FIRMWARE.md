# Boot and Firmware Design (BIOS & UEFI)

This document records the technical details and design rationale behind how
`bootie` stages one-shot live environments and configures target OS boot on
both **BIOS** and **UEFI** x86_64 machines. It is intended as a durable
reference for maintaining boot compatibility as firmware, bootloaders, and
upstream cloud images evolve.

## 1. Host-side staging (`GRUB` one-shot handoff)

`bootie` boots into its RAM live or rescue environment using the source host's
existing GRUB installation (`GRUB_DEFAULT=saved` + `grub-reboot` /
`grub2-reboot`):

1. **One-shot safety:** `grub-reboot` sets `next_entry` in `grubenv` for a
   single boot. The prior OS remains the saved default, so any reboot before
   the destructive write returns to the original OS unchanged.
2. **Separate `/boot` partition handling (`boot_separate`):**
   - When `/boot` lives on the root filesystem, GRUB expects kernel and initrd
     paths prefixed with `/boot/` (`/boot/vmlinuz-<kver>`,
     `/boot/initrd-bootie.img`).
   - When `/boot` is a dedicated partition (common on UEFI Debian and Ubuntu
     cloud images), GRUB's root device for `/boot` is that partition itself, so
     paths must omit `/boot` (`/vmlinuz-<kver>`, `/initrd-bootie.img`).
   - `engine/facts.sh` probes `/proc/mounts` and emits `boot_separate=yes|no`.
     `bootie-main` uses that fact to render `/etc/grub.d/41_bootie` and
     `/etc/grub.d/41_bootie_rescue` with the right prefix without hardcoding
     filesystem UUID search stanzas.
3. **BIOS vs. UEFI GRUB tooling:**
   - If `grub-reboot` is missing on an apt-based host, `bootie-main` suggests
     `grub-efi` when `/sys/firmware/efi` exists and `grub-pc` otherwise.
   - Modern Debian and Ubuntu GRUB2 use the unified `linux` / `initrd` commands
     on both BIOS and UEFI (no `linuxefi` split required).
   - `grubenv` on `btrfs` or `LVM` root remains refused by the disk-topology
     probe because GRUB cannot reliably write `next_entry` into copy-on-write
     or stacked volumes.

## 2. Why Secure Boot OFF is a hard UEFI prerequisite

`bootie` treats **Secure Boot disabled** as a universal prerequisite on UEFI
hosts rather than maintaining per-manifest Secure Boot exceptions:

- While official Debian and Ubuntu cloud images carry Microsoft-signed shims,
  unsigned targets (such as Omarchy's Limine + UKI) and future compact rescue
  kernels (such as Alpine `virt` or iPXE) cannot boot under Secure Boot.
- Shim, MOK, and SBAT revocation churn creates a fragile, failure-prone
  compatibility surface that conflicts with `bootie`'s fail-closed posture.
- Most KVM VPS providers default to Secure Boot OFF (or expose a single toggle
  in the control panel). Making Secure Boot OFF one uniform rule keeps
  preflight predictable across every manifest and rescue mode.

### How `secure_boot` is probed (`engine/facts.sh`)

On BIOS (`[ ! -d /sys/firmware/efi ]`), `secure_boot` is `na`. On UEFI,
`engine/facts.sh` determines Secure Boot state conservatively:

1. **Primary check (`/sys/firmware/efi/efivars/SecureBoot-*`):** reads the
   5-byte EFI variable (4-byte attributes + 1-byte value). Final byte `0x01`
   reports `enabled`; `0x00` reports `disabled`. Corrupt/truncated variables
   report `unknown` (never assumed disabled).
2. **`mokutil --sb-state` fallback:** parses both stdout and stderr —
   `SecureBoot enabled` → `enabled`; `SecureBoot disabled` or
   `doesn't support Secure Boot` → `disabled`.
3. **Non-Secure-Boot UEFI firmware check:** standard non-Secure-Boot firmwares
   (such as `OVMF_CODE_4M.fd` without SMM) expose a readable `efivarfs` with
   standard variables (`BootOrder-*`, `BootCurrent-*`, or `ConOut-*`) while
   omitting `SecureBoot-*` entirely. When those standard variables are readable
   and `SecureBoot-*` is absent, `facts.sh` reports `disabled`.
4. **Fail closed on ambiguity:** if `efivarfs` is unmounted, unreadable, or
   corrupt and `mokutil` cannot confirm disabled, `facts.sh` reports `unknown`.

In `engine/preflight.py`, `firmware=uefi` passes **only** when
`secure_boot=disabled`. Both `enabled` and `unknown`/`na`/missing always emit
`[fail]` and cannot be overridden by `--accept-risk`.

## 3. Target-disk boot after overwriting GPT (UEFI)

Streaming a fresh `qcow2` disk image onto `/dev/<disk>` replaces the entire
GPT partition table and every partition UUID (`PARTUUID`). On a UEFI machine,
this has two important consequences:

1. **Old NVRAM entries become stale:** the previous OS's UEFI NVRAM entry
   (e.g. `debian` or `ubuntu`) points to the old ESP's `PARTUUID`, which no
   longer exists on disk.
2. **Two-layer boot resilience (`BOOTX64.EFI` + `efibootmgr`):**
   - **Required fallback (`\EFI\BOOT\BOOTX64.EFI`):** per the UEFI
     specification, compliant firmwares fall back to `\EFI\BOOT\BOOTX64.EFI` on
     the GPT EFI System Partition (`EF00`, FAT32) when no valid NVRAM entry
     matches. All bundled target images ship this fallback (Debian 13, Ubuntu
     24.04/26.04, and Omarchy Limine). During both `personalize` and `verify`,
     `engine/liveenv.sh` locates the ESP case-insensitively and **fails closed
     before reboot** if `BOOTX64.EFI` is missing or empty.
   - **Best-effort NVRAM registration (`efibootmgr`):** strict UEFI firmwares
     sometimes drop to the UEFI shell instead of scanning fallback paths when
     stale NVRAM entries remain. On UEFI installs, `bootie-main` adds
     `efibootmgr` to the liveenv packages and `engine/initramfs-hook.sh` stages
     `efibootmgr` alongside the `efivarfs` kernel module. During
     personalization, `liveenv.sh` mounts `efivarfs` and registers a fresh
     NVRAM entry (`efibootmgr -c -d "$PLAN_DISK" -p "$esp_pnum" -L "bootie-$MANIFEST_NAME" -l '\EFI\BOOT\BOOTX64.EFI'`).
     NVRAM write failure is logged as a warning rather than a hard failure
     because virtualized UEFI firmwares occasionally expose read-only or
     ephemeral NVRAM — and `BOOTX64.EFI` has already been verified.

### Separate `/boot` inside target cloud images

Ubuntu cloud images (24.04 `noble` and 26.04 `resolute`) store kernels and
`grub.cfg` on a dedicated ext4 `LABEL=BOOT` partition separate from `/` and
the FAT32 ESP. During `mount_target()`, `engine/liveenv.sh` inspects
`/target/etc/fstab` for a `/boot` entry, resolves `LABEL=`, `UUID=`, or
`PARTUUID=` strictly among partitions on `$PLAN_DISK`, mounts it at
`/target/boot`, and unmounts it cleanly in `umount_target()`. This allows
`cmd_verify()` to verify `/target/boot/vmlinuz*` and GRUB config on both
single-partition (Debian) and split-`/boot` (Ubuntu) layouts.

## 4. Target-disk boot on BIOS

Target manifests declare `personalize.bios_boot` explicitly:

- **`image-native` (Debian 13, Ubuntu 24.04/26.04):** official cloud images
  ship a hybrid GPT layout with a BIOS boot partition and pre-installed GRUB.
  `bootie` leaves the image's native bootloader intact and verifies kernel and
  `grub.cfg` presence before reboot.
- **`limine` (Omarchy 4.5):** Omarchy's sealed VM image is UEFI-native (Limine
  + UKI on the ESP). On BIOS targets only (`[ "$FIRMWARE" = bios ]`),
  `liveenv.sh` deploys `limine-bios.sys` onto the ESP, fetches the matching
  unpacked kernel/initrd, adds a Limine Linux-protocol entry to
  `/esp/limine.conf`, installs the Limine MBR/GPT BIOS stage, and verifies
  every component before reboot. On UEFI targets, this BIOS path is skipped
  completely and Omarchy boots natively via Limine + UKI — and its firstboot
  upgrade script guards the BIOS `/boot/vmlinuz` copy with
  `if [ ! -d /sys/firmware/efi ]` so UEFI UKIs remain managed natively by
  `limine-entry-tool`.

## 5. Validation summary and non-goals

Both BIOS and OVMF UEFI (Secure Boot OFF) paths are validated end-to-end on
disposable **x86_64 KVM guests** (including a `q35+SMM` Secure Boot ON
fail-closed check, non-destructive `bootie rescue` + `--clean`, and full
unattended reinstalls of Debian 13, Ubuntu 24.04, and Omarchy 4.5).

Intentionally out of scope:

- **ARM (`aarch64` / `arm64`):** no ARM install or rescue boot path has been
  validated; these firmware results do not imply ARM support.
- **UEFI Secure Boot enabled:** permanently fail-closed by design.
- **Non-GRUB source hosts (`systemd-boot`, `rEFInd`, direct EFISTUB):** fail
  closed in the `bootloader` probe until a dedicated non-GRUB staging adapter
  is implemented and validated.

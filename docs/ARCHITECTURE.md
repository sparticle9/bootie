# bootie architecture

## Product shape

`bootie` is modular in the source repository and single-file at the point of
use. Operators download or pipe one self-extracting `bootie.sh`; maintainers
edit and test the modular source. The generated artifact is a release product,
never the editing surface.

There is no controller, agent daemon, or Ansible runtime dependency.

## Execution model

For `install`, the end-to-end lifecycle is:

```text
probe facts
  -> evaluate support envelope (fail closed)
  -> resolve manifest & upstream artifact
  -> build plan (hardware fingerprint + approval token)
  -> optional/desktop per-install password setup
  -> print review + double-confirm artifact URLs & checksums
  -> typed approval token
  -> stage live environment & one-shot GRUB entry
  -> reboot into RAM live environment
  -> re-verify hardware fingerprint
  -> stream upstream image to target disk (qemu-img convert)
  -> personalize (resize, fstab/boot, locale/timezone, users, sudo, SSH key-only,
                  network, packages, firstboot units, BIOS/UEFI boot registration)
  -> in-environment verify (filesystem + kernel/ESP/bootloader assertions)
  -> reboot into new OS
  -> firstboot tasks (exactly-once oneshot units + optional post-upgrade reboot)
```

Everything before the live-environment `write` step is boot-reversible: the
prior OS remains the saved GRUB default, and a normal reboot returns to it
unchanged. Immediately before writing, `engine/liveenv.sh` re-derives the
hardware fingerprint inside the RAM environment and refuses on any mismatch.

## Source modules

| path | role |
|---|---|
| `bootie-main` | POSIX shell CLI, privilege/dependency checks, key discovery, password prompts, review, approval, staging |
| `engine/facts.sh` | POSIX machine-identity, Secure Boot, `/boot`, and support-envelope fact probe (host & initramfs) |
| `engine/preflight.py` | Manifest validation, upstream artifact resolution, plan/fingerprint/approval generation, support-envelope evaluation |
| `engine/password.py` | Stdlib-only per-install alphanumeric password generator, pure-Python SHA-512 crypt (`$6$`), and `plan.json` user patching |
| `engine/stage.py` | Stdlib-only rendering of `plan.env` (POSIX single-quoted) and staged payload trees |
| `engine/liveenv.sh` | In-initramfs `write` / `personalize` / `verify` / `auto` state machine with idempotent phase markers |
| `engine/initramfs-hook.sh` | `initramfs-tools` hook staging binaries, CA certificates, kernel modules (`virtio`, `efivarfs`, etc.), and `/bootie` |
| `engine/initramfs-autostart.sh` | `init-premount` script launching `auto` mode only when `/bootie/autostart` is staged |
| `engine/rescue-hook.sh` | Dedicated `initramfs-tools` hook staging only the non-destructive rescue tree |
| `engine/rescue-helper.sh` | Operator helper inside RAM rescue (`info`, `net-up`, `mount-ro`, `umount`, `return`) |
| `engine/keyfilter.sh` | `authorized_keys` line filter supporting options-prefixed keys and quoted spaces |
| `engine/merge-key-files.sh` | Multi-source public-key merge and exact-line deduplication |
| `engine/prompt.sh` | `/dev/tty`-aware normal and hidden-echo (`stty -echo`) prompt helpers for file and pipe modes |
| `engine/auth-summary.py` | Authentication-shape classifier (`key`, `password-only`, `FATAL`) |
| `engine/dhcp_probe.py` | Read-only DHCPDISCOVER probe surfaced by `check` (never sends DHCPREQUEST) |
| `manifests/` | Bundled v2 manifests pre-converted to JSON at bundle time |
| `schema/` | Machine-validatable JSON Schema (`manifest-v2.schema.json`) |
| `payload/om-desktop` | Opt-in Omarchy desktop helper installed only when `postinstall.install_om_desktop: true` |
| `scripts/bundle` | Packages modular sources into the self-extracting `bootie.sh` heredoc bundle |
| `scripts/test-bundle` | Verifies file-mode and pipe-mode bundle extraction |

The bundle preserves this modular layout inside a temporary extraction
directory so `bootie-main` resolves relative paths identically in source and
bundled execution.

## Host staging and boot paths (`debian-grub-initramfs`)

The staging backend targets Linux apt-based source systems with GRUB and
`initramfs-tools`:

- **Separate `/boot` detection:** `engine/facts.sh` emits `boot_separate=yes|no`
  so `bootie-main` writes `/vmlinuz-*` and `/initrd-bootie*.img` without a
  duplicate `/boot` prefix when `/boot` is its own partition.
- **BIOS boot path:** `limine` profiles deploy `limine-bios.sys`, unpacked
  kernel/initrd, and a BIOS entry onto the ESP; `image-native` cloud images
  keep their shipped GRUB bootloader.
- **UEFI boot path (Secure Boot disabled):**
  - `engine/facts.sh` inspects `/sys/firmware/efi/efivars/SecureBoot-*`,
    `mokutil --sb-state`, and readable standard UEFI variables to confirm
    Secure Boot is disabled. Enabled or unconfirmed states always fail closed.
  - On UEFI installs, `bootie-main` includes `efibootmgr` in the liveenv
    packages and `initramfs-hook.sh` stages `efibootmgr` + `efivarfs`.
  - During personalization and verification, `liveenv.sh` asserts the written
    ESP exists and contains a non-empty `/EFI/BOOT/BOOTX64.EFI` fallback
    (plus Limine UKI checks on `limine` targets), and performs best-effort
    `efibootmgr` NVRAM registration (`bootie-<manifest>`) so strict UEFI
    firmwares boot the new disk immediately without relying solely on fallback
    scanning.
  - On Ubuntu cloud images with a separate `LABEL=BOOT` partition, `liveenv.sh`
    mounts `/boot` from `/target/etc/fstab` strictly on `$PLAN_DISK` during
    personalization and verification.

See [BOOT_AND_FIRMWARE.md](BOOT_AND_FIRMWARE.md) for the full technical design
of BIOS/UEFI boot handling, Secure Boot probing, and ESP/NVRAM behavior.

## Non-destructive rescue path

`bootie rescue` is structurally separate from `install`:

- Runs `preflight.py rescue-plan` completely offline (no manifest, no OS
  artifact resolution, no network fetch) and evaluates the same support
  envelope with a 448 MiB RAM floor (512 MiB nominal minus kernel reservation).
- Requires the distinct typed confirmation token `rescue:<hostname>`.
- Stages only into `/usr/local/share/bootie-rescue`, installs the dedicated
  `/etc/initramfs-tools/hooks/bootie-rescue` hook, builds
  `/boot/initrd-bootie-rescue.img`, and arms the one-shot GRUB entry
  `BOOTIE rescue (one-shot)`.
- Stages no `plan.env`, `liveenv.sh`, `qemu-img`, install payload, or
  autostart script.
- Refuses headless keyless rescue unless `--console-only` explicitly
  acknowledges provider console access.
- `sh bootie.sh rescue --clean` removes all rescue staging artifacts and
  unsets any armed rescue `next_entry` after returning to the prior OS.

See [RESCUE_DESIGN.md](RESCUE_DESIGN.md) for the rescue architecture, lab and
emergency security boundaries, and live-environment backend tradeoffs.

## Keys, passwords, and SSH access

1. Without `--key`, `bootie` discovers and merges `authorized_keys` from the
   invoking user and `root`.
2. Desktop manifests (`boot_target: desktop`) without a manifest-declared
   password automatically generate a unique 10-character alphanumeric password
   at install time via `engine/password.py`, display it once in the review
   block, and stage only its SHA-512 crypt (`$6$`) hash.
3. Operators can override or supply a password on any manifest via `--password`
   (hidden TTY prompt + confirmation) or `--password-file PATH`.
4. Whenever SSH public keys are installed, `liveenv.sh` writes
   `/etc/ssh/sshd_config.d/90-bootie-keyonly.conf` (`PasswordAuthentication no`,
   `KbdInteractiveAuthentication no`) so SSH remains key-only while passwords
   work for `sudo` and local/desktop login.
5. With zero authentication material, install refuses before staging.

## Artifact policy

`bootie` does not host, mirror, repack, or redistribute OS images. Target
machines stream official upstream artifacts directly from upstream release
locations via `qemu-img convert` (HTTPS block driver). For checksum-indexed
releases (Debian/Ubuntu), `--mirror URL` lets an operator substitute an HTTPS
release-directory mirror at runtime; both `check` and the pre-destruction
review print the exact artifact URL, index URL, expected digest, and any
mirror override for confirmation.

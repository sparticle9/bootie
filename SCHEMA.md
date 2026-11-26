# bootie manifest schema (version 2)

A `bootie` manifest is the declarative contract for one installation target.
The **canonical, machine-validatable JSON Schema** lives in
[`schema/manifest-v2.schema.json`](schema/manifest-v2.schema.json) and is
enforced against every shipped and example manifest by `tests/test_schema.py`.

This document explains the structure, semantics, and execution rules behind
that schema. For concrete, ready-to-use YAML files, see [`manifests/`](manifests/)
and [`examples/manifests/`](examples/manifests/).

Alpine kexec rescue is CLI-selected and performs no manifest resolution.
The install manifest's `liveenv.kind` continues to select `debian-initramfs`.

## Two-ring design

Every version-2 manifest separates ordinary OS configuration from low-level
installation mechanics:

1. **Extension ring** (`manifest_version`, `name`, `version`, `arch`,
   `channel`, `artifact`, `target`, `liveenv`, `write`, `personalize`,
   `firstboot`, `postinstall`): hardware gates, upstream artifact resolution,
   live-environment composition, write method, and distro adapters.
2. **Standard ring** (`cloud_config`): a cloud-init-inspired subset for users,
   SSH keys, files, packages, locale, timezone, hostname, and firstboot
   commands.

`bootie` is not `cloud-init`. At plan time, `engine/preflight.py` validates and
transpiles `cloud_config` into concrete engine operations that run offline in
the RAM live environment or as exactly-once firstboot `systemd` units. Unknown
or unsupported keys fail closed rather than silently no-oping.

## Top-level sections

| section | required | purpose |
|---|---|---|
| `manifest_version` | yes | Must be `2`. |
| `name`, `version`, `arch` | yes | Target identity (`omarchy`, `debian`, `ubuntu`, etc.). All bundled targets use `arch: x86_64`; other architectures are unsupported. |
| `channel` | no | Optional channel guard; on JSON-index manifests, must appear as a path segment in `artifact.index_url`. |
| `artifact` | yes | Upstream release source (see below). |
| `target` | yes | Minimum disk (`disk_min_size_gib`), RAM (`memory_min_mib`), and allowed firmware (`[bios, uefi]`). |
| `liveenv` | yes | Live environment kind (`debian-initramfs`), apt packages, `kernel_cmdline`, `ssh_port`, and `mode` (`auto` or `hold`). |
| `write` | yes | Write method (`qemu-img-stream`) and post-write scrub flag (`scrub_after`). |
| `personalize` | no | Filesystem, network, BIOS boot, and target customization adapters. |
| `firstboot` | no | Partition/filesystem resize flags (`grow_partition`, `btrfs_resize`). |
| `postinstall` | no | `managed_user`, `boot_target` (`console` or `desktop`), and opt-in `install_om_desktop`. |
| `cloud_config` | no | Standard-ring system configuration. |
| `x-*` | no | Forward-compatible metadata ignored by preflight. |

## Disk-image artifact resolution

`artifact.kind: disk-image` is the implemented artifact kind for the
`qemu-img-stream` write path. It supports two mutually exclusive upstream
resolution forms:

1. **Upstream JSON index (`index_url`)** — used by Omarchy (`https://nightly.omarchy.org/stable/latest.json`). The JSON index provides the image URL, SHA-256 digest, size, unpacked kernel/initrd URLs, and upstream user. When `channel` is set on the manifest, `/{channel}/` must appear in `index_url`'s path.
2. **Upstream checksum file (`checksums_url` + `image_file` + optional `checksum_alg`)** — used by Debian (`SHA512SUMS`, `sha512`) and Ubuntu (`SHA256SUMS`, `sha256`). `image_file` must be a plain basename (no path separators or globs); the image URL is resolved from the same directory as `checksums_url`. Coreutils text and binary (`*filename`) lines are supported; missing or malformed entries fail closed.

At runtime, operators may substitute an HTTPS release-directory mirror for
checksum-indexed manifests via `--mirror URL`. Both `check` and the
pre-destruction review print the resolved image URL, checksum index URL,
expected digest, and any mirror override for double confirmation.

## Personalization adapters

Version-2 manifests declare distro-specific adaptation explicitly rather than
relying on heuristics:

- `personalize.rootfs`: `btrfs` or `ext4`. Selects mount, check (`btrfs scrub`
  vs `e2fsck`), and resize behavior. `btrfs` profiles may also set
  `root_subvol` and `esp_subvol`.
- `personalize.network`: `networkmanager`, `systemd-networkd`, `netplan`, or
  `none`. Renders the target's observed IPv4/IPv6/DNS facts into the native
  network stack.
- `personalize.bios_boot`: `limine`, `image-native`, or `none`. `limine` stages
  Limine BIOS boot + unpacked kernel/initrd onto the ESP; `image-native` uses
  the cloud image's shipped bootloader.
- `personalize.connectivity_host`: plain upstream hostname (no scheme, path, or
  port) used by the firstboot DNS readiness wait (e.g. `deb.debian.org`,
  `archive.ubuntu.com`, `archlinux.org`).
- Narrow extension operations: `ssh_host_keys`, `remove_webapps` (plain
  `.desktop` basenames), `drop_pkgs` (leaf-only removals), and `late_commands`
  (root chroot escape hatch; nonzero aborts personalization).

## Standard-ring (`cloud_config`) execution mapping

| `cloud_config` key | `bootie` execution | parity |
|---|---|---|
| `users[].name`, `groups`, `shell` | `useradd`/`usermod` in the target chroot | exact for supported fields |
| `users[].ssh_authorized_keys` | written to `~/.ssh/authorized_keys`; carried/`--key` keys are appended and deduplicated | exact |
| `users[].sudo` | mode-0440 fragment under `/etc/sudoers.d/90-bootie-<user>` | exact for string form |
| `users[].lock_passwd` | `passwd -l` in chroot (defaults to `true`) | exact |
| `users[].passwd` | pre-hashed shadow string applied verbatim when `lock_passwd: false`; never printed in reviews or logs | exact |
| `write_files[]` | written offline with path, owner, permissions (`plain` or `b64`/`base64`; `append` unsupported) | exact for supported subset |
| `packages`, `package_update` | target-native package manager in chroot (`pacman` or noninteractive `apt-get`) | semantic |
| `runcmd` | scripts + ordered, self-disabling, exactly-once firstboot systemd oneshot units | semantic |
| `hostname`, `fqdn` | `/etc/hostname` and `/etc/hosts` (defaults to observed target hostname when omitted) | exact |
| `locale` | `/etc/locale.conf` (+ `/etc/default/locale`) and best-effort `locale-gen`; defaults to `en_US.UTF-8` | semantic |
| `timezone` | `/etc/localtime` symlink + `/etc/timezone`; omitted preserves image default | exact |

Recognized `cloud-init` keys outside the supported subset fail closed with an
explicit error: `network`, `ssh_keys`, `mounts`, `disk_setup`, `ntp`,
`keyboard`, `apt`, `yum_repos`, `snap`, and `snapshots`.

## Validation rules

- **Strict key checking:** unknown keys anywhere fail closed with the exact key
  path; only `x-`-prefixed metadata keys are ignored.
- **Upstream-only URLs:** artifact URLs must be HTTPS (excluding legacy Debian
  HTTP netboot) and must not point to object-storage/rehosted domains (`r2.dev`,
  `amazonaws.com`, `storage.googleapis`, etc.).
- **Schema parity:** `tests/test_schema.py` validates every file in
  `manifests/*.yml` and `examples/manifests/*.yml` against
  [`schema/manifest-v2.schema.json`](schema/manifest-v2.schema.json) and asserts
  key-set parity with `engine/preflight.py`.
- **`liveenv.mode`:** `auto` runs the detached target-resident state machine
  (`write -> personalize -> verify -> delayed reboot`) with idempotent phase
  markers; `hold` pauses in RAM for operator-driven phases.

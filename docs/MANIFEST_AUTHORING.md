# Manifest authoring guide

Manifests are `bootie`'s primary configuration surface. Customize target OSes
by copying and editing a manifest and passing `--manifest-file PATH`, rather
than adding distro-specific CLI flags.

Before writing a manifest:

- read [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md) — a manifest cannot make an
  unsupported architecture, firmware, network, driver, or disk layout safe;
- review [SCHEMA.md](../SCHEMA.md) and the machine-validatable JSON Schema in
  [`schema/manifest-v2.schema.json`](../schema/manifest-v2.schema.json).

All bundled manifests and examples declare `arch: x86_64`, the only currently
supported target architecture. Changing that field or selecting an upstream
ARM image does not add an ARM installation backend or validation evidence.

## Starting from an existing manifest

Copy one of the bundled manifests under `manifests/` (`debian-13.yml`,
`ubuntu-24.04.yml`, `ubuntu-26.04.yml`, `omarchy-4.5.yml`) or a template under
`examples/manifests/`, then validate it locally with:

```sh
uv run python -m unittest tests/test_schema.py -v
```

You can also enable live editor validation in YAML-aware IDEs by adding:

```yaml
# yaml-language-server: $schema=./schema/manifest-v2.schema.json
```

## Artifact policy

Reference **only** official upstream release locations. `bootie` refuses
non-HTTPS URLs (except legacy Debian HTTP netboot) and rejects object-storage
or rehosted domains (`r2.dev`, `amazonaws.com`, `storage.googleapis`, etc.).

- **Checksum-indexed cloud images (Debian/Ubuntu):** set `checksums_url`,
  `image_file` (exact plain basename, no slashes or globs), and `checksum_alg`
  (`sha256` or `sha512`). Operators can override the base release directory at
  runtime with `--mirror URL`.
- **JSON-indexed images (Omarchy):** set `index_url` (and `channel`, which must
  appear as a path segment in `index_url`).

## Personalization adapters

Always declare target adapters explicitly in version-2 manifests:

- `personalize.rootfs`: `ext4` (Debian/Ubuntu cloud images) or `btrfs`
  (Omarchy, with `root_subvol: "@"`).
- `personalize.network`: `systemd-networkd` (Debian), `netplan` (Ubuntu),
  `networkmanager` (Omarchy), or `none`.
- `personalize.bios_boot`: `image-native` (Debian/Ubuntu cloud images that ship
  hybrid GRUB) or `limine` (Omarchy) or `none`.
- `personalize.connectivity_host`: plain upstream hostname for firstboot DNS
  readiness (e.g. `deb.debian.org`, `archive.ubuntu.com`, `archlinux.org`) — no
  scheme, path, or port.

## Standard-ring (`cloud_config`) rules

- Every user in `cloud_config.users` receives carried/`--key` SSH public keys
  in addition to any manifest-declared `ssh_authorized_keys`.
- Never embed a plaintext or static default password in a shared manifest:
  - for server profiles, use `lock_passwd: true` with SSH keys (and optionally
    let operators pass `--password` or `--password-file` at install time);
  - for desktop profiles (`postinstall.boot_target: desktop`), omit `passwd`
    and set `sudo: "ALL=(ALL:ALL) ALL"` — `bootie` automatically generates a
    unique 10-character alphanumeric password per install (or honors
    `--password`) while keeping SSH key-only.
- Keep `runcmd` scripts small, idempotent, and noninteractive. Each entry runs
  as an ordered, self-disabling firstboot systemd oneshot unit.
- `packages` / `package_update` run noninteractively inside the target chroot
  (`apt-get` or `pacman`). Large desktop package sets (`ubuntu-desktop-minimal`)
  need corresponding disk/RAM minimums in `target`.
- `locale` defaults to `en_US.UTF-8` when omitted; `timezone` preserves the
  image default when omitted (use standard IANA names like `UTC` or
  `Europe/Berlin`).
- Unsupported `cloud-init` keys fail closed rather than silently no-oping.

## Users, helpers, and removals

- `postinstall.managed_user` selects the primary user printed in post-staging
  instructions and targeted by `--password` / per-install desktop passwords.
- `postinstall.install_om_desktop: true` is an explicit Omarchy opt-in and
  defaults to `false`.
- `personalize.remove_webapps` accepts only plain `.desktop` basenames;
  `personalize.drop_pkgs` performs leaf-only removals (never force-removing
  required packages).

## Authoring checklist

Before running a custom manifest on a disposable VM:

- validates cleanly against `schema/manifest-v2.schema.json` and
  `engine/preflight.py`;
- uses only official upstream HTTPS artifact URLs;
- sets honest `target` disk, RAM, and firmware minimums;
- declares `rootfs`, `network`, `bios_boot`, and `connectivity_host` adapters
  matching the actual image;
- contains no private keys, static passwords, API/VPN tokens, private
  hostnames, or private IPs;
- passes `sh bootie.sh check --manifest-file <path>` cleanly before attempting
  an install.

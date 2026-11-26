# bootie

`bootie` is a small, auditable, target-resident reinstall tool for provisioning
Linux VPSes cleanly from official upstream images. It runs **directly on the
machine being rebuilt** — no controller, no Ansible, no self-hosted OS mirrors —
and ships as a single self-extracting shell script:

```sh
curl -LO https://github.com/sparticle9/bootie/releases/latest/download/bootie.sh
sh bootie.sh check
sh bootie.sh --manifest debian-13
```

Pipe mode is also supported:

```sh
curl -fsSL https://github.com/sparticle9/bootie/releases/latest/download/bootie.sh | sh -s -- check
curl -fsSL https://github.com/sparticle9/bootie/releases/latest/download/bootie.sh | sh -s -- --manifest debian-13
```

> **Destructive operation warning**
>
> Installing erases the target machine's system disk. Always run `check` first,
> read the pre-mutation review block carefully, and run `bootie` only on
> machines whose disk loss and reboot are intended. Before the write phase
> starts inside the RAM live environment, rebooting returns to the prior OS
> unchanged; once the write begins, the old OS is gone.

## Why bootie?

Excellent general-purpose reinstall scripts already exist (such as
`bin456789/reinstall` and `debi.sh`). They optimize for **maximum breadth** —
supporting dozens of distributions, Windows, ARM, and exotic provider quirks
inside large imperative shell scripts.

`bootie` takes a deliberately narrower path: **auditability, modularity, and
fail-closed predictability** for a focused set of Linux VPS workflows.

### What bootie is built for

- **Clean headless Linux servers:** reproducible **Debian 13** and **Ubuntu
  24.04 / 26.04 LTS** instances provisioned directly from official upstream
  cloud images — well-suited for lightweight services and agent runtimes.
- **Developer & coding workstations:** **Omarchy 4.5** instances (graphical or
  console-first) with per-install password generation for `sudo`/desktop login
  and key-only SSH.
- **Non-destructive RAM rescue:** `bootie rescue` boots a clean RAM recovery
  shell with no write engine staged, useful both for lab testing and emergency
  disk inspection.
- **Declarative, schema-validated customization:** distro knowledge lives in
  versioned YAML manifests validated against
  [schema/manifest-v2.schema.json](schema/manifest-v2.schema.json), not buried
  in sprawling shell conditionals.

### Explicit non-goals

`bootie` is **not** a general-purpose remote OS installer:

- **No Windows** — neither installing Windows nor reinstalling from Windows.
- **No broad distro catalog for its own sake** or ARM/container
  (OpenVZ/LXC) support.
- **No self-hosted or mirrored OS images** — targets always pull directly from
  official upstream release endpoints (or an explicit operator `--mirror`).
- **No controller, daemon, reverse-tunneling glue (`frp`), or credential
  custody** — no embedded VPN/tailnet auth keys, private keys, or static
  default passwords.
- **No silent improvisation** — unsupported firmware, bootloaders, complex
  routing (`/32` onlink), or RAID/LVM/encrypted layouts fail closed with clear
  explanations.

## Design principles

- **Fail-closed support envelope:** six preflight probes (`virt`, `bootloader`,
  `firmware`, `network`, `disk-topology`, `drivers`) refuse unsupported or
  ambiguous environments before touching the system.
- **Direct upstream artifacts:** `bootie` never mirrors, repacks, or hosts OS
  images. Targets stream official upstream images directly from the
  distribution's release index or checksum file, verified and displayed before
  approval.
- **One explicit approval, then unattended:** an operator-typed approval token
  binds the hostname, manifest, and hardware fingerprint. Inside the RAM live
  environment, `bootie` re-derives the hardware fingerprint before writing to
  disk.
- **Modular source, single-file release:** the repository stays modular and
  unit-tested; `scripts/bundle` packages it into one self-extracting
  `bootie.sh` for distribution.

## Future direction

`bootie` expands cautiously — only through explicit adapters, offline tests,
and disposable-VM validation:

- Broader validated storage/NIC driver coverage (e.g. NVMe and non-virtio NICs)
  beyond the current virtio baseline.
- A compact `alpine-virt` RAM live/rescue backend (documented in
  [docs/RESCUE_DESIGN.md](docs/RESCUE_DESIGN.md)) to decouple from Debian/apt
  on the source host and provide richer disk-repair tooling.
- Optional DHCP-backed liveenv networking where the read-only `dhcp_available`
  probe confirms it, unlocking DHCP-served `/32` VPS shapes safely.
- Explicit, credential-safe post-boot hooks (e.g. opt-in Tailscale setup
  without secret custody).
- **NixOS target support:** a planned target requiring an upstream installation
  strategy, declarative configuration handoff, explicit adapters, and VM
  validation before it can be supported.

See [docs/ROADMAP.md](docs/ROADMAP.md) for planned work and support-promotion
criteria; roadmap items are not current support.

## Supported environments and manifests

**All currently supported targets are x86_64 (`amd64` / `x64`) only.**
Omarchy, Debian, and Ubuntu have not been install-tested on ARM (`aarch64` /
`arm64`); ARM installation and rescue are unsupported. Running build or unit
tests on an ARM64 development machine does not validate ARM OS installation.

End-to-end validation covers KVM + virtio + simple-IPv4 guests, using the
current Debian/Ubuntu + GRUB source-host staging backend. Firmware coverage
varies by target:

| target | bundled manifest | validated architecture | validated firmware | notes |
|---|---|---|---|---|
| Omarchy 4.5 (stable) | `omarchy-4.5` | x86_64 | UEFI (Secure Boot off), BIOS | Official sealed VM qcow2, btrfs, Limine, `NetworkManager`, desktop |
| Debian 13 (`trixie`) | `debian-13` | x86_64 | BIOS, UEFI (Secure Boot off) | Official cloud qcow2 (`SHA512SUMS`), ext4, `systemd-networkd` |
| Ubuntu 24.04 LTS (`noble`) | `ubuntu-24.04` | x86_64 | BIOS, UEFI (Secure Boot off) | Official cloud qcow2 (`SHA256SUMS`), ext4, `netplan` |
| Ubuntu 26.04 LTS (`resolute`) | `ubuntu-26.04` | x86_64 | BIOS | Official cloud qcow2 (`SHA256SUMS`), ext4, `netplan` |
| RAM Rescue | `bootie rescue` | x86_64 | BIOS, UEFI (Secure Boot off) | Structurally non-destructive `debian-initramfs` rescue shell |

UEFI with **Secure Boot enabled** (or unconfirmed) always fails closed —
disable Secure Boot in your provider or firmware settings first. See
[docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md) for the complete support
envelope, refusal rules, and validation status.

## Commands and options

```sh
sh bootie.sh check                       # read-only probe, plan fit, support-envelope verdict
sh bootie.sh version                     # print build version
sh bootie.sh --manifest debian-13        # review + typed approval + unattended reinstall
sh bootie.sh --manifest omarchy-4.5      # reinstall Omarchy (auto-generates per-install sudo/desktop password)
sh bootie.sh rescue                      # typed confirmation + non-destructive RAM rescue boot
sh bootie.sh rescue --console-only       # acknowledge provider-console-only rescue access
sh bootie.sh rescue --clean              # remove rescue initramfs, GRUB entry, hook, and staged files
sh bootie.sh --help                      # full CLI help
```

Options:

```text
--manifest NAME        select a bundled manifest (default: omarchy-4.5)
--manifest-file PATH   use a custom manifest file
--key FILE             add SSH public keys in authorized_keys format
--password             install only: prompt interactively for the managed user's
                       password (blank auto-generates a 10-char password)
--password-file PATH   install only: read the managed user's password from PATH
--accept-risk CLASS    explicitly accept a documented risk override (currently: drivers)
--mirror URL           override the HTTPS release-directory URL for checksum-indexed
                       releases (Debian/Ubuntu); resolved URLs are double-confirmed
--console-only         rescue only: allow rescue without SSH keys when console access exists
--clean                rescue only: remove staged rescue artifacts after returning
--no-reboot            install/rescue: stage everything but leave the reboot to you
```

### Keys, passwords, and SSH access

- **SSH keys:** without `--key`, `bootie` discovers keys already authorized for
  the invoking user and `root`, merges and deduplicates them, and carries them
  into both the RAM live/rescue environment and the new OS's users.
- **Desktop passwords (`sudo` / local login):** desktop manifests without a
  manifest-declared password (such as `omarchy-4.5`) generate a unique
  10-character alphanumeric password per install and display it once in the
  pre-approval review (never committed to manifests or logged on disk). Use
  `--password` or `--password-file` on any manifest to set your own password.
- **SSH key-only:** whenever SSH public keys are installed, `bootie` writes
  `/etc/ssh/sshd_config.d/90-bootie-keyonly.conf` (`PasswordAuthentication no`,
  `KbdInteractiveAuthentication no`) so SSH remains key-only while passwords
  work for `sudo` and local/desktop login.
- **Fail-closed auth:** if no authentication material exists at all, install
  refuses before staging.

### Non-destructive rescue mode

`bootie rescue` boots a separate RAM rescue environment (`debian-initramfs`)
without resolving any manifest or OS image, and without staging any write
command or autostart script. It uses a separate staging directory
(`/usr/local/share/bootie-rescue`), a dedicated one-shot GRUB entry
(`BOOTIE rescue (one-shot)`), and the confirmation token `rescue:<hostname>`.
Rebooting (or running `/bootie-rescue/rescue-helper.sh return`) returns to the
prior OS unchanged, and `sh bootie.sh rescue --clean` removes all rescue
staging files afterward.

## Repository layout

```text
bootie-main             Target-resident POSIX shell CLI entrypoint (packaged into bootie.sh).
engine/                 Core runtime modules bundled into bootie.sh:
                          facts.sh, preflight.py, stage.py, liveenv.sh, password.py,
                          auth-summary.py, dhcp_probe.py, initramfs/rescue hooks & helpers.
manifests/              Bundled, first-class target manifests (Debian 13, Ubuntu 24.04/26.04,
                          Omarchy 4.5), converted to JSON at bundle time so targets need no PyYAML.
schema/                 Machine-validatable JSON Schema definitions (manifest-v2.schema.json)
                          for editor validation and CI/test enforcement.
examples/manifests/     Opinionated, non-default manifest templates (e.g. coding workspace,
                          headless agent runtime, Ubuntu desktop) meant to be copied, reviewed,
                          and passed via --manifest-file.
payload/                Static helper payloads embedded into the bundle and installed only when
                          a manifest explicitly opts in (currently om-desktop for Omarchy).
scripts/                Local build and packaging utilities:
                          scripts/bundle builds the single-file bootie.sh release artifact;
                          scripts/test-bundle smoke-tests file-mode and pipe-mode extraction.
tests/                  Offline unit, schema, shell-lint, and bundle regression test suite.
docs/                   Architecture, support matrix, security model, authoring, recovery, and dev docs.
.github/workflows/      CI verification and tagged GitHub Release workflows (with SHA256SUMS & provenance).
```

The generated `bootie.sh` is a release artifact only (gitignored and never
committed).

## Local development

Requires Python 3.10+, PyYAML (managed via `uv` or a virtualenv), `bash`,
POSIX `sh`/`dash`, and optionally `shellcheck`:

```sh
uv sync --locked
uv run --locked python -m unittest discover -s tests -v
uv run --locked sh scripts/test-bundle
uv run --locked bash scripts/bundle /tmp/bootie.sh
```

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) and [CONTRIBUTING.md](CONTRIBUTING.md)
for full verification commands and contribution guidelines.

## Documentation

- [SCHEMA.md](SCHEMA.md) — human-readable manifest schema reference (machine schema in [schema/manifest-v2.schema.json](schema/manifest-v2.schema.json))
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — execution model, staging flow, and module boundaries
- [docs/BOOT_AND_FIRMWARE.md](docs/BOOT_AND_FIRMWARE.md) — BIOS & UEFI boot design, Secure Boot policy, ESP/NVRAM handling, and separate `/boot`
- [docs/RESCUE_DESIGN.md](docs/RESCUE_DESIGN.md) — live & rescue environment philosophy, lab/emergency security boundaries, and backend tradeoffs
- [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md) — validated environments, refusal rules, and probe behavior
- [docs/ROADMAP.md](docs/ROADMAP.md) — planned targets and backends, including NixOS; not current support
- [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) — threat model, trust boundaries, and destructive-operation controls
- [docs/MANIFEST_AUTHORING.md](docs/MANIFEST_AUTHORING.md) — writing and validating custom manifests
- [docs/RECOVERY.md](docs/RECOVERY.md) — abort points, liveenv inspection, and rescue workflow
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) — local toolchain, test suite, and coding invariants
- [CONTRIBUTING.md](CONTRIBUTING.md) — contributor and pull-request guidelines
- [SECURITY.md](SECURITY.md) — vulnerability reporting policy

## License

[MIT](LICENSE) — Copyright (c) 2026 Sparticle.

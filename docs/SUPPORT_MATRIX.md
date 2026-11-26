# bootie support matrix

This matrix is a core safety feature: it defines what `bootie` is validated to
handle and where it intentionally fails closed. Do not treat absence from this
matrix as support.

## Validation labels

- **drill-proven:** exercised end-to-end on disposable KVM guests using the
  bundled `bootie.sh` artifact.
- **implemented, not drill-proven:** code and offline tests exist, but no
  end-to-end VM rehearsal has validated it yet.
- **refused:** outside the support envelope; `bootie` refuses before mutation.
- **unsupported, not drill-proven:** no support claim or end-to-end validation;
  this label does not promise that every command has an explicit refusal gate.

## Architecture scope

The current target architecture is **x86_64** (also called `amd64` or `x64`).
All bundled manifests and example profiles declare `arch: x86_64`.

- **Omarchy 4.5, Debian 13, and Ubuntu 24.04/26.04:** installation validation
  covers x86_64 only. No ARM (`aarch64` / `arm64`) installation has been
  validated, and ARM targets are unsupported even if upstream offers an image.
- **RAM rescue:** roundtrip validation also covers x86_64 only; ARM rescue is
  unsupported and unvalidated.
- **Enforcement:** bundled install manifests reject a host architecture that
  differs from their `arch` field. This is not a universal architecture gate:
  default rescue has no manifest-architecture fit check, and changing a custom
  manifest's `arch` does not implement or validate another architecture.
- **Development and CI hosts:** building the bundle or passing offline tests
  on ARM64 proves tooling behavior, not ARM kernel/initramfs boot, disk writing,
  personalization, or firstboot. It does not expand target support.

## Platform envelope

| dimension | status | notes |
|---|---|---|
| x86_64 KVM-like full virtualization | drill-proven | BIOS and UEFI (Secure Boot off) + virtio + simple-network shapes |
| bare metal x86_64 | intended, not drill-proven | needs explicit validation; `--accept-risk drivers` is not support |
| ARM (`aarch64`, `arm64`, etc.) | unsupported, not drill-proven | no validated install or rescue path; bundled x86_64 install manifests reject the architecture mismatch |
| OpenVZ / LXC / container virtualization | refused | no kernel/initramfs control |
| BIOS + GRUB | drill-proven | validated across Debian 13, Ubuntu 24.04/26.04, and `bootie rescue` |
| UEFI + GRUB, Secure Boot disabled | drill-proven (OVMF) | validated across `bootie rescue`, Debian 13, Ubuntu 24.04, and Omarchy 4.5 (`BOOTX64.EFI` + best-effort `efibootmgr`) |
| UEFI Secure Boot enabled or unconfirmed | refused | hard prerequisite: disable Secure Boot and ensure efivars are readable; never risk-overridable |
| non-GRUB boot management | refused | default staging requires GRUB; see experimental Alpine rescue below |
| apt-based Debian/Ubuntu source OS | drill-proven | current staging backend requirement (`initramfs-tools` + GRUB) |
| non-apt source OS | refused | default staging requires apt; see experimental Alpine rescue below |
| one clear system disk | drill-proven | hardware fingerprint still required |
| multiple simple disks | warn / review | operator must verify target disk and fingerprint before approval |
| RAID, LVM, encrypted root, multiboot | refused | ambiguous destructive boundary |
| virtio storage and virtio NIC | drill-proven | both families required for a driver pass |
| mixed, non-virtio, or unknown drivers | fail closed unless accepted | `--accept-risk drivers` only when provider console recovery exists; still unverified |
| simple static or DHCP-derived IPv4 + gateway | drill-proven | rendered into initramfs `ip=` cmdline |
| `/32` point-to-point IPv4 | refused | requires onlink route handling |
| missing IPv4 gateway | refused | artifact fetch and firstboot require outbound connectivity |
| split / policy / multi-default routing | refused | unsupported network shape |
| provider console / reinstall recovery | strongly recommended | required in practice for unattended reinstalls and mandatory before using `--accept-risk drivers` |

## Manifest and mode status

| target | architecture | state | notes |
|---|---|---|---|
| `omarchy-4.5` | x86_64 | drill-proven (UEFI Secure Boot off + virtio); BIOS validated | Official Omarchy 4.5 sealed VM qcow2; OVMF UEFI drill passed (native Limine/UKI, btrfs grow + scrub, NetworkManager, `om-desktop`, unattended firstboot upgrade + reboot) |
| `debian-13` | x86_64 | drill-proven (BIOS + UEFI Secure Boot off, virtio) | Official Debian 13 (`trixie`) cloud qcow2 via `SHA512SUMS`; 100% unattended BIOS & OVMF UEFI drills passed |
| `ubuntu-24.04` | x86_64 | drill-proven (BIOS + UEFI Secure Boot off, virtio) | Official Ubuntu 24.04 LTS (`noble`) cloud qcow2 via `SHA256SUMS`; 100% unattended BIOS & OVMF UEFI drills passed (incl. separate `/boot`, ext4 grow, netplan, locale) |
| `ubuntu-26.04` | x86_64 | drill-proven (BIOS + virtio) | Official Ubuntu 26.04 LTS (`resolute`) cloud qcow2 via `SHA256SUMS`; 100% unattended BIOS drill passed |
| `bootie rescue` (`debian-initramfs`) | x86_64 | drill-proven (BIOS + UEFI Secure Boot off, virtio) | Non-destructive RAM rescue roundtrip (`info`, `mount-ro`, `umount`, `return`, `rescue --clean`) passed on BIOS and OVMF UEFI |
| `bootie rescue --rescue-backend alpine-kexec` | x86_64 | drill-proven (Debian 13 KVM, BIOS and OVMF UEFI with Secure Boot off) | 2 GiB RAM, virtio-blk, virtio-net, simple DHCP-derived IPv4, key-only SSH on BIOS and UEFI, explicit serial console-only mode on BIOS. |
| `alpine-kexec` from Omarchy 4.5.0-3 | x86_64 | drill-proven (KVM, Limine/OVMF UEFI with Secure Boot off) | Source requires `kexec-tools`; verified with 2 GiB RAM, virtio-blk/net, simple DHCP-derived IPv4, key-only SSH, read-only Btrfs inspection, and native return. VMware remains outside the current envelope. |
| `examples/manifests/*` | x86_64 (declared, not drill-proven) | example profiles, not drill-proven | Opinionated templates (Ubuntu desktop, coding workspace, headless agent runtime) meant to be reviewed and customized |

NixOS is a [planned target](ROADMAP.md#nixos-target-support), not an implemented
or validated target in this matrix.

## Preflight probes

`engine/preflight.py` evaluates six named probes. `pass` means the probe fits
the current backend; `warn` requires visible operator review; `fail` blocks
staging.

- `virt` — passes on KVM-like VMs (`vm:*`) and bare metal (`none`); refuses
  containers (`container:*`); warns on `unknown`.
- `bootloader` — requires GRUB (`grub-reboot` / `grub2-reboot` + `grub.cfg`);
  all other bootloaders fail closed.
- `firmware` — passes on BIOS and on UEFI with Secure Boot confirmed disabled.
  UEFI with Secure Boot enabled, unknown, or unconfirmed always fails closed.
- `network` — passes on simple IPv4 CIDR + default gateway; refuses `/32`,
  missing gateway, `onlink`, and `multi-default` routes.
- `disk-topology` — passes on a single simple disk; warns on multiple disks;
  refuses RAID, LVM, encrypted root, and complex device-mapper stacks.
- `drivers` — passes when both storage and NIC drivers are virtio; mixed,
  non-virtio, or unknown families fail closed unless `--accept-risk drivers` is
  passed.

### Explicit risk override (`--accept-risk`)

`--accept-risk` accepts comma-separated or repeated classes. Currently the only
supported class is `drivers`, intended strictly for targets with provider
console or reinstall recovery where unverified non-virtio drivers are
acceptable to test. Accepted risks are recorded in `plan.json` and printed in
both `check` output and the pre-mutation review. Accepting a risk is an
explicit operator override, never validation evidence.

## Expansion rule

Support expands only through explicit adapters, offline regression tests, and
disposable-VM validation evidence. A successful run on one environment is
evidence for that shape, not proof of universal compatibility.

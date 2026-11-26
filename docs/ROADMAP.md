# bootie roadmap

This roadmap records planned work, not current support or a release schedule.
[SUPPORT_MATRIX.md](SUPPORT_MATRIX.md) remains authoritative for implemented,
drill-proven, unvalidated, and unsupported scenarios.

## Current baseline

Bundled targets are Omarchy 4.5, Debian 13, and Ubuntu 24.04/26.04, with
x86_64-only installation validation and target-specific firmware coverage.
RAM rescue is also validated only on x86_64. ARM installation and rescue are
unsupported; ARM64 build or unit-test results do not expand that boundary.

The current source-host staging backend requires Debian/Ubuntu package tools,
initramfs-tools, and GRUB. Installing a target OS does not imply that bootie
can subsequently stage another reinstall or rescue from that OS.

## Planned after initial publication

### RAM live/rescue backend beyond Debian/Ubuntu

- Evaluate an `alpine-virt` + `kexec` backend so rescue can be staged from
  Omarchy and other non-apt/non-GRUB source hosts without assuming GRUB or
  Limine integration. This is a design candidate, not implemented support.
- Define fail-closed kernel, boot-handoff, driver, networking, and SSH-access
  prerequisites; preserve structural separation from the disk-write engine.
- Validate non-destructive entry, SSH access, and return to the prior OS on
  disposable VMs before claiming any new source-host compatibility.

See [RESCUE_DESIGN.md](RESCUE_DESIGN.md) for current rescue boundaries and
live-environment tradeoffs.

### NixOS target support

**Status: planned; no bundled manifest, implementation, or installation
validation yet.** NixOS is not currently a supported target.

- Select the NixOS release scope, official upstream artifacts, integrity
  verification, and installation strategy before implementing a manifest.
- Design a declarative NixOS configuration handoff, including SSH access,
  networking, and boot configuration, without embedding credentials.
- Implement the required installation, filesystem, boot, and personalization
  adapters explicitly; changing an OS name or image URL is not enough.
- Keep initial work within the existing x86_64 VPS envelope. ARM support is
  a separate design and validation decision, not implied by NixOS support.
- Add offline regression tests and disposable-VM install/firstboot/recovery
  drills before promoting a particular NixOS release and firmware shape to
  the support matrix.

NixOS as an installation target and NixOS as a source host are separate
capabilities. A target manifest alone would not remove the current
Debian/Ubuntu source-host staging requirement.

### Incremental support-envelope and integration work

- Broaden storage/NIC driver coverage through explicit adapters and VM drills,
  rather than treating `--accept-risk drivers` as validation.
- Design DHCP-backed liveenv networking for confirmed DHCP-served `/32`
  shapes without weakening refusal of ambiguous routing.
- Define opt-in, credential-safe post-boot integration hooks, including the
  Tailscale enrollment seam, without adding credential custody.

## Support-promotion gate

Every expansion needs a defined source/target architecture and firmware
shape, official artifact provenance, offline tests, disposable-VM evidence,
and aligned support/recovery documentation. Passing CI or an ARM64 tooling
simulation alone is never evidence of a supported OS installation path.

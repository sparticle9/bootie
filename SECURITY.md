# Security policy

bootie is a destructive system-installation tool. Incorrect use can erase the
machine on which it is run. The tool is intentionally narrow: unsupported or
unrecognized scenarios must fail closed rather than improvise.

## Reporting vulnerabilities

Please report security vulnerabilities privately using GitHub's **Private
Vulnerability Reporting** (**Security** tab → **Report a vulnerability**).
Do not open a public issue or post exploit details publicly.

Include the affected `bootie` version/commit, target environment (virtualization,
firmware, distro), and minimal reproduction steps so the issue can be triaged
and fixed before disclosure.

## Supported versions

`bootie` is pre-1.0. Security fixes are applied to `main` and the latest tagged
release.

## Operational security summary

- `check` is read-only on the target: it probes facts, resolves the reviewed
  plan, and reports support-envelope status without installing, staging, or
  changing boot state.
- Install mode mutates dependencies, staging, and boot configuration only
  after the operator types the approval token. Before the destructive write
  starts, the one-shot GRUB design returns the machine to the prior OS on a
  normal reboot; staging artifacts and any installed packages are still local
  mutations the operator should clean up or account for.
- The approval token is bound to the reviewed host, manifest, and machine
  fingerprint. The live environment re-derives that fingerprint immediately
  before writing and refuses on mismatch.
- `--accept-risk drivers` is an explicit operator override for unverified
  mixed, non-virtio, or unknown storage/NIC drivers. It is visible in check
  output and the review; it is never silent support or validation evidence.
- `--mirror URL` is an HTTPS-only operator override for checksum-indexed
  Debian/Ubuntu-style release directories. The exact artifact URL,
  `source_index`, checksum, and mirror override are printed before the
  approval token for double confirmation.
- `bootie rescue` is structurally non-destructive: separate rescue staging,
  a separate one-shot GRUB entry, no install payload, no write engine, and no
  autostart. It refuses keyless headless use unless `--console-only`
  explicitly acknowledges provider-console-only access.
- SSH public keys are the preferred access path. Desktop manifests (such as
  `omarchy-4.5`) generate a unique per-install alphanumeric password at install
  time (or accept an operator-supplied password via `--password` /
  `--password-file`) for `sudo` and local/desktop login while keeping SSH
  key-only whenever SSH keys are installed. Password hashes are never printed in
  reviews or logs, and no static default password is ever embedded in manifests.
- bootie does not host or mirror OS images; target machines fetch upstream
  artifacts directly from the resolved release locations. Displayed checksums
  aid review but are not yet a complete artifact-provenance or signature
  verification model.
- bootie does not embed Tailscale auth keys, tailnet identity, private keys,
  API tokens, or credential custody logic.

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for the full threat
model, residual risks, and destructive-operation controls.

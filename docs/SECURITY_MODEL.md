# bootie security model

## Scope and threat context

`bootie` intentionally performs destructive operations. The security objective
is not to make erasing a disk safe in the abstract; it is to ensure the
operator knows **exactly** which machine, disk, manifest, artifact, and access
configuration they are approving, and to make unsupported or ambiguous
scenarios fail closed before mutation.

`bootie` is target-resident. It maintains no control plane, receives no remote
commands, and contacts no `bootie`-operated infrastructure. A compromised
target, compromised operator terminal, or compromised upstream release source
cannot be defeated solely by a target-resident script; the controls below are
designed to make mistakes visible and narrow blast radius.

## Trust boundaries

1. **Operator to target** — the operator runs `bootie` directly on the machine
   (typically over SSH), inheriting that session's authentication and trust.
2. **Target to upstream release sites** — the target resolves and streams OS
   images directly from upstream release locations. `bootie` never hosts,
   mirrors, or repacks OS images.
3. **Operator to optional mirror** — `--mirror URL` is an explicit HTTPS-only
   operator override; trusting that mirror is the operator's responsibility.
4. **Old OS to RAM live environment** — the reviewed plan is staged locally
   into a one-shot initramfs. Once booted, the live environment never fetches
   configuration from the network.
5. **Live environment to disk** — the destructive boundary. `liveenv.sh`
   re-derives the hardware fingerprint immediately before writing and refuses
   on any mismatch.
6. **New OS to operator** — SSH host keys are pre-generated during
   personalization and their fingerprints are logged in the live environment so
   first SSH contact can be verified.
7. **Repository to release artifact** — `bootie.sh` is built by the release
   workflow alongside `SHA256SUMS` and GitHub build-provenance attestations; it
   is never committed to the source tree.

## Approval and hardware-fingerprint binding

The install approval token (`<host>:<manifest>:<version>:<fingerprint>`) is a
typed interlock bound to:

- the reviewed hostname, manifest name, and manifest version;
- a 16-hex-char hardware fingerprint derived from architecture, firmware, disk
  path/model/size/serial/WWN, partition-table UUIDs, and primary NIC MAC.

Hostname is displayed in the token for human verification but excluded from the
hardware fingerprint. Before `write`, the live environment recomputes the
fingerprint with the same POSIX `facts.sh` implementation and aborts on any
difference.

Rescue mode uses the separate typed token `rescue:<hostname>` while still
displaying the disk identity and hardware fingerprint in the review.

## Read-only, reversible, and point-of-no-return phases

- `check` is read-only on the target: it collects facts, resolves the plan, and
  reports fit/envelope status (plus a read-only DHCPDISCOVER probe) without
  installing packages, staging files, or altering GRUB.
- `install` and `rescue` mutate dependencies, staging directories, and GRUB
  only after the operator types the confirmation token.
- Before the live-environment `write` starts, rebooting returns to the prior OS
  unchanged (one-shot GRUB entry; prior OS remains `GRUB_DEFAULT=saved`). Local
  staging artifacts and installed packages remain on the prior OS until cleaned
  up.
- **Point of no return:** once `qemu-img convert` starts writing to the target
  disk, the old OS must be treated as gone.

## Fail-closed support envelope and `--accept-risk`

Unsupported virtualization, bootloaders, firmware (including UEFI Secure Boot
enabled or unconfirmed), complex network shapes, RAID/LVM/encrypted root
layouts, and unimplemented artifact backends fail closed before mutation.

`--accept-risk drivers` is the only risk override. It downgrades the `drivers`
probe from `fail` to `warn` for mixed/non-virtio/unknown storage or NIC drivers
when provider console recovery is available, is recorded in `plan.json`, and is
printed in both `check` output and the pre-mutation review. It is never a
general force flag and cannot override firmware, Secure Boot, container,
network, or disk-topology failures.

## Artifact resolution, checksums, and `--mirror`

Upstream release indexes (`index_url` JSON or `checksums_url` SHA256SUMS /
SHA512SUMS) are resolved at plan time. Both `check` and the pre-destruction
review print the resolved image URL, index URL, expected digest, and any
`--mirror` override.

`--mirror URL` enforces HTTPS, a valid hostname, and no whitespace, applies
only to checksum-indexed manifests, and substitutes the base URL for both the
checksum file and image file. Because a mirror controls both files, HTTPS
validates transport to the mirror rather than independent upstream provenance;
only use mirrors you independently trust.

`qemu-img convert` checks the remote image header/virtual size before writing
and streams compressed `qcow2` ranges directly to disk without buffering
multi-gigabyte archives in RAM (keeping small VPSes viable). Integrity relies
on HTTPS transport to the reviewed URL, header/size validation, and post-write
filesystem verification (`btrfs scrub` or `e2fsck`). Full pre-write signature
verification remains a known limitation below.

## Non-destructive rescue boundary

`bootie rescue` isolates recovery from installation structurally:

- offline `rescue-plan` (no manifest or OS artifact resolution);
- separate staging directory (`/usr/local/share/bootie-rescue`), initramfs hook
  (`bootie-rescue`), initrd (`/boot/initrd-bootie-rescue.img`), and GRUB entry
  (`BOOTIE rescue (one-shot)`);
- no `plan.env`, `liveenv.sh`, `qemu-img`, install payload, or autostart staged;
- read-only default helper (`rescue-helper.sh mount-ro`) and `rescue --clean`;
- refuses keyless headless rescue unless `--console-only` is passed.

The rescue environment still provides a root shell (manual disk writes remain
possible if the operator runs them deliberately), so treat rescue access with
the same care as root SSH access.

## Authentication, passwords, and secrets

- **SSH public keys:** carried from `--key` or discovered from the invoking
  user and `root`, merged and deduplicated, and installed into dropbear
  initramfs and target users.
- **Desktop and operator passwords:** desktop manifests (`boot_target: desktop`)
  without a manifest-declared password generate a unique 10-character
  alphanumeric password at install time (`engine/password.py`), print it once
  in the review block, and immediately delete the temporary plaintext file.
  `--password` prompts with echo disabled (`stty -echo`) and `--password-file`
  reads from a file so plaintext passwords never appear in `ps` argv. Only the
  SHA-512 crypt (`$6$`) hash enters `plan.json` and `plan.env` (both mode
  `0600`), and hashes are never printed in reviews or logs. No static default
  password is ever embedded in public manifests.
- **SSH key-only enforcement:** whenever SSH public keys are installed,
  `liveenv.sh` writes `/etc/ssh/sshd_config.d/90-bootie-keyonly.conf`
  (`PasswordAuthentication no`, `KbdInteractiveAuthentication no`) so passwords
  work for `sudo` and local/desktop login without opening SSH to password
  brute-forcing.
- **Zero-auth refusal:** if no SSH keys and no password material exist, install
  refuses before staging.
- **No credential custody:** `bootie` embeds no private keys, passwords, API
  tokens, or VPN/tailnet auth keys, and uploads no target state anywhere.

## Threat-model summary

| scenario | mitigation | residual risk |
|---|---|---|
| Approving the wrong machine or disk | Review shows host, disk, size, manifest, fingerprint; typed token binds them; liveenv re-verifies fingerprint before write | Token is an operator interlock, not cryptographic auth against a compromised target/terminal |
| Accidental execution in pipe mode | No mutation before typed approval; prompts read from `/dev/tty` when stdin is piped | Operator can still type the token carelessly |
| Unsupported firmware/network/disk/virt | Six-probe support envelope fails closed with remediation message | Novel platforms could theoretically be misclassified |
| Unverified non-virtio drivers | Fails closed by default; `--accept-risk drivers` is explicit and visible | Accepted non-virtio drivers may still fail inside initramfs, requiring provider console |
| Untrusted `--mirror` | HTTPS-only; URL, index, digest, and override repeated before approval | Mirror controls both index and image; operator must independently trust it |
| Liveenv/rescue SSH exposure | Only carried/`--key` public keys authorized; ephemeral host key warning | Any holder of a matching private key can access the RAM shell while booted |
| Interrupted write/personalize | Idempotent phase markers prevent blind replay of completed phases | Interruption after write starts leaves partial disk requiring console/reinstall recovery |
| Release artifact tampering | `bootie.sh` never committed; release workflow publishes `SHA256SUMS` and build-provenance attestations | Operators should verify checksums/attestations before running |

## Known limitations

- The approval interlock cannot protect against an attacker who already controls
  the target host or operator terminal.
- The staged plan is local and not externally signed.
- UEFI Secure Boot enabled (or unconfirmed) and complex network shapes (`/32`
  onlink, multi-default routing) fail closed.
- Non-virtio storage/NIC drivers and bare-metal targets are not yet
  drill-proven.
- Target OS image integrity relies on HTTPS transport, reviewed checksums,
  header/size checks, and post-write filesystem verification rather than full
  pre-write cryptographic signature verification.

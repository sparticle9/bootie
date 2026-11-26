# Contributing to bootie

`bootie` is a destructive, target-resident system reinstall tool licensed under
the [MIT License](LICENSE). Contributions must preserve its core safety rule:
unsupported or ambiguous scenarios fail closed before mutation rather than
improvising compatibility.

## Scope and support expectations

The narrow support envelope is intentional. Before opening an issue or proposing
a feature, read [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md). A scenario
marked refused, unsupported, or not drill-proven is not automatically a bug.
Expanding support requires an explicit adapter, offline regression tests, and
VM validation evidence proportionate to the risk.

Welcome contributions include:

- fixes for incorrect fail-open behavior, unclear refusal messages, or
  misleading review/approval output;
- offline regression tests for schema validation, plan generation, key/password
  handling, artifact resolution, shell quoting, support-envelope probes, or
  bundle extraction;
- narrow bug fixes that preserve fail-closed behavior everywhere outside the
  validated envelope;
- documentation improvements that keep implemented, drill-proven, and refused
  states accurate.

Support-expansion proposals should describe the exact machine shape, why it
belongs in the support envelope, what can fail closed, and what VM evidence
validates it.

## Reporting issues

For non-security bugs, include:

- the `bootie` version or commit (`sh bootie.sh version`);
- the command and manifest name (or custom manifest shape);
- redacted `check` output, especially the support-envelope probe lines;
- whether the target was a disposable VM or a real machine, and which phase
  failed (preflight, staging, liveenv, or post-boot);
- relevant logs with secrets, private hostnames, private IP addresses, and
  infrastructure inventories removed.

For suspected security vulnerabilities, do **not** open a public issue — follow
[SECURITY.md](SECURITY.md) (GitHub Private Vulnerability Reporting). Never
attach unredacted `plan.env`, password hashes, private keys, or tokens to an
issue or pull request.

## Local verification

Run the full verification suite before opening a pull request:

```sh
uv sync --locked
uv run --locked python -m compileall -q engine tests
uv run --locked python -m unittest discover -s tests -v

for f in bootie-main engine/*.sh scripts/test-bundle; do
  dash -n "$f"   # sh -n is an acceptable fallback when dash is absent
done
bash -n scripts/bundle payload/om-desktop

shellcheck -S info -s sh bootie-main engine/*.sh scripts/test-bundle
shellcheck -S info -s bash scripts/bundle payload/om-desktop

uv run --locked sh scripts/test-bundle
```

`tests/test_schema.py` validates every manifest under `manifests/` and
`examples/manifests/` against `schema/manifest-v2.schema.json` and verifies
parity with `engine/preflight.py`.

## Implementation rules

- Never edit a generated `bootie.sh`; edit the modular sources and regenerate
  with `scripts/bundle`.
- Never commit `bootie.sh`; it is a release-only artifact.
- Target-side Python (`engine/*.py`) must use the **Python standard library
  only** (Python 3.10+). PyYAML is strictly a build/test-time dependency.
- Target-side shell (`bootie-main`, `engine/*.sh`) must remain POSIX and
  busybox-safe. Only `scripts/bundle` and `payload/om-desktop` are bash-scoped.
- Every `apt-get` call must run with `DEBIAN_FRONTEND=noninteractive`.
- Do not introduce controller dependencies, self-hosted OS image mirrors,
  hidden network enrollment, secret custody, or static default passwords.
- Unknown manifest keys and unsupported machine shapes must remain hard errors
  or fail-closed checks.
- Do not copy GPL-licensed code into this MIT-licensed repository.

## Destructive-change evidence

Changes to disk writing, bootloader/UEFI behavior, initramfs startup,
personalization, firstboot, rescue, or recovery cannot be marked validated on
unit tests alone. Provide appropriate disposable-VM evidence:

1. read-only `check` output for probe or plan changes;
2. non-destructive liveenv or `bootie rescue` roundtrip for staging/boot
   changes;
3. full unattended destructive VM drill for write/personalize/firstboot changes;
4. clean return-to-prior-OS and `--clean` verification for rescue and one-shot
   boot changes.

## Pull request guidelines

Keep pull requests small and conventional-commit friendly. Describe the safety
boundary affected, the checks run, and any area that remains unverified or
fail-closed. Call out any change touching approval binding, fingerprint checks,
checksum/mirror review, password handling, or artifact bundling in the opening
paragraph.

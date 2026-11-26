# bootie development guide

## Ground rules

- Edit the modular sources (`bootie-main`, `engine/`, `manifests/`, `schema/`,
  `payload/`) and regenerate `bootie.sh` with `scripts/bundle`. Never edit or
  commit a generated `bootie.sh`.
- Keep target-side Python (`engine/*.py`) **standard-library only** (Python
  3.10+). PyYAML is strictly a build/test-time dependency for converting YAML
  manifests to JSON and running tests.
- Keep target-side shell (`bootie-main`, `engine/*.sh`) POSIX and
  `busybox`-compatible. Only `scripts/bundle` and `payload/om-desktop` are
  bash-scoped.
- Keep failure handling strict: unknown manifest keys and unsupported hardware
  or network shapes must fail closed with clear remediation messages.

## Toolchain

Required locally:

- Python 3.10+
- PyYAML (declared in `pyproject.toml`; managed via `uv` or a standard venv)
- POSIX `sh` / `dash`, `bash`, `tar`, `base64`
- `shellcheck` (recommended locally; enforced in CI and unit tests when present)

`bootie` is not distributed as a Python package; `pyproject.toml` exists only
to pin the small build/test dependency cleanly.

## Standard verification

From the repository root:

```sh
# Install exactly the dependencies committed in uv.lock.
uv sync --locked

# Python compilation + full offline unit & schema test suite
uv run --locked python -m compileall -q engine tests
uv run --locked python -m unittest discover -s tests -v

# POSIX & bash syntax checks
for f in bootie-main engine/*.sh scripts/test-bundle; do
  dash -n "$f"   # sh -n fallback if dash is not installed
done
bash -n scripts/bundle payload/om-desktop

# Static shell analysis
shellcheck -S info -s sh bootie-main engine/*.sh scripts/test-bundle
shellcheck -S info -s bash scripts/bundle payload/om-desktop

# Bundle build + file-mode and pipe-mode extraction smoke test
uv run --locked sh scripts/test-bundle
```

If `uv` is unavailable, create a standard virtual environment, install
`PyYAML>=6.0.2,<7`, and run the same commands with that venv's `python`.

## CI and release workflows

- **CI** (`.github/workflows/ci.yml`) runs on pushes, pull requests, and manual
  dispatch. It has read-only repository permissions and never publishes.
- **Release** (`.github/workflows/release.yml`) repeats the same verification
  before building `bootie.sh` and `SHA256SUMS`. Attestation upload and GitHub
  Release creation require a `v*` tag; a manual run on a branch builds and
  verifies without publishing. Release creation requires an existing tag.
- Actions are pinned to full upstream commit SHAs, with release versions in
  comments. `astral-sh/setup-uv` manages uv and the Python 3.12 selection;
  `latest-known` selects the uv release bundled with that pinned action, with
  a required checksum. Dependencies are installed from `uv.lock` using
  `uv sync --locked`; Python and bundle commands use `uv run --locked`.
- GitHub-hosted Ubuntu images already include ShellCheck. Both workflows
  verify its availability and lint at `-S info`; neither runs apt nor replaces
  the linter. A different local runner image must provide ShellCheck itself.
- Checkout does not persist repository credentials. uv cache uploads are
  disabled: the single small Python dependency does not justify cache storage
  or service overhead.

Local tests and an `act` run can exercise the verification commands, action
setup, and event selection, but are not a hosted GitHub Actions result. Runner
image/architecture differences, repository permissions, hosted checkout,
OIDC attestations, and release publication still need their own verification.
Do not run the release workflow as a local CI simulation.

Build/test-host architecture is separate from target-OS support. Offline tests
or CI verification steps can pass on an ARM64 workstation or container without
booting or installing any ARM OS. Current Omarchy, Debian, Ubuntu, and RAM
rescue validation is x86_64 only; ARM targets remain unsupported. See
[SUPPORT_MATRIX.md](SUPPORT_MATRIX.md#architecture-scope).

## Building `bootie.sh` locally

```sh
uv run --locked bash scripts/bundle /tmp/bootie.sh
sh /tmp/bootie.sh version
```

`/bootie.sh` at the repo root is gitignored to prevent accidental commits.

## Test pyramid

1. **Schema validation (`tests/test_schema.py`):** validates every file in
   `manifests/*.yml` and `examples/manifests/*.yml` against
   `schema/manifest-v2.schema.json` and verifies key-set parity with
   `engine/preflight.py`.
2. **Offline unit tests (`tests/test_*.py`):** cover fact parsing, Secure Boot
   probing, support-envelope classification, artifact/mirror resolution,
   per-install password generation and SHA-512 crypt vectors, POSIX shell
   quoting roundtrips, approval binding, rescue plan/helper contracts, and
   liveenv personalization/verification logic.
3. **Static & bundle checks (`scripts/test-bundle`, `shellcheck`):** verify
   POSIX/bash syntax, shellcheck cleanliness, embedded payload completeness,
   and both file-mode and pipe-mode execution.
4. **Disposable-VM drills (BIOS & OVMF UEFI):** run deliberately before
   shipping changes that touch disk writes, bootloaders, initramfs hooks,
   personalization, firstboot, or rescue behavior.

## Key invariants pinned by tests

- `plan.env` round-trips through POSIX single-quoting, including single quotes,
  `$`, backticks, and multi-line `authorized_keys`.
- Both storage and NIC drivers must be virtio for a `drivers` pass; mixed or
  non-virtio shapes fail closed unless `--accept-risk drivers` is passed.
- UEFI Secure Boot enabled or unconfirmed always fails closed and is never
  risk-overridable.
- Options-prefixed `authorized_keys` lines (including quoted spaces) survive
  filtering and multi-source deduplication.
- Interactive prompts read from `/dev/tty` in pipe mode (`curl ... | sh`), and
  `bootie_prompt_secret` disables terminal echo for `--password`.
- Every `apt-get` invocation runs with `DEBIAN_FRONTEND=noninteractive`.
- SHA-512 crypt output in `engine/password.py` matches standard Drepper test
  vectors and `openssl passwd -6` without requiring Python's removed `crypt`
  module.
- SSH `PasswordAuthentication` is disabled automatically whenever SSH public
  keys are installed, while password-only installs preserve SSH password login.
- Heredoc bundle extraction works identically in file mode and pipe mode.

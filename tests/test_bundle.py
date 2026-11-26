"""CLI, key-discovery, prompt, apt-interaction, and bundle regression tests."""
import base64
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "bootie-main").read_text()
LIVE = (ROOT / "engine/liveenv.sh").read_text()
BUILDER = (ROOT / "scripts/bundle").read_text()

KEY1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEfakefakefakefakefakefakefakefakefakef key-one"
KEY2 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCfakefakefakefakefakefakefakekey key-two"
KEY3 = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIfakefakefakekey key-three"


def run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, **kwargs)


class KeyDiscoveryTests(unittest.TestCase):
    def test_keyfilter_accepts_options_prefixed_keys(self):
        data = KEY1 + "\nrestrict " + KEY1 + "\n# comment\nnot-a-key line\n"
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            tmp.write(data)
            path = tmp.name
        try:
            with open(path) as fh:
                r = subprocess.run([str(ROOT / "engine/keyfilter.sh")], stdin=fh,
                                   capture_output=True, text=True, cwd=ROOT)
        finally:
            Path(path).unlink()
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = r.stdout.splitlines()
        self.assertIn(KEY1, lines)
        self.assertIn("restrict " + KEY1, lines)
        self.assertNotIn("not-a-key line", lines)

    def test_keyfilter_accepts_options_with_quoted_spaces(self):
        quoted = 'command="/usr/bin/foo --bar",no-port-forwarding ' + KEY1
        escaped = r'command="/usr/bin/foo --name \"quoted value\"",restrict ' + KEY2
        data = quoted + "\n" + escaped + "\n"
        r = subprocess.run([str(ROOT / "engine/keyfilter.sh")], input=data,
                           capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = r.stdout.splitlines()
        self.assertIn(quoted, lines)
        self.assertIn(escaped, lines)

    def test_multi_key_merge_dedupes_across_sources_preserving_order(self):
        with tempfile.TemporaryDirectory() as td:
            a = Path(td) / "a_keys"
            b = Path(td) / "b_keys"
            out = Path(td) / "out"
            a.write_text(KEY1 + "\n" + KEY2 + "\n")
            b.write_text("restrict " + KEY1 + "\n" + KEY2 + "\n" + KEY3 + "\n")
            r = run([str(ROOT / "engine/merge-key-files.sh"), str(out), str(a), str(b)])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(out.read_text().splitlines(), [KEY1, KEY2, "restrict " + KEY1, KEY3])

    def test_keyfilter_dedupes_exact_lines(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            tmp.write(KEY1 + "\n" + KEY1 + "\n")
            path = tmp.name
        try:
            with open(path) as fh:
                r = subprocess.run([str(ROOT / "engine/keyfilter.sh")], stdin=fh,
                                   capture_output=True, text=True, cwd=ROOT)
        finally:
            Path(path).unlink()
        self.assertEqual(r.stdout.splitlines(), [KEY1])

    def test_entrypoint_uses_testable_merge_implementation(self):
        self.assertIn("engine/merge-key-files.sh", MAIN)
        self.assertIn("$HOME/.ssh/authorized_keys", MAIN)
        self.assertIn("/root/.ssh/authorized_keys", MAIN)


class PromptAndAuthTests(unittest.TestCase):
    def test_prompt_prefers_tty_path_over_piped_stdin(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as tty:
            tty.write("tty-answer\n")
            tty_path = tty.name
        try:
            script = ". engine/prompt.sh; bootie_prompt_read; printf '%s' \"$REPLY\""
            r = subprocess.run(
                ["sh", "-c", script], input="stdin-answer\n", capture_output=True, text=True,
                cwd=ROOT, env={**os.environ, "BOOTIE_PROMPT_TTY": tty_path},
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout, "tty-answer")
        finally:
            Path(tty_path).unlink()

    def test_prompt_falls_back_to_stdin_without_tty(self):
        script = ". engine/prompt.sh; bootie_prompt_read; printf '%s' \"$REPLY\""
        r = subprocess.run(
            ["sh", "-c", script], input="stdin-answer\n", capture_output=True, text=True,
            cwd=ROOT, env={**os.environ, "BOOTIE_PROMPT_TTY": "/definitely/not/a/tty"},
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, "stdin-answer")

    def test_prompt_secret_prefers_tty_and_falls_back_to_stdin(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as tty:
            tty.write("tty-secret\n")
            tty_path = tty.name
        try:
            script = ". engine/prompt.sh; bootie_prompt_secret; printf '%s' \"$REPLY\""
            r_tty = subprocess.run(
                ["sh", "-c", script], input="stdin-secret\n", capture_output=True, text=True,
                cwd=ROOT, env={**os.environ, "BOOTIE_PROMPT_TTY": tty_path},
            )
            self.assertEqual(r_tty.returncode, 0, r_tty.stderr)
            self.assertEqual(r_tty.stdout, "tty-secret")
        finally:
            Path(tty_path).unlink()
        r_stdin = subprocess.run(
            ["sh", "-c", script], input="stdin-secret\n", capture_output=True, text=True,
            cwd=ROOT, env={**os.environ, "BOOTIE_PROMPT_TTY": "/definitely/not/a/tty"},
        )
        self.assertEqual(r_stdin.returncode, 0, r_stdin.stderr)
        self.assertEqual(r_stdin.stdout, "stdin-secret")

    def test_entrypoint_tty_contract_is_before_approval_use(self):
        self.assertIn('/dev/tty', (ROOT / "engine/prompt.sh").read_text())
        self.assertIn("bootie_prompt_read", MAIN)
        self.assertLess(MAIN.index("prompt_read"), MAIN.index("typed_approval"))

    def test_auth_summary_zero_authentication_is_fatal(self):
        with tempfile.TemporaryDirectory() as td:
            plan = Path(td) / "plan.json"
            plan.write_text('{"cloud_ops": {"users": []}}')
            r = run([str(ROOT / "engine/auth-summary.py"), str(plan), "0"])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("FATAL", r.stdout)

    def test_auth_summary_password_only_and_key_shapes(self):
        with tempfile.TemporaryDirectory() as td:
            plan = Path(td) / "plan.json"
            plan.write_text('{"cloud_ops": {"users": [{"name":"agent","passwd":"hash","lock_passwd":false}]}}')
            r = run([str(ROOT / "engine/auth-summary.py"), str(plan), "0"])
            self.assertIn("password-only", r.stdout)
            plan.write_text('{"cloud_ops": {"users": [{"name":"agent","keys":["ssh-ed25519 AAAA"]}]}}')
            r = run([str(ROOT / "engine/auth-summary.py"), str(plan), "1"])
            self.assertIn("keys=2 carried=1 manifest_keys=1", r.stdout)
            self.assertIn("key", r.stdout)


class CliAndReviewTests(unittest.TestCase):
    def test_cli_option_missing_value_exits_cleanly(self):
        for flag in ("--key", "--password-file", "--manifest", "--manifest-file", "--accept-risk", "--mirror"):
            with self.subTest(flag=flag):
                r = run(["sh", "bootie-main", flag])
                self.assertEqual(r.returncode, 2, r.stderr + r.stdout)
                self.assertIn(f"{flag} requires", r.stderr)
                self.assertIn("usage: bootie", r.stderr)
                self.assertNotIn("unbound variable", r.stderr)
                self.assertNotIn("parameter not set", r.stderr)

    def test_help_documents_accept_risk_and_mirror(self):
        r = run(["sh", "bootie-main", "--help"])
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertIn("--password", r.stderr)
        self.assertIn("--password-file PATH", r.stderr)
        self.assertIn("--accept-risk CLASS", r.stderr)
        self.assertIn("drivers", r.stderr)
        self.assertNotIn("not yet drill-proven", r.stderr)
        self.assertIn("provider console", r.stderr)
        self.assertIn("--mirror URL", r.stderr)
        self.assertIn("checksum-indexed releases", r.stderr)
        self.assertIn("double confirmation", r.stderr)

    def test_password_option_validation_rejects_bad_combinations_before_privilege(self):
        cases = (
            (["check", "--password"], "--password only applies to install"),
            (["rescue", "--password"], "--password only applies to install"),
            (["check", "--password-file", "/tmp/pw"], "--password-file only applies to install"),
            (["rescue", "--password-file", "/tmp/pw"], "--password-file only applies to install"),
            (["install", "--password", "--password-file", "/tmp/pw"], "--password and --password-file cannot be used together"),
            (["install", "--password-file", "/definitely/missing/pwfile"], "password file not found"),
        )
        for argv, message in cases:
            with self.subTest(argv=argv):
                r = run(["sh", "bootie-main", *argv])
                self.assertEqual(r.returncode, 2, r.stderr + r.stdout)
                self.assertIn(message, r.stderr)
                self.assertNotIn("privilege model", r.stdout)

    def test_help_documents_rescue_command_and_options(self):
        r = run(["sh", "bootie-main", "--help"])
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertIn("rescue         boot into a non-destructive RAM rescue environment", r.stderr)
        self.assertIn("--console-only", r.stderr)
        self.assertIn("--clean", r.stderr)
        self.assertIn("stages no write command or autostart", r.stderr)
        self.assertIn("--rescue-backend alpine-kexec", r.stderr)
        self.assertIn("--rescue-console TTY", r.stderr)
        self.assertIn("install/rescue", r.stderr)

    def test_rescue_rejects_manifest_mirror_options_before_privilege_or_facts(self):
        cases = (
            (["rescue", "--manifest", "omarchy-4.5"], "--manifest does not apply to rescue"),
            (["rescue", "--manifest-file", "x"], "--manifest-file does not apply to rescue"),
            (["rescue", "--mirror", "https://mirror.invalid"], "--mirror does not apply to rescue"),
        )
        for argv, message in cases:
            with self.subTest(argv=argv):
                r = run(["sh", "bootie-main", *argv])
                self.assertEqual(r.returncode, 2, r.stderr + r.stdout)
                self.assertIn(message, r.stderr)
                self.assertIn("usage: bootie", r.stderr)
                self.assertNotIn("privilege model", r.stdout)
                self.assertNotIn("collecting machine facts", r.stdout)
        self.assertIn("manifest=$2; manifest_set=1; shift 2", MAIN)
        self.assertLess(MAIN.index("--manifest does not apply to rescue"), MAIN.index("# --- privilege model"))

    def test_install_and_check_reject_rescue_only_options_before_privilege(self):
        cases = (
            (["install", "--clean"], "--clean only applies to rescue"),
            (["install", "--console-only"], "--console-only only applies to rescue"),
            (["check", "--clean"], "--clean only applies to rescue"),
            (["check", "--console-only"], "--console-only only applies to rescue"),
            (["check", "--no-reboot"], "--no-reboot only applies to install and rescue"),
        )
        for argv, message in cases:
            with self.subTest(argv=argv):
                r = run(["sh", "bootie-main", *argv])
                self.assertEqual(r.returncode, 2, r.stderr + r.stdout)
                self.assertIn(message, r.stderr)
                self.assertIn("usage: bootie", r.stderr)
                self.assertNotIn("privilege model", r.stdout)

    def test_rescue_cli_contract_is_separate_and_structurally_non_destructive(self):
        self.assertIn("rescue) cmd=rescue; shift ;;", MAIN)
        self.assertIn('python3 "$here/engine/preflight.py" rescue-plan "$@"', MAIN)
        self.assertIn(
            "REFUSING: rescue mode has no SSH keys and --console-only was not passed — "
            "pass --key, ensure authorized_keys exists, or pass --console-only if you have provider console access",
            MAIN,
        )
        self.assertIn("staging=/usr/local/share/bootie-rescue", MAIN)
        self.assertIn("/etc/grub.d/41_bootie_rescue", MAIN)
        self.assertIn("BOOTIE rescue (one-shot)", MAIN)
        self.assertIn("/etc/initramfs-tools/hooks/bootie-rescue", MAIN)
        self.assertIn('"$here/engine/rescue-helper.sh"', MAIN)
        self.assertIn('"$here/engine/rescue-hook.sh"', MAIN)
        self.assertIn("/bootie-rescue/rescue-helper.sh info", MAIN)
        self.assertIn("/bootie-rescue/rescue-helper.sh return", MAIN)
        self.assertIn("sh bootie.sh rescue --clean", MAIN)
        self.assertIn("/boot/initrd-bootie-rescue.img", MAIN)
        self.assertIn("grub_editenv=$(command -v grub-editenv || true)", MAIN)
        self.assertIn("next_entry=BOOTIE rescue (one-shot)", MAIN)
        self.assertIn("rescue cleanup complete", MAIN)
        self.assertIn('if [ "$cmd" = install ] || [ "$cmd" = rescue ]; then', MAIN)
        self.assertLess(MAIN.index('if [ "$cmd" = rescue ] && [ -n "$rescue_clean" ]; then'),
                        MAIN.index("# --- dependencies"))
        start = MAIN.index("# --- rescue review + non-destructive staging")
        end = MAIN.index("# --- operator review + one typed approval", start)
        branch = MAIN[start:end]
        self.assertLess(branch.index("/etc/dropbear/initramfs/authorized_keys"),
                        branch.index("installing rescue live env packages"))
        self.assertNotIn("stage.py", branch)
        self.assertNotIn("qemu-img", branch)
        self.assertNotIn("initramfs-hook.sh", branch)
        self.assertNotIn("initramfs-autostart.sh", branch)

    def test_rescue_review_is_clear_and_non_destructive(self):
        marker = "python3 - \"$work/plan.json\" \"$carried_keys\" \"$key_sources\" \"$console_only\" <<'PY'\n"
        start = MAIN.index(marker) + len(marker)
        script = MAIN[start:MAIN.index("\nPY\n", start)]
        with tempfile.TemporaryDirectory() as td:
            plan = Path(td) / "plan.json"
            plan.write_text(json.dumps({
                "host": "rescuehost",
                "facts": {
                    "disk_path": "/dev/vda",
                    "disk_size_bytes": 20 * 1024 ** 3,
                },
                "fingerprint": "fp123",
                "accepted_risks": ["drivers"],
                "approval": "rescue:rescuehost",
            }))
            with_keys = subprocess.run(
                [sys.executable, "-", str(plan), "2", "--key carried-keys", ""],
                input=script, capture_output=True, text=True, cwd=ROOT,
            )
            console_only = subprocess.run(
                [sys.executable, "-", str(plan), "0", "", "1"],
                input=script, capture_output=True, text=True, cwd=ROOT,
            )
        self.assertEqual(with_keys.returncode, 0, with_keys.stderr)
        self.assertIn("Rescue review:", with_keys.stdout)
        self.assertIn("host=rescuehost disk=/dev/vda size=20GiB", with_keys.stdout)
        self.assertIn("fingerprint=fp123", with_keys.stdout)
        self.assertIn("accepted_risks=drivers (explicit operator override)", with_keys.stdout)
        self.assertIn("ssh_rescue_keys=2 key(s) (--key carried-keys)", with_keys.stdout)
        self.assertIn("NON-DESTRUCTIVE: no OS image or write command will be staged; rebooting returns to the prior OS unchanged", with_keys.stdout)
        self.assertIn("Confirmation token: rescue:rescuehost", with_keys.stdout)
        self.assertEqual(console_only.returncode, 0, console_only.stderr)
        self.assertIn("ssh_rescue_keys=none (console-only access explicitly acknowledged)", console_only.stdout)

    def test_rescue_env_renderer_contains_only_needed_posix_quoted_values(self):
        marker = "python3 - \"$work/plan.json\" > \"$work/rescue.env\" <<'PY'\n"
        start = MAIN.index(marker) + len(marker)
        script = MAIN[start:MAIN.index("\nPY\n", start)]
        with tempfile.TemporaryDirectory() as td:
            plan = Path(td) / "plan.json"
            plan.write_text(json.dumps({
                "host": "rescuehost",
                "fingerprint": "fp123",
                "facts": {
                    "hostname": "rescuehost",
                    "disk_path": "/dev/vda",
                    "net_if": "eth0",
                    "ipv4_addr": "192.0.2.10/24",
                    "ipv4_gateway": "192.0.2.1",
                    "ipv6_addr": "2001:db8::10/64",
                    "ipv6_gateway": "2001:db8::1",
                    "dns": "192.0.2.53",
                },
            }))
            r = subprocess.run(
                [sys.executable, "-", str(plan)],
                input=script, capture_output=True, text=True, cwd=ROOT,
            )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.splitlines(), [
            "HOSTNAME_V='rescuehost'",
            "PLAN_DISK='/dev/vda'",
            "FP_EXPECTED='fp123'",
            "NET_IF='eth0'",
            "IPV4_ADDR='192.0.2.10/24'",
            "IPV4_GW='192.0.2.1'",
            "IPV6_ADDR='2001:db8::10/64'",
            "IPV6_GW='2001:db8::1'",
            "DNS='192.0.2.53'",
        ])

    def test_accept_risk_rejects_empty_or_unsafe_class_tokens(self):
        for value in ("", ",drivers", "drivers,", "drivers,,other", "drivers;rm", "drivers other"):
            with self.subTest(value=value):
                r = run(["sh", "bootie-main", "--accept-risk", value])
                self.assertEqual(r.returncode, 2, r.stderr + r.stdout)
                self.assertIn("invalid --accept-risk CLASS", r.stderr)

    def test_mirror_rejects_an_empty_url(self):
        r = run(["sh", "bootie-main", "--mirror", ""])
        self.assertEqual(r.returncode, 2, r.stderr + r.stdout)
        self.assertIn("--mirror requires a non-empty URL", r.stderr)
        self.assertNotIn("unbound variable", r.stderr)
        self.assertNotIn("parameter not set", r.stderr)

    def test_accept_risk_and_mirror_are_forwarded_as_preflight_arguments(self):
        self.assertIn('accept_risks="${accept_risks:+$accept_risks,}$2"', MAIN)
        self.assertIn('set -- "$@" --accept-risk "$accept_risks"', MAIN)
        self.assertIn('set -- "$@" --mirror "$mirror"', MAIN)
        self.assertIn('python3 "$here/engine/preflight.py" plan "$@"', MAIN)

    def test_grub_entries_use_boot_separate_fact_and_prefix(self):
        self.assertIn("boot_separate=$(sed -n 's/^boot_separate=//p' \"$work/facts\" | head -1)", MAIN)
        self.assertIn('if [ "$boot_separate" = yes ]; then', MAIN)
        self.assertIn("grub_boot_prefix=", MAIN)
        self.assertIn("grub_boot_prefix=/boot", MAIN)
        self.assertEqual(MAIN.count("linux $grub_boot_prefix/vmlinuz-$kernel"), 2)
        self.assertIn("initrd $grub_boot_prefix/initrd-bootie-rescue.img", MAIN)
        self.assertIn("initrd $grub_boot_prefix/initrd-bootie.img", MAIN)
        self.assertNotIn("linux /boot/vmlinuz-$kernel", MAIN)
        self.assertNotIn("initrd /boot/initrd-bootie.img\n", MAIN)
        self.assertNotIn("initrd /boot/initrd-bootie-rescue.img\n", MAIN)

    def test_uefi_install_appends_efibootmgr_without_duplicate(self):
        self.assertIn('firmware=$(sed -n \'s/^firmware=//p\' "$work/facts" | head -1)', MAIN)
        condition = 'if [ "$firmware" = uefi ]; then'
        self.assertIn(condition, MAIN)
        self.assertIn('*" efibootmgr "*) ;;', MAIN)
        self.assertIn('pkgs="${pkgs:+$pkgs }efibootmgr"', MAIN)
        install_start = MAIN.index("# --- operator review + one typed approval")
        pkgs_pos = MAIN.index(
            'pkgs=$(python3 -c \'import json,sys; print(" ".join(json.load(open(sys.argv[1]))["liveenv"].get("packages") or []))\' "$work/plan.json")',
            install_start,
        )
        condition_pos = MAIN.index(condition, install_start)
        install_pos = MAIN.index("installing live env packages", install_start)
        self.assertLess(pkgs_pos, condition_pos)
        self.assertLess(condition_pos, install_pos)

    def test_envelope_display_makes_accepted_risks_visible(self):
        marker = "python3 - \"$work/plan.json\" <<'PY'\n"
        start = MAIN.index(marker) + len(marker)
        script = MAIN[start:MAIN.index("\nPY\n", start)]
        with tempfile.TemporaryDirectory() as td:
            plan = Path(td) / "plan.json"
            plan.write_text(json.dumps({
                "accepted_risks": ["drivers"],
                "artifact": {
                    "url": "https://mirror.invalid/debian/image.qcow2",
                    "source_index": "https://mirror.invalid/debian/SHA512SUMS",
                    "checksum_alg": "sha512",
                    "checksum": "abc123",
                    "mirror_override": "https://mirror.invalid/debian",
                },
                "envelope": [{"name": "drivers", "status": "warn", "note": "unverified"}],
            }))
            r = subprocess.run(
                [sys.executable, "-", str(plan)],
                input=script, capture_output=True, text=True, cwd=ROOT,
            )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("source:\n", r.stdout)
        self.assertIn("  url: https://mirror.invalid/debian/image.qcow2", r.stdout)
        self.assertIn("  index: https://mirror.invalid/debian/SHA512SUMS", r.stdout)
        self.assertIn("  checksum: sha512:abc123", r.stdout)
        self.assertIn("  mirror_override: https://mirror.invalid/debian (operator override)", r.stdout)
        self.assertIn("[warn] drivers: unverified", r.stdout)
        self.assertIn("accepted_risks: drivers", r.stdout)

    def test_review_lists_users_and_password_auth_without_hash(self):
        marker = "python3 - \"$work/plan.json\" \"$carried_keys\" \"$key_sources\" \"$auth_summary\" <<'PY'\n"
        start = MAIN.index(marker) + len(marker)
        script = MAIN[start:MAIN.index("\nPY\n", start)]
        secret_hash = "$6$rounds=5000$salt$hash"
        with tempfile.TemporaryDirectory() as td:
            plan = Path(td) / "plan.json"
            plan.write_text(json.dumps({
                "host": "testhost",
                "manifest": {"name": "mini", "version": "1"},
                "facts": {"disk_path": "/dev/vda", "disk_size_bytes": 20 * 1024 ** 3},
                "fingerprint": "fingerprint",
                "artifact": {
                    "url": "https://mirror.invalid/images/disk.raw",
                    "source_index": "https://mirror.invalid/images/SHA256SUMS",
                    "sha256": "a" * 64,
                    "mirror_override": "https://mirror.invalid/images",
                },
                "postinstall": {"boot_target": "multi-user.target", "managed_user": "agent"},
                "accepted_risks": ["drivers"],
                "cloud_ops": {"users": [
                    {"name": "agent", "passwd": secret_hash, "lock_passwd": False,
                     "keys": ["ssh-ed25519 AAAA"]},
                    {"name": "keys-only", "keys": ["ssh-ed25519 BBBB"]},
                ]},
                "approval": "approve-me",
            }))
            r = subprocess.run(
                [sys.executable, "-", str(plan), "1", "--key carried-keys",
                 "keys=3 carried=1 manifest_keys=2 password_users=agent key"],
                input=script, capture_output=True, text=True, cwd=ROOT,
            )
            custom = json.loads(plan.read_text())
            custom["cloud_ops"]["locale"] = "zh_CN.UTF-8"
            custom["cloud_ops"]["timezone"] = "Asia/Shanghai"
            plan.write_text(json.dumps(custom))
            r_custom = subprocess.run(
                [sys.executable, "-", str(plan), "1", "--key carried-keys",
                 "keys=3 carried=1 manifest_keys=2 password_users=agent key"],
                input=script, capture_output=True, text=True, cwd=ROOT,
            )
            gen_pw_file = Path(td) / "generated.pw"
            gen_pw_file.write_text("K7mP2xR9qL\n")
            r_gen = subprocess.run(
                [sys.executable, "-", str(plan), "1", "--key carried-keys",
                 "keys=3 carried=1 manifest_keys=2 password_users=agent key"],
                input=script, capture_output=True, text=True, cwd=ROOT,
                env={
                    **os.environ,
                    "BOOTIE_GENERATED_PW_FILE": str(gen_pw_file),
                    "BOOTIE_GENERATED_PW_USER": "agent",
                },
            )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("artifact=https://mirror.invalid/images/disk.raw", r.stdout)
        self.assertIn("source_index=https://mirror.invalid/images/SHA256SUMS", r.stdout)
        self.assertIn("source_checksum=sha256:" + "a" * 64, r.stdout)
        self.assertIn("mirror_override=https://mirror.invalid/images (explicit operator override)", r.stdout)
        self.assertIn("locale=en_US.UTF-8", r.stdout)
        self.assertIn("timezone=<image-default>", r.stdout)
        self.assertEqual(r_custom.returncode, 0, r_custom.stderr)
        self.assertIn("locale=zh_CN.UTF-8", r_custom.stdout)
        self.assertIn("timezone=Asia/Shanghai", r_custom.stdout)
        self.assertIn("users=agent,keys-only", r.stdout)
        self.assertIn("accepted_risks=drivers (explicit operator override)", r.stdout)
        self.assertIn("access: 1 carried key(s) (--key carried-keys) + 2 manifest-declared key(s)", r.stdout)
        self.assertIn("liveenv_rescue_ssh: enabled (1 key(s))", r.stdout)
        self.assertIn("password_auth=agent", r.stdout)
        self.assertIn("ssh_password_auth=disabled (SSH remains key-only; password is for sudo and desktop/console login)", r.stdout)
        self.assertIn("Approval token: approve-me", r.stdout)
        self.assertNotIn(secret_hash, r.stdout)
        self.assertEqual(r_gen.returncode, 0, r_gen.stderr)
        self.assertIn("generated_password (agent): K7mP2xR9qL", r_gen.stdout)
        self.assertIn("pass --password to choose your own", r_gen.stdout)
        self.assertNotIn(secret_hash, r_gen.stdout)


class AptAndSyntaxTests(unittest.TestCase):
    def test_every_real_apt_operation_is_noninteractive(self):
        offenders = []
        for path in (ROOT / "bootie-main", ROOT / "engine/liveenv.sh"):
            for lineno, line in enumerate(path.read_text().splitlines(), 1):
                stripped = line.strip()
                if ("apt-get" not in stripped or stripped.startswith("#")
                        or stripped.startswith("echo") or "command -v apt-get" in stripped
                        or "install the missing dependencies" in stripped
                        or stripped.startswith("elif [ -x")
                        or stripped.startswith("log ")):
                    continue
                if "DEBIAN_FRONTEND=noninteractive" not in stripped:
                    offenders.append(f"{path.name}:{lineno}:{stripped}")
        self.assertEqual(offenders, [])

    def test_shell_syntax(self):
        for script in [ROOT / "bootie-main", *sorted((ROOT / "engine").glob("*.sh")),
                       ROOT / "scripts/test-bundle"]:
            r = run(["sh", "-n", str(script)])
            self.assertEqual(r.returncode, 0, f"{script}: {r.stderr}")
        for script in [ROOT / "scripts/bundle", ROOT / "payload/om-desktop"]:
            r = run(["bash", "-n", str(script)])
            self.assertEqual(r.returncode, 0, f"{script}: {r.stderr}")

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck not installed")
    def test_shellcheck_clean(self):
        sh_scripts = [ROOT / "bootie-main", *sorted((ROOT / "engine").glob("*.sh")),
                      ROOT / "scripts/test-bundle"]
        bash_scripts = [ROOT / "scripts/bundle", ROOT / "payload/om-desktop"]
        for shell, scripts in (("sh", sh_scripts), ("bash", bash_scripts)):
            with self.subTest(shell=shell):
                r = run(["shellcheck", "-S", "warning", "-s", shell,
                         *[str(script) for script in scripts]])
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_python_files_compile(self):
        r = run([
            "python3", "-m", "py_compile",
            "engine/preflight.py", "engine/stage.py",
            "engine/auth-summary.py", "engine/dhcp_probe.py",
            "engine/password.py",
        ])
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_smoke_regression_pins_in_entrypoint_and_liveenv(self):
        self.assertIn("sudo -n true 2>/dev/null || sudo -v", MAIN)
        self.assertLess(
            MAIN.index("/etc/dropbear/initramfs/authorized_keys"),
            MAIN.index("installing live env packages"),
        )
        self.assertIn("==> staged (mode=hold).", MAIN)
        self.assertIn("no automatic disk write will run in hold mode", MAIN)
        self.assertIn("dhcp_available:", MAIN)
        self.assertIn("setsid sh -c 'sleep 1; sync; reboot -f'", LIVE)
        self.assertIn("sshd_config.d/90-bootie-keyonly.conf", LIVE)
        self.assertIn("PasswordAuthentication no", LIVE)
        self.assertIn('if [ "${ANY_SSH_KEYS:-0}" = 1 ] && [ -d /target/etc/ssh ]; then', LIVE)


class BundleTests(unittest.TestCase):
    def test_builder_uses_heredoc_payload_not_tail_extraction(self):
        self.assertIn("<<'__BOOTIE_PAYLOAD__'", BUILDER)
        self.assertNotIn('tail -n +"$line"', BUILDER)
        self.assertIn("cp engine/*.sh engine/*.py", BUILDER)

    def test_embedded_payload_contains_complete_engine_manifests_and_payload(self):
        with tempfile.TemporaryDirectory() as td:
            artifact = Path(td) / "bootie.sh"
            r = run(["bash", "scripts/bundle", str(artifact)])
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
            text = artifact.read_text()
            lines = text.splitlines()
            start = next(i for i, line in enumerate(lines) if line.startswith("base64 -d <<'__BOOTIE_PAYLOAD__'")) + 1
            end = lines.index("__BOOTIE_PAYLOAD__", start)
            blob = base64.b64decode("".join(lines[start:end]))
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
                names = {name[2:] if name.startswith("./") else name for name in tf.getnames()}
        required = {
            "bootie-main", "VERSION",
            "engine/facts.sh", "engine/liveenv.sh", "engine/stage.py", "engine/preflight.py",
            "engine/initramfs-hook.sh", "engine/initramfs-autostart.sh",
            "engine/rescue-hook.sh", "engine/rescue-helper.sh",
            "engine/keyfilter.sh", "engine/merge-key-files.sh", "engine/prompt.sh",
            "engine/auth-summary.py", "engine/dhcp_probe.py", "engine/password.py", "payload/om-desktop",
            "manifests/omarchy-4.5.json", "manifests/debian-13.json",
            "manifests/ubuntu-24.04.json", "manifests/ubuntu-26.04.json",
        }
        self.assertTrue(required <= names, sorted(required - names))

    def test_cli_shape_and_generated_artifact_policy(self):
        for needle in ("check)", "version)", "install)", "--manifest", "--no-reboot", "--key"):
            self.assertIn(needle, MAIN)
        self.assertNotIn('[ -n "$key" ] || { usage', MAIN)
        self.assertIn("/bootie.sh", (ROOT / ".gitignore").read_text())

    def test_check_mode_reports_missing_dependencies_without_installing(self):
        self.assertIn("check mode: not installing anything", MAIN)
        self.assertLess(MAIN.index("check mode: not installing anything"), MAIN.index("collecting machine facts"))
        self.assertIn('if [ "$cmd" = install ]; then', MAIN)

    def test_file_mode_and_pipe_mode_extraction_smoke(self):
        r = run(["sh", "scripts/test-bundle"])
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertIn("file-mode and pipe-mode extraction", r.stdout)


if __name__ == "__main__":
    unittest.main()

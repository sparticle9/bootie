"""Offline staging and plan.env rendering tests."""
import base64
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import stage as rs  # noqa: E402


def minimal_plan():
    return {
        "manifest": {"name": "omarchy", "version": "4.5.0", "arch": "x86_64"},
        "fingerprint": "0123456789abcdef",
        "facts": {
            "disk_path": "/dev/vda",
            "firmware": "bios",
            "hostname": "h'ost",
            "net_if": "ens18",
            "ipv4_addr": "192.0.2.10/24",
            "ipv4_gateway": "192.0.2.1",
            "ipv6_addr": "",
            "ipv6_gateway": "",
            "dns": "192.0.2.53",
        },
        "artifact": {
            "url": "https://upstream.example/image.qcow2?a=b&c=d",
            "sha256": "f" * 64,
            "unpacked_url": "https://upstream.example/unpacked/",
        },
        "personalize": {"remove_webapps": ["A webapp"], "drop_pkgs": ["leafpkg"],
                        "late_commands": ["echo late"]},
        "postinstall": {"boot_target": "console", "managed_user": "agent",
                        "install_om_desktop": True},
        "cloud_ops": {
            "users": [{
                "name": "agent",
                "groups": ["wheel"],
                "shell": "/bin/bash",
                "lock_passwd": False,
                "passwd": "$6$rounds=5000$salt$hash",
                "sudo": "ALL=(ALL) NOPASSWD: ALL",
                "keys": ["ssh-ed25519 AAAA key-comment"],
            }],
            "files": [{"path": "/etc/example", "owner": "root:root",
                       "permissions": "0640", "content_b64": base64.b64encode(b"content").decode()}],
            "runcmd": ["echo first"],
            "packages": ["git"],
            "package_update": True,
        },
    }


def roundtrip_plan_env(env, names):
    """Source rendered plan.env in POSIX sh and return single-line values."""
    with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as tmp:
        tmp.write(env)
        path = tmp.name
    try:
        script = [". " + shlex.quote(path)]
        script.extend(f"printf '%s\\n' \"${name}\"" for name in names)
        r = subprocess.run(
            ["sh", "-c", "\n".join(script)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            raise AssertionError(f"plan.env did not source cleanly: {r.stderr}")
        values = r.stdout.splitlines()
        if len(values) != len(names):
            raise AssertionError(f"roundtrip returned {len(values)} values for {len(names)} names")
        return dict(zip(names, values))
    finally:
        Path(path).unlink()


class PlanEnvRenderTests(unittest.TestCase):
    def test_target_adapter_defaults_preserve_minimal_plan_compatibility(self):
        env = rs.render_plan_env(minimal_plan(), "")
        got = roundtrip_plan_env(env, [
            "ROOTFS_TYPE", "NET_BACKEND", "BIOS_BOOT_METHOD",
            "FIRSTBOOT_CHECK_HOST", "ART_CHECKSUM_ALG", "ART_CHECKSUM",
            "ART_SHA256", "ART_UNPACKED",
        ])
        self.assertEqual(got, {
            "ROOTFS_TYPE": "btrfs",
            "NET_BACKEND": "networkmanager",
            "BIOS_BOOT_METHOD": "limine",
            "FIRSTBOOT_CHECK_HOST": "archlinux.org",
            "ART_CHECKSUM_ALG": "sha256",
            "ART_CHECKSUM": "f" * 64,
            "ART_SHA256": "f" * 64,
            "ART_UNPACKED": "https://upstream.example/unpacked/",
        })

    def test_locale_timezone_defaults_roundtrip(self):
        env = rs.render_plan_env(minimal_plan(), "")
        got = roundtrip_plan_env(env, ["LOCALE_V", "TIMEZONE_V"])
        self.assertEqual(got, {
            "LOCALE_V": "en_US.UTF-8",
            "TIMEZONE_V": "",
        })

    def test_locale_timezone_custom_values_roundtrip(self):
        plan = minimal_plan()
        plan["cloud_ops"]["locale"] = "zh_CN.UTF-8"
        plan["cloud_ops"]["timezone"] = "Asia/Shanghai"
        env = rs.render_plan_env(plan, "")
        got = roundtrip_plan_env(env, ["LOCALE_V", "TIMEZONE_V"])
        self.assertEqual(got, {
            "LOCALE_V": "zh_CN.UTF-8",
            "TIMEZONE_V": "Asia/Shanghai",
        })

    def test_ext4_systemd_networkd_image_native_sha512_plan_roundtrips(self):
        plan = minimal_plan()
        plan["artifact"] = {
            "url": "https://cloud-images.example/debian-13-amd64.qcow2",
            "checksum_alg": "sha512",
            "checksum": "a" * 128,
        }
        plan["personalize"].update({
            "rootfs": "ext4",
            "network": "systemd-networkd",
            "bios_boot": "image-native",
            "connectivity_host": "debian.org",
        })
        env = rs.render_plan_env(plan, "")
        got = roundtrip_plan_env(env, [
            "ROOTFS_TYPE", "NET_BACKEND", "BIOS_BOOT_METHOD",
            "FIRSTBOOT_CHECK_HOST", "ART_CHECKSUM_ALG", "ART_CHECKSUM",
            "ART_SHA256", "ART_UNPACKED",
        ])
        self.assertEqual(got, {
            "ROOTFS_TYPE": "ext4",
            "NET_BACKEND": "systemd-networkd",
            "BIOS_BOOT_METHOD": "image-native",
            "FIRSTBOOT_CHECK_HOST": "debian.org",
            "ART_CHECKSUM_ALG": "sha512",
            "ART_CHECKSUM": "a" * 128,
            "ART_SHA256": "",
            "ART_UNPACKED": "",
        })

    def test_netplan_target_adapter_plan_roundtrips(self):
        plan = minimal_plan()
        plan["personalize"].update({
            "rootfs": "ext4",
            "network": "netplan",
            "bios_boot": "image-native",
            "connectivity_host": "ubuntu.com",
        })
        env = rs.render_plan_env(plan, "")
        got = roundtrip_plan_env(env, [
            "ROOTFS_TYPE", "NET_BACKEND", "BIOS_BOOT_METHOD",
            "FIRSTBOOT_CHECK_HOST", "ART_CHECKSUM_ALG", "ART_CHECKSUM",
        ])
        self.assertEqual(got, {
            "ROOTFS_TYPE": "ext4",
            "NET_BACKEND": "netplan",
            "BIOS_BOOT_METHOD": "image-native",
            "FIRSTBOOT_CHECK_HOST": "ubuntu.com",
            "ART_CHECKSUM_ALG": "sha256",
            "ART_CHECKSUM": "f" * 64,
        })

    def test_posix_shell_quoting_roundtrip_metacharacters_and_multiline(self):
        authkey = "line1\nke'y2 $HOME `id`\nline3"
        env = rs.render_plan_env(minimal_plan(), authkey)
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as tmp:
            tmp.write(env)
            path = tmp.name
        try:
            checks = {
                "AUTHKEY": authkey,
                "ART_URL": "https://upstream.example/image.qcow2?a=b&c=d",
                "HOSTNAME_V": "h'ost",
                "BOOT_TARGET": "console",
                "MANAGED_USER": "agent",
            }
            for var, want in checks.items():
                r = subprocess.run(
                    ["sh", "-c", f". {path}; printf '%s' \"${var}\""],
                    capture_output=True, text=True,
                )
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(r.stdout, want, f"{var} roundtrip broke")
        finally:
            Path(path).unlink()

    def test_cloud_ops_hostname_overrides_facts_and_shell_quotes_safely(self):
        plan = minimal_plan()
        want = "chosen'host$`id`"
        plan["cloud_ops"]["hostname"] = want
        env = rs.render_plan_env(plan, "")
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as tmp:
            tmp.write(env)
            path = tmp.name
        try:
            r = subprocess.run(
                ["sh", "-c", f'. {path}; printf %s "$HOSTNAME_V"'],
                capture_output=True, text=True,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout, want)
        finally:
            Path(path).unlink()

    def test_hostname_falls_back_to_facts_when_cloud_ops_hostname_unset_or_empty(self):
        def roundtrip_hostname(env):
            with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as tmp:
                tmp.write(env)
                path = tmp.name
            try:
                r = subprocess.run(
                    ["sh", "-c", f'. {path}; printf %s "$HOSTNAME_V"'],
                    capture_output=True, text=True,
                )
                self.assertEqual(r.returncode, 0, r.stderr)
                return r.stdout
            finally:
                Path(path).unlink()

        for state in ("absent", "none", "empty"):
            with self.subTest(state=state):
                plan = minimal_plan()
                if state == "none":
                    plan["cloud_ops"]["hostname"] = None
                elif state == "empty":
                    plan["cloud_ops"]["hostname"] = ""
                env = rs.render_plan_env(plan, "")
                self.assertEqual(roundtrip_hostname(env), "h'ost")

    def test_multiline_options_prefixed_authkey_roundtrips_exactly(self):
        authkey = (
            'command="/usr/bin/foo --bar",no-port-forwarding ssh-ed25519 AAAATESTKEY "quoted comment"\n'
            "ssh-ed25519 BBBBTESTKEY operator's-second-key"
        )
        env = rs.render_plan_env(minimal_plan(), authkey)
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as tmp:
            tmp.write(env)
            path = tmp.name
        try:
            r = subprocess.run(
                ["sh", "-c", f'. {path}; printf %s "$AUTHKEY"'],
                capture_output=True, text=True,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout, authkey)
        finally:
            Path(path).unlink()

    def test_sensitive_and_list_values_are_encoded_not_shell_expanded(self):
        env = rs.render_plan_env(minimal_plan(), "")
        self.assertNotIn("$6$rounds=5000$salt$hash\n", env)
        passwd_line = next(line for line in env.splitlines() if line.startswith("USER_1_PASSWD_B64="))
        encoded = passwd_line.split("=", 1)[1].strip("'")
        self.assertEqual(base64.b64decode(encoded).decode(), "$6$rounds=5000$salt$hash")
        self.assertIn("REMOVE_WEBAPP_COUNT=1", env)
        self.assertIn("USER_COUNT=1", env)
        self.assertIn("FILE_COUNT=1", env)
        self.assertIn("RUNCMD_COUNT=1", env)
        self.assertIn("LATE_COUNT=1", env)

    def test_stage_payload_materializes_modes_and_contents(self):
        with tempfile.TemporaryDirectory() as td:
            plan_path = Path(td) / "plan.json"
            key_path = Path(td) / "keys"
            dest = Path(td) / "staging"
            plan_path.write_text(json.dumps(minimal_plan()))
            key_path.write_text("ssh-ed25519 AAAA key\n")
            r = subprocess.run(
                [sys.executable, str(ROOT / "engine/stage.py"), "--plan", str(plan_path),
                 "--key", str(key_path), "--dest", str(dest)],
                capture_output=True, text=True,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            plan_env = dest / "plan.env"
            self.assertEqual(plan_env.stat().st_mode & 0o777, 0o600)
            self.assertEqual((dest / "payload/files/1").read_bytes(), b"content")
            self.assertEqual((dest / "payload/files/1").stat().st_mode & 0o777, 0o600)
            self.assertTrue((dest / "payload/runcmd/1.sh").read_text().startswith("#!/bin/sh\necho first"))
            self.assertEqual((dest / "payload/runcmd/1.sh").stat().st_mode & 0o777, 0o700)
            self.assertTrue((dest / "payload/late/1.sh").read_text().startswith("#!/bin/sh\necho late"))
            self.assertEqual((dest / "payload/late/1.sh").stat().st_mode & 0o777, 0o700)

    def test_stdout_mode_when_dest_omitted(self):
        with tempfile.TemporaryDirectory() as td:
            plan_path = Path(td) / "plan.json"
            key_path = Path(td) / "keys"
            plan_path.write_text(json.dumps(minimal_plan()))
            key_path.write_text("")
            r = subprocess.run(
                [sys.executable, str(ROOT / "engine/stage.py"), "--plan", str(plan_path), "--key", str(key_path)],
                capture_output=True, text=True,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("FP_EXPECTED='0123456789abcdef'", r.stdout)
            self.assertIn("MANIFEST_NAME='omarchy'", r.stdout)
        self.assertIn("INSTALL_OM_DESKTOP='1'", r.stdout)


if __name__ == "__main__":
    unittest.main()

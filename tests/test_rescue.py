"""Offline rescue-plan and non-destructive rescue-shell contract tests."""
import io
import json
import os
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import preflight as rp  # noqa: E402

HOOK_PATH = ROOT / "engine/rescue-hook.sh"
HELPER_PATH = ROOT / "engine/rescue-helper.sh"
HOOK = HOOK_PATH.read_text()
HELPER = HELPER_PATH.read_text()

FACTS_TEXT = """\
hostname=testhost
firmware=bios
arch=x86_64
mem_mib=3921
disk_path=/dev/vda
disk_size_bytes=69793218560
disk_model=Virtual
disk_serial=none
disk_wwn=none
disk_partuuids=aaaaaaaa-1111,bbbbbbbb-2222
net_if=ens18
net_mac=52:54:00:12:34:56
ipv4_addr=192.0.2.10/24
ipv4_gateway=192.0.2.1
ipv6_addr=2001:db8::10/64
ipv6_gateway=2001:db8::1
dns=192.0.2.53
disk_driver=virtio-pci
net_driver=virtio-pci
disk_count=1
virt=vm:kvm
root_stack=simple
bootloader=grub
ipv4_route_shape=simple
"""

EXPECTED_PACKAGES = [
    "busybox-static", "dropbear-initramfs", "e2fsprogs", "btrfs-progs",
    "dosfstools", "fdisk", "gdisk", "curl",
]


def write_temp(data, suffix=".tmp"):
    tmp = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
    tmp.write(data)
    tmp.close()
    return Path(tmp.name)


def parse_facts(text=FACTS_TEXT):
    return rp.parse_facts(text)


class RescueShellSyntaxTests(unittest.TestCase):
    def assert_shell_syntax(self, shell, path):
        result = subprocess.run(
            [shell, "-n", str(path)], capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_sh_syntax_and_executable_bits(self):
        for path in (HOOK_PATH, HELPER_PATH):
            with self.subTest(path=path):
                self.assert_shell_syntax("sh", path)
                self.assertTrue(os.access(path, os.X_OK), f"{path} is not executable")

    def test_dash_syntax_when_dash_is_present(self):
        if shutil.which("dash") is None:
            self.skipTest("dash not installed")
        for path in (HOOK_PATH, HELPER_PATH):
            with self.subTest(path=path):
                self.assert_shell_syntax("dash", path)


class RescueHookStructureTests(unittest.TestCase):
    def test_hook_is_an_initramfs_hook_and_stages_rescue_tree(self):
        self.assertIn("prereqs", HOOK)
        self.assertIn(". /usr/share/initramfs-tools/hook-functions", HOOK)
        self.assertIn('cp -a /usr/local/share/bootie-rescue/. "$DESTDIR/bootie-rescue/"', HOOK)
        self.assertIn('chmod +x "$DESTDIR/bootie-rescue/"*.sh', HOOK)

    def test_hook_stages_only_inspection_repair_and_network_binary_paths(self):
        for binary in (
            "/usr/bin/curl",
            "/sbin/btrfs", "/usr/sbin/btrfs", "/sbin/blkid",
            "/bin/lsblk", "/usr/bin/lsblk",
            "/sbin/sfdisk", "/sbin/fdisk", "/sbin/sgdisk",
            "/usr/sbin/partx", "/usr/sbin/blockdev",
            "/sbin/e2fsck", "/usr/sbin/e2fsck",
            "/sbin/fsck.ext4", "/usr/sbin/fsck.ext4",
            "/sbin/resize2fs", "/usr/sbin/resize2fs",
            "/bin/mount", "/bin/umount",
        ):
            with self.subTest(binary=binary):
                self.assertIn(binary, HOOK)
        for module in (
            "btrfs", "ext4", "vfat", "nls_cp437", "nls_ascii",
            "virtio_blk", "virtio_net",
        ):
            with self.subTest(module=module):
                self.assertIn(f"manual_add_modules {module}", HOOK)
        self.assertIn("/etc/ssl/certs", HOOK)
        self.assertIn("/etc/ssl/openssl.cnf", HOOK)

    def test_hook_structurally_excludes_install_material(self):
        self.assertIn('rm -f "$DESTDIR/bootie/autostart"', HOOK)
        self.assertIn('rm -rf "$DESTDIR/bootie"', HOOK)
        self.assertNotIn("qemu-img", HOOK)
        self.assertNotIn("block-curl.so", HOOK)
        self.assertNotIn("liveenv.sh", HOOK)
        self.assertNotIn("plan.env", HOOK)


class RescueHelperStructureTests(unittest.TestCase):
    def test_helper_has_no_disk_write_or_wipe_utility_references(self):
        for forbidden in ("qemu-img", "wipefs", "mkfs", "dd "):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, HELPER)

    def test_helper_is_read_only_and_returns_with_a_detached_reboot(self):
        self.assertIn("mount -o ro", HELPER)
        self.assertIn('[ -b "$part" ]', HELPER)
        self.assertIn("returning to prior OS in 1 second (one-shot rescue entry is cleared)", HELPER)
        self.assertIn("setsid sh -c 'sleep 1; sync; reboot -f' </dev/null >/dev/null 2>&1 &", HELPER)

    def test_helper_sources_rescue_env_and_has_required_subcommands(self):
        self.assertIn("${BOOTIE_RESCUE_ENV:-/bootie-rescue/rescue.env}", HELPER)
        for subcommand in ("info", "net-up", "mount-ro", "umount", "return"):
            with self.subTest(subcommand=subcommand):
                self.assertIn(subcommand, HELPER)
        self.assertIn("exit 2", HELPER)

    def test_unknown_subcommand_exits_2_with_usage(self):
        result = subprocess.run(
            ["sh", str(HELPER_PATH), "bogus"], capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("usage: rescue-helper.sh", result.stderr)

    def test_info_prints_banner_metadata_and_operator_instructions(self):
        with tempfile.TemporaryDirectory() as td:
            env_path = Path(td) / "rescue.env"
            env_path.write_text(
                "HOSTNAME_V=testhost\n"
                "PLAN_DISK=/dev/vda\n"
                "FP_EXPECTED=0123456789abcdef\n"
                "NET_IF=ens18\n"
                "IPV4_ADDR=192.0.2.10/24\n"
                "IPV4_GW=192.0.2.1\n"
                "DNS=192.0.2.53\n"
            )
            env = dict(os.environ)
            env["BOOTIE_RESCUE_ENV"] = str(env_path)
            result = subprocess.run(
                ["sh", str(HELPER_PATH), "info"], capture_output=True, text=True, env=env,
            )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertIn(
            "BOOTIE RESCUE MODE — non-destructive RAM environment; "
            "host disks are unmounted and no write is staged",
            result.stdout,
        )
        self.assertIn("host: testhost", result.stdout)
        self.assertIn("target disk: /dev/vda", result.stdout)
        self.assertIn("fingerprint: 0123456789abcdef", result.stdout)
        self.assertIn("network: if=ens18 ipv4=192.0.2.10/24 gateway=192.0.2.1 dns=192.0.2.53", result.stdout)
        self.assertIn("read-only mount example: rescue-helper.sh mount-ro /dev/<part>", result.stdout)
        self.assertIn("chroot repair hint:", result.stdout)
        self.assertIn("return to prior OS: rescue-helper.sh return", result.stdout)


class RescuePlanBuildTests(unittest.TestCase):
    def test_build_rescue_plan_is_offline_and_matches_contract(self):
        facts = parse_facts()
        with mock.patch.object(rp, "_fetch", side_effect=AssertionError("network access")):
            plan = rp.build_rescue_plan(facts)
        self.assertEqual(plan["schema"], 1)
        self.assertEqual(plan["mode"], "rescue")
        self.assertEqual(plan["host"], "testhost")
        self.assertEqual(plan["facts"], facts)
        self.assertEqual(plan["liveenv"], {
            "kind": "debian-initramfs",
            "mode": "rescue",
            "packages": EXPECTED_PACKAGES,
            "kernel_cmdline": "break=mount console=ttyS0,115200 console=tty0",
            "ssh_port": 22,
        })
        self.assertEqual(rp.RESCUE_PACKAGES, EXPECTED_PACKAGES)
        self.assertIsNot(plan["liveenv"]["packages"], rp.RESCUE_PACKAGES)
        self.assertEqual(plan["accepted_risks"], [])
        self.assertEqual(plan["fingerprint"], rp.fingerprint(facts))
        self.assertEqual(
            plan["ip_cmdline"],
            "ip=192.0.2.10::192.0.2.1:255.255.255.0:testhost:ens18:off",
        )
        self.assertEqual(plan["approval"], "rescue:testhost")
        self.assertEqual(rp.approval_token(plan), "rescue:testhost")
        self.assertNotIn("artifact", plan)
        self.assertNotIn("target_rules", plan)
        self.assertNotIn("write", plan)
        self.assertEqual(
            {p["name"] for p in plan["envelope"]},
            {"virt", "bootloader", "firmware", "network", "disk-topology", "drivers"},
        )
        self.assertTrue(all(p["status"] == "pass" for p in plan["envelope"]))

    def test_build_rescue_plan_normalizes_driver_risk_acceptance(self):
        facts = dict(parse_facts(), disk_driver="nvme")
        plan = rp.build_rescue_plan(facts, accepted_risks=[" drivers,", "drivers"])
        self.assertEqual(plan["accepted_risks"], ["drivers"])
        drivers = {p["name"]: p for p in plan["envelope"]}["drivers"]
        self.assertEqual(drivers["status"], "warn")
        self.assertIn("risk accepted via --accept-risk drivers", drivers["note"])

    def test_build_rescue_plan_rejects_unknown_risk_classes(self):
        with self.assertRaises(ValueError):
            rp.build_rescue_plan(parse_facts(), accepted_risks=["bogus"])

    def test_rescue_fit_issues_skip_install_image_manifest_and_size_rules(self):
        facts = dict(parse_facts(), arch="aarch64", disk_size_bytes="1")
        plan = rp.build_rescue_plan(facts)
        self.assertEqual(rp.fit_issues(plan), [])

    def test_rescue_fit_issues_enforce_rescue_ram_floor(self):
        facts = dict(parse_facts(), mem_mib="447")
        plan = rp.build_rescue_plan(facts)
        issues = rp.fit_issues(plan)
        self.assertEqual(len(issues), 1)
        self.assertIn("RAM 447 MiB below 448 MiB rescue floor", issues[0])

        facts = dict(parse_facts(), mem_mib="448")
        self.assertEqual(rp.fit_issues(rp.build_rescue_plan(facts)), [])


class RescuePlanCliTests(unittest.TestCase):
    def run_rescue_plan_cli(self, extra_args=(), facts_text=FACTS_TEXT):
        facts_path = write_temp(facts_text, suffix=".facts")
        out, err = io.StringIO(), io.StringIO()
        try:
            with mock.patch.object(rp, "_fetch", side_effect=AssertionError("network access")):
                with redirect_stdout(out), redirect_stderr(err):
                    rc = rp.main(["rescue-plan", "--facts", str(facts_path), *extra_args])
        finally:
            facts_path.unlink()
        return rc, out.getvalue(), err.getvalue()

    def write_plan(self, plan):
        plan_path = write_temp(json.dumps(plan), suffix=".json")
        self.addCleanup(plan_path.unlink)
        return plan_path

    def run_check(self, plan):
        plan_path = self.write_plan(plan)
        err = io.StringIO()
        with redirect_stderr(err):
            rc = rp.main(["check", "--plan", str(plan_path)])
        return rc, err.getvalue()

    def test_rescue_plan_cli_prints_offline_plan_json(self):
        rc, out, err = self.run_rescue_plan_cli(["--host", "testhost"])
        self.assertEqual(rc, 0, err)
        self.assertEqual(err, "")
        plan = json.loads(out)
        self.assertEqual(plan["mode"], "rescue")
        self.assertEqual(plan["approval"], "rescue:testhost")
        self.assertEqual(plan["liveenv"]["packages"], EXPECTED_PACKAGES)
        self.assertEqual(len(plan["envelope"]), 6)

    def test_rescue_plan_cli_accepts_documented_driver_risk(self):
        facts_text = FACTS_TEXT.replace("disk_driver=virtio-pci", "disk_driver=nvme")
        rc, out, err = self.run_rescue_plan_cli(["--accept-risk", "drivers"], facts_text)
        self.assertEqual(rc, 0, err)
        plan = json.loads(out)
        self.assertEqual(plan["accepted_risks"], ["drivers"])
        drivers = {p["name"]: p for p in plan["envelope"]}["drivers"]
        self.assertEqual(drivers["status"], "warn")

    def test_rescue_plan_cli_rejects_invalid_risk_with_exit_2(self):
        rc, out, err = self.run_rescue_plan_cli(["--accept-risk", "bogus"])
        self.assertEqual(rc, 2)
        self.assertEqual(out, "")
        self.assertIn("invalid --accept-risk", err)
        self.assertIn("unknown risk class(es): bogus", err)
        self.assertIn("allowed: drivers", err)

    def test_rescue_plan_cli_host_mismatch_and_bad_facts_are_concise_errors(self):
        rc, out, err = self.run_rescue_plan_cli(["--host", "otherhost"])
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")
        self.assertIn("facts hostname testhost != otherhost", err)
        self.assertNotIn("Traceback", err)

        rc, out, err = self.run_rescue_plan_cli([], "hostname=testhost\n")
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")
        self.assertIn("preflight error: facts missing:", err)
        self.assertNotIn("Traceback", err)

    def test_check_accepts_valid_bios_virtio_rescue_plan(self):
        plan = rp.build_rescue_plan(parse_facts())
        rc, err = self.run_check(plan)
        self.assertEqual(rc, 0, err)
        self.assertNotIn("ENVELOPE-FAIL", err)
        self.assertNotIn("BLOCKER:", err)

    def test_check_accepts_valid_uefi_secure_boot_disabled_rescue_plan(self):
        facts = dict(parse_facts(), firmware="uefi", secure_boot="disabled")
        plan = rp.build_rescue_plan(facts)
        rc, err = self.run_check(plan)
        self.assertEqual(rc, 0, err)
        self.assertNotIn("ENVELOPE-FAIL", err)
        self.assertNotIn("BLOCKER:", err)

    def test_check_rejects_uefi_secure_boot_container_non_virtio_and_low_ram(self):
        base = parse_facts()
        cases = {
            "uefi-secboot-enabled": dict(base, firmware="uefi", secure_boot="enabled"),
            "uefi-secboot-unknown": dict(base, firmware="uefi", secure_boot="unknown"),
            "uefi-secboot-na": dict(base, firmware="uefi"),
            "container": dict(base, virt="container:lxc"),
            "non-virtio": dict(base, disk_driver="nvme"),
            "low-ram": dict(base, mem_mib="447"),
        }
        for name, facts in cases.items():
            with self.subTest(name=name):
                rc, err = self.run_check(rp.build_rescue_plan(facts))
                self.assertEqual(rc, 1)
                self.assertTrue("ENVELOPE-FAIL" in err or "BLOCKER:" in err)


class AlpineRescueTests(unittest.TestCase):
    def facts(self):
        return dict(parse_facts(), bootloader="unknown", disk_driver="virtio_blk",
                    net_driver="virtio_net")

    def test_btrfs_inspection_mount_is_read_only_with_log_replay_disabled(self):
        script = ROOT / "engine/alpine-rescue-inspect.sh"
        result = subprocess.run(
            ["sh", "-c", r'''
                test() { [ "$1" = -b ] && [ "$2" = /dev/vda2 ]; }
                mount() { printf '%s\n' "$@"; }
                helper=$1
                set -- mount-ro btrfs /dev/vda2
                . "$helper"
            ''', "test-helper", str(script)],
            capture_output=True, text=True, check=True,
        )
        self.assertEqual(result.stdout.splitlines(), [
            "-t", "btrfs", "-o", "ro,rescue=nologreplay,nodev,nosuid,noexec",
            "/dev/vda2", "/mnt",
        ])

    def test_explicit_backend_plans_offline_without_install_payload_or_grub(self):
        facts = self.facts()
        plan = rp.build_rescue_plan(facts, backend="alpine-kexec")
        self.assertEqual(rp.fit_issues(plan), [])
        self.assertFalse(any(probe["status"] == "fail" for probe in plan["envelope"]))
        self.assertEqual(plan["approval"], rp.approval_token(plan))
        self.assertTrue(plan["approval"].startswith("alpine-rescue:testhost:"))
        self.assertTrue({"artifact", "manifest", "write"}.isdisjoint(plan))
        self.assertEqual(rp.build_rescue_plan(facts)["approval"], "rescue:testhost")

    def test_alpine_refuses_unsupported_shapes(self):
        for change in ({"arch": "aarch64"}, {"virt": "container:lxc"},
                       {"mem_mib": "1024"}, {"ipv4_addr": "192.0.2.10/32"},
                       {"ipv4_gateway": "192.0.3.1"}, {"net_driver": "e1000"},
                       {"disk_count": "2"}, {"disk_driver": "virtio_scsi"}):
            with self.subTest(change=change):
                plan = rp.build_rescue_plan(dict(self.facts(), **change), backend="alpine-kexec")
                self.assertTrue(rp.fit_issues(plan))
        for secure_boot in ("enabled", "unknown"):
            plan = rp.build_rescue_plan(dict(self.facts(), firmware="uefi", secure_boot=secure_boot),
                                        backend="alpine-kexec")
            self.assertTrue(any(probe["name"] == "firmware" and probe["status"] == "fail"
                                for probe in plan["envelope"]))
        with self.assertRaisesRegex(ValueError, "no risk override"):
            rp.build_rescue_plan(self.facts(), ["drivers"], backend="alpine-kexec")

    def test_corrupt_iso_is_rejected_before_extraction(self):
        import alpine_rescue as alpine
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            plan = rp.build_rescue_plan(self.facts(), backend="alpine-kexec")
            (work / "plan.json").write_text(json.dumps(plan))
            (work / "alpine.iso").write_bytes(b"bad")
            with mock.patch.object(alpine, "run") as run:
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    alpine.assemble(work, "ttyS0", True)
            self.assertEqual(run.call_count, 1)
            self.assertFalse((work / "image").exists())

    def test_load_failure_cannot_request_shutdown_and_shutdown_failure_unloads(self):
        import alpine_rescue as alpine
        for failed_command in ("kexec", "systemctl"):
            with self.subTest(failed_command=failed_command), tempfile.TemporaryFile() as lock:
                calls = []

                def run(*args):
                    calls.append(args)
                    if args[0] == failed_command:
                        raise subprocess.CalledProcessError(1, args)

                with (mock.patch.object(alpine.os, "open", return_value=os.dup(lock.fileno())),
                      mock.patch.object(alpine, "precheck"),
                      mock.patch.object(alpine.signal, "signal"),
                      mock.patch.object(alpine, "run", side_effect=run)):
                    with self.assertRaises(subprocess.CalledProcessError):
                        alpine.handoff(Path("/stage"), "ttyS0")
                self.assertEqual(calls[0][:3], ("kexec", "-s", "-l"))
                self.assertIn("rdinit=/init", calls[0][-1])
                self.assertEqual(calls[1:], [] if failed_command == "kexec" else
                                 [("systemctl", "kexec"), ("kexec", "-s", "-u")])


if __name__ == "__main__":
    unittest.main()

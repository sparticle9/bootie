"""Offline tests for the POSIX facts collector."""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FACTS = ROOT / "engine" / "facts.sh"
SOURCE = FACTS.read_text()
SH = "/bin/sh"

FINGERPRINT_KEYS = [
    "arch", "disk_model", "disk_partuuids", "disk_path", "disk_serial",
    "disk_size_bytes", "disk_wwn", "firmware", "net_mac",
]
ENVELOPE_KEYS = [
    "virt", "root_stack", "bootloader", "ipv4_route_shape",
    "secure_boot", "boot_separate",
]


def shell_function(name):
    match = re.search(rf"^{re.escape(name)}\(\) \{{\n.*?^\}}", SOURCE, re.M | re.S)
    if not match:
        raise AssertionError(f"shell function not found: {name}")
    return match.group(0)


def run_shell(functions, call, *, bin_dir=None, path=None, env_extra=None):
    with tempfile.TemporaryDirectory() as td:
        script = Path(td) / "run.sh"
        body = "\n\n".join(shell_function(name) for name in functions)
        script.write_text(f"set -eu\n\n{body}\n\n{call}\n")
        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)
        if path is not None:
            env["PATH"] = str(path)
        elif bin_dir is not None:
            env["PATH"] = os.pathsep.join([str(bin_dir), env.get("PATH", "")])
        result = subprocess.run([SH, str(script)], capture_output=True, text=True, env=env)
    if result.returncode != 0:
        raise AssertionError(
            f"shell helper failed rc={result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}")
    return result.stdout.strip()


def write_exe(path, content):
    path.write_text(content)
    path.chmod(0o755)


def write_command_stub(path, output):
    if output:
        body = output.rstrip("\n") + "\n"
        content = f"#!/bin/sh\ncat <<'EOF'\n{body}EOF\n"
    else:
        content = "#!/bin/sh\nexit 0\n"
    write_exe(path, content)


def write_systemd_detect_virt_stub(path, container, vm, bare):
    def branch(flag, result):
        output, rc = result
        emit = f"printf '%s\\n' '{output}'" if output else ":"
        return f"    {flag})\n        {emit}\n        exit {rc}\n        ;;\n"

    content = (
        "#!/bin/sh\n"
        "case \"${1:-}\" in\n"
        + branch("--container", container)
        + branch("--vm", vm)
        + branch("*", bare)
        + "esac\n"
    )
    write_exe(path, content)


class StaticFactsContractTests(unittest.TestCase):
    def test_posix_shell_syntax(self):
        result = subprocess.run(["sh", "-n", str(FACTS)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def output_key_lists(self):
        loops = re.findall(r"for k in\s+([^;]+?); do", SOURCE, re.S)
        return [loop.replace("\\", " ").split() for loop in loops]

    def test_fingerprint_mode_keeps_exact_canonical_keys(self):
        loops = self.output_key_lists()
        self.assertGreaterEqual(len(loops), 2)
        self.assertEqual(loops[0], FINGERPRINT_KEYS)

    def test_all_mode_appends_support_envelope_keys(self):
        loops = self.output_key_lists()
        self.assertGreaterEqual(len(loops), 2)
        self.assertEqual(loops[1][-len(ENVELOPE_KEYS):], ENVELOPE_KEYS)


class DiskOfTests(unittest.TestCase):
    def test_partition_and_device_name_unwrapping(self):
        output = run_shell(
            ["disk_of"],
            "disk_of /dev/vda1\n"
            "disk_of /dev/nvme0n1p2\n"
            "disk_of /dev/sda\n"
            "disk_of /dev/xvda1",
        )
        self.assertEqual(output.splitlines(), ["vda", "nvme0n1", "sda", "xvda"])


class RootDevUnwrapTests(unittest.TestCase):
    def run_unwrap(self, source, setup):
        with tempfile.TemporaryDirectory() as td:
            sysblock = Path(td) / "sysblock"
            sysblock.mkdir()
            setup(sysblock)
            call = "root_dev_unwrap {} {}".format(shlex.quote(source), shlex.quote(str(sysblock)))
            return run_shell(["root_dev_unwrap"], call)

    def test_single_device_mapper_slave_is_unwrapped(self):
        def setup(sysblock):
            (sysblock / "dm-0" / "slaves" / "sda2").mkdir(parents=True)

        self.assertEqual(self.run_unwrap("/dev/dm-0", setup), "/dev/sda2")

    def test_single_slave_device_mapper_chain_is_unwrapped(self):
        def setup(sysblock):
            (sysblock / "dm-0" / "slaves" / "dm-1").mkdir(parents=True)
            (sysblock / "dm-1" / "slaves" / "sda1").mkdir(parents=True)

        self.assertEqual(self.run_unwrap("/dev/dm-0", setup), "/dev/sda1")

    def test_single_md_slave_is_unwrapped(self):
        def setup(sysblock):
            (sysblock / "md0" / "slaves" / "sdb1").mkdir(parents=True)

        self.assertEqual(self.run_unwrap("/dev/md0", setup), "/dev/sdb1")

    def test_multi_slave_md_is_not_arbitrarily_unwrapped(self):
        def setup(sysblock):
            (sysblock / "md0" / "slaves" / "sda1").mkdir(parents=True)
            (sysblock / "md0" / "slaves" / "sdb1").mkdir()

        self.assertEqual(self.run_unwrap("/dev/md0", setup), "/dev/md0")


class VirtTests(unittest.TestCase):
    def run_stubbed_virt(self, container, vm, bare):
        with tempfile.TemporaryDirectory() as td:
            bin_dir = Path(td) / "bin"
            bin_dir.mkdir()
            write_systemd_detect_virt_stub(bin_dir / "systemd-detect-virt", container, vm, bare)
            return run_shell(["virt_fallback", "virt_detect"], "virt_detect", bin_dir=bin_dir)

    def test_systemd_container_result_wins(self):
        self.assertEqual(
            self.run_stubbed_virt(("docker", 0), ("kvm", 0), ("none", 1)),
            "container:docker",
        )

    def test_systemd_vm_result_is_used_when_no_container(self):
        self.assertEqual(
            self.run_stubbed_virt(("none", 1), ("kvm", 0), ("none", 1)),
            "vm:kvm",
        )

    def test_systemd_bare_none_means_no_virtualization(self):
        self.assertEqual(
            self.run_stubbed_virt(("none", 1), ("none", 1), ("none", 1)),
            "none",
        )

    def test_systemd_inconclusive_result_is_unknown(self):
        self.assertEqual(
            self.run_stubbed_virt(("", 1), ("", 1), ("", 1)),
            "unknown",
        )

    def run_fallback(self, setup):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            proc = base / "proc"
            root = base / "root"
            run = base / "run"
            for directory in (proc, root, run):
                directory.mkdir()
            setup(proc, root, run)
            call = "virt_fallback {} {} {}".format(
                shlex.quote(str(proc)), shlex.quote(str(root)), shlex.quote(str(run)))
            return run_shell(["virt_fallback"], call)

    def test_fallback_detects_openvz(self):
        def setup(proc, root, run):
            (proc / "vz").mkdir()

        self.assertEqual(self.run_fallback(setup), "container:openvz")

    def test_fallback_detects_container_environ_nul_separated(self):
        def setup(proc, root, run):
            (proc / "1").mkdir()
            (proc / "1" / "environ").write_bytes(b"x=1\0container=podman\0")

        self.assertEqual(self.run_fallback(setup), "container:unknown")

    def test_fallback_detects_dockerenv_and_containerenv(self):
        for name in (".dockerenv", ".containerenv"):
            with self.subTest(name=name):
                def setup(proc, root, run):
                    target = root / name if name == ".dockerenv" else run / name
                    target.write_text("")

                self.assertEqual(self.run_fallback(setup), "container:unknown")

    def test_fallback_detects_cpu_hypervisor_flag(self):
        def setup(proc, root, run):
            (proc / "cpuinfo").write_text("flags\t\t: fpu hypervisor mmx\n")

        self.assertEqual(self.run_fallback(setup), "vm:unknown")

    def test_fallback_empty_system_is_unknown(self):
        self.assertEqual(self.run_fallback(lambda proc, root, run: None), "unknown")


class RootStackTests(unittest.TestCase):
    def run_root_stack(self, source, sysblock=None):
        args = shlex.quote(source)
        if sysblock is not None:
            args += " " + shlex.quote(str(sysblock))
        return run_shell(["root_stack_for_source"], f"root_stack_for_source {args}")

    def test_direct_block_sources_are_simple(self):
        for source in ("/dev/vda1", "/dev/nvme0n1p2", "/dev/sda", "/dev/xvda1", "/dev/mmcblk0p1"):
            with self.subTest(source=source):
                self.assertEqual(self.run_root_stack(source), "simple")

    def test_md_and_non_block_sources(self):
        self.assertEqual(self.run_root_stack("/dev/md0"), "raid")
        for source in ("", "overlay", "tmpfs", "zfs/root"):
            with self.subTest(source=source):
                self.assertEqual(self.run_root_stack(source), "unknown")

    def run_dm_case(self, uuid, slave_count):
        with tempfile.TemporaryDirectory() as td:
            sysblock = Path(td) / "sysblock"
            dm = sysblock / "vg-root"
            (dm / "dm").mkdir(parents=True)
            (dm / "dm" / "uuid").write_text(uuid)
            slaves = dm / "slaves"
            slaves.mkdir()
            for index in range(slave_count):
                (slaves / f"sd{chr(ord('a') + index)}").mkdir()
            return self.run_root_stack("/dev/mapper/vg-root", sysblock)

    def test_device_mapper_uuid_classification(self):
        cases = [
            ("CRYPT-LUKS2-abc", 1, "encrypted"),
            ("LVM-abc", 1, "lvm"),
            ("LVM-abc", 2, "lvm-multi"),
            ("MD-abc", 2, "raid"),
            ("DMRAID-abc", 2, "raid"),
            ("something-else", 1, "dm-other"),
        ]
        for uuid, slave_count, want in cases:
            with self.subTest(uuid=uuid, slave_count=slave_count):
                self.assertEqual(self.run_dm_case(uuid, slave_count), want)

    def test_liveenv_facts_disk_wins_before_proc_mounts(self):
        output = run_shell(
            ["root_stack_for_source", "root_stack_detect"],
            "root_stack_detect",
            env_extra={"FACTS_DISK": "/dev/vda"},
        )
        self.assertEqual(output, "liveenv")


class BootloaderTests(unittest.TestCase):
    def run_bootloader(self, setup, *, grub_tool=None):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            boot = base / "boot"
            root = base / "root"
            bin_dir = base / "bin"
            boot.mkdir()
            root.mkdir()
            bin_dir.mkdir()
            setup(boot, root)
            if grub_tool:
                write_exe(bin_dir / grub_tool, "#!/bin/sh\nexit 0\n")
            call = "bootloader_for_paths {} {}".format(shlex.quote(str(boot)), shlex.quote(str(root)))
            return run_shell(["bootloader_for_paths"], call, path=bin_dir)

    def test_grub_requires_tool_and_config_and_wins_precedence(self):
        def setup(boot, root):
            (boot / "grub").mkdir()
            (boot / "grub" / "grub.cfg").write_text("")
            (boot / "limine").mkdir()

        self.assertEqual(self.run_bootloader(setup, grub_tool="grub-reboot"), "grub")

    def test_grub2_tool_and_config_are_accepted(self):
        def setup(boot, root):
            (boot / "grub2").mkdir()
            (boot / "grub2" / "grub.cfg").write_text("")

        self.assertEqual(self.run_bootloader(setup, grub_tool="grub2-reboot"), "grub")

    def test_grub_config_without_tool_is_not_grub(self):
        def setup(boot, root):
            (boot / "grub").mkdir()
            (boot / "grub" / "grub.cfg").write_text("")

        self.assertEqual(self.run_bootloader(setup), "unknown")

    def test_limine_extlinux_systemd_boot_and_unknown(self):
        def limine_setup(boot, root):
            (boot / "limine").mkdir()

        def extlinux_setup(boot, root):
            (boot / "extlinux").mkdir()
            (boot / "extlinux" / "extlinux.conf").write_text("")

        def systemd_setup(boot, root):
            (root / "efi" / "loader" / "entries").mkdir(parents=True)

        cases = [
            (limine_setup, "limine"),
            (extlinux_setup, "extlinux"),
            (systemd_setup, "systemd-boot"),
            (lambda boot, root: None, "unknown"),
        ]
        for setup, want in cases:
            with self.subTest(want=want):
                self.assertEqual(self.run_bootloader(setup), want)

    def test_liveenv_facts_disk_wins(self):
        output = run_shell(
            ["bootloader_for_paths", "bootloader_detect"],
            "bootloader_detect",
            env_extra={"FACTS_DISK": "/dev/vda"},
        )
        self.assertEqual(output, "liveenv")


class SecureBootTests(unittest.TestCase):
    def run_secure_boot(self, firmware="uefi", setup=None, mokutil_output="unexpected"):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            efivars = base / "efivars"
            bin_dir = base / "bin"
            efivars.mkdir()
            bin_dir.mkdir()
            if setup:
                setup(efivars)
            if mokutil_output is not None:
                write_command_stub(bin_dir / "mokutil", mokutil_output)
            call = "secure_boot_for_paths {} {}".format(
                shlex.quote(firmware), shlex.quote(str(efivars)))
            return run_shell(["secure_boot_for_paths"], call, bin_dir=bin_dir)

    @staticmethod
    def write_secureboot_efivar(path, final_byte, size=5):
        if size < 1:
            data = b""
        else:
            data = b"\x00" * (size - 1) + bytes([final_byte])
        (path / "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c").write_bytes(data)

    def test_bios_reports_na_without_touching_efivars(self):
        self.assertEqual(self.run_secure_boot(firmware="bios"), "na")

    def test_uefi_final_byte_one_reports_enabled(self):
        def setup(efivars):
            self.write_secureboot_efivar(efivars, 1)

        self.assertEqual(self.run_secure_boot(setup=setup), "enabled")

    def test_uefi_final_byte_zero_reports_disabled(self):
        def setup(efivars):
            self.write_secureboot_efivar(efivars, 0)

        self.assertEqual(self.run_secure_boot(setup=setup), "disabled")

    def test_short_or_unrecognized_efivar_falls_back_to_mokutil(self):
        for size, final_byte in ((4, 0), (5, 2)):
            with self.subTest(size=size, final_byte=final_byte):
                def setup(efivars):
                    self.write_secureboot_efivar(efivars, final_byte, size=size)

                self.assertEqual(
                    self.run_secure_boot(setup=setup, mokutil_output="SecureBoot disabled"),
                    "disabled",
                )

    def test_mokutil_enabled_and_disabled_fallbacks(self):
        cases = (
            ("SecureBoot enabled", "enabled"),
            ("SecureBoot disabled", "disabled"),
            ("This system doesn't support Secure Boot", "disabled"),
            ("This system does not support Secure Boot", "disabled"),
        )
        for output, want in cases:
            with self.subTest(output=output):
                self.assertEqual(self.run_secure_boot(mokutil_output=output), want)

    def test_readable_efivarfs_without_secureboot_variable_reports_disabled(self):
        def setup(efivars):
            (efivars / "BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c").write_bytes(b"\x07\x00\x00\x00\x00\x00")

        self.assertEqual(self.run_secure_boot(setup=setup), "disabled")

    def test_corrupt_secureboot_var_does_not_fall_back_to_disabled_via_bootorder(self):
        def setup(efivars):
            self.write_secureboot_efivar(efivars, 2, size=5)
            (efivars / "BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c").write_bytes(b"\x07\x00\x00\x00\x00\x00")

        self.assertEqual(self.run_secure_boot(setup=setup), "unknown")

    def test_missing_or_unreadable_state_is_unknown(self):
        self.assertEqual(self.run_secure_boot(mokutil_output="unexpected output"), "unknown")


class BootSeparateTests(unittest.TestCase):
    def run_boot_separate(self, mounts_text=None, env_extra=None):
        with tempfile.TemporaryDirectory() as td:
            mounts = Path(td) / "mounts"
            if mounts_text is not None:
                mounts.write_text(mounts_text)
            call = f"boot_separate_for_mounts {shlex.quote(str(mounts))}"
            return run_shell(["boot_separate_for_mounts"], call, env_extra=env_extra)

    def test_boot_mountpoint_reports_yes(self):
        output = self.run_boot_separate(
            "/dev/vda1 / ext4 rw 0 0\n"
            "/dev/vda15 /boot ext4 rw 0 0\n"
        )
        self.assertEqual(output, "yes")

    def test_no_boot_mountpoint_reports_no(self):
        output = self.run_boot_separate(
            "/dev/vda1 / ext4 rw 0 0\n"
            "/dev/vda15 /boot/efi vfat rw 0 0\n"
        )
        self.assertEqual(output, "no")

    def test_missing_mounts_file_is_nonfatal_no(self):
        self.assertEqual(self.run_boot_separate(), "no")

    def test_liveenv_facts_disk_reports_liveenv(self):
        output = self.run_boot_separate(
            "/dev/vda15 /boot ext4 rw 0 0\n",
            env_extra={"FACTS_DISK": "/dev/vda"},
        )
        self.assertEqual(output, "liveenv")


class IPv4RouteShapeTests(unittest.TestCase):
    def run_with_routes(self, output):
        with tempfile.TemporaryDirectory() as td:
            bin_dir = Path(td) / "bin"
            bin_dir.mkdir()
            write_command_stub(bin_dir / "ip", output)
            return run_shell(["ipv4_route_shape_detect"], "ipv4_route_shape_detect", bin_dir=bin_dir)

    def test_route_count_and_onlink_classification(self):
        cases = [
            ("", "no-gateway"),
            ("default via 192.0.2.1 dev eth0\n", "simple"),
            ("default via 192.0.2.1 dev eth0 proto static onlink\n", "onlink"),
            (
                "default via 192.0.2.1 dev eth0\n"
                "default via 198.51.100.1 dev eth1\n",
                "multi-default",
            ),
        ]
        for routes, want in cases:
            with self.subTest(want=want):
                self.assertEqual(self.run_with_routes(routes), want)

    def test_missing_ip_command_is_unknown(self):
        with tempfile.TemporaryDirectory() as td:
            output = run_shell(["ipv4_route_shape_detect"], "ipv4_route_shape_detect", path=td)
        self.assertEqual(output, "unknown")


if __name__ == "__main__":
    unittest.main()

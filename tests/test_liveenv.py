"""Regression pins for the liveenv and target-local safety contract.

These are offline tests. Several intentionally inspect shell structure because
the real behavior is destructive or requires an initramfs boot; small
non-destructive fragments are executed against temporary trees where practical.
"""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
LIVE = (ROOT / "engine/liveenv.sh").read_text()
MAIN = (ROOT / "bootie-main").read_text()
HOOK = (ROOT / "engine/initramfs-hook.sh").read_text()
AUTOSTART = (ROOT / "engine/initramfs-autostart.sh").read_text()
STAGE = (ROOT / "engine/stage.py").read_text()


def shell_function(name):
    start = LIVE.index(f"{name}() {{")
    end = LIVE.index("\n}\n", start) + len("\n}\n")
    return LIVE[start:end]


def network_case_script():
    personalize = shell_function("cmd_personalize")
    start = personalize.index("    net_backend=${NET_BACKEND:-networkmanager}")
    end = personalize.index("\n    esac", start) + len("\n    esac")
    return personalize[start:end]


def run_network_case(backend, target):
    work = target.parent
    bin_dir = work / "bin"
    bin_dir.mkdir(exist_ok=True)
    cat_stub = bin_dir / "cat"
    cat_stub.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = /proc/sys/kernel/random/uuid ]; then\n"
        "    echo 01234567-89ab-cdef-0123-456789abcdef\n"
        "    exit 0\n"
        "fi\n"
        "exec /bin/cat \"$@\"\n"
    )
    cat_stub.chmod(0o755)
    assignments = {
        "NET_BACKEND": backend,
        "NET_IF": "ens18",
        "IPV4_ADDR": "192.0.2.10/24",
        "IPV4_GW": "192.0.2.1",
        "IPV6_ADDR": "2001:db8::10/64",
        "IPV6_GW": "2001:db8::1",
        "DNS": "192.0.2.53",
    }
    lines = [
        "#!/bin/sh",
        "set -eu",
        'die() { echo "$*" >&2; exit 1; }',
        'log() { echo "[liveenv] $*"; }',
    ]
    lines.extend(f"{name}={shlex.quote(value)}" for name, value in assignments.items())
    lines.append(network_case_script().replace("/target", str(target)))
    script = work / f"run-{backend}.sh"
    script.write_text("\n".join(lines) + "\n")
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
    return subprocess.run(["sh", str(script)], capture_output=True, text=True, env=env)


def run_systemd_unit_path(target, unit):
    function = shell_function("systemd_unit_path").replace("/target", str(target))
    script = target.parent / "run-systemd-unit-path.sh"
    script.write_text(function + '\nsystemd_unit_path "$1"\n')
    return subprocess.run(["sh", str(script), unit], capture_output=True, text=True)


def write_exe(path, content):
    path.write_text(content)
    path.chmod(0o755)


def run_find_efi_bootx64(esp):
    function = shell_function("find_efi_bootx64").replace("/esp", str(esp))
    script = esp.parent / "run-find-efi-bootx64.sh"
    script.write_text(function + "\nfind_efi_bootx64\n")
    return subprocess.run(["/bin/sh", str(script)], capture_output=True, text=True)


def run_uefi_boot(esp, *, esp_part="/dev/vda15", bootx64_bytes=b"efi", efibootmgr_rc=None):
    root = esp.parent
    bin_dir = root / "bin"
    bin_dir.mkdir()
    for command in ("find", "awk", "grep"):
        target = shutil.which(command)
        if target is None:
            raise AssertionError(f"required test command not found: {command}")
        os.symlink(target, bin_dir / command)
    write_exe(bin_dir / "modprobe", "#!/bin/sh\nexit 0\n")

    args_file = root / "efibootmgr.args"
    if efibootmgr_rc is not None:
        write_exe(bin_dir / "efibootmgr", (
            "#!/bin/sh\n"
            f"printf '%s\\n' \"$@\" > {shlex.quote(str(args_file))}\n"
            f"exit {efibootmgr_rc}\n"
        ))

    if bootx64_bytes is not None:
        bootx64 = esp / "EFI" / "BOOT" / "BOOTX64.EFI"
        bootx64.parent.mkdir(parents=True)
        bootx64.write_bytes(bootx64_bytes)

    find_fn = shell_function("find_efi_bootx64").replace("/esp", str(esp))
    uefi_fn = shell_function("uefi_boot")
    uefi_fn = uefi_fn.replace("/sys/firmware/efi/efivars", str(root / "no-efivars"))
    uefi_fn = uefi_fn.replace("/esp", str(esp))
    lines = [
        "set -eu",
        'die() { echo "$*" >&2; exit 1; }',
        'log() { echo "[liveenv] $*"; }',
        f"ESP_PART={shlex.quote(esp_part)}",
        "PLAN_DISK=/dev/vda",
        "MANIFEST_NAME=testos",
        find_fn,
        uefi_fn,
        "uefi_boot",
    ]
    script = root / "run-uefi-boot.sh"
    script.write_text("\n\n".join(lines) + "\n")
    env = dict(os.environ)
    env["PATH"] = str(bin_dir)
    result = subprocess.run(["/bin/sh", str(script)], capture_output=True, text=True, env=env)
    return result, args_file


def temp_target():
    return tempfile.TemporaryDirectory(dir="/tmp")


class LiveenvSafetyTests(unittest.TestCase):
    def test_bios_verify_is_real_not_legacy_noop(self):
        self.assertNotIn("[ -f /esp/limine-bios.sys ] || true", LIVE)
        self.assertIn("bios boot unverified", LIVE)
        self.assertIn("BIOS boot setup failed", LIVE)
        self.assertIn("grep -q 'Bootie BIOS'", LIVE)

    def test_guarded_write_order_and_single_disk_writer(self):
        self.assertIn("guard_disk", LIVE)
        self.assertLess(LIVE.index("guard_disk"), LIVE.index("qemu-img convert"))
        invocations = [line for line in LIVE.splitlines() if line.lstrip().startswith("qemu-img convert")]
        self.assertEqual(len(invocations), 1)

    def test_pre_write_abort_order_in_entrypoint(self):
        approval = MAIN.index("typed_approval")
        staging = MAIN.index("staging live env")
        self.assertLess(approval, staging)
        self.assertNotIn("qemu-img convert", MAIN)
        self.assertIn("before the\n  write, a reboot returns to this OS unchanged", MAIN)
        self.assertLess(MAIN.index('if [ -n "$no_reboot" ]'), MAIN.index("$SUDO reboot"))

    def test_zero_authentication_refuses_before_staging(self):
        self.assertIn("REFUSING: no authentication material", MAIN)
        self.assertLess(MAIN.index("REFUSING: no authentication material"), MAIN.index("staging live env"))

    def test_auto_state_machine_target_resident_and_resumable(self):
        for needle in (
            "cmd_auto()",
            "write -> personalize -> verify -> osboot",
            "/bootie/auto.write.done",
            "/bootie/auto.personalize.done",
            "/bootie/auto.verify.done",
            "sleep 60; sync; reboot -f",
            "write|personalize|auto",
            "finished earlier with rc=$old_rc — retrying",
        ):
            self.assertIn(needle, LIVE)

    def test_initramfs_autostart_order_contract(self):
        self.assertNotIn("zz_bootie_autostart", HOOK)
        self.assertIn('"$DESTDIR/bootie"', HOOK)
        self.assertIn("prereqs", AUTOSTART)
        self.assertIn("/bootie/autostart", AUTOSTART)
        self.assertIn("/bootie/engine/liveenv.sh run auto", AUTOSTART)
        self.assertIn("/proc/net/route", AUTOSTART)
        self.assertIn("autostart-boot.log", AUTOSTART)
        self.assertIn("/etc/initramfs-tools/scripts/init-premount", MAIN)

    def test_liveenv_uses_staged_engine_facts_path(self):
        self.assertIn("/bootie/engine/facts.sh fingerprint", LIVE)
        self.assertIn("/bootie/engine/facts.sh", LIVE)
        self.assertIn("/bootie/plan.env", LIVE)

    def test_runcmd_units_preserve_manifest_order_and_exactly_once(self):
        self.assertIn('if [ "$i" -gt 1 ]; then', LIVE)
        self.assertIn("After=bootie-firstboot-$((i - 1)).service", LIVE)
        self.assertIn("ExecStopPost=-/usr/bin/systemctl disable %n", LIVE)
        self.assertIn("bootie-firstboot-finish", LIVE)
        self.assertIn("firstboot-system-upgrade-ok", LIVE)

    def test_boot_target_and_omdesktop_engine_contract(self):
        for needle in (
            "multi-user.target",
            "graphical.target",
            "INSTALL_OM_DESKTOP",
            "/bootie/payload/om-desktop",
            ".local/bin/om-desktop",
            "unknown BOOT_TARGET",
        ):
            self.assertIn(needle, LIVE)
        self.assertIn("BOOT_TARGET", STAGE)
        self.assertIn("MANAGED_USER", STAGE)

    def test_webapp_removal_targets_canonical_and_seeded_copies(self):
        for needle in (
            "/target/usr/share/omarchy/applications/",
            "/target/etc/skel/.local/share/applications/",
            "/target/home/*",
            'webapp_copy_present "$app" && die',
            "REMOVE_WEBAPP_COUNT",
            "base64 -d",
        ):
            self.assertIn(needle, LIVE if needle != "REMOVE_WEBAPP_COUNT" else STAGE)

    def test_leaf_only_package_removal(self):
        self.assertIn("required by", LIVE)
        self.assertIn("left installed", LIVE)
        self.assertNotIn("pacman -Rdd", LIVE)

    def test_host_key_fingerprints_printed_before_reboot(self):
        self.assertIn("NEW HOST KEY FINGERPRINTS", LIVE)
        self.assertIn("ssh-keygen -lf", LIVE)
        self.assertLess(LIVE.index("NEW HOST KEY FINGERPRINTS"), LIVE.index("personalize complete"))

    def test_ext4_partition_detection_mount_resize_and_verify(self):
        find = shell_function("find_parts")
        mount = shell_function("mount_target")
        subvols = shell_function("subvol_mounts")
        personalize = shell_function("cmd_personalize")
        verify = shell_function("cmd_verify")

        self.assertIn("rootfs_type=${ROOTFS_TYPE:-btrfs}", find)
        self.assertIn("/sys/class/block/${p##*/}/size", find)
        self.assertIn('[ "$size" -gt "$root_size" ]', find)
        self.assertIn("no ext4 partition found on $PLAN_DISK", find)
        self.assertIn("unsupported ROOTFS_TYPE: $rootfs_type", find)
        self.assertIn("modprobe ext4", mount)
        self.assertIn('mount -t ext4 "$ROOT_PART" /target', mount)
        self.assertIn('[ "${ROOTFS_TYPE:-btrfs}" = btrfs ] || return 0', subvols)

        self.assertLess(personalize.index('partx -u --nr'), personalize.index('e2fsck -fy "$ROOT_PART"'))
        self.assertLess(personalize.index('e2fsck -fy "$ROOT_PART"'), personalize.index('resize2fs "$ROOT_PART"'))
        self.assertLess(personalize.index('resize2fs "$ROOT_PART"'), personalize.index("mount_target"))
        self.assertIn('resize2fs "$ROOT_PART" >/dev/null 2>&1 || log "ext4 resize deferred"', personalize)
        self.assertIn('btrfs filesystem resize max /target || log "btrfs resize deferred"', personalize)
        self.assertIn('btrfs scrub start -B /target || die "scrub reported errors"', verify)
        self.assertLess(verify.index("sync; umount_target"), verify.index('e2fsck -fn "$ROOT_PART"'))
        self.assertIn('e2fsck -fn "$ROOT_PART" >/dev/null 2>&1 || die "e2fsck reported errors"', verify)

    def test_network_backends_render_target_files(self):
        personalize = shell_function("cmd_personalize")
        nm_start = personalize.index("        networkmanager)")
        networkd_start = personalize.index("        systemd-networkd)")
        netplan_start = personalize.index("        netplan)")
        none_start = personalize.index("        none)")
        unknown_start = personalize.index("        *)", none_start)
        nm = personalize[nm_start:networkd_start]
        networkd = personalize[networkd_start:netplan_start]
        netplan = personalize[netplan_start:none_start]
        none = personalize[none_start:unknown_start]

        for needle in (
            "/target/etc/NetworkManager/system-connections/bootie-static.nmconnection",
            "chmod 600 /target/etc/NetworkManager/system-connections/bootie-static.nmconnection",
            "address1=$IPV4_ADDR,$IPV4_GW",
            "dns=$DNS",
            "address1=$IPV6_ADDR,$IPV6_GW",
            'echo "[ipv6]"; echo "method=disabled"',
        ):
            self.assertIn(needle, nm)

        for needle in (
            "mkdir -p /target/etc/systemd/network",
            'echo "Name=$NET_IF"',
            'echo "Address=$IPV4_ADDR"',
            'echo "Gateway=$IPV4_GW"',
            'echo "DNS=$DNS"',
            'echo "Address=$IPV6_ADDR"',
            'echo "Gateway=$IPV6_GW"',
            "chmod 644 /target/etc/systemd/network/10-bootie-static.network",
            "rm -f /target/etc/systemd/network/10-cloud-init-*.network",
            "/target/etc/systemd/system/multi-user.target.wants/systemd-networkd.service",
        ):
            self.assertIn(needle, networkd)

        for needle in (
            "mkdir -p /target/etc/netplan",
            "network:",
            "version: 2",
            "dhcp4: false",
            "- $IPV4_ADDR",
            "- $IPV6_ADDR",
            "to: default",
            "via: $IPV4_GW",
            "via: $IPV6_GW",
            "nameservers:",
            "- $DNS",
            "chmod 600 /target/etc/netplan/99-bootie-static.yaml",
            "rm -f /target/etc/netplan/50-cloud-init.yaml",
        ):
            self.assertIn(needle, netplan)

        self.assertIn("network: backend none — skipped", none)
        self.assertIn("unknown NET_BACKEND '${NET_BACKEND}'", personalize)

    def test_networkmanager_branch_renders_exact_keyfile(self):
        with temp_target() as td:
            target = Path(td) / "target"
            target.mkdir()
            r = run_network_case("networkmanager", target)
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
            path = target / "etc/NetworkManager/system-connections/bootie-static.nmconnection"
            self.assertEqual(path.read_text(), (
                "[connection]\n"
                "id=bootie-static\n"
                "uuid=01234567-89ab-cdef-0123-456789abcdef\n"
                "type=ethernet\n"
                "interface-name=ens18\n"
                "autoconnect=true\n"
                "autoconnect-priority=10\n"
                "[ipv4]\n"
                "method=manual\n"
                "address1=192.0.2.10/24,192.0.2.1\n"
                "dns=192.0.2.53\n"
                "[ipv6]\n"
                "method=manual\n"
                "address1=2001:db8::10/64,2001:db8::1\n"
            ))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_systemd_networkd_branch_renders_file_and_enables_unit(self):
        with temp_target() as td:
            target = Path(td) / "target"
            cloud = target / "etc/systemd/network/10-cloud-init-ens18.network"
            cloud.parent.mkdir(parents=True)
            cloud.write_text("[Match]\nName=ens18\n")
            unit = target / "usr/lib/systemd/system/systemd-networkd.service"
            unit.parent.mkdir(parents=True)
            unit.write_text("[Unit]\n")

            r = run_network_case("systemd-networkd", target)
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
            path = target / "etc/systemd/network/10-bootie-static.network"
            self.assertEqual(path.read_text(), (
                "[Match]\n"
                "Name=ens18\n"
                "\n"
                "[Network]\n"
                "Address=192.0.2.10/24\n"
                "Gateway=192.0.2.1\n"
                "DNS=192.0.2.53\n"
                "Address=2001:db8::10/64\n"
                "Gateway=2001:db8::1\n"
            ))
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            self.assertFalse(cloud.exists())
            link = target / "etc/systemd/system/multi-user.target.wants/systemd-networkd.service"
            self.assertTrue(link.is_symlink())
            self.assertEqual(os.readlink(link), "/usr/lib/systemd/system/systemd-networkd.service")

    def test_netplan_branch_renders_valid_static_yaml(self):
        with temp_target() as td:
            target = Path(td) / "target"
            cloud = target / "etc/netplan/50-cloud-init.yaml"
            cloud.parent.mkdir(parents=True)
            cloud.write_text("network:\n  version: 2\n")

            r = run_network_case("netplan", target)
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
            path = target / "etc/netplan/99-bootie-static.yaml"
            self.assertEqual(yaml.safe_load(path.read_text()), {
                "network": {
                    "version": 2,
                    "ethernets": {
                        "ens18": {
                            "dhcp4": False,
                            "addresses": ["192.0.2.10/24", "2001:db8::10/64"],
                            "routes": [
                                {"to": "default", "via": "192.0.2.1"},
                                {"to": "default", "via": "2001:db8::1"},
                            ],
                            "nameservers": {"addresses": ["192.0.2.53"]},
                        },
                    },
                },
            })
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(cloud.exists())

    def test_network_backend_none_and_unknown_paths(self):
        with temp_target() as td:
            target = Path(td) / "target"
            target.mkdir()
            r = run_network_case("none", target)
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
            self.assertIn("skipped", r.stdout)
            self.assertFalse((target / "etc/NetworkManager").exists())
            self.assertFalse((target / "etc/systemd/network").exists())
            self.assertFalse((target / "etc/netplan").exists())

            r = run_network_case("bogus", target)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("unknown NET_BACKEND 'bogus'", r.stderr)

    def test_verify_checks_injected_files_for_selected_network_backend(self):
        verify = shell_function("cmd_verify")
        for needle in (
            "/target/etc/hostname",
            "/target/etc/ssh/ssh_host_ed25519_key",
            "net_file=/target/etc/NetworkManager/system-connections/bootie-static.nmconnection",
            "net_file=/target/etc/systemd/network/10-bootie-static.network",
            "net_file=/target/etc/netplan/99-bootie-static.yaml",
            '[ -f "$net_file" ] || die "missing $net_file"',
            "unknown NET_BACKEND '${NET_BACKEND}'",
        ):
            self.assertIn(needle, verify)

    def test_cloud_init_is_disabled_before_offline_personalization(self):
        personalize = shell_function("cmd_personalize")
        self.assertIn("if [ -d /target/etc/cloud ]; then", personalize)
        self.assertIn(": > /target/etc/cloud/cloud-init.disabled", personalize)
        self.assertLess(
            personalize.index("/target/etc/cloud/cloud-init.disabled"),
            personalize.index('echo "$HOSTNAME_V" > /target/etc/hostname'),
        )

    def test_locale_configuration_and_verification_contract(self):
        personalize = shell_function("cmd_personalize")
        verify = shell_function("cmd_verify")
        for needle in (
            "target_locale=${LOCALE_V:-en_US.UTF-8}",
            "printf 'LANG=%s\\n' \"$target_locale\" > /target/etc/locale.conf",
            "printf 'LANG=%s\\n' \"$target_locale\" > /target/etc/default/locale",
            "/target/etc/locale.gen",
            "sed -i \"s/^# *\\(${escaped_loc}[[:space:]].*\\)/\\1/\" /target/etc/locale.gen",
            "chroot /target locale-gen",
            'log "locale configured: $target_locale"',
        ):
            self.assertIn(needle, personalize)
        self.assertLess(
            personalize.index('echo "$HOSTNAME_V" > /target/etc/hostname'),
            personalize.index("target_locale=${LOCALE_V:-en_US.UTF-8}"),
        )
        self.assertLess(
            personalize.index("target_locale=${LOCALE_V:-en_US.UTF-8}"),
            personalize.index("# cloud_ops users"),
        )
        for needle in (
            'locale_expected="LANG=${LOCALE_V:-en_US.UTF-8}"',
            '[ -f /target/etc/locale.conf ] || die "missing /target/etc/locale.conf"',
            'grep -qxF "$locale_expected" /target/etc/locale.conf',
            'die "locale.conf mismatch: missing $locale_expected"',
        ):
            self.assertIn(needle, verify)

    def test_timezone_configuration_and_verification_contract(self):
        personalize = shell_function("cmd_personalize")
        verify = shell_function("cmd_verify")
        for needle in (
            'if [ -n "${TIMEZONE_V:-}" ]; then',
            '[ -f "/target/usr/share/zoneinfo/$TIMEZONE_V" ] || die "timezone not found in target: $TIMEZONE_V"',
            'ln -sf "/usr/share/zoneinfo/$TIMEZONE_V" /target/etc/localtime',
            "printf '%s\\n' \"$TIMEZONE_V\" > /target/etc/timezone",
            'log "timezone configured: $TIMEZONE_V"',
        ):
            self.assertIn(needle, personalize)
        self.assertLess(
            personalize.index("target_locale=${LOCALE_V:-en_US.UTF-8}"),
            personalize.index('if [ -n "${TIMEZONE_V:-}" ]; then'),
        )
        self.assertLess(
            personalize.index('if [ -n "${TIMEZONE_V:-}" ]; then'),
            personalize.index("# cloud_ops users"),
        )
        for needle in (
            '[ -L /target/etc/localtime ] || die "timezone symlink missing: /target/etc/localtime"',
            '"$(readlink /target/etc/localtime 2>/dev/null || true)" = "/usr/share/zoneinfo/$TIMEZONE_V"',
            'die "timezone symlink mismatch"',
        ):
            self.assertIn(needle, verify)

    def test_bios_boot_method_selects_limine_or_image_native(self):
        personalize = shell_function("cmd_personalize")
        verify = shell_function("cmd_verify")
        limine_condition = '[ "$FIRMWARE" = bios ] && [ "${BIOS_BOOT_METHOD:-limine}" = limine ]'
        self.assertIn(limine_condition, personalize)
        self.assertIn('bios_boot || die "BIOS boot setup failed"', personalize)
        self.assertIn('if [ "${BIOS_BOOT_METHOD:-limine}" = image-native ]; then', personalize)
        self.assertIn('log "BIOS boot: using image-native bootloader"', personalize)

        self.assertIn(limine_condition, verify)
        self.assertIn("[ -f /esp/limine-bios.sys ]", verify)
        self.assertIn("grep -q 'Bootie BIOS' /esp/limine.conf", verify)
        self.assertIn('if [ "${BIOS_BOOT_METHOD:-limine}" = image-native ]; then', verify)
        self.assertIn("/target/boot/grub/grub.cfg", verify)
        self.assertIn("/target/boot/grub2/grub.cfg", verify)
        self.assertIn("/target/boot/vmlinuz*", verify)
        self.assertIn("kernel_found=1", verify)

    def test_find_efi_bootx64_matches_case_insensitive_fallback_path(self):
        cases = (
            ("EFI", "BOOT", "BOOTX64.EFI"),
            ("efi", "boot", "bootx64.efi"),
            ("EFI", "boot", "BootX64.efi"),
        )
        for vendor, bootdir, filename in cases:
            with self.subTest(path=(vendor, bootdir, filename)), temp_target() as td:
                esp = Path(td) / "esp"
                bootx64 = esp / vendor / bootdir / filename
                bootx64.parent.mkdir(parents=True)
                bootx64.write_bytes(b"efi")
                r = run_find_efi_bootx64(esp)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(r.stdout.strip(), str(bootx64))

    def test_find_efi_bootx64_rejects_wrong_or_missing_path(self):
        with temp_target() as td:
            esp = Path(td) / "esp"
            wrong = esp / "EFI" / "BOOTX64.EFI"
            wrong.parent.mkdir(parents=True)
            wrong.write_bytes(b"efi")
            r = run_find_efi_bootx64(esp)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), "")

    def test_uefi_boot_registers_nvram_when_efibootmgr_is_available(self):
        with temp_target() as td:
            esp = Path(td) / "esp"
            esp.mkdir()
            r, args_file = run_uefi_boot(esp, efibootmgr_rc=0)
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
            self.assertIn("efibootmgr registered bootie-testos on /dev/vda15", r.stdout)
            self.assertNotIn("WARN: efibootmgr registration", r.stdout)
            self.assertEqual(args_file.read_text().splitlines(), [
                "-c",
                "-d",
                "/dev/vda",
                "-p",
                "15",
                "-L",
                "bootie-testos",
                "-l",
                "\\EFI\\BOOT\\BOOTX64.EFI",
            ])

    def test_uefi_boot_nvram_failure_or_absent_tool_is_nonfatal_with_fallback(self):
        for efibootmgr_rc in (1, None):
            with self.subTest(efibootmgr_rc=efibootmgr_rc), temp_target() as td:
                esp = Path(td) / "esp"
                esp.mkdir()
                r, args_file = run_uefi_boot(esp, efibootmgr_rc=efibootmgr_rc)
                self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
                self.assertIn(
                    "WARN: efibootmgr registration skipped/failed (BOOTX64.EFI fallback present)",
                    r.stdout,
                )
                if efibootmgr_rc is None:
                    self.assertFalse(args_file.exists())
                else:
                    self.assertTrue(args_file.exists())

    def test_uefi_boot_requires_esp_partition(self):
        with temp_target() as td:
            esp = Path(td) / "esp"
            esp.mkdir()
            r, _ = run_uefi_boot(esp, esp_part="", efibootmgr_rc=0)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("UEFI firmware but no FAT32 ESP partition found on /dev/vda", r.stderr)

    def test_uefi_boot_requires_non_empty_bootx64_fallback(self):
        for bootx64_bytes in (None, b""):
            with self.subTest(bootx64_bytes=bootx64_bytes), temp_target() as td:
                esp = Path(td) / "esp"
                esp.mkdir()
                r, _ = run_uefi_boot(esp, bootx64_bytes=bootx64_bytes, efibootmgr_rc=0)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("UEFI firmware but no EFI/BOOT/BOOTX64.EFI on ESP", r.stderr)

    def test_personalize_calls_uefi_boot_only_on_uefi_before_unmount(self):
        personalize = shell_function("cmd_personalize")
        condition = 'if [ "$FIRMWARE" = uefi ]; then'
        self.assertIn(condition, personalize)
        self.assertIn("uefi_boot", personalize)
        self.assertLess(personalize.index(condition), personalize.index("sync; umount_target"))
        self.assertLess(personalize.index(condition), personalize.index('if [ "$FIRMWARE" = bios ]'))

    def test_uefi_boot_best_effort_nvram_contract(self):
        uefi_fn = shell_function("uefi_boot")
        for needle in (
            "modprobe efivarfs 2>/dev/null || true",
            "mount -t efivarfs efivarfs",
            "esp_pnum=$(echo \"$ESP_PART\" | grep -o '[0-9]*$')",
            'efibootmgr -c -d "$PLAN_DISK" -p "$esp_pnum"',
            '-L "bootie-$MANIFEST_NAME" -l \'\\EFI\\BOOT\\BOOTX64.EFI\'',
            "WARN: efibootmgr registration skipped/failed (BOOTX64.EFI fallback present)",
        ):
            self.assertIn(needle, uefi_fn)

    def test_uefi_verify_enforces_esp_bootx64_and_limine_uki(self):
        verify = shell_function("cmd_verify")
        uefi_condition = 'if [ "$FIRMWARE" = uefi ]; then'
        self.assertIn(uefi_condition, verify)
        start = verify.index(uefi_condition)
        end = verify.index('if [ "$FIRMWARE" = bios ]', start)
        branch = verify[start:end]
        for needle in (
            '[ -n "$ESP_PART" ] || die "UEFI firmware but no ESP partition found"',
            "bootx64=$(find_efi_bootx64)",
            '[ -s "$bootx64" ]',
            "UEFI firmware but no EFI/BOOT/BOOTX64.EFI on ESP — UEFI boot unverified",
            '[ -f /esp/limine.conf ]',
            "find /esp -maxdepth 3 -type f -iname '*.efi'",
            "/\\/(efi\\/linux|boot)\\/.+\\.efi$/",
            "UEFI firmware but no Limine UKI on ESP — UEFI boot unverified",
        ):
            self.assertIn(needle, branch)

    def test_initramfs_stages_uefi_tooling_and_efivarfs_module(self):
        for needle in (
            "/usr/bin/efibootmgr",
            "/sbin/efibootmgr",
            "manual_add_modules efivarfs",
        ):
            self.assertIn(needle, HOOK)

    def test_firstboot_connectivity_check_host_is_parameterized(self):
        line = next(line for line in LIVE.splitlines() if "ExecStartPre=/bin/sh -c" in line)
        self.assertIn("${FIRSTBOOT_CHECK_HOST:-archlinux.org}", line)
        self.assertNotIn("getent hosts archlinux.org", line)

    def test_systemd_boot_target_unit_dir_resolution(self):
        for needle in (
            "/target/usr/lib/systemd/system/multi-user.target",
            "/target/lib/systemd/system/multi-user.target",
            "/target/usr/lib/systemd/system/graphical.target",
            "/target/lib/systemd/system/graphical.target",
            'ln -sf "$boot_unit_path" /target/etc/systemd/system/default.target',
        ):
            self.assertIn(needle, LIVE)

    def test_systemd_unit_path_prefers_usr_lib_and_falls_back_to_lib(self):
        with temp_target() as td:
            target = Path(td) / "target"
            usr_multi = target / "usr/lib/systemd/system/multi-user.target"
            lib_multi = target / "lib/systemd/system/multi-user.target"
            lib_graphical = target / "lib/systemd/system/graphical.target"
            for unit_file in (usr_multi, lib_multi, lib_graphical):
                unit_file.parent.mkdir(parents=True, exist_ok=True)
                unit_file.write_text("[Unit]\n")

            r = run_systemd_unit_path(target, "multi-user.target")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), "/usr/lib/systemd/system/multi-user.target")

            usr_multi.unlink()
            r = run_systemd_unit_path(target, "multi-user.target")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), "/lib/systemd/system/multi-user.target")

            r = run_systemd_unit_path(target, "graphical.target")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), "/lib/systemd/system/graphical.target")

            lib_multi.unlink()
            r = run_systemd_unit_path(target, "multi-user.target")
            self.assertNotEqual(r.returncode, 0)

    def test_checksum_status_uses_algorithm_aware_value_with_sha256_fallback(self):
        self.assertIn(
            'echo "checksum: ${ART_CHECKSUM_ALG:-sha256}:${ART_CHECKSUM:-${ART_SHA256:-none}}"',
            LIVE,
        )
        self.assertIn('echo "sha256  : $ART_SHA256"', LIVE)

    def test_initramfs_stages_ext4_tooling_and_module(self):
        for needle in (
            "/sbin/resize2fs",
            "/usr/sbin/resize2fs",
            "/sbin/e2fsck",
            "/usr/sbin/e2fsck",
            "/sbin/fsck.ext4",
            "/usr/sbin/fsck.ext4",
            "manual_add_modules ext4",
            "manual_add_modules btrfs",
            "manual_add_modules vfat",
        ):
            self.assertIn(needle, HOOK)

    def test_authkey_is_not_quote_stripped_per_line(self):
        self.assertIn("AUTHKEY=${AUTHKEY:-}", LIVE)
        self.assertNotIn('AUTHKEY=$(echo "${AUTHKEY:-}" | sed', LIVE)
        self.assertNotRegex(LIVE, r"AUTHKEY=.*sed")

    def test_mount_target_mounts_separate_fstab_boot_partition_by_label_or_uuid(self):
        self.assertIn("fstab_boot_mount()", LIVE)
        self.assertLess(LIVE.index("fstab_boot_mount()"), LIVE.index("mount_target()"))
        mount_fn = shell_function("mount_target")
        self.assertIn("fstab_boot_mount", mount_fn)
        boot_fn = shell_function("fstab_boot_mount")
        for needle in (
            '$2 == "/boot"',
            "LABEL=*|UUID=*|PARTUUID=*)",
            'for p in "$PLAN_DISK"?*; do',
            'blkid -o value -s "$boot_tag" "$p"',
            "mount -t \"$boot_fstype\" \"$boot_part\" /target/boot",
        ):
            self.assertIn(needle, boot_fn)

    def test_cmd_status_explains_post_write_fingerprint_change(self):
        status_fn = shell_function("cmd_status")
        self.assertIn("/bootie/auto.write.done", status_fn)
        self.assertIn("PARTUUIDs change after write", status_fn)

    def test_entrypoint_only_mentions_firstboot_upgrade_when_runcmd_present(self):
        self.assertIn("runcmd_count=", MAIN)
        self.assertIn('if [ "${runcmd_count:-0}" -gt 0 ]; then', MAIN)


if __name__ == "__main__":
    unittest.main()

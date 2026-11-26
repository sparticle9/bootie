"""Support-envelope classification tests."""
import io
import json
from contextlib import redirect_stderr
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import preflight as rp  # noqa: E402


def facts(**overrides):
    base = {
        "firmware": "bios",
        "ipv4_addr": "192.0.2.10/24",
        "ipv4_gateway": "192.0.2.1",
        "ipv4_route_shape": "simple",
        "disk_count": "1",
        "root_stack": "simple",
        "virt": "vm:kvm",
        "bootloader": "grub",
        "disk_driver": "virtio-pci",
        "net_driver": "virtio-pci",
    }
    base.update(overrides)
    return base


def probes(fact_map, accepted_risks=None):
    plan = {"facts": fact_map}
    if accepted_risks is not None:
        plan["accepted_risks"] = accepted_risks
    return {p["name"]: p for p in rp.support_envelope(plan)}


def statuses(fact_map):
    return {name: probe["status"] for name, probe in probes(fact_map).items()}


class SupportEnvelopeTests(unittest.TestCase):
    def test_baseline_passes_every_probe(self):
        self.assertEqual(statuses(facts()), {
            "virt": "pass",
            "bootloader": "pass",
            "firmware": "pass",
            "network": "pass",
            "disk-topology": "pass",
            "drivers": "pass",
        })

    def test_container_virt_fails_closed_with_remediation(self):
        expected = ("container virtualization lacks kernel/initramfs control "
                    "and cannot be reinstalled by bootie")
        for virt in ("container:lxc", "container:openvz"):
            with self.subTest(virt=virt):
                probe = probes(facts(virt=virt))["virt"]
                self.assertEqual(probe["status"], "fail")
                self.assertEqual(probe["note"], expected)

    def test_vm_and_bare_metal_virt_pass_unknown_warns(self):
        for virt in ("vm:kvm", "none"):
            with self.subTest(virt=virt):
                self.assertEqual(statuses(facts(virt=virt))["virt"], "pass")
        self.assertEqual(statuses(facts(virt="unknown"))["virt"], "warn")
        missing = facts()
        del missing["virt"]
        self.assertEqual(statuses(missing)["virt"], "warn")

    def test_bootloader_grub_passes_and_others_fail_closed(self):
        self.assertEqual(statuses(facts())["bootloader"], "pass")
        for bootloader in ("limine", "systemd-boot", "extlinux", "unknown"):
            with self.subTest(bootloader=bootloader):
                probe = probes(facts(bootloader=bootloader))["bootloader"]
                self.assertEqual(probe["status"], "fail")
                self.assertEqual(
                    probe["note"],
                    f"bootloader '{bootloader}' is outside the current support envelope "
                    "(requires GRUB with grub-reboot/grub2-reboot and grub.cfg)",
                )

    def test_firmware_bios_passes(self):
        probe = probes(facts())["firmware"]
        self.assertEqual(probe["status"], "pass")
        self.assertEqual(probe["note"], "BIOS — drill-proven path")

    def test_uefi_secure_boot_enabled_always_fails(self):
        expected = ("UEFI Secure Boot is enabled — disable Secure Boot in your provider or "
                    "firmware settings before running bootie")
        for accepted in (None, ["drivers"]):
            with self.subTest(accepted=accepted):
                probe = probes(
                    facts(firmware="uefi", secure_boot="enabled"),
                    accepted_risks=accepted,
                )["firmware"]
                self.assertEqual(probe["status"], "fail")
                self.assertEqual(probe["note"], expected)

    def test_uefi_secure_boot_unknown_or_na_always_fails(self):
        for secure_boot in ("unknown", "na", "unexpected"):
            with self.subTest(secure_boot=secure_boot):
                probe = probes(
                    facts(firmware="uefi", secure_boot=secure_boot),
                )["firmware"]
                self.assertEqual(probe["status"], "fail")
                self.assertEqual(
                    probe["note"],
                    "UEFI Secure Boot state could not be confirmed disabled "
                    f"(observed: {secure_boot}) — disable Secure Boot and ensure efivars "
                    "are readable before running bootie",
                )

    def test_uefi_missing_secure_boot_fact_fails_closed_as_unknown(self):
        fact_map = facts(firmware="uefi")
        fact_map.pop("secure_boot", None)
        probe = probes(fact_map)["firmware"]
        self.assertEqual(probe["status"], "fail")
        self.assertIn("(observed: unknown)", probe["note"])

    def test_uefi_secure_boot_disabled_passes(self):
        probe = probes(facts(firmware="uefi", secure_boot="disabled"))["firmware"]
        self.assertEqual(probe["status"], "pass")
        self.assertEqual(probe["note"], "UEFI (Secure Boot disabled) — drill-proven path")

    def test_other_firmware_values_fail_closed(self):
        probe = probes(facts(firmware="other"))["firmware"]
        self.assertEqual(probe["status"], "fail")
        self.assertEqual(probe["note"], "firmware 'other' is outside the current support envelope")

    def test_simple_ipv4_with_gateway_passes(self):
        probe = probes(facts())["network"]
        self.assertEqual(probe["status"], "pass")
        self.assertEqual(probe["note"], "static-or-dhcp-derived 192.0.2.10/24 via 192.0.2.1")

    def test_slash32_point_to_point_fails_closed(self):
        probe = probes(facts(ipv4_addr="192.0.2.10/32"))["network"]
        self.assertEqual(probe["status"], "fail")
        self.assertEqual(probe["note"], "/32 point-to-point addressing requires onlink routes — "
                                        "outside the current support envelope")

    def test_missing_ipv4_or_gateway_fails_closed(self):
        self.assertEqual(statuses(facts(ipv4_addr=""))["network"], "fail")
        no_gateway = probes(facts(ipv4_gateway=""))["network"]
        self.assertEqual(no_gateway["status"], "fail")
        self.assertEqual(no_gateway["note"], "no IPv4 default gateway — artifact fetch and "
                                             "firstboot upgrade require outbound connectivity")

    def test_no_gateway_route_shape_fails_closed_even_with_gateway_fact(self):
        probe = probes(facts(ipv4_route_shape="no-gateway"))["network"]
        self.assertEqual(probe["status"], "fail")
        self.assertEqual(probe["note"], "no IPv4 default gateway — artifact fetch and "
                                        "firstboot upgrade require outbound connectivity")

    def test_onlink_and_multi_default_route_shapes_fail_closed(self):
        cases = {
            "onlink": "onlink IPv4 default route is outside the current support envelope "
                      "(initramfs ip= supports simple gateway routes only)",
            "multi-default": "multiple IPv4 default routes detected — policy/multi-interface "
                             "routing is outside the current support envelope",
        }
        for shape, expected in cases.items():
            with self.subTest(shape=shape):
                probe = probes(facts(ipv4_route_shape=shape))["network"]
                self.assertEqual(probe["status"], "fail")
                self.assertEqual(probe["note"], expected)

    def test_complex_root_stacks_fail_closed(self):
        for stack in ("raid", "encrypted", "lvm", "lvm-multi", "dm-other", "unknown"):
            with self.subTest(stack=stack):
                probe = probes(facts(root_stack=stack))["disk-topology"]
                self.assertEqual(probe["status"], "fail")
                self.assertIn(f"root filesystem uses {stack}", probe["note"])
                self.assertIn("refused to avoid partial-disk corruption", probe["note"])

    def test_disk_topology_simple_single_passes_and_multiple_disks_warn(self):
        probe = probes(facts(disk_count="1"))["disk-topology"]
        self.assertEqual(probe["status"], "pass")
        self.assertEqual(probe["note"], "single-disk simple topology")
        probe = probes(facts(disk_count="2"))["disk-topology"]
        self.assertEqual(probe["status"], "warn")
        self.assertEqual(probe["note"], "2 disks present — verify the target disk path and "
                                        "fingerprint carefully before approval")

    def test_both_driver_families_virtio_passes(self):
        self.assertEqual(statuses(facts())["drivers"], "pass")

    def test_mixed_non_virtio_and_unknown_drivers_fail_closed_by_default(self):
        cases = (
            {"net_driver": "e1000"},
            {"disk_driver": "nvme"},
            {"disk_driver": "nvme", "net_driver": "e1000"},
            {"disk_driver": "unknown"},
            {"net_driver": "unknown"},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                probe = probes(facts(**overrides))["drivers"]
                self.assertEqual(probe["status"], "fail")
                self.assertIn("mixed or non-virtio/unknown driver families", probe["note"])
                self.assertIn("unverified in the liveenv initramfs", probe["note"])
                self.assertIn("failing closed by default", probe["note"])
                self.assertIn("re-run with `--accept-risk drivers` only if you have "
                              "provider console/reinstall recovery", probe["note"])

    def test_accepted_drivers_risk_downgrades_driver_failures_to_warn(self):
        cases = (
            {"net_driver": "e1000"},
            {"disk_driver": "nvme"},
            {"disk_driver": "nvme", "net_driver": "e1000"},
            {"disk_driver": "unknown"},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                probe = probes(facts(**overrides), accepted_risks=["drivers"])["drivers"]
                self.assertEqual(probe["status"], "warn")
                self.assertIn("risk accepted via --accept-risk drivers", probe["note"])
                self.assertIn("disk=", probe["note"])
                self.assertIn("net=", probe["note"])
                self.assertIn("non-virtio side is unverified in the liveenv initramfs",
                              probe["note"])
                self.assertIn("requires provider console recovery", probe["note"])

    def test_accepted_driver_warning_does_not_block_check(self):
        fact_map = facts(disk_driver="nvme")
        fact_map.update({
            "disk_size_bytes": str(100 * 1024 ** 3),
            "mem_mib": "4096",
            "disk_path": "/dev/vda",
            "arch": "x86_64",
        })
        plan = {
            "facts": fact_map,
            "target_rules": {"disk_min_size_gib": 1, "memory_min_mib": 1,
                             "firmware": ["bios"]},
            "manifest": {"arch": "x86_64"},
            "artifact": {"kind": "disk-image"},
            "artifact_requires": {},
            "envelope": rp.support_envelope({
                "facts": fact_map,
                "accepted_risks": ["drivers"],
            }),
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
            json.dump(plan, tmp)
            path = Path(tmp.name)
        err = io.StringIO()
        try:
            with redirect_stderr(err):
                rc = rp.main(["check", "--plan", str(path)])
        finally:
            path.unlink()
        self.assertEqual(rc, 0)
        self.assertIn("envelope-warn [drivers]", err.getvalue())
        self.assertNotIn("ENVELOPE-FAIL", err.getvalue())

    def test_unimplemented_artifact_kind_is_a_fit_blocker(self):
        plan = {
            "facts": {
                "disk_size_bytes": str(100 * 1024 ** 3),
                "mem_mib": "4096",
                "firmware": "bios",
                "arch": "x86_64",
                "disk_path": "/dev/vda",
            },
            "target_rules": {"disk_min_size_gib": 1, "memory_min_mib": 1, "firmware": ["bios"]},
            "manifest": {"arch": "x86_64"},
            "artifact": {"kind": "netboot-installer"},
            "artifact_requires": {},
        }
        issues = rp.fit_issues(plan)
        self.assertTrue(any("netboot-installer" in issue and "not implemented" in issue for issue in issues))


if __name__ == "__main__":
    unittest.main()

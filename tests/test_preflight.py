"""Offline manifest, fact, plan, and approval tests for bootie."""
import base64
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import preflight as rp  # noqa: E402


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
secure_boot=na
boot_separate=no
"""

INDEX_JSON = {
    "version": "4.5.0", "channel": "stable",
    "url": "https://iso.omarchy.org/omarchy-4.5.0-x86.iso",
    "sha256": "5d6288bc57f96f6231719830457582c846a2291985201c36a9a7d1216978b00f",
    "vm": {
        "url": "https://nightly.omarchy.org/stable/4.5.0/494/omarchy-4.5.0.qcow2",
        "sha256": "fea962bb66bef8f922900018f8241e50a2d1a00268715541882479016235dc9f",
        "size": 4192291328,
        "unpacked": "https://nightly.omarchy.org/stable/4.5.0/494/unpacked/",
        "unpacked_files": ["vmlinuz", "initrd", "cmdline", "vm-boot", "SHA256SUMS"],
        "user": "omarchy",
    },
}

DEBIAN_IMAGE_FILE = "debian-13-generic-amd64.qcow2"
DEBIAN_SHA512 = "a" * 128
DEBIAN_SHA512SUMS = (
    f"{DEBIAN_SHA512}  debian-13-genericarm64.qcow2\n"
    f"{DEBIAN_SHA512}  {DEBIAN_IMAGE_FILE}\n"
)
UBUNTU_IMAGE_FILE = "noble-server-cloudimg-amd64.img"
UBUNTU_SHA256 = "b" * 64
UBUNTU_SHA256SUMS = (
    f"{UBUNTU_SHA256} *noble-server-cloudimg-arm64.img\n"
    f"{UBUNTU_SHA256} *{UBUNTU_IMAGE_FILE}\n"
)


def manifest_with_artifact(artifact):
    return {
        "manifest_version": 2,
        "name": "fixture-os",
        "version": "1.0",
        "arch": "x86_64",
        "artifact": artifact,
        "target": {"disk_min_size_gib": 1, "memory_min_mib": 512,
                   "firmware": ["bios", "uefi"]},
        "liveenv": {"kind": "debian-initramfs", "mode": "auto"},
        "write": {"method": "qemu-img-stream"},
        "personalize": {"network": "networkmanager"},
        "firstboot": {"grow_partition": False, "btrfs_resize": False},
    }


def netboot_manifest_fixture():
    return manifest_with_artifact({
        "kind": "netboot-installer",
        "base_url": "http://deb.debian.org/debian/dists/trixie/main/installer-amd64/current/images",
        "files": {
            "kernel": "netboot/debian-installer/amd64/linux",
            "initrd": "netboot/debian-installer/amd64/initrd.gz",
        },
        "checksums": "netboot/debian-installer/amd64/SHA256SUMS",
    })


def checksum_image_manifest(checksums_url, image_file, checksum_alg=None):
    artifact = {
        "kind": "disk-image",
        "checksums_url": checksums_url,
        "image_file": image_file,
    }
    if checksum_alg is not None:
        artifact["checksum_alg"] = checksum_alg
    return manifest_with_artifact(artifact)


def artifact_fixture():
    return {
        "kind": "disk-image",
        "url": "https://nightly.omarchy.org/example.qcow2",
        "sha256": "f" * 64,
        "unpacked_url": "https://nightly.omarchy.org/unpacked/",
        "size_bytes": 1,
    }


def write_temp(data, suffix=".yml"):
    tmp = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
    if isinstance(data, str):
        tmp.write(data)
    else:
        yaml.safe_dump(data, tmp)
    tmp.close()
    return Path(tmp.name)


class FactParsingTests(unittest.TestCase):
    def test_parse_and_fingerprint_roundtrip(self):
        facts = rp.parse_facts(FACTS_TEXT)
        self.assertEqual(facts["hostname"], "testhost")
        self.assertEqual(facts["disk_path"], "/dev/vda")
        fp = rp.fingerprint(facts)
        self.assertRegex(fp, r"^[0-9a-f]{16}$")
        self.assertEqual(fp, rp.fingerprint(rp.parse_facts(FACTS_TEXT)))

    def test_optional_support_envelope_facts_are_not_required(self):
        optional = {
            "virt", "root_stack", "bootloader", "ipv4_route_shape",
            "secure_boot", "boot_separate",
        }
        lines = [line for line in FACTS_TEXT.splitlines()
                 if line.split("=", 1)[0] not in optional]
        facts = rp.parse_facts("\n".join(lines) + "\n")
        self.assertEqual(facts["hostname"], "testhost")
        for key in optional:
            self.assertNotIn(key, facts)

    def test_fingerprint_changes_only_with_machine_identity(self):
        facts = rp.parse_facts(FACTS_TEXT)
        self.assertNotEqual(rp.fingerprint(facts), rp.fingerprint(dict(facts, disk_size_bytes="1000")))
        self.assertNotEqual(rp.fingerprint(facts), rp.fingerprint(dict(facts, net_mac="52:54:00:ff:ff:ff")))
        self.assertEqual(rp.fingerprint(facts), rp.fingerprint(dict(facts, hostname="other")))
        support_facts = dict(facts, virt="none", root_stack="raid",
                             bootloader="limine", ipv4_route_shape="onlink")
        self.assertEqual(rp.fingerprint(facts), rp.fingerprint(support_facts))

    def test_facts_validation_rejects_missing_nonnumeric_and_noncidr(self):
        with self.assertRaises(ValueError):
            rp.parse_facts("hostname=testhost\n")
        with self.assertRaises(ValueError):
            rp.parse_facts(FACTS_TEXT.replace("69793218560", "abc"))
        with self.assertRaises(ValueError):
            rp.parse_facts(FACTS_TEXT.replace("192.0.2.10/24", "192.0.2.10"))


class RiskAcceptanceTests(unittest.TestCase):
    def test_parse_accepted_risks_normalizes_commas_whitespace_and_duplicates(self):
        self.assertEqual(rp.parse_accepted_risks(None), [])
        self.assertEqual(rp.parse_accepted_risks([]), [])
        self.assertEqual(rp.parse_accepted_risks(["drivers"]), ["drivers"])
        self.assertEqual(rp.parse_accepted_risks([" drivers, ", "drivers"]), ["drivers"])
        self.assertEqual(rp.parse_accepted_risks(iter(["drivers,drivers"])), ["drivers"])

    def test_parse_accepted_risks_rejects_unknown_classes(self):
        with self.assertRaises(ValueError) as cm:
            rp.parse_accepted_risks(["drivers,bogus"])
        message = str(cm.exception)
        self.assertIn("unknown risk class(es): bogus", message)
        self.assertIn("allowed: drivers", message)

        with self.assertRaises(ValueError) as cm:
            rp.parse_accepted_risks(["uefi"])
        message = str(cm.exception)
        self.assertIn("unknown risk class(es): uefi", message)
        self.assertIn("allowed: drivers", message)

        with self.assertRaises(ValueError) as cm:
            rp.parse_accepted_risks(["bogus,other"])
        message = str(cm.exception)
        self.assertIn("bogus", message)
        self.assertIn("other", message)
        self.assertIn("allowed: drivers", message)


class ManifestTests(unittest.TestCase):
    def test_shipped_manifests_load(self):
        for name in ("omarchy-4.5", "debian-13"):
            m = rp.load_manifest(ROOT / "manifests" / f"{name}.yml")
            self.assertEqual(m["manifest_version"], 2)
            self.assertIn(m["artifact"]["kind"], ("disk-image", "netboot-installer"))
            self.assertTrue(m["liveenv"])
            self.assertTrue(m["write"])

    def test_cloud_config_transpile(self):
        cc = {
            "users": [
                {"name": "omarchy", "lock_passwd": True, "ssh_authorized_keys": []},
                {"name": "agent", "groups": ["wheel"], "shell": "/bin/bash",
                 "sudo": "ALL=(ALL) NOPASSWD: ALL", "lock_passwd": True,
                 "ssh_authorized_keys": []},
            ],
            "write_files": [{"path": "/etc/motd", "content": "hi", "permissions": "0644"}],
            "runcmd": ["echo hi && true", ["echo", "a b"]],
            "packages": ["git"],
        }
        ops = rp.transpile_cloud_config(cc)
        self.assertEqual([u["name"] for u in ops["users"]], ["omarchy", "agent"])
        self.assertEqual(ops["users"][1]["groups"], ["wheel"])
        self.assertEqual(len(ops["runcmd"]), 2)
        self.assertEqual(ops["runcmd"][1], "echo 'a b'")
        self.assertEqual(base64.b64decode(ops["files"][0]["content_b64"]), b"hi")
        self.assertEqual(ops["packages"], ["git"])
        self.assertEqual(ops["locale"], "en_US.UTF-8")
        self.assertEqual(ops["timezone"], "")

    def test_cloud_config_locale_defaults_and_validates_values(self):
        self.assertEqual(rp.transpile_cloud_config({})["locale"], "en_US.UTF-8")
        self.assertEqual(rp.transpile_cloud_config({"locale": None})["locale"], "en_US.UTF-8")
        for locale in ("C.UTF-8", "zh_CN.UTF-8", "en_US.UTF8", "C"):
            with self.subTest(locale=locale):
                ops = rp.transpile_cloud_config({"locale": locale})
                self.assertEqual(ops["locale"], locale)
        for bad in ("", "en US", "en/US", "en;US", "en_US.UTF-8\n", 3):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    rp.transpile_cloud_config({"locale": bad})

    def test_cloud_config_timezone_defaults_and_validates_values(self):
        self.assertEqual(rp.transpile_cloud_config({})["timezone"], "")
        self.assertEqual(rp.transpile_cloud_config({"timezone": None})["timezone"], "")
        for timezone in ("UTC", "Etc/UTC", "Asia/Shanghai", "America/New_York",
                         "America/Argentina/Buenos_Aires"):
            with self.subTest(timezone=timezone):
                ops = rp.transpile_cloud_config({"timezone": timezone})
                self.assertEqual(ops["timezone"], timezone)
        for bad in ("/etc/passwd", "../UTC", "bad zone", "", "UTC/", 3,
                    "America//New_York", "America/../UTC", "UTC;rm"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    rp.transpile_cloud_config({"timezone": bad})

    def test_cloud_config_unknown_or_unsupported_keys_rejected(self):
        for bad in (
            {"userz": []},
            {"users": [{"name": "x", "passwod": 1}]},
            {"write_files": [{"path": "/f", "encoding": "gz"}]},
            {"write_files": [{"path": "/f", "append": True}]},
            {"network": {"version": 2}},
        ):
            with self.assertRaises(ValueError, msg=str(bad)):
                rp.transpile_cloud_config(bad)

    def test_manifest_v2_unknown_top_keys_rejected(self):
        m = yaml.safe_load((ROOT / "manifests" / "omarchy-4.5.yml").read_text())
        m["cloud_confg"] = {}
        path = write_temp(m)
        try:
            with self.assertRaises(ValueError):
                rp.load_manifest(path)
        finally:
            path.unlink()

    def test_manifest_v1_legacy_keys_load_and_synthesize_cloud_ops(self):
        m = {
            "manifest_version": 1,
            "name": "legacy",
            "version": "1.0",
            "arch": "x86_64",
            "artifact": {
                "kind": "disk-image",
                "index_url": "https://upstream.example/stable/latest.json",
            },
            "target": {"disk_min_size_gib": 1, "memory_min_mib": 512},
            "liveenv": {"kind": "debian-initramfs"},
            "write": {"method": "qemu-img-stream"},
            "personalize": {
                "ssh_user": "legacyuser",
                "authorized_keys_target": "legacyuser",
            },
            "firstboot": {"run": [{"run": "echo v1-firstboot"}]},
        }
        path = write_temp(m)
        try:
            loaded = rp.load_manifest(path)
            plan = rp.build_plan(rp.parse_facts(FACTS_TEXT), loaded, artifact_fixture())
        finally:
            path.unlink()
        self.assertEqual([u["name"] for u in plan["cloud_ops"]["users"]], ["legacyuser"])
        self.assertEqual(plan["cloud_ops"]["runcmd"], ["echo v1-firstboot"])
        self.assertEqual(plan["cloud_ops"]["locale"], "en_US.UTF-8")
        self.assertEqual(plan["cloud_ops"]["timezone"], "")

        v2 = yaml.safe_load((ROOT / "manifests" / "omarchy-4.5.yml").read_text())
        v2["personalize"]["ssh_user"] = "legacyuser"
        path = write_temp(v2)
        try:
            with self.assertRaises(ValueError):
                rp.load_manifest(path)
        finally:
            path.unlink()

    def test_remove_webapps_validation(self):
        rp.validate_remove_webapps(["Basecamp", "Google Photos"])
        for bad in ("../x", "a/b", "", ".", "..", 3):
            with self.assertRaises(ValueError, msg=repr(bad)):
                rp.validate_remove_webapps([bad])
        with self.assertRaises(ValueError):
            rp.validate_remove_webapps("Basecamp")

    def test_liveenv_mode_validation_and_legacy_mapping(self):
        omarchy = rp.load_manifest(ROOT / "manifests" / "omarchy-4.5.yml")
        debian = rp.load_manifest(ROOT / "manifests" / "debian-13.yml")
        self.assertEqual(omarchy["liveenv"]["mode"], "auto")
        self.assertEqual(debian["liveenv"]["mode"], "auto")
        base = yaml.safe_load((ROOT / "manifests" / "omarchy-4.5.yml").read_text())
        edits = (
            lambda m: m["liveenv"].__setitem__("mode", "sometimes"),
            lambda m: m["liveenv"].__setitem__("hold", "yes"),
            lambda m: (m["liveenv"].__setitem__("mode", "auto"), m["liveenv"].__setitem__("hold", True)),
        )
        for edit in edits:
            mutated = yaml.safe_load(yaml.safe_dump(base))
            edit(mutated)
            path = write_temp(mutated)
            try:
                with self.assertRaises(ValueError):
                    rp.load_manifest(path)
            finally:
                path.unlink()

    def test_boot_target_validation(self):
        base = yaml.safe_load((ROOT / "manifests" / "omarchy-4.5.yml").read_text())
        base["postinstall"]["boot_target"] = "tiling"
        path = write_temp(base)
        try:
            with self.assertRaises(ValueError):
                rp.load_manifest(path)
        finally:
            path.unlink()

    def test_extension_section_unknown_keys_rejected(self):
        base = yaml.safe_load((ROOT / "manifests" / "omarchy-4.5.yml").read_text())
        for section, key in (
            ("artifact", "url"),
            ("target", "cpu_min"),
            ("liveenv", "rescure"),
            ("write", "verify"),
            ("personalize", "remove_webapp"),
            ("firstboot", "resize"),
        ):
            mutated = yaml.safe_load(yaml.safe_dump(base))
            mutated[section][key] = True
            path = write_temp(mutated)
            try:
                with self.assertRaises(ValueError, msg=f"{section}.{key}"):
                    rp.load_manifest(path)
            finally:
                path.unlink()

    def test_postinstall_unknown_keys_rejected(self):
        base = yaml.safe_load((ROOT / "manifests" / "omarchy-4.5.yml").read_text())
        base["postinstall"]["image_user_policy"] = "lock"
        path = write_temp(base)
        try:
            with self.assertRaises(ValueError):
                rp.load_manifest(path)
        finally:
            path.unlink()

    def test_postinstall_x_extension_keys_accepted(self):
        base = yaml.safe_load((ROOT / "manifests" / "omarchy-4.5.yml").read_text())
        base["postinstall"]["x-note"] = "operator note"
        path = write_temp(base)
        try:
            loaded = rp.load_manifest(path)
        finally:
            path.unlink()
        self.assertEqual(loaded["postinstall"]["x-note"], "operator note")

    def test_install_om_desktop_is_boolean_and_defaults_false(self):
        base = yaml.safe_load((ROOT / "manifests" / "omarchy-4.5.yml").read_text())
        self.assertIs(base["postinstall"]["install_om_desktop"], True)
        base["postinstall"].pop("install_om_desktop")
        path = write_temp(base)
        try:
            self.assertIs(rp.load_manifest(path)["postinstall"]["install_om_desktop"], False)
        finally:
            path.unlink()
        base["postinstall"]["install_om_desktop"] = "yes"
        path = write_temp(base)
        try:
            with self.assertRaises(ValueError):
                rp.load_manifest(path)
        finally:
            path.unlink()

    def test_plan_carries_cloud_ops(self):
        m = rp.load_manifest(ROOT / "manifests" / "omarchy-4.5.yml")
        plan = rp.build_plan(rp.parse_facts(FACTS_TEXT), m, artifact_fixture())
        names = [u["name"] for u in plan["cloud_ops"]["users"]]
        self.assertIn("omarchy", names)
        self.assertTrue(plan["cloud_ops"]["runcmd"])

    def test_generic_omarchy_has_no_owner_removal_defaults(self):
        m = rp.load_manifest(ROOT / "manifests" / "omarchy-4.5.yml")
        self.assertEqual(m["personalize"].get("remove_webapps"), [])
        self.assertEqual(m["personalize"].get("drop_pkgs"), [])
        self.assertEqual(m["postinstall"].get("managed_user"), "omarchy")

    def test_generic_firstboot_upgrade_contract(self):
        m = yaml.safe_load((ROOT / "manifests" / "omarchy-4.5.yml").read_text())
        script = m["cloud_config"]["runcmd"][0]
        for needle in (
            "OMARCHY_UPDATE_UNATTENDED=1",
            "omarchy-update-keyring",
            "omarchy-update-system-pkgs",
            "internet unreachable; skipping first-boot Omarchy system upgrade",
            "/boot/$machine_id/linux-omarchy",
            "/var/lib/bootie/firstboot-system-upgrade-ok",
        ):
            self.assertIn(needle, script)
        self.assertNotIn("voxtype", script)

    def test_hosted_artifact_urls_rejected(self):
        m = yaml.safe_load((ROOT / "manifests" / "omarchy-4.5.yml").read_text())
        m["artifact"]["index_url"] = "https://images.r2.dev/omarchy.qcow2"
        path = write_temp(m)
        try:
            with self.assertRaises(ValueError):
                rp.load_manifest(path)
        finally:
            path.unlink()

    def test_non_https_rejected_except_debian_mirror(self):
        m = yaml.safe_load((ROOT / "manifests" / "omarchy-4.5.yml").read_text())
        for url in (
            "http://nightly.omarchy.org/stable/latest.json",
            "http://evil.example/deb.debian.org/latest.json",
        ):
            m["artifact"]["index_url"] = url
            path = write_temp(m)
            try:
                with self.assertRaises(ValueError, msg=url):
                    rp.load_manifest(path)
            finally:
                path.unlink()
        debian_netboot = write_temp(netboot_manifest_fixture())
        try:
            rp.load_manifest(debian_netboot)
        finally:
            debian_netboot.unlink()

    def test_examples_load_and_keep_opinion_explicit(self):
        coding = rp.load_manifest(ROOT / "examples/manifests/coding-workspace-omarchy.yml")
        debian = rp.load_manifest(ROOT / "examples/manifests/agent-runtime-debian.yml")
        self.assertEqual(coding["postinstall"]["boot_target"], "console")
        self.assertEqual(coding["postinstall"]["managed_user"], "agent")
        self.assertEqual(debian["artifact"]["kind"], "disk-image")
        self.assertEqual(debian["postinstall"]["managed_user"], "agent")
        self.assertEqual(debian["postinstall"]["boot_target"], "console")
        self.assertEqual(debian["personalize"]["rootfs"], "ext4")


class ChecksumImageTests(unittest.TestCase):
    debian_checksums_url = "https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS"
    ubuntu_checksums_url = "https://cloud-images.ubuntu.com/noble/current/SHA256SUMS"

    def load_fixture(self, manifest):
        path = write_temp(manifest)
        try:
            return rp.load_manifest(path)
        finally:
            path.unlink()

    def test_parse_checksums_index_debian_ubuntu_and_dot_prefix_formats(self):
        self.assertEqual(
            rp.parse_checksums_index(DEBIAN_SHA512SUMS, DEBIAN_IMAGE_FILE, alg="sha512"),
            DEBIAN_SHA512,
        )
        self.assertEqual(
            rp.parse_checksums_index(UBUNTU_SHA256SUMS, UBUNTU_IMAGE_FILE, alg="sha256"),
            UBUNTU_SHA256,
        )
        prefixed = f"{UBUNTU_SHA256}  ./{UBUNTU_IMAGE_FILE}\n"
        self.assertEqual(
            rp.parse_checksums_index(prefixed, UBUNTU_IMAGE_FILE, alg="sha256"),
            UBUNTU_SHA256,
        )

    def test_resolve_debian_sha512sums_offline(self):
        manifest = self.load_fixture(checksum_image_manifest(
            self.debian_checksums_url, DEBIAN_IMAGE_FILE, checksum_alg="sha512"))
        index_path = write_temp(DEBIAN_SHA512SUMS, suffix=".txt")
        try:
            art = rp.resolve_artifact(manifest, index_file=str(index_path), fetch=False)
        finally:
            index_path.unlink()
        self.assertEqual(art, {
            "kind": "disk-image",
            "source_index": self.debian_checksums_url,
            "url": "https://cloud.debian.org/images/cloud/trixie/latest/" + DEBIAN_IMAGE_FILE,
            "checksum_alg": "sha512",
            "checksum": DEBIAN_SHA512,
            "sha256": "",
            "unpacked_url": "",
            "image_file": DEBIAN_IMAGE_FILE,
        })

    def test_resolve_ubuntu_sha256sums_offline_defaults_to_sha256(self):
        manifest = self.load_fixture(checksum_image_manifest(
            self.ubuntu_checksums_url, UBUNTU_IMAGE_FILE))
        index_path = write_temp(UBUNTU_SHA256SUMS, suffix=".txt")
        try:
            art = rp.resolve_artifact(manifest, index_file=str(index_path), fetch=False)
        finally:
            index_path.unlink()
        self.assertEqual(art["source_index"], self.ubuntu_checksums_url)
        self.assertEqual(art["url"],
                         "https://cloud-images.ubuntu.com/noble/current/" + UBUNTU_IMAGE_FILE)
        self.assertEqual(art["checksum_alg"], "sha256")
        self.assertEqual(art["checksum"], UBUNTU_SHA256)
        self.assertEqual(art["sha256"], UBUNTU_SHA256)
        self.assertEqual(art["image_file"], UBUNTU_IMAGE_FILE)

    def test_checksums_resolution_requires_index_file_or_fetch(self):
        manifest = self.load_fixture(checksum_image_manifest(
            self.ubuntu_checksums_url, UBUNTU_IMAGE_FILE))
        with self.assertRaisesRegex(ValueError, "--index-file or --fetch"):
            rp.resolve_artifact(manifest, fetch=False)

    def test_mirror_rewrites_checksum_index_and_image_url_for_debian_and_ubuntu(self):
        mirror_base = "https://mirror.example/releases"
        cases = (
            ("debian", self.debian_checksums_url, DEBIAN_IMAGE_FILE,
             DEBIAN_SHA512SUMS, "sha512", "SHA512SUMS"),
            ("ubuntu", self.ubuntu_checksums_url, UBUNTU_IMAGE_FILE,
             UBUNTU_SHA256SUMS, None, "SHA256SUMS"),
        )
        for name, checksums_url, image_file, sums_text, alg, sums_basename in cases:
            with self.subTest(name=name):
                manifest = self.load_fixture(checksum_image_manifest(
                    checksums_url, image_file, checksum_alg=alg))
                index_path = write_temp(sums_text, suffix=".txt")
                try:
                    art = rp.resolve_artifact(
                        manifest, index_file=str(index_path), fetch=False,
                        mirror=mirror_base + "/")
                finally:
                    index_path.unlink()
                self.assertEqual(art["source_index"], f"{mirror_base}/{sums_basename}")
                self.assertEqual(art["url"], f"{mirror_base}/{image_file}")
                self.assertEqual(art["mirror_override"], mirror_base)

    def test_validate_mirror_url_requires_clean_https_url(self):
        rp.validate_mirror_url("https://mirror.example/releases")
        rp.validate_mirror_url("https://mirror.example:8443/releases/")
        for bad in ("http://mirror.example/releases", "https://", "",
                    "https://mirror.example/bad path", "https://mirror.example/\tpath",
                    None, 3):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    rp.validate_mirror_url(bad)

    def test_non_https_mirror_is_rejected_before_resolution(self):
        manifest = self.load_fixture(checksum_image_manifest(
            self.ubuntu_checksums_url, UBUNTU_IMAGE_FILE))
        with self.assertRaisesRegex(ValueError, "--mirror"):
            rp.resolve_artifact(manifest, fetch=False,
                                mirror="http://mirror.example/releases")

    def test_mirror_is_rejected_for_omarchy_json_index_and_netboot(self):
        omarchy = rp.load_manifest(ROOT / "manifests" / "omarchy-4.5.yml")
        with self.assertRaisesRegex(ValueError, "not JSON-index manifests"):
            rp.resolve_artifact(omarchy, fetch=False,
                                mirror="https://mirror.example/releases")

        netboot_path = write_temp(netboot_manifest_fixture())
        try:
            netboot = rp.load_manifest(netboot_path)
        finally:
            netboot_path.unlink()
        with self.assertRaisesRegex(ValueError, "netboot-installer"):
            rp.resolve_artifact(netboot, fetch=False,
                                mirror="https://mirror.example/releases")

    def test_plan_cli_rejects_invalid_mirror_cleanly(self):
        manifest_path = write_temp(checksum_image_manifest(
            self.ubuntu_checksums_url, UBUNTU_IMAGE_FILE))
        facts_path = write_temp(FACTS_TEXT, suffix=".facts")
        index_path = write_temp(UBUNTU_SHA256SUMS, suffix=".txt")
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err):
                rc = rp.main([
                    "plan",
                    "--manifest", str(manifest_path),
                    "--facts", str(facts_path),
                    "--index-file", str(index_path),
                    "--no-fetch",
                    "--mirror", "http://mirror.example/releases",
                ])
        finally:
            manifest_path.unlink()
            facts_path.unlink()
            index_path.unlink()
        self.assertEqual(rc, 1)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("preflight error:", err.getvalue())
        self.assertIn("--mirror", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())

    def test_checksum_index_missing_or_malformed_entries_rejected(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            rp.parse_checksums_index(UBUNTU_SHA256SUMS, "missing.img", alg="sha256")
        bad_indexes = [
            f"{'0' * 63} *{UBUNTU_IMAGE_FILE}\n",
            f"{'z' * 64} *{UBUNTU_IMAGE_FILE}\n",
            f"{'A' * 64} *{UBUNTU_IMAGE_FILE}\n",
            "not-a-checksum-line\n",
        ]
        for text in bad_indexes:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    rp.parse_checksums_index(text, UBUNTU_IMAGE_FILE, alg="sha256")
        with self.assertRaises(ValueError):
            rp.parse_checksums_index(UBUNTU_SHA256SUMS, UBUNTU_IMAGE_FILE, alg="sha512")
        with self.assertRaises(ValueError):
            rp.parse_checksums_index(UBUNTU_SHA256SUMS, UBUNTU_IMAGE_FILE, alg="sha1")

    def test_disk_image_source_selection_is_mutually_exclusive_and_complete(self):
        both = checksum_image_manifest(self.ubuntu_checksums_url, UBUNTU_IMAGE_FILE)
        both["artifact"]["index_url"] = "https://nightly.omarchy.org/stable/latest.json"
        with self.assertRaisesRegex(ValueError, "conflicts"):
            self.load_fixture(both)

        missing_image = checksum_image_manifest(self.ubuntu_checksums_url, UBUNTU_IMAGE_FILE)
        del missing_image["artifact"]["image_file"]
        with self.assertRaisesRegex(ValueError, r"checksums_url \+ image_file"):
            self.load_fixture(missing_image)

        missing_checksums = checksum_image_manifest(self.ubuntu_checksums_url, UBUNTU_IMAGE_FILE)
        del missing_checksums["artifact"]["checksums_url"]
        with self.assertRaisesRegex(ValueError, r"checksums_url \+ image_file"):
            self.load_fixture(missing_checksums)

        neither = checksum_image_manifest(self.ubuntu_checksums_url, UBUNTU_IMAGE_FILE)
        del neither["artifact"]["checksums_url"]
        del neither["artifact"]["image_file"]
        with self.assertRaisesRegex(ValueError, "either index_url"):
            self.load_fixture(neither)

    def test_checksum_alg_validation(self):
        for alg in ("sha256", "sha512"):
            with self.subTest(alg=alg):
                loaded = self.load_fixture(checksum_image_manifest(
                    self.ubuntu_checksums_url, UBUNTU_IMAGE_FILE, checksum_alg=alg))
                self.assertEqual(loaded["artifact"]["checksum_alg"], alg)
        for alg in ("sha1", "", None, 256):
            with self.subTest(alg=alg):
                manifest = checksum_image_manifest(self.ubuntu_checksums_url, UBUNTU_IMAGE_FILE)
                manifest["artifact"]["checksum_alg"] = alg
                with self.assertRaises(ValueError):
                    self.load_fixture(manifest)

    def test_image_file_must_be_plain_filename(self):
        for bad in ("../image.qcow2", "images/image.qcow2", "", ".", "..", 3, None):
            with self.subTest(bad=bad):
                manifest = checksum_image_manifest(self.ubuntu_checksums_url, bad)
                with self.assertRaises(ValueError):
                    self.load_fixture(manifest)


class PersonalizeSchemaTests(unittest.TestCase):
    def load_with_personalize_value(self, key, value):
        manifest = yaml.safe_load((ROOT / "manifests" / "omarchy-4.5.yml").read_text())
        manifest["personalize"][key] = value
        path = write_temp(manifest)
        try:
            return rp.load_manifest(path)
        finally:
            path.unlink()

    def test_valid_m2_personalize_values(self):
        cases = {
            "rootfs": ("btrfs", "ext4"),
            "network": ("networkmanager", "systemd-networkd", "netplan", "none"),
            "bios_boot": ("limine", "image-native", "none", None),
            "connectivity_host": ("archlinux.org", "host-1.example.com"),
        }
        for key, values in cases.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    loaded = self.load_with_personalize_value(key, value)
                    self.assertEqual(loaded["personalize"][key], value)

    def test_invalid_m2_personalize_values(self):
        cases = {
            "rootfs": ("zfs", "", None, 1),
            "network": ("dhcp", "", None, 1),
            "bios_boot": ("grub", "", 1),
            "connectivity_host": ("bad host", "bad;host", "", "under_score", None, 3),
        }
        for key, values in cases.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    with self.assertRaises(ValueError):
                        self.load_with_personalize_value(key, value)

    def test_m2_personalize_keys_may_be_absent(self):
        manifest = yaml.safe_load((ROOT / "manifests" / "omarchy-4.5.yml").read_text())
        for key in ("rootfs", "connectivity_host", "network", "bios_boot"):
            manifest["personalize"].pop(key, None)
        path = write_temp(manifest)
        try:
            loaded = rp.load_manifest(path)
        finally:
            path.unlink()
        for key in ("rootfs", "connectivity_host", "network", "bios_boot"):
            self.assertNotIn(key, loaded["personalize"])


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.manifest = rp.load_manifest(ROOT / "manifests" / "omarchy-4.5.yml")
        self.facts = rp.parse_facts(FACTS_TEXT)

    def test_resolve_offline_index(self):
        path = write_temp(json.dumps(INDEX_JSON), suffix=".json")
        try:
            art = rp.resolve_artifact(self.manifest, index_file=str(path), fetch=False)
        finally:
            path.unlink()
        self.assertEqual(art["kind"], "disk-image")
        self.assertEqual(art["source_index"], self.manifest["artifact"]["index_url"])
        self.assertTrue(art["url"].endswith(".qcow2"))
        self.assertRegex(art["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(art["checksum_alg"], "sha256")
        self.assertEqual(art["checksum"], art["sha256"])
        self.assertTrue(art["unpacked_url"].endswith("/unpacked/"))

    def test_plan_ip_and_approval_binding(self):
        plan = rp.build_plan(self.facts, self.manifest, artifact_fixture())
        self.assertEqual(plan["host"], "testhost")
        self.assertRegex(plan["approval"], r"^testhost:omarchy:4\.5\.0:[0-9a-f]{16}$")
        self.assertEqual(rp.approval_token(plan), plan["approval"])
        self.assertEqual(
            plan["ip_cmdline"],
            "ip=192.0.2.10::192.0.2.1:255.255.255.0:testhost:ens18:off",
        )
        mutations = [
            dict(plan, host="otherhost"),
            dict(plan, manifest=dict(plan["manifest"], name="otheros")),
            dict(plan, manifest=dict(plan["manifest"], version="0.0")),
            dict(plan, fingerprint="0" * 16),
        ]
        for changed in mutations:
            self.assertNotEqual(rp.approval_token(changed), plan["approval"])

    def test_build_plan_normalizes_and_carries_accepted_risks(self):
        facts = dict(self.facts, disk_driver="nvme")
        plan = rp.build_plan(facts, self.manifest, artifact_fixture(),
                             accepted_risks=[" drivers,", "drivers"])
        self.assertEqual(plan["accepted_risks"], ["drivers"])
        drivers = {p["name"]: p for p in plan["envelope"]}["drivers"]
        self.assertEqual(drivers["status"], "warn")
        self.assertIn("risk accepted via --accept-risk drivers", drivers["note"])

    def test_build_plan_uefi_secure_boot_disabled_passes_without_risk_override(self):
        uefi_facts = dict(self.facts, firmware="uefi", secure_boot="disabled")
        plan = rp.build_plan(uefi_facts, self.manifest, artifact_fixture())
        self.assertEqual(plan["accepted_risks"], [])
        firmware = {p["name"]: p for p in plan["envelope"]}["firmware"]
        self.assertEqual(firmware["status"], "pass")
        self.assertEqual(firmware["note"], "UEFI (Secure Boot disabled) — drill-proven path")

    def test_build_plan_uefi_secure_boot_enabled_fails_closed(self):
        uefi_facts = dict(self.facts, firmware="uefi", secure_boot="enabled")
        plan = rp.build_plan(uefi_facts, self.manifest, artifact_fixture())
        firmware = {p["name"]: p for p in plan["envelope"]}["firmware"]
        self.assertEqual(firmware["status"], "fail")
        self.assertEqual(
            firmware["note"],
            "UEFI Secure Boot is enabled — disable Secure Boot in your provider or "
            "firmware settings before running bootie",
        )

    def test_plan_cli_passes_uefi_secure_boot_disabled_without_risk_flag(self):
        facts_text = FACTS_TEXT.replace("firmware=bios", "firmware=uefi").replace(
            "secure_boot=na", "secure_boot=disabled")
        facts_path = write_temp(facts_text, suffix=".facts")
        index_path = write_temp(json.dumps(INDEX_JSON), suffix=".json")
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err):
                rc = rp.main([
                    "plan",
                    "--manifest", str(ROOT / "manifests" / "omarchy-4.5.yml"),
                    "--facts", str(facts_path),
                    "--index-file", str(index_path),
                    "--no-fetch",
                ])
        finally:
            facts_path.unlink()
            index_path.unlink()
        self.assertEqual(rc, 0, err.getvalue())
        plan = json.loads(out.getvalue())
        self.assertEqual(plan["accepted_risks"], [])
        firmware = {p["name"]: p for p in plan["envelope"]}["firmware"]
        self.assertEqual(firmware["status"], "pass")

    def test_plan_cli_rejects_invalid_accept_risk_cleanly(self):
        facts_path = write_temp(FACTS_TEXT, suffix=".facts")
        index_path = write_temp(json.dumps(INDEX_JSON), suffix=".json")
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err):
                rc = rp.main([
                    "plan",
                    "--manifest", str(ROOT / "manifests" / "omarchy-4.5.yml"),
                    "--facts", str(facts_path),
                    "--index-file", str(index_path),
                    "--no-fetch",
                    "--accept-risk", "bogus",
                ])
        finally:
            facts_path.unlink()
            index_path.unlink()
        self.assertEqual(rc, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("invalid --accept-risk", err.getvalue())
        self.assertIn("unknown risk class(es): bogus", err.getvalue())
        self.assertIn("allowed: drivers", err.getvalue())

    def test_plan_cli_accepts_comma_separated_documented_risk(self):
        facts_text = FACTS_TEXT.replace("disk_driver=virtio-pci", "disk_driver=nvme")
        facts_path = write_temp(facts_text, suffix=".facts")
        index_path = write_temp(json.dumps(INDEX_JSON), suffix=".json")
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err):
                rc = rp.main([
                    "plan",
                    "--manifest", str(ROOT / "manifests" / "omarchy-4.5.yml"),
                    "--facts", str(facts_path),
                    "--index-file", str(index_path),
                    "--no-fetch",
                    "--accept-risk", "drivers,drivers",
                ])
        finally:
            facts_path.unlink()
            index_path.unlink()
        self.assertEqual(rc, 0, err.getvalue())
        plan = json.loads(out.getvalue())
        self.assertEqual(plan["accepted_risks"], ["drivers"])
        drivers = {p["name"]: p for p in plan["envelope"]}["drivers"]
        self.assertEqual(drivers["status"], "warn")

    def test_fit_blockers(self):
        small = dict(self.facts, mem_mib="512")
        plan = rp.build_plan(small, self.manifest, artifact_fixture())
        plan["artifact_requires"] = self.manifest["artifact"].get("requires", {})
        self.assertTrue(any("RAM" in i for i in rp.fit_issues(plan)))

        # Nominal 2048 MiB KVM guests expose ~1974 MiB MemTotal after kernel/firmware reservation.
        nominal_2g = dict(self.facts, mem_mib="1974")
        plan = rp.build_plan(nominal_2g, self.manifest, artifact_fixture())
        plan["artifact_requires"] = self.manifest["artifact"].get("requires", {})
        self.assertFalse(any("RAM" in i for i in rp.fit_issues(plan)))

        # Nominal 1024 MiB guests expose ~950-980 MiB MemTotal.
        debian = rp.load_manifest(ROOT / "manifests" / "debian-13.yml")
        nominal_1g = dict(self.facts, mem_mib="950")
        plan = rp.build_plan(nominal_1g, debian, artifact_fixture())
        self.assertFalse(any("RAM" in i for i in rp.fit_issues(plan)))

        wrong_arch = dict(self.facts, arch="aarch64")
        plan = rp.build_plan(wrong_arch, self.manifest, artifact_fixture())
        self.assertTrue(any("arch" in i for i in rp.fit_issues(plan)))

    def test_plan_cli_handles_network_error_without_traceback(self):
        import urllib.error
        from unittest import mock

        facts_path = write_temp(FACTS_TEXT, suffix=".facts")
        out, err = io.StringIO(), io.StringIO()
        try:
            with mock.patch.object(rp, "_fetch", side_effect=urllib.error.URLError("Network is unreachable")):
                with redirect_stdout(out), redirect_stderr(err):
                    rc = rp.main([
                        "plan",
                        "--manifest", str(ROOT / "manifests" / "omarchy-4.5.yml"),
                        "--facts", str(facts_path),
                    ])
        finally:
            facts_path.unlink()
        self.assertEqual(rc, 1)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("preflight error:", err.getvalue())
        self.assertIn("Network is unreachable", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())

    def test_netboot_resolution_is_explicitly_fail_closed(self):
        path = write_temp(netboot_manifest_fixture())
        try:
            manifest = rp.load_manifest(path)
        finally:
            path.unlink()
        art = rp.resolve_artifact(manifest, fetch=False)
        self.assertEqual(art["kind"], "netboot-installer")
        self.assertIn("netboot/debian-installer/amd64/linux", art["kernel_url"])
        plan = rp.build_plan(self.facts, manifest, art)
        self.assertTrue(any("not implemented" in i for i in rp.fit_issues(plan)))

    def test_netmask(self):
        self.assertEqual(rp._netmask_of("26"), "255.255.255.192")
        self.assertEqual(rp._netmask_of("24"), "255.255.255.0")
        self.assertEqual(rp._netmask_of("0"), "0.0.0.0")
        self.assertEqual(rp._netmask_of("32"), "255.255.255.255")
        with self.assertRaises(ValueError):
            rp._netmask_of("33")


if __name__ == "__main__":
    unittest.main()

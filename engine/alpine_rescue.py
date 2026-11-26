#!/usr/bin/env python3
"""Offline assembly and explicit host handoff for Alpine rescue."""
import fcntl
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys

ISO_URL = ("https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/"
           "alpine-virt-3.24.4-x86_64.iso")
ISO_SIZE = 70254592
ISO_SHA256 = "157d353f8e54252cad2d9812a0d56bb7fa2231fc154a110e1d180d7480ef8b4f"
MIB = 1024 ** 2


def fit_issues(facts):
    issues = []
    if facts["arch"] != "x86_64" or facts.get("virt") not in {"vm:kvm", "vm:qemu"}:
        issues.append("Alpine rescue requires an x86_64 KVM/QEMU guest")
    if int(facts["mem_mib"]) < 1536:
        issues.append("Alpine rescue requires at least 1536 MiB MemTotal")
    if (facts.get("disk_count") != "1" or facts.get("root_stack") != "simple"
            or not re.fullmatch(r"/dev/vd[a-z]+", facts["disk_path"])
            or facts.get("disk_driver") != "virtio_blk"
            or facts.get("net_driver") != "virtio_net"):
        issues.append("Alpine rescue requires one simple virtio-blk disk and virtio-net")
    try:
        address = ipaddress.IPv4Interface(facts["ipv4_addr"])
        gateway = ipaddress.IPv4Address(facts["ipv4_gateway"])
        if (facts.get("ipv4_route_shape") != "simple" or address.network.prefixlen > 30
                or gateway not in address.network
                or gateway in {address.ip, address.network.network_address,
                               address.network.broadcast_address}
                or address.ip in {address.network.network_address,
                                  address.network.broadcast_address}
                or any(ip.is_loopback or ip.is_link_local or ip.is_multicast
                       or ip.is_unspecified for ip in (address.ip, gateway))
                or not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", facts["net_mac"])):
            raise ValueError
    except (KeyError, ValueError):
        issues.append("Alpine rescue requires simple IPv4 with an on-subnet gateway and NIC MAC")
    return issues


def run(*args):
    subprocess.run(args, check=True)


def network_precheck(facts):
    rules = json.loads(subprocess.check_output(("ip", "-j", "-4", "rule", "show")))
    if [(rule.get("priority"), rule.get("table")) for rule in rules] != [
        (0, "local"), (32766, "main"), (32767, "default")
    ] or any(rule.get("src") != "all" or set(rule) - {"priority", "table", "src", "protocol"}
             for rule in rules):
        raise ValueError("Alpine rescue does not support IPv4 policy routing")
    interfaces = json.loads(subprocess.check_output(
        ("ip", "-j", "-4", "addr", "show", "dev", facts["net_if"], "scope", "global")))
    addresses = [f"{address['local']}/{address['prefixlen']}" for interface in interfaces
                 for address in interface.get("addr_info", [])]
    if addresses != [facts["ipv4_addr"]]:
        raise ValueError("Alpine rescue requires exactly one global IPv4 address on the default NIC")
    if Path("/sys/class/net", facts["net_if"], "addr_assign_type").read_text().strip() != "0":
        raise ValueError("Alpine rescue requires the NIC hardware MAC")


def precheck(work, console, *, staging=True):
    if not Path("/run/systemd/system").is_dir():
        raise ValueError("Alpine rescue requires a systemd source host")
    if not Path("/dev", console).is_char_device():
        raise ValueError(f"source console /dev/{console} is unavailable")
    for name in ("kexec_load_disabled", "kexec_load_limit_reboot", "kexec_loaded"):
        path = Path("/sys/kernel/kexec_loaded") if name == "kexec_loaded" else Path("/proc/sys/kernel", name)
        if name == "kexec_load_limit_reboot" and not path.exists():
            continue
        expected = "-1" if name == "kexec_load_limit_reboot" else "0"
        if path.read_text().strip() != expected:
            raise ValueError(f"{name} must be {expected} for an unloadable handoff")
    facts = json.loads((work / "plan.json").read_text())["facts"]
    network_precheck(facts)
    lockdown = Path("/sys/kernel/security/lockdown")
    if lockdown.exists() and "[none]" not in lockdown.read_text().split():
        raise ValueError("source kernel lockdown is active")
    status = Path("/proc/self/status").read_text()
    capabilities = re.search(r"^CapEff:\s*([0-9a-f]+)$", status, re.MULTILINE)
    if not capabilities or not int(capabilities[1], 16) & (1 << 22):
        raise ValueError("source process lacks CAP_SYS_BOOT")
    config = Path("/proc/config.gz")
    if config.exists() and "CONFIG_KEXEC_FILE=y" not in gzip.decompress(config.read_bytes()).decode().splitlines():
        raise ValueError("source kernel lacks CONFIG_KEXEC_FILE")
    available = next((line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                      if line.startswith("MemAvailable:")), "0")
    if int(available) < 512 * 1024:
        raise ValueError("Alpine rescue needs 512 MiB available RAM")
    if staging and shutil.disk_usage(work).free < 384 * MIB:
        raise ValueError("Alpine rescue needs 384 MiB free staging space")


def append_cpio(output, entries):
    """Write a root-owned newc archive for concatenation to Alpine's initramfs."""
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as archive:
        for inode, (name, mode, data) in enumerate(
                [*entries, ("TRAILER!!!", 0, b"")], start=1):
            name = name.encode() + b"\0"
            fields = (inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0)
            archive.write(b"070701" + "".join(f"{value:08x}" for value in fields).encode())
            archive.write(name)
            archive.write(b"\0" * (-(110 + len(name)) % 4))
            archive.write(data)
            archive.write(b"\0" * (-len(data) % 4))


def assemble(work, console, console_only):
    plan = json.loads((work / "plan.json").read_text())
    facts = plan["facts"]
    keys = b"" if console_only else (work / "keys").read_bytes()
    if not console_only and not keys:
        raise ValueError("SSH requires at least one authorized key")
    if len(keys) > 128 * 1024:
        raise ValueError("Alpine rescue keys exceed 128 KiB")
    iso = work / "alpine.iso"
    run("curl", "--disable", "--fail", "--silent", "--show-error", "--proto", "=https",
        "--connect-timeout", "15", "--max-time", "180", "--max-filesize", str(ISO_SIZE),
        "--output", str(iso), ISO_URL)
    if iso.stat().st_size != ISO_SIZE or hashlib.sha256(iso.read_bytes()).hexdigest() != ISO_SHA256:
        raise ValueError("Alpine virt ISO failed pinned size or SHA-256 verification")
    image = work / "image"
    image.mkdir()
    paths = ["boot/vmlinuz-virt", "boot/initramfs-virt", "boot/modloop-virt"]
    if keys:
        paths.append("apks/x86_64")
    try:
        run("bsdtar", "-xf", str(iso), "-C", str(image), *paths)
    finally:
        # ISO directories may be read-only, including after partial extraction.
        for directory, _, _ in os.walk(image):
            Path(directory).chmod(0o700)
    iso.unlink()
    source = Path(__file__).resolve().parent
    config = "\n".join((console, facts["disk_path"], facts["net_mac"],
                        facts["ipv4_addr"], facts["ipv4_gateway"])) + "\n"
    prefix = "bootie-rescue/"
    entries = [
        ("bootie-rescue", 0o40700, b""),
        (prefix + "settings", 0o100600, config.encode()),
        (prefix + "keys", 0o100600, keys),
        (prefix + "modloop", 0o100400, (image / paths[2]).read_bytes()),
        (prefix + "inspect", 0o100755, (source / "alpine-rescue-inspect.sh").read_bytes()),
        ("init", 0o100755, (source / "alpine-rescue-init.sh").read_bytes()),
    ]
    if keys:
        entries.append((prefix + "repo", 0o40700, b""))
        entries.append((prefix + "repo/x86_64", 0o40700, b""))
        for package in sorted((image / "apks/x86_64").iterdir()):
            if package.is_file():
                entries.append((prefix + "repo/x86_64/" + package.name,
                                0o100400, package.read_bytes()))
    shutil.copyfile(image / paths[0], work / "vmlinuz")
    with (image / paths[1]).open("rb") as stock, (work / "initrd").open("wb") as output:
        shutil.copyfileobj(stock, output)
        output.write(b"\0" * (-output.tell() % 4))
        append_cpio(output, entries)
    shutil.rmtree(image)


def handoff(work, console):
    # Serialize Bootie callers without claiming ownership of any preexisting load.
    fd = os.open("/run/lock/bootie-alpine.lock", os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR, 0o600)
    with os.fdopen(fd, "wb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        precheck(work, console, staging=False)
        target = "ttyS0,115200" if console == "ttyS0" else "tty0"
        # A terminal hangup during the load must not strand an armed image.
        for interruption in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            signal.signal(interruption, signal.SIG_IGN)
        run("kexec", "-s", "-l", str(work / "vmlinuz"),
            f"--initrd={work / 'initrd'}",
            f"--append=rdinit=/init console={target} raid=noautodetect")
        try:
            run("systemctl", "kexec")
        except (OSError, subprocess.CalledProcessError):
            try:
                run("kexec", "-s", "-u")
            except (OSError, subprocess.CalledProcessError) as exc:
                raise ValueError("handoff and unload failed; a rescue image may still be armed") from exc
            raise


def main():
    action, directory, console = sys.argv[1:4]
    work = Path(directory)
    try:
        if action == "precheck":
            precheck(work, console)
        elif action == "assemble":
            assemble(work, console, bool(sys.argv[4]))
        elif action == "handoff":
            handoff(work, console)
        else:
            raise ValueError("unknown Alpine rescue action")
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Alpine rescue: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

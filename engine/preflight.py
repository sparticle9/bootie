#!/usr/bin/env python3
"""preflight.py — build the reviewed bootie reinstall plan.

Reads the target's facts.sh output and a distribution manifest,
resolves the upstream artifact (from the distro's own index — never from us),
and emits a plan JSON with a machine fingerprint. The plan is what the
operator reviews; the write phase re-derives the fingerprint on the target
and refuses on any mismatch.

Nothing here touches the target. Fetching goes to the upstream index only,
or to a local --index-file for rehearsal/tests.
"""
import argparse
import hashlib
import json
import re
import shlex
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

try:
    import yaml
except ModuleNotFoundError:           # controller python may lack pyyaml;
    yaml = None                       # manifests-as-JSON work without it

FP_KEYS = [
    "arch", "disk_model", "disk_partuuids", "disk_path", "disk_serial",
    "disk_size_bytes", "disk_wwn", "firmware", "net_mac",
]
REQUIRED_FACTS = FP_KEYS + ["hostname", "net_if", "ipv4_addr", "ipv4_gateway", "mem_mib"]
ALLOWED_RISK_CLASSES = {"drivers"}
RESCUE_PACKAGES = [
    "busybox-static", "dropbear-initramfs", "e2fsprogs", "btrfs-progs",
    "dosfstools", "fdisk", "gdisk", "curl",
]


def parse_facts(text):
    facts = {}
    for line in text.splitlines():
        line = line.strip()
        if line and "=" in line:
            k, v = line.split("=", 1)
            facts[k.strip()] = v.strip()
    missing = [k for k in REQUIRED_FACTS if not facts.get(k)]
    if missing:
        raise ValueError(f"facts missing: {', '.join(missing)}")
    if not re.match(r"^\d+$", facts["disk_size_bytes"]):
        raise ValueError("disk_size_bytes not numeric")
    if "/" not in facts.get("ipv4_addr", ""):
        raise ValueError("ipv4_addr must be CIDR (addr/prefix)")
    return facts


def fingerprint_lines(facts):
    return "".join(f"{k}={facts[k]}\n" for k in FP_KEYS)


def fingerprint(facts):
    return hashlib.sha256(fingerprint_lines(facts).encode()).hexdigest()[:16]


def validate_remove_webapps(entries):
    if entries is None:
        return
    if not isinstance(entries, list):
        raise ValueError("personalize.remove_webapps must be a list")
    for i, app in enumerate(entries):
        if (not isinstance(app, str) or not app or app in (".", "..")
                or "/" in app):
            raise ValueError(
                f"personalize.remove_webapps[{i}] must be a plain desktop-file basename")


def validate_personalize_schema(personalize):
    if "rootfs" in personalize and personalize["rootfs"] not in ("btrfs", "ext4"):
        raise ValueError("personalize.rootfs must be btrfs or ext4")
    if ("network" in personalize and personalize["network"] not in
            ("networkmanager", "systemd-networkd", "netplan", "none")):
        raise ValueError(
            "personalize.network must be networkmanager, systemd-networkd, netplan, or none")
    if ("bios_boot" in personalize and personalize["bios_boot"] not in
            ("limine", "image-native", "none", None)):
        raise ValueError("personalize.bios_boot must be limine, image-native, none, or null")
    if "connectivity_host" in personalize:
        host = personalize["connectivity_host"]
        if not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
            raise ValueError(
                "personalize.connectivity_host must be a hostname using only letters, digits, dots, and hyphens")


def load_manifest(path):
    path = Path(path)
    text = path.read_text()
    if path.suffix == ".json" or text.lstrip().startswith("{"):
        m = json.loads(text)
    else:
        if yaml is None:
            raise SystemExit("pyyaml missing and manifest is not JSON")
        m = yaml.safe_load(text)
    if m.get("manifest_version") not in (1, 2):
        raise ValueError("unsupported manifest_version")
    if m["manifest_version"] == 2:
        allowed = {"manifest_version", "name", "version", "channel", "arch",
                   "artifact", "target", "liveenv", "write", "personalize",
                   "firstboot", "cloud_config", "postinstall"}
        bad = [k for k in m if k not in allowed and not str(k).startswith("x-")]
        if bad:
            raise ValueError(f"manifest: unknown top-level keys {bad}")
        personalize = m.get("personalize") or {}
        if not isinstance(personalize, dict):
            raise ValueError("personalize must be a mapping")
        validate_remove_webapps(personalize.get("remove_webapps"))
    for key in ("name", "version", "arch", "artifact", "target", "liveenv", "write"):
        if key not in m:
            raise ValueError(f"manifest missing section: {key}")
    extension_keys = {
        "target": {"disk_min_size_gib", "memory_min_mib", "firmware"},
        "liveenv": {"kind", "mode", "hold", "packages", "kernel_cmdline", "ssh_port"},
        "write": {"method", "disk_guard", "scrub_after"},
        "personalize": {"network", "bios_boot", "ssh_host_keys", "root_subvol",
                        "esp_subvol", "rootfs", "connectivity_host",
                        "remove_webapps", "drop_pkgs", "late_commands"},
        "firstboot": {"grow_partition", "btrfs_resize"},
    }
    strict_extensions = m["manifest_version"] == 2
    for section, allowed in extension_keys.items():
        value = m.get(section) or {}
        if not isinstance(value, dict):
            raise ValueError(f"{section} must be a mapping")
        if strict_extensions:
            unknown = _unknown_keys(value, allowed, section)
            if unknown:
                raise ValueError(f"{section}: unknown keys {unknown}")
    validate_personalize_schema(m.get("personalize") or {})
    artifact = m["artifact"]
    if not isinstance(artifact, dict):
        raise ValueError("artifact must be a mapping")
    artifact_kind = artifact.get("kind")
    artifact_allowed = {
        "disk-image": {"kind", "index_url", "checksums_url", "image_file",
                       "checksum_alg", "requires"},
        "netboot-installer": {"kind", "base_url", "checksums", "files"},
    }.get(artifact_kind, {"kind"})
    if strict_extensions:
        unknown = _unknown_keys(artifact, artifact_allowed, "artifact")
        if unknown:
            raise ValueError(f"artifact: unknown keys {unknown}")
    if artifact_kind == "disk-image":
        index_key = "index_url" in artifact
        checksums_key = "checksums_url" in artifact
        image_key = "image_file" in artifact
        has_index = bool(artifact.get("index_url"))
        has_checksums = bool(artifact.get("checksums_url"))
        has_image_file = bool(artifact.get("image_file"))
        if index_key and (checksums_key or image_key):
            raise ValueError(
                "artifact.disk-image: index_url conflicts with checksums_url/image_file")
        if not has_index and not (has_checksums and has_image_file):
            raise ValueError(
                "artifact.disk-image requires either index_url or checksums_url + image_file")
        if has_checksums and not isinstance(artifact["checksums_url"], str):
            raise ValueError("artifact.checksums_url must be a string")
        alg = artifact.get("checksum_alg", "sha256")
        if alg not in ("sha256", "sha512"):
            raise ValueError("artifact.checksum_alg must be sha256 or sha512")
        if "image_file" in artifact:
            image_file = artifact["image_file"]
            if (not isinstance(image_file, str) or not image_file
                    or "/" in image_file or image_file in (".", "..")):
                raise ValueError("artifact.image_file must be a plain filename")
    liveenv = m["liveenv"]
    if not isinstance(liveenv, dict):
        raise ValueError("liveenv must be a mapping")
    mode = liveenv.get("mode")
    hold = liveenv.get("hold")
    if mode is not None and mode not in ("hold", "auto"):
        raise ValueError("liveenv.mode must be hold or auto")
    if hold is not None and not isinstance(hold, bool):
        raise ValueError("liveenv.hold must be a boolean")
    legacy_mode = "hold" if hold is not False else "auto"
    if mode is not None and hold is not None and mode != legacy_mode:
        raise ValueError("liveenv.mode conflicts with legacy liveenv.hold")
    liveenv["mode"] = mode or legacy_mode
    kind = m["artifact"].get("kind")
    if kind not in ("disk-image", "netboot-installer"):
        raise ValueError(f"unsupported artifact kind: {kind}")
    postinstall = m.get("postinstall") or {}
    if not isinstance(postinstall, dict):
        raise ValueError("postinstall must be a mapping")
    allowed_postinstall = {"managed_user", "boot_target", "install_om_desktop"}
    unknown_postinstall = sorted(_unknown_keys(postinstall, allowed_postinstall, "postinstall"))
    if unknown_postinstall:
        raise ValueError(f"postinstall unknown keys: {', '.join(unknown_postinstall)}")
    boot_target = postinstall.get("boot_target", "desktop")
    if boot_target not in ("console", "desktop"):
        raise ValueError("postinstall.boot_target must be console or desktop")
    postinstall["boot_target"] = boot_target
    install_om_desktop = postinstall.get("install_om_desktop", False)
    if not isinstance(install_om_desktop, bool):
        raise ValueError("postinstall.install_om_desktop must be a boolean")
    postinstall["install_om_desktop"] = install_om_desktop
    _check_no_hosted_artifacts(m)
    return m


def _check_no_hosted_artifacts(node, path=""):
    """Guardrail: manifests may only reference upstream release sites.

    Any URL in a manifest must be https and must not point at object storage
    or any domain that could be ours — the project never hosts images.
    """
    bad_hosts = ("r2.dev", "cloudflarestorage", "amazonaws.com", "storage.googleapis",
                 "digitaloceanspaces", "blob.core.windows.net")
    if isinstance(node, dict):
        for k, v in node.items():
            _check_no_hosted_artifacts(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _check_no_hosted_artifacts(v, f"{path}[{i}]")
    elif isinstance(node, str) and node.startswith("http"):
        parsed = urlparse(node)
        debian_http_mirror = parsed.scheme == "http" and parsed.hostname == "deb.debian.org"
        if parsed.scheme != "https" and not debian_http_mirror:
            raise ValueError(f"non-https artifact url at {path}: {node}")
        if any(h in node for h in bad_hosts):
            raise ValueError(f"manifest references a hosted/self artifact: {node}")


def _fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "bootie/0.1"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def parse_checksums_index(text, image_file, alg="sha256"):
    """Resolve one image entry in a GNU coreutils checksum index."""
    digest_len = {"sha256": 64, "sha512": 128}.get(alg)
    if digest_len is None:
        raise ValueError("checksum algorithm must be sha256 or sha512")
    if (not isinstance(image_file, str) or not image_file
            or "/" in image_file or image_file in (".", "..")):
        raise ValueError("image_file must be a plain filename")
    digest_re = re.compile(rf"[0-9a-f]{{{digest_len}}}")
    for lineno, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        match = re.match(r"^(\S+)\s+\*?(.+)$", line)
        if not match:
            raise ValueError(f"checksums line {lineno} malformed")
        digest, filename = match.groups()
        if not digest_re.fullmatch(digest):
            raise ValueError(f"checksums line {lineno}: malformed {alg} digest")
        if filename.startswith("./"):
            filename = filename[2:]
        if filename == image_file:
            return digest
    raise ValueError(f"checksums index missing {image_file}")


def validate_mirror_url(url):
    """Validate an operator-supplied HTTPS artifact mirror base URL."""
    if not isinstance(url, str):
        raise ValueError("--mirror must be a valid https URL with a hostname")
    parsed = urlparse(url)
    if (parsed.scheme != "https" or not parsed.hostname
            or any(ch.isspace() for ch in url)):
        raise ValueError("--mirror must be a valid https URL with a hostname")


def resolve_artifact(manifest, index_file=None, fetch=True, mirror=None):
    art = manifest["artifact"]
    if art["kind"] == "disk-image":
        if art.get("index_url"):
            if mirror is not None:
                raise ValueError(
                    "--mirror is only supported for checksum-indexed release manifests "
                    "(Debian/Ubuntu), not JSON-index manifests")
            # Channel guardrail: the manifest's `channel` must appear as a path
            # segment of index_url — nightly.omarchy.org serves every channel;
            # the /stable/ component is what actually pins stable.
            channel = manifest.get("channel")
            if channel and f"/{channel}/" not in urlparse(art["index_url"]).path:
                raise ValueError(
                    f"index_url does not resolve inside declared channel '{channel}'")
            if index_file:
                index = json.loads(Path(index_file).read_text())
            elif fetch:
                index = json.loads(_fetch(art["index_url"]))
            else:
                raise ValueError("disk-image needs --index-file or --fetch")
            vm = index.get("vm") or {}
            out = {
                "kind": "disk-image",
                "index_version": index.get("version"),
                "source_index": art["index_url"],
                "url": vm.get("url"),
                "sha256": vm.get("sha256"),
                "size_bytes": vm.get("size"),
                "unpacked_url": vm.get("unpacked"),
                "unpacked_files": vm.get("unpacked_files", []),
                "image_user": vm.get("user"),
            }
            for k in ("url", "sha256", "unpacked_url"):
                if not out[k]:
                    raise ValueError(f"index missing vm field for {k}")
            if not re.match(r"^[0-9a-f]{64}$", out["sha256"]):
                raise ValueError("index vm.sha256 malformed")
            out["checksum_alg"] = "sha256"
            out["checksum"] = out["sha256"]
            return out

        alg = art.get("checksum_alg", "sha256")
        if mirror is not None:
            validate_mirror_url(mirror)
            mirror_base = mirror.rstrip("/")
            checksums_basename = art["checksums_url"].rsplit("/", 1)[-1]
            effective_checksums_url = f"{mirror_base}/{checksums_basename}"
            image_url = f"{mirror_base}/{art['image_file']}"
        else:
            mirror_base = None
            effective_checksums_url = art["checksums_url"]
            image_url = art["checksums_url"].rsplit("/", 1)[0] + "/" + art["image_file"]
        if index_file:
            checksums_text = Path(index_file).read_text()
        elif fetch:
            checksums_text = _fetch(effective_checksums_url).decode("utf-8")
        else:
            raise ValueError("disk-image needs --index-file or --fetch")
        digest = parse_checksums_index(checksums_text, art["image_file"], alg=alg)
        out = {
            "kind": "disk-image",
            "source_index": effective_checksums_url,
            "url": image_url,
            "checksum_alg": alg,
            "checksum": digest,
            "sha256": digest if alg == "sha256" else "",
            "unpacked_url": "",
            "image_file": art["image_file"],
        }
        if mirror_base is not None:
            out["mirror_override"] = mirror_base
        return out
    if art["kind"] == "netboot-installer":
        if mirror is not None:
            raise ValueError("--mirror is not supported for netboot-installer manifests")
        base = art["base_url"].rstrip("/")
        files = art["files"]
        return {
            "kind": "netboot-installer",
            "kernel_url": f"{base}/{files['kernel']}",
            "initrd_url": f"{base}/{files['initrd']}",
            "checksums_url": f"{base}/{art['checksums']}",
        }
    raise ValueError("unreachable")


# --- cloud-config (standard ring) validation + transpilation -------------
# The cloud_config subtree is a verbatim cloud-init user-data document.
# The engine reaches the same end state offline (see SCHEMA.md). Unknown
# keys are hard errors — typos must never no-op; x- keys are ignored.
CC_TOP_SUPPORTED = {
    "users", "write_files", "runcmd", "packages", "package_update",
    "hostname", "fqdn", "locale", "timezone",
}
CC_TOP_RECOGNIZED_UNSUPPORTED = {
    "network", "ssh_keys", "mounts", "disk_setup", "ntp",
    "keyboard", "apt", "yum_repos", "snap", "snapshots",
}
CC_USER_KEYS = {
    "name", "groups", "shell", "sudo", "ssh_authorized_keys", "lock_passwd",
    "passwd",
}
CC_FILE_KEYS = {
    "path", "content", "owner", "permissions", "encoding", "append",
}


def _unknown_keys(mapping, allowed, path):
    return [k for k in mapping
            if k not in allowed and not str(k).startswith("x-")]


def validate_cloud_config(cc):
    if not isinstance(cc, dict):
        raise ValueError("cloud_config must be a mapping")
    unknown = _unknown_keys(cc, CC_TOP_SUPPORTED | CC_TOP_RECOGNIZED_UNSUPPORTED,
                            "cloud_config")
    if unknown:
        raise ValueError(f"cloud_config: unknown keys {unknown}")
    unsupported = [k for k in cc if k in CC_TOP_RECOGNIZED_UNSUPPORTED]
    if unsupported:
        raise ValueError(
            f"cloud_config keys not yet supported by this engine: {unsupported} "
            f"(supported: {sorted(CC_TOP_SUPPORTED)})")
    locale = cc.get("locale")
    if locale is not None:
        if not isinstance(locale, str) or not re.fullmatch(r"[A-Za-z0-9_.@-]+", locale):
            raise ValueError(
                "cloud_config.locale must be a non-empty string using only "
                "letters, digits, '_', '.', '@', and '-'")
    timezone = cc.get("timezone")
    if timezone is not None:
        if (not isinstance(timezone, str)
                or not re.fullmatch(r"[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*", timezone)
                or ".." in timezone.split("/")):
            raise ValueError(
                "cloud_config.timezone must be a non-empty zoneinfo path using only "
                "letters, digits, '_', '+', '-', and '/' separators")
    for i, u in enumerate(cc.get("users") or []):
        if not isinstance(u, dict) or not u.get("name"):
            raise ValueError(f"cloud_config.users[{i}]: entry needs a name")
        bad = _unknown_keys(u, CC_USER_KEYS, f"users[{i}]")
        if bad:
            raise ValueError(f"cloud_config.users[{i}]: unknown keys {bad}")
    for i, f in enumerate(cc.get("write_files") or []):
        if not isinstance(f, dict) or not f.get("path"):
            raise ValueError(f"cloud_config.write_files[{i}]: entry needs a path")
        bad = _unknown_keys(f, CC_FILE_KEYS, f"write_files[{i}]")
        if bad:
            raise ValueError(f"cloud_config.write_files[{i}]: unknown keys {bad}")
        enc = f.get("encoding", "plain")
        if enc not in ("plain", "b64", "base64"):
            raise ValueError(
                f"cloud_config.write_files[{i}]: encoding {enc} unsupported "
                "(plain and b64 only)")
        if f.get("append"):
            raise ValueError(
                f"cloud_config.write_files[{i}]: append not supported (offline write)")


def _runcmd_entry_to_script(entry):
    """cloud-init runcmd shape: string → sh -c; list → direct exec argv.

    Both normalize to a shell script body here — list entries get shlex
    quoting so `sh -c` executes the same argv.
    """
    if isinstance(entry, str):
        return entry
    if isinstance(entry, list) and entry and all(isinstance(x, str) for x in entry):
        return shlex.join(entry)
    raise ValueError(f"runcmd entry must be a string or list of strings: {entry!r}")


def transpile_cloud_config(cc):
    """cloud_config → concrete engine ops embedded in the plan."""
    validate_cloud_config(cc)
    out = {"users": [], "files": [], "runcmd": [], "packages": [],
           "package_update": bool(cc.get("package_update")),
           "hostname": cc.get("hostname") or cc.get("fqdn"),
           "locale": cc.get("locale") or "en_US.UTF-8",
           "timezone": cc.get("timezone") or ""}
    for u in cc.get("users") or []:
        groups = u.get("groups") or []
        if isinstance(groups, str):
            groups = [g.strip() for g in groups.split(",") if g.strip()]
        keys = u.get("ssh_authorized_keys") or []
        out["users"].append({
            "name": u["name"],
            "groups": groups,
            "shell": u.get("shell") or "",
            "sudo": u.get("sudo") or "",
            "lock_passwd": bool(u.get("lock_passwd", True)),
            "passwd": u.get("passwd") or "",
            "keys": list(keys),
        })
    import base64
    for f in cc.get("write_files") or []:
        content = f.get("content", "")
        if f.get("encoding") in ("b64", "base64"):
            raw = base64.b64decode(content)
        else:
            raw = content.encode()
        out["files"].append({
            "path": f["path"],
            "owner": f.get("owner") or "root:root",
            "permissions": str(f.get("permissions") or "0644"),
            "content_b64": base64.b64encode(raw).decode(),
        })
    for entry in cc.get("runcmd") or []:
        out["runcmd"].append(_runcmd_entry_to_script(entry))
    out["packages"] = list(cc.get("packages") or [])
    return out


def _synthesize_v1_cloud_ops(manifest):
    """v1 manifests carry no cloud_config — map their keys onto the same
    engine ops so the live env has exactly one execution path."""
    pers = manifest.get("personalize", {})
    user = pers.get("ssh_user")
    ops = {"users": [], "files": [], "runcmd": [], "packages": [],
           "package_update": False, "hostname": None,
           "locale": "en_US.UTF-8", "timezone": ""}
    if user:
        ops["users"].append({"name": user, "groups": [], "shell": "",
                             "sudo": "", "lock_passwd": False, "keys": []})
    for fb in (manifest.get("firstboot", {}) or {}).get("run") or []:
        run = fb.get("run", "")
        as_user = fb.get("as_user") or "root"
        if as_user != "root":
            run = f"runuser -l {shlex.quote(as_user)} -c {shlex.quote(run)}"
        ops["runcmd"].append(run)
    return ops


def parse_accepted_risks(values):
    """Normalize --accept-risk values into a sorted, deduplicated list."""
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise ValueError("accepted risk classes must be an iterable of strings") from exc

    accepted = set()
    unknown = set()
    for value in iterator:
        if not isinstance(value, str):
            raise ValueError("accepted risk classes must be strings")
        for item in value.split(","):
            item = item.strip()
            if not item:
                continue
            if item in ALLOWED_RISK_CLASSES:
                accepted.add(item)
            else:
                unknown.add(item)
    if unknown:
        raise ValueError(
            f"unknown risk class(es): {', '.join(sorted(unknown))}; "
            f"allowed: {', '.join(sorted(ALLOWED_RISK_CLASSES))}"
        )
    return sorted(accepted)


def build_plan(facts, manifest, artifact, liveenv_overrides=None, accepted_risks=None):
    fp = fingerprint(facts)
    accepted_risks = parse_accepted_risks(accepted_risks)
    plan = {
        "schema": 1,
        "host": facts["hostname"],
        "manifest": {"name": manifest["name"], "version": str(manifest["version"]),
                     "arch": manifest["arch"], "channel": manifest.get("channel")},
        "facts": facts,
        "artifact": artifact,
        "liveenv": manifest["liveenv"],
        "write": manifest["write"],
        "personalize": manifest.get("personalize", {}),
        "firstboot": manifest.get("firstboot", {}),
        "postinstall": manifest.get("postinstall", {}),
        "target_rules": manifest["target"],
        "accepted_risks": accepted_risks,
        "fingerprint": fp,
    }
    if manifest.get("cloud_config"):
        plan["cloud_ops"] = transpile_cloud_config(manifest["cloud_config"])
    else:
        plan["cloud_ops"] = _synthesize_v1_cloud_ops(manifest)
    if liveenv_overrides:
        plan["liveenv"].update(liveenv_overrides)
    plan["ip_cmdline"] = ip_cmdline(facts)
    plan["envelope"] = support_envelope(plan)
    plan["approval"] = approval_token(plan)
    return plan


def build_rescue_plan(facts, accepted_risks=None, backend="debian-initramfs"):
    """Build the offline, non-destructive rescue plan.

    Unlike install planning, rescue planning resolves no OS artifact and makes
    no network calls: every field derives from the supplied facts.
    """
    fp = fingerprint(facts)
    accepted_risks = parse_accepted_risks(accepted_risks)
    plan = {
        "schema": 1,
        "mode": "rescue",
        "host": facts["hostname"],
        "facts": facts,
        "liveenv": {
            "kind": "debian-initramfs",
            "mode": "rescue",
            "packages": list(RESCUE_PACKAGES),
            "kernel_cmdline": "break=mount console=ttyS0,115200 console=tty0",
            "ssh_port": 22,
        },
        "accepted_risks": accepted_risks,
        "fingerprint": fp,
    }
    if backend == "alpine-kexec":
        if accepted_risks:
            raise ValueError("Alpine rescue allows no risk override")
        plan["liveenv"] = {"kind": backend, "mode": "rescue", "ssh_port": 22}
    else:
        plan["ip_cmdline"] = ip_cmdline(facts)
    plan["envelope"] = support_envelope(plan)
    plan["approval"] = approval_token(plan)
    return plan


def approval_token(plan):
    if plan.get("mode") == "rescue":
        if plan.get("liveenv", {}).get("kind") == "alpine-kexec":
            return f"alpine-rescue:{plan['host']}:{plan['fingerprint']}"
        return f"rescue:{plan['host']}"
    m = plan["manifest"]
    return f"{plan['host']}:{m['name']}:{m['version']}:{plan['fingerprint']}"


def _netmask_of(prefix):
    bits = int(prefix)
    if not 0 <= bits <= 32:
        raise ValueError(f"bad prefix length {prefix}")
    v = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    return ".".join(str(v >> s & 0xFF) for s in (24, 16, 8, 0))


def ip_cmdline(facts):
    """Debian initramfs ip= line: static config, no autoconf.

    ip=<client>:<server>:<gw>:<netmask>:<host>:<dev>:<autoconf>
    """
    addr, prefix = facts["ipv4_addr"].split("/")
    return (f"ip={addr}::{facts['ipv4_gateway']}:{_netmask_of(prefix)}:"
            f"{facts['hostname']}:{facts['net_if']}:off")


def support_envelope(plan):
    """Cross-cutting support-envelope probes — the boundaries where VPS
    providers differ. The design goal is progressive compatibility
    expansion: every probe names one portability boundary explicitly and
    fails closed instead of hiding an assumption.

    pass = drill-proven shape. warn = inside only with the operator's
    typed acknowledgment. fail = outside the envelope, refuse.
    """
    probes = []
    f = plan["facts"]

    # virtualization — containers share the host kernel, so bootie cannot
    # control the kernel/initramfs handoff needed for a target-resident reinstall.
    virt = f.get("virt") or "unknown"
    if virt.startswith("container:"):
        probes.append({"name": "virt", "status": "fail",
                       "note": "container virtualization lacks kernel/initramfs control "
                               "and cannot be reinstalled by bootie"})
    elif virt.startswith("vm:") or virt == "none":
        probes.append({"name": "virt", "status": "pass",
                       "note": f"virtualization {virt} — kernel/initramfs control available"})
    else:
        probes.append({"name": "virt", "status": "warn",
                       "note": f"virtualization type '{virt}' is unknown — verify the target "
                               "is a VM or bare metal before approval"})

    # bootloader — the staging path uses GRUB's one-shot boot entry support.
    bootloader = f.get("bootloader") or "unknown"
    alpine = plan.get("liveenv", {}).get("kind") == "alpine-kexec"
    if alpine:
        probes.append({"name": "bootloader", "status": "warn",
                       "note": "experimental kexec handoff; kernel admission checked before shutdown"})
    elif bootloader == "grub":
        probes.append({"name": "bootloader", "status": "pass",
                       "note": "GRUB with grub-reboot — drill-proven staging path"})
    else:
        probes.append({"name": "bootloader", "status": "fail",
                       "note": f"bootloader '{bootloader}' is outside the current support envelope "
                               "(requires GRUB with grub-reboot/grub2-reboot and grub.cfg)"})

    # firmware — BIOS + GRUB and UEFI (Secure Boot disabled) + GRUB are
    # drill-proven. Secure Boot is a hard UEFI prerequisite: enabled or
    # unconfirmed state always fails closed and is never risk-overridable.
    accepted = set(plan.get("accepted_risks") or [])
    firmware = f["firmware"]
    if firmware == "bios":
        probes.append({"name": "firmware", "status": "pass",
                       "note": "BIOS observed" if alpine else "BIOS — drill-proven path"})
    elif firmware == "uefi":
        sb = f.get("secure_boot", "unknown")
        if sb == "enabled":
            probes.append({"name": "firmware", "status": "fail",
                           "note": "UEFI Secure Boot is enabled — disable Secure Boot in your "
                                   "provider or firmware settings before running bootie"})
        elif sb != "disabled":
            probes.append({"name": "firmware", "status": "fail",
                           "note": "UEFI Secure Boot state could not be confirmed disabled "
                                   f"(observed: {sb}) — disable Secure Boot and ensure efivars "
                                   "are readable before running bootie"})
        else:
            probes.append({"name": "firmware", "status": "pass",
                           "note": "UEFI (Secure Boot disabled)" if alpine else
                                   "UEFI (Secure Boot disabled) — drill-proven path"})
    else:
        probes.append({"name": "firmware", "status": "fail",
                       "note": f"firmware '{firmware}' is outside the current support envelope"})

    # network shape — the liveenv reconstructs connectivity from a static
    # ip= cmdline derived from the observed address/gateway. shapes that
    # do not fit that model fail closed.
    addr = f.get("ipv4_addr") or ""
    route_shape = f.get("ipv4_route_shape") or "unknown"
    if not addr:
        probes.append({"name": "network", "status": "fail",
                       "note": "no IPv4 address — the liveenv cannot reconstruct connectivity; "
                               "verify the target network facts before reinstall"})
    elif addr.endswith("/32"):
        probes.append({"name": "network", "status": "fail",
                       "note": "/32 point-to-point addressing requires onlink routes — "
                               "outside the current support envelope"})
    elif not f.get("ipv4_gateway") or route_shape == "no-gateway":
        probes.append({"name": "network", "status": "fail",
                       "note": "no IPv4 default gateway — artifact fetch and firstboot upgrade "
                               "require outbound connectivity"})
    elif route_shape == "onlink":
        probes.append({"name": "network", "status": "fail",
                       "note": "onlink IPv4 default route is outside the current support envelope "
                               "(initramfs ip= supports simple gateway routes only)"})
    elif route_shape == "multi-default":
        probes.append({"name": "network", "status": "fail",
                       "note": "multiple IPv4 default routes detected — policy/multi-interface "
                               "routing is outside the current support envelope"})
    else:
        probes.append({"name": "network", "status": "pass",
                       "note": f"static-or-dhcp-derived {addr} via {f['ipv4_gateway']}"})

    # disk topology — complex root stacks are refused rather than partially
    # written; multiple simple disks still demand extra operator care.
    root_stack = f.get("root_stack", "simple") or "unknown"
    try:
        count = int(f.get("disk_count") or 1)
    except ValueError:
        count = 1
    if root_stack in ("raid", "encrypted", "lvm", "lvm-multi", "dm-other", "unknown"):
        probes.append({"name": "disk-topology", "status": "fail",
                       "note": f"root filesystem uses {root_stack}; RAID, LVM, encrypted root, "
                               "and complex device-mapper layouts are refused to avoid "
                               "partial-disk corruption"})
    elif count > 1:
        probes.append({"name": "disk-topology", "status": "warn",
                       "note": f"{count} disks present — verify the target disk path and "
                               "fingerprint carefully before approval"})
    else:
        probes.append({"name": "disk-topology", "status": "pass",
                       "note": "single-disk simple topology"})

    # driver families — the initramfs stages virtio modules explicitly;
    # other storage/nic drivers are unverified and fail closed unless the
    # operator explicitly accepts the documented recovery risk.
    disk_driver = f.get("disk_driver", "unknown")
    net_driver = f.get("net_driver", "unknown")
    driver_note = f"disk={disk_driver}, net={net_driver}"
    if ("virtio" in disk_driver and "virtio" in net_driver
            and disk_driver != "unknown" and net_driver != "unknown"):
        probes.append({"name": "drivers", "status": "pass",
                       "note": "virtio storage/net — drill-proven"})
    elif "drivers" in accepted:
        probes.append({"name": "drivers", "status": "warn",
                       "note": f"risk accepted via --accept-risk drivers — driver families "
                               f"({driver_note}) are mixed or non-virtio/unknown; the non-virtio "
                               "side is unverified in the liveenv initramfs and requires "
                               "provider console recovery"})
    else:
        probes.append({"name": "drivers", "status": "fail",
                       "note": f"mixed or non-virtio/unknown driver families ({driver_note}) "
                               "are unverified in the liveenv initramfs; failing closed by "
                               "default — re-run with `--accept-risk drivers` only if you have "
                               "provider console/reinstall recovery"})
    return probes


def fit_issues(plan):
    """Blocking mismatches between the approved machine and the manifest.

    The image's virtual size itself is verified at stage time with
    `qemu-img info` over https (cheap header read) — here we check the
    target against the manifest's declared limits.
    """
    issues = []
    f = plan["facts"]
    if plan.get("mode") == "rescue":
        if plan.get("liveenv", {}).get("kind") == "alpine-kexec":
            from alpine_rescue import fit_issues as alpine_fit_issues
            return alpine_fit_issues(f)
        # Rescue carries no target OS image, so artifact/manifest size and arch
        # rules do not apply. The floor is a nominal 512 MiB VPS minus the RAM
        # Linux reserves before MemTotal is exposed.
        if int(f["mem_mib"]) < 448:
            issues.append(
                f"RAM {f['mem_mib']} MiB below 448 MiB rescue floor "
                "(512 MiB nominal minus kernel reservation)"
            )
        return issues

    t = plan["target_rules"]
    artifact_kind = (plan.get("artifact") or {}).get("kind")
    if artifact_kind != "disk-image":
        issues.append(
            f"artifact kind {artifact_kind or '<missing>'} is not implemented by "
            "the current debian-grub-initramfs/qemu-img backend"
        )
    gib = 1024 ** 3
    if int(f["disk_size_bytes"]) < int(t.get("disk_min_size_gib", 0)) * gib:
        issues.append(f"disk {f['disk_path']} below {t['disk_min_size_gib']} GiB")
    req_mem = int(t.get("memory_min_mib", 0))
    # Linux MemTotal excludes kernel/firmware-reserved RAM (e.g. a nominal
    # 2048 MiB KVM guest exposes ~1974 MiB). Allow up to 10% (capped at 192 MiB)
    # of reservation headroom so nominal VPS tiers are not falsely blocked.
    mem_floor = req_mem - min(192, req_mem // 10) if req_mem > 0 else 0
    if int(f["mem_mib"]) < mem_floor:
        issues.append(
            f"RAM {f['mem_mib']} MiB below {req_mem} MiB "
            f"(effective floor {mem_floor} MiB allowing kernel reservation)"
        )
    if f["firmware"] not in t.get("firmware", []):
        issues.append(f"firmware {f['firmware']} not in {t['firmware']}")
    req = plan.get("manifest", {}).get("arch")
    if req and f["arch"] != req:
        issues.append(f"arch {f['arch']} != {req}")
    need_gib = plan.get("artifact_requires", {}).get("min_size_gib")
    if need_gib and int(f["disk_size_bytes"]) < int(need_gib) * gib:
        issues.append(f"disk below image minimum {need_gib} GiB")
    return issues


def main(argv=None):
    ap = argparse.ArgumentParser(prog="bootie-preflight")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("plan", help="build plan JSON")
    p.add_argument("--manifest", required=True)
    p.add_argument("--facts", required=True, help="facts.sh output")
    p.add_argument("--index-file", help="offline index json (disk-image manifests)")
    p.add_argument("--no-fetch", action="store_true")
    p.add_argument("--host", help="require facts hostname to match")
    p.add_argument("--accept-risk", action="append", default=[],
                   help="explicitly accept a documented support-envelope risk class (allowed: drivers)")
    p.add_argument("--mirror",
                   help="HTTPS mirror base URL for checksum-indexed release artifacts")

    p = sub.add_parser("rescue-plan", help="build non-destructive rescue plan JSON offline")
    p.add_argument("--backend", choices=("debian-initramfs", "alpine-kexec"), default="debian-initramfs")
    p.add_argument("--facts", required=True, help="facts.sh output")
    p.add_argument("--host", help="require facts hostname to match")
    p.add_argument("--accept-risk", action="append", default=[],
                   help="explicitly accept a documented support-envelope risk class (allowed: drivers)")

    p = sub.add_parser("fingerprint", help="print machine fingerprint from facts")
    p.add_argument("--facts", required=True)

    p = sub.add_parser("approval", help="print approval token from a plan")
    p.add_argument("--plan", required=True)

    p = sub.add_parser("check", help="report fit issues; nonzero on blockers")
    p.add_argument("--plan", required=True)

    args = ap.parse_args(argv)
    if args.cmd == "fingerprint":
        print(fingerprint(parse_facts(Path(args.facts).read_text())))
        return 0
    if args.cmd == "approval":
        print(approval_token(json.loads(Path(args.plan).read_text())))
        return 0
    if args.cmd == "check":
        plan = json.loads(Path(args.plan).read_text())
        issues = fit_issues(plan)
        for i in issues:
            print(f"BLOCKER: {i}", file=sys.stderr)
        envelope = plan.get("envelope") or support_envelope(plan)
        fails = 0
        for probe in envelope:
            if probe["status"] == "fail":
                print(f"ENVELOPE-FAIL [{probe['name']}]: {probe['note']}", file=sys.stderr)
                fails += 1
            elif probe["status"] == "warn":
                print(f"envelope-warn [{probe['name']}]: {probe['note']}", file=sys.stderr)
        return 1 if (issues or fails) else 0

    if args.cmd == "rescue-plan":
        try:
            accepted_risks = parse_accepted_risks(args.accept_risk)
        except ValueError as exc:
            print(f"invalid --accept-risk: {exc}", file=sys.stderr)
            return 2
        try:
            facts = parse_facts(Path(args.facts).read_text())
            if args.host and facts["hostname"] != args.host:
                print(f"facts hostname {facts['hostname']} != {args.host}", file=sys.stderr)
                return 1
            plan = build_rescue_plan(facts, accepted_risks=accepted_risks, backend=args.backend)
        except (OSError, ValueError) as exc:
            print(f"preflight error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0

    try:
        accepted_risks = parse_accepted_risks(args.accept_risk)
    except ValueError as exc:
        print(f"invalid --accept-risk: {exc}", file=sys.stderr)
        return 2

    try:
        manifest = load_manifest(args.manifest)
        facts = parse_facts(Path(args.facts).read_text())
        if args.host and facts["hostname"] != args.host:
            print(f"facts hostname {facts['hostname']} != {args.host}", file=sys.stderr)
            return 1
        artifact = resolve_artifact(manifest, index_file=args.index_file,
                                  fetch=not args.no_fetch, mirror=args.mirror)
        plan = build_plan(facts, manifest, artifact, accepted_risks=accepted_risks)
        plan["artifact_requires"] = manifest["artifact"].get("requires", {})
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        print(f"preflight error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

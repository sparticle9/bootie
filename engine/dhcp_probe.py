#!/usr/bin/env python3
"""Read-only DHCP availability probe (stdlib only).

Sends DHCPDISCOVER with the interface's real MAC address and listens for a
matching DHCPOFFER. It never sends DHCPREQUEST and never changes interfaces,
routes, or leases; unavailable raw-socket support is reported as "unknown".
"""
import argparse
import re
import secrets
import socket
import struct
import sys
import time

MAGIC_COOKIE = b"\x63\x82\x53\x63"
BROADCAST_FLAG = 0x8000
ETH_P_ALL = 0x0003


def _mac_bytes(mac):
    if isinstance(mac, str):
        parts = mac.split(":")
        if len(parts) != 6 or not all(re.fullmatch(r"[0-9A-Fa-f]{2}", part) for part in parts):
            raise ValueError("MAC address must use six two-digit hexadecimal octets")
        return bytes(int(part, 16) for part in parts)
    if isinstance(mac, (bytes, bytearray)) and len(mac) == 6:
        return bytes(mac)
    raise ValueError("MAC address must be six bytes or xx:xx:xx:xx:xx:xx")


def build_dhcp_discover(mac, xid=None):
    """Build a minimal DHCPDISCOVER BOOTP payload for a MAC address."""
    mac_bytes = _mac_bytes(mac)
    if xid is None:
        xid = secrets.randbits(32)
    if not isinstance(xid, int) or not 0 <= xid <= 0xFFFFFFFF:
        raise ValueError("xid must be a 32-bit integer")
    fixed = struct.pack(
        "!BBBBIHHIIII16s64s128s",
        1,                  # op: BOOTREQUEST
        1,                  # htype: Ethernet
        6,                  # hlen
        0,                  # hops
        xid,
        0,                  # secs
        BROADCAST_FLAG,
        0,                  # ciaddr
        0,                  # yiaddr
        0,                  # siaddr
        0,                  # giaddr
        mac_bytes + b"\x00" * 10,
        b"\x00" * 64,       # sname
        b"\x00" * 128,      # file
    )
    return fixed + MAGIC_COOKIE + b"\x35\x01\x01" + b"\xff"


def _internet_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _broadcast_l2_frame(payload, mac):
    """Wrap the BOOTP payload in a broadcast Ethernet/IPv4/UDP frame.

    The UDP checksum is zero, which is legal for IPv4. Sending at L2 keeps the
    probe from binding UDP port 68 or otherwise interacting with the host's
    DHCP client state.
    """
    mac_bytes = _mac_bytes(mac)
    udp_len = 8 + len(payload)
    total_len = 20 + udp_len
    ip_without_sum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, 0, 0, 64, 17, 0,
        b"\x00\x00\x00\x00", b"\xff\xff\xff\xff",
    )
    ip_header = ip_without_sum[:10] + struct.pack("!H", _internet_checksum(ip_without_sum)) + ip_without_sum[12:]
    udp_header = struct.pack("!HHHH", 68, 67, udp_len, 0)
    return b"\xff" * 6 + mac_bytes + b"\x08\x00" + ip_header + udp_header + payload


def _extract_dhcp_payload(frame):
    """Return a BOOTP payload from either a raw payload or Ethernet frame."""
    if len(frame) >= 240 and frame[0] in (1, 2) and frame[236:240] == MAGIC_COOKIE:
        return frame
    if len(frame) < 14:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    while ethertype in (0x8100, 0x88A8):
        if len(frame) < offset + 4:
            return None
        ethertype = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
        offset += 4
    if ethertype != 0x0800 or len(frame) < offset + 20:
        return None

    ip_start = offset
    first = frame[ip_start]
    ihl = (first & 0x0F) * 4
    if first >> 4 != 4 or ihl < 20 or len(frame) < ip_start + ihl:
        return None
    total_len = struct.unpack("!H", frame[ip_start + 2:ip_start + 4])[0]
    if total_len < ihl + 8 or len(frame) < ip_start + total_len:
        return None
    fragment = struct.unpack("!H", frame[ip_start + 6:ip_start + 8])[0]
    if fragment & 0x3FFF or frame[ip_start + 9] != 17:
        return None

    udp_start = ip_start + ihl
    src_port, dst_port, udp_len, _checksum = struct.unpack(
        "!HHHH", frame[udp_start:udp_start + 8])
    if (src_port, dst_port) != (67, 68):
        return None
    if udp_len < 8 or udp_start + udp_len > ip_start + total_len:
        return None
    return frame[udp_start + 8:udp_start + udp_len]


def parse_dhcp_offer(packet, xid, mac):
    """Parse a matching DHCPOFFER; return None for unrelated/bad frames."""
    try:
        mac_bytes = _mac_bytes(mac)
    except ValueError:
        return None
    payload = _extract_dhcp_payload(packet)
    if payload is None or len(payload) < 240:
        return None
    try:
        fields = struct.unpack("!BBBBIHHIIII16s64s128s", payload[:236])
    except struct.error:
        return None
    (op, htype, hlen, _hops, packet_xid, _secs, _flags,
     _ciaddr, yiaddr, _siaddr, _giaddr, chaddr, _sname, _file) = fields
    if op != 2 or htype != 1 or hlen != 6:
        return None
    if packet_xid != xid or chaddr[:6] != mac_bytes:
        return None
    if payload[236:240] != MAGIC_COOKIE:
        return None

    message_type = None
    server_id = ""
    saw_end = False
    pos = 240
    while pos < len(payload):
        code = payload[pos]
        pos += 1
        if code == 0:
            continue
        if code == 255:
            saw_end = True
            break
        if pos >= len(payload):
            return None
        length = payload[pos]
        pos += 1
        if pos + length > len(payload):
            return None
        value = payload[pos:pos + length]
        pos += length
        if code == 53:
            if length != 1:
                return None
            message_type = value[0]
        elif code == 54 and length == 4:
            server_id = socket.inet_ntoa(value)
    if not saw_end or message_type != 2:
        return None
    return {
        "xid": packet_xid,
        "yiaddr": socket.inet_ntoa(struct.pack("!I", yiaddr)),
        "server_id": server_id,
    }


def probe(iface, mac, timeout=3.0, retries=2):
    """Return "yes", "no", or "unknown" for DHCP server availability."""
    if not sys.platform.startswith("linux") or not hasattr(socket, "AF_PACKET"):
        return "unknown"
    try:
        mac_bytes = _mac_bytes(mac)
        timeout = max(0.0, float(timeout))
        attempts = max(1, int(retries) + 1)
    except (TypeError, ValueError):
        return "unknown"

    xid = secrets.randbits(32)
    discover = build_dhcp_discover(mac_bytes, xid=xid)
    frame = _broadcast_l2_frame(discover, mac_bytes)
    try:
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)) as sock:
            sock.bind((iface, 0))
            for _attempt in range(attempts):
                sock.send(frame)
                deadline = time.monotonic() + timeout
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    sock.settimeout(remaining)
                    try:
                        packet, _addr = sock.recvfrom(65535)
                    except socket.timeout:
                        break
                    if parse_dhcp_offer(packet, xid, mac_bytes):
                        return "yes"
            return "no"
    except OSError:
        return "unknown"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="dhcp_probe.py")
    ap.add_argument("--iface", required=True)
    ap.add_argument("--mac", required=True)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--retries", type=int, default=2)
    args = ap.parse_args(argv)
    print(probe(args.iface, args.mac, timeout=args.timeout, retries=args.retries))
    return 0


if __name__ == "__main__":
    sys.exit(main())

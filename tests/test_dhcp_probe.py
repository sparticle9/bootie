"""Offline tests for the read-only DHCPDISCOVER probe."""
import io
import socket
import struct
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import dhcp_probe as dp  # noqa: E402

XID = 0x12345678
MAC = "52:54:00:12:34:56"
MAC_BYTES = bytes.fromhex("525400123456")


def make_offer(xid=XID, mac=MAC, message_type=2):
    payload = bytearray(dp.build_dhcp_discover(mac, xid=xid))
    payload[0] = 2  # BOOTREPLY
    payload[16:20] = socket.inet_aton("192.0.2.10")
    payload[242] = message_type
    return bytes(payload)


def wrap_offer_in_l2(offer):
    frame = bytearray(dp._broadcast_l2_frame(offer, MAC_BYTES))
    frame[34:36] = (67).to_bytes(2, "big")
    frame[36:38] = (68).to_bytes(2, "big")
    return bytes(frame)


class BuildDiscoverTests(unittest.TestCase):
    def test_build_dhcp_discover_fixed_fields_and_options(self):
        frame = dp.build_dhcp_discover(MAC, xid=XID)
        self.assertEqual(len(frame), 244)
        self.assertEqual(frame[0:4], b"\x01\x01\x06\x00")
        self.assertEqual(struct.unpack("!I", frame[4:8])[0], XID)
        self.assertEqual(struct.unpack("!H", frame[10:12])[0], 0x8000)
        self.assertEqual(frame[28:34], MAC_BYTES)
        self.assertEqual(frame[236:240], b"\x63\x82\x53\x63")
        self.assertEqual(frame[240:243], b"\x35\x01\x01")
        self.assertEqual(frame[243], 0xFF)

    def test_build_dhcp_discover_rejects_bad_mac_and_xid(self):
        for bad_mac in ("52:54:00:12:34", "not-a-mac", b"\x00" * 5, None):
            with self.subTest(bad_mac=bad_mac):
                with self.assertRaises(ValueError):
                    dp.build_dhcp_discover(bad_mac, xid=XID)
        for bad_xid in (-1, 0x100000000, "xid"):
            with self.subTest(bad_xid=bad_xid):
                with self.assertRaises(ValueError):
                    dp.build_dhcp_discover(MAC, xid=bad_xid)


class ParseOfferTests(unittest.TestCase):
    def test_valid_offer_matching_xid_and_mac(self):
        offer = make_offer()
        parsed = dp.parse_dhcp_offer(offer, XID, MAC)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["xid"], XID)
        self.assertEqual(parsed["yiaddr"], "192.0.2.10")

    def test_valid_offer_inside_ethernet_ipv4_udp_frame(self):
        parsed = dp.parse_dhcp_offer(wrap_offer_in_l2(make_offer()), XID, MAC)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["xid"], XID)

    def test_wrong_xid_ignored(self):
        self.assertIsNone(dp.parse_dhcp_offer(make_offer(), XID + 1, MAC))

    def test_wrong_mac_ignored(self):
        self.assertIsNone(dp.parse_dhcp_offer(make_offer(), XID, "52:54:00:12:34:57"))

    def test_non_offer_message_type_ignored(self):
        for message_type in (1, 3, 5):
            with self.subTest(message_type=message_type):
                self.assertIsNone(
                    dp.parse_dhcp_offer(make_offer(message_type=message_type), XID, MAC))

    def test_truncated_frame_ignored(self):
        offer = make_offer()
        for length in (0, 50, 239, 240, 243):
            with self.subTest(length=length):
                self.assertIsNone(dp.parse_dhcp_offer(offer[:length], XID, MAC))

    def test_malformed_options_ignored(self):
        offer = bytearray(make_offer())
        offer[241] = 20  # option 53 length runs beyond the end of the frame
        self.assertIsNone(dp.parse_dhcp_offer(bytes(offer), XID, MAC))


class ProbeFallbackTests(unittest.TestCase):
    def test_non_linux_reports_unknown(self):
        with mock.patch.object(dp.sys, "platform", "darwin"):
            self.assertEqual(dp.probe("en0", MAC), "unknown")

    def test_permission_error_reports_unknown(self):
        with mock.patch.object(dp.sys, "platform", "linux"), \
                mock.patch.object(dp.socket, "AF_PACKET", 999, create=True), \
                mock.patch.object(dp.socket, "socket",
                                  side_effect=PermissionError(13, "operation not permitted")):
            self.assertEqual(dp.probe("eth0", MAC), "unknown")

    def test_cli_prints_probe_result_and_exits_zero(self):
        out = io.StringIO()
        with mock.patch.object(dp, "probe", return_value="unknown") as probe, \
                redirect_stdout(out):
            rc = dp.main(["--iface", "eth0", "--mac", MAC, "--timeout", "0.1", "--retries", "0"])
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue(), "unknown\n")
        probe.assert_called_once_with("eth0", MAC, timeout=0.1, retries=0)


if __name__ == "__main__":
    unittest.main()

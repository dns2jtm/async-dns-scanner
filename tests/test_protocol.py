"""Unit tests for RFC 1035 DNS wire protocol serializer and parser."""

import unittest
import struct
from dns_scanner.protocol import (
    build_dns_query,
    parse_dns_header,
    is_nxdomain,
    is_noerror,
    QTYPE_A,
    QTYPE_AAAA,
    QCLASS_IN,
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    RCODE_SERVFAIL,
)


class TestDNSProtocol(unittest.TestCase):

    def test_build_dns_query_header_structure(self):
        tx_id = 0x1234
        packet = build_dns_query("example.com", qtype=QTYPE_A, tx_id=tx_id)

        # Minimum length: 12 bytes header + 13 bytes QNAME + 4 bytes QTYPE/QCLASS = 29 bytes
        self.assertGreaterEqual(len(packet), 29)

        # Verify header fields
        unpacked_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
        self.assertEqual(unpacked_id, 0x1234)
        self.assertEqual(flags, 0x0100)  # RD = 1
        self.assertEqual(qdcount, 1)
        self.assertEqual(ancount, 0)
        self.assertEqual(nscount, 0)
        self.assertEqual(arcount, 0)

    def test_build_dns_query_qname_encoding(self):
        packet = build_dns_query("test.org", qtype=QTYPE_AAAA, tx_id=0xAAAA)
        qname_part = packet[12:-4]

        # \x04test\x03org\x00
        expected_qname = b"\x04test\x03org\x00"
        self.assertEqual(qname_part, expected_qname)

        qtype, qclass = struct.unpack("!HH", packet[-4:])
        self.assertEqual(qtype, QTYPE_AAAA)
        self.assertEqual(qclass, QCLASS_IN)

    def test_parse_dns_header_success(self):
        # Construct synthetic response with RCODE = 0 (NOERROR), QR = 1, ANCOUNT = 1
        flags = 0x8180  # QR=1, RD=1, RA=1, RCODE=0
        synthetic_resp = struct.pack("!HHHHHH", 0x5678, flags, 1, 1, 0, 0) + b"\x00" * 20

        parsed = parse_dns_header(synthetic_resp)
        self.assertIsNotNone(parsed)
        tx_id, rcode, is_resp, ancount = parsed
        self.assertEqual(tx_id, 0x5678)
        self.assertEqual(rcode, RCODE_NOERROR)
        self.assertTrue(is_resp)
        self.assertEqual(ancount, 1)
        self.assertTrue(is_noerror(synthetic_resp))
        self.assertFalse(is_nxdomain(synthetic_resp))

    def test_parse_dns_header_nxdomain(self):
        # Flags with QR=1, RCODE=3 (NXDOMAIN)
        flags = 0x8183
        synthetic_resp = struct.pack("!HHHHHH", 0x9999, flags, 1, 0, 0, 0)

        parsed = parse_dns_header(synthetic_resp)
        self.assertIsNotNone(parsed)
        tx_id, rcode, is_resp, ancount = parsed
        self.assertEqual(rcode, RCODE_NXDOMAIN)
        self.assertTrue(is_resp)
        self.assertTrue(is_nxdomain(synthetic_resp))
        self.assertFalse(is_noerror(synthetic_resp))

    def test_parse_dns_header_malformed(self):
        short_packet = b"\x01\x02\x03"
        self.assertIsNone(parse_dns_header(short_packet))
        self.assertFalse(is_nxdomain(short_packet))
        self.assertFalse(is_noerror(short_packet))


if __name__ == "__main__":
    unittest.main()

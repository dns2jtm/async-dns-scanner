"""Low-level RFC 1035 DNS wire-protocol packet serialization and deserialization."""

import struct
import random
from typing import Optional, Tuple

# DNS Query Types
QTYPE_A = 1
QTYPE_NS = 2
QTYPE_CNAME = 5
QTYPE_SOA = 6
QTYPE_MX = 15
QTYPE_TXT = 16
QTYPE_AAAA = 28

# DNS Query Classes
QCLASS_IN = 1

# RCODE Definitions
RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4
RCODE_REFUSED = 5

def build_dns_query(domain: str, qtype: int = QTYPE_A, qclass: int = QCLASS_IN, tx_id: Optional[int] = None) -> bytes:
    """
    Serializes a raw RFC 1035 DNS query packet.
    Header format: [ID (2B), Flags (2B), QDCOUNT (2B), ANCOUNT (2B), NSCOUNT (2B), ARCOUNT (2B)]
    """
    if tx_id is None:
        tx_id = random.randint(0, 0xFFFF)

    # Standard query with Recursion Desired (RD = 1) -> 0x0100
    flags = 0x0100
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack("!HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)

    # Encode domain name as length-prefixed labels
    qname = bytearray()
    for part in domain.strip(".").split("."):
        if not part:
            continue
        encoded_part = part.encode("ascii", errors="ignore")
        qname.append(len(encoded_part))
        qname.extend(encoded_part)
    qname.append(0)  # Null terminator for root label

    question = bytes(qname) + struct.pack("!HH", qtype, qclass)
    return header + question

def parse_dns_header(packet: bytes) -> Optional[Tuple[int, int, int, int]]:
    """
    Parses a raw DNS packet header and returns (tx_id, rcode, is_response, ancount).
    Returns None if packet is malformed.
    """
    if len(packet) < 12:
        return None

    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    is_response = bool((flags >> 15) & 0x1)
    rcode = flags & 0x000F

    return tx_id, rcode, is_response, ancount

RCODE_NAMES = {
    RCODE_NOERROR: "NOERROR",
    RCODE_FORMERR: "FORMERR",
    RCODE_SERVFAIL: "SERVFAIL",
    RCODE_NXDOMAIN: "NXDOMAIN",
    RCODE_NOTIMP: "NOTIMP",
    RCODE_REFUSED: "REFUSED",
}

def is_nxdomain(packet: bytes) -> bool:
    """Returns True if the response indicates the domain does not exist (RCODE == 3)."""
    parsed = parse_dns_header(packet)
    if not parsed:
        return False
    _, rcode, is_resp, _ = parsed
    return is_resp and rcode == RCODE_NXDOMAIN

def is_noerror(packet: bytes) -> bool:
    """Returns True if the response indicates NOERROR (RCODE == 0)."""
    parsed = parse_dns_header(packet)
    if not parsed:
        return False
    _, rcode, is_resp, _ = parsed
    return is_resp and rcode == RCODE_NOERROR

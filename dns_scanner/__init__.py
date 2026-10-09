"""Async DNS Scanner: High-concurrency RFC 1035 UDP scanner and domain linguistic valuator."""

from .protocol import (
    build_dns_query,
    parse_dns_header,
    is_nxdomain,
    is_noerror,
    QTYPE_A,
    QTYPE_NS,
    QTYPE_AAAA,
    QTYPE_MX,
    QTYPE_TXT,
)
from .resolver import AsyncDNSScanner, DNSResponse
from .valuator import DomainValuator
from .whois import query_whois, query_whois_async, WhoisRecord
from .generator import (
    generate_cv_pattern,
    generate_morpheme_domains,
    filter_top_candidates,
)

__version__ = "1.0.0"

__all__ = [
    "AsyncDNSScanner",
    "DNSResponse",
    "DomainValuator",
    "query_whois",
    "query_whois_async",
    "WhoisRecord",
    "build_dns_query",
    "parse_dns_header",
    "is_nxdomain",
    "is_noerror",
    "generate_cv_pattern",
    "generate_morpheme_domains",
    "filter_top_candidates",
    "QTYPE_A",
    "QTYPE_NS",
    "QTYPE_AAAA",
    "QTYPE_MX",
    "QTYPE_TXT",
]

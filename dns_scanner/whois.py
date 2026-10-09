"""Lightweight raw TCP port 43 WHOIS client and record parser."""

import socket
import asyncio
import re
from dataclasses import dataclass
from typing import Optional, List, Dict

TLD_WHOIS_SERVERS: Dict[str, str] = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io": "whois.nic.io",
    "ai": "whois.nic.ai",
    "uk": "whois.nic.uk",
    "co.uk": "whois.nic.uk",
    "me": "whois.nic.me",
    "dev": "whois.nic.google",
    "app": "whois.nic.google",
    "xyz": "whois.nic.xyz",
    "info": "whois.afilias.net",
    "biz": "whois.biz",
}

@dataclass
class WhoisRecord:
    domain: str
    server: str
    registered: bool
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    name_servers: List[str] = None  # type: ignore
    raw_text: str = ""

    def __post_init__(self):
        if self.name_servers is None:
            self.name_servers = []


def get_tld_whois_server(domain: str) -> str:
    """Extracts TLD and returns the corresponding WHOIS server hostname."""
    parts = domain.strip().lower().split(".")
    if len(parts) >= 2:
        two_part_tld = ".".join(parts[-2:])
        if two_part_tld in TLD_WHOIS_SERVERS:
            return TLD_WHOIS_SERVERS[two_part_tld]
        tld = parts[-1]
        if tld in TLD_WHOIS_SERVERS:
            return TLD_WHOIS_SERVERS[tld]
    return "whois.iana.org"


def parse_whois_response(domain: str, server: str, raw_text: str) -> WhoisRecord:
    """Parses raw text returned by WHOIS server into structured attributes."""
    lowered = raw_text.lower()
    
    # Check indicators of non-registration
    not_found_patterns = [
        "no match",
        "not found",
        "no data found",
        "domain not found",
        "no entries found",
        "status: available",
        "is free",
    ]
    registered = not any(pattern in lowered for pattern in not_found_patterns)
    if "reserved" in lowered and not registered:
        registered = True

    registrar = None
    reg_match = re.search(r"(?:Registrar|registrar name):\s*([^\r\n]+)", raw_text, re.IGNORECASE)
    if reg_match:
        registrar = reg_match.group(1).strip()

    creation_date = None
    create_match = re.search(r"(?:Creation Date|Created On|Registered on|Registration Time):\s*([^\r\n]+)", raw_text, re.IGNORECASE)
    if create_match:
        creation_date = create_match.group(1).strip()

    expiration_date = None
    exp_match = re.search(r"(?:Registry Expiry Date|Expiration Date|Expires on|Expiry Date):\s*([^\r\n]+)", raw_text, re.IGNORECASE)
    if exp_match:
        expiration_date = exp_match.group(1).strip()

    ns_list: List[str] = []
    for match in re.finditer(r"(?:Name Server|nserver):\s*([^\r\n]+)", raw_text, re.IGNORECASE):
        ns = match.group(1).strip().lower().rstrip(".")
        if ns and ns not in ns_list:
            ns_list.append(ns)

    return WhoisRecord(
        domain=domain,
        server=server,
        registered=registered,
        registrar=registrar,
        creation_date=creation_date,
        expiration_date=expiration_date,
        name_servers=ns_list,
        raw_text=raw_text,
    )


def query_whois(domain: str, server: Optional[str] = None, timeout: float = 5.0) -> WhoisRecord:
    """Synchronous socket connection to port 43 WHOIS server."""
    target_server = server or get_tld_whois_server(domain)
    clean_domain = domain.strip().lower()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    response_data = b""

    try:
        s.connect((target_server, 43))
        query_str = f"{clean_domain}\r\n"
        s.sendall(query_str.encode("utf-8"))

        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response_data += chunk
    except Exception as ex:
        return WhoisRecord(
            domain=clean_domain,
            server=target_server,
            registered=False,
            raw_text=f"Socket connection error: {ex}",
        )
    finally:
        s.close()

    text = response_data.decode("utf-8", errors="replace")
    return parse_whois_response(clean_domain, target_server, text)


async def query_whois_async(domain: str, server: Optional[str] = None, timeout: float = 5.0) -> WhoisRecord:
    """Asynchronous TCP stream connection to port 43 WHOIS server."""
    target_server = server or get_tld_whois_server(domain)
    clean_domain = domain.strip().lower()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target_server, 43),
            timeout=timeout,
        )
        writer.write(f"{clean_domain}\r\n".encode("utf-8"))
        await writer.drain()

        chunks = []
        while True:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            if not chunk:
                break
            chunks.append(chunk)

        writer.close()
        await writer.wait_closed()
        text = b"".join(chunks).decode("utf-8", errors="replace")
        return parse_whois_response(clean_domain, target_server, text)
    except Exception as ex:
        return WhoisRecord(
            domain=clean_domain,
            server=target_server,
            registered=False,
            raw_text=f"Async socket error: {ex}",
        )

"""Asynchronous high-concurrency RFC 1035 UDP DNS scanner."""

import asyncio
import time
import struct
import random
from dataclasses import dataclass
from typing import List, Optional, Callable, AsyncIterator, Sequence

from .protocol import (
    build_dns_query,
    parse_dns_header,
    QTYPE_A,
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    RCODE_NAMES,
)

def backoff_delay(attempt: int, base: float = 0.1, cap: float = 2.0) -> float:
    """Exponential backoff with full jitter: uniform(0, min(cap, base * 2**attempt))."""
    return random.uniform(0.0, min(cap, base * (2 ** attempt)))


DEFAULT_NAMESERVERS = [
    "1.1.1.1",       # Cloudflare Primary
    "1.0.0.1",       # Cloudflare Secondary
    "8.8.8.8",       # Google Primary
    "8.8.4.4",       # Google Secondary
    "9.9.9.9",       # Quad9 Primary
]

@dataclass
class DNSResponse:
    domain: str
    status: str          # "AVAILABLE", "REGISTERED", "SERVFAIL", "TIMEOUT", "ERROR", etc.
    rcode: Optional[int]
    rcode_name: str
    latency_ms: float
    nameserver: str
    ancount: int = 0
    error: Optional[str] = None

    @property
    def is_available(self) -> bool:
        return self.status == "AVAILABLE"

    @property
    def is_registered(self) -> bool:
        return self.status == "REGISTERED"


class _DNSDatagramProtocol(asyncio.DatagramProtocol):
    """Internal datagram protocol for handling individual UDP DNS response packets."""

    def __init__(self, tx_id: int, on_response: asyncio.Future):
        self.tx_id = tx_id
        self.on_response = on_response
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore

    def datagram_received(self, data: bytes, addr) -> None:
        if len(data) >= 12:
            resp_tx_id = struct.unpack("!H", data[:2])[0]
            if resp_tx_id == self.tx_id and not self.on_response.done():
                self.on_response.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.on_response.done():
            self.on_response.set_exception(exc)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc and not self.on_response.done():
            self.on_response.set_exception(exc)


class AsyncDNSScanner:
    """
    High-performance asynchronous DNS scanner utilizing raw UDP wire-format queries
    with concurrency throttling and nameserver pool balancing.
    """

    def __init__(
        self,
        nameservers: Optional[List[str]] = None,
        port: int = 53,
        timeout: float = 2.5,
        max_concurrency: int = 150,
        retries: int = 1,
    ):
        self.nameservers = nameservers or DEFAULT_NAMESERVERS
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._ns_index = 0

    def _select_nameserver(self) -> str:
        ns = self.nameservers[self._ns_index % len(self.nameservers)]
        self._ns_index += 1
        return ns

    async def query(self, domain: str, qtype: int = QTYPE_A) -> DNSResponse:
        """Queries a single domain with retry logic and round-robin nameserver selection."""
        async with self._semaphore:
            domain = domain.strip().lower()
            last_err = None

            for attempt in range(self.retries + 1):
                nameserver = self._select_nameserver()
                tx_id = random.randint(1, 0xFFFF)
                query_packet = build_dns_query(domain, qtype=qtype, tx_id=tx_id)

                loop = asyncio.get_running_loop()
                on_response: asyncio.Future = loop.create_future()
                transport = None
                start_time = time.perf_counter()

                try:
                    transport, _ = await loop.create_datagram_endpoint(
                        lambda: _DNSDatagramProtocol(tx_id, on_response),
                        remote_addr=(nameserver, self.port)
                    )
                    transport.sendto(query_packet)
                    resp_bytes = await asyncio.wait_for(on_response, timeout=self.timeout)
                    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

                    parsed = parse_dns_header(resp_bytes)
                    if not parsed:
                        return DNSResponse(
                            domain=domain,
                            status="CORRUPT",
                            rcode=None,
                            rcode_name="CORRUPT",
                            latency_ms=elapsed_ms,
                            nameserver=nameserver,
                            error="Malformed response packet"
                        )

                    _, rcode, is_resp, ancount = parsed
                    rcode_str = RCODE_NAMES.get(rcode, f"RCODE_{rcode}")

                    if rcode == RCODE_NXDOMAIN:
                        status = "AVAILABLE"
                    elif rcode == RCODE_NOERROR:
                        status = "REGISTERED"
                    else:
                        status = rcode_str

                    return DNSResponse(
                        domain=domain,
                        status=status,
                        rcode=rcode,
                        rcode_name=rcode_str,
                        latency_ms=round(elapsed_ms, 2),
                        nameserver=nameserver,
                        ancount=ancount,
                    )

                except asyncio.TimeoutError:
                    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                    last_err = f"Timeout ({self.timeout}s) querying {nameserver}"
                    if attempt < self.retries:
                        await asyncio.sleep(backoff_delay(attempt))
                        continue
                    return DNSResponse(
                        domain=domain,
                        status="TIMEOUT",
                        rcode=None,
                        rcode_name="TIMEOUT",
                        latency_ms=round(elapsed_ms, 2),
                        nameserver=nameserver,
                        error=last_err,
                    )

                except Exception as ex:
                    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                    last_err = str(ex)
                    if attempt < self.retries:
                        await asyncio.sleep(backoff_delay(attempt))
                        continue
                    return DNSResponse(
                        domain=domain,
                        status="ERROR",
                        rcode=None,
                        rcode_name="ERROR",
                        latency_ms=round(elapsed_ms, 2),
                        nameserver=nameserver,
                        error=last_err,
                    )

                finally:
                    if transport:
                        transport.close()

            return DNSResponse(
                domain=domain,
                status="ERROR",
                rcode=None,
                rcode_name="ERROR",
                latency_ms=0.0,
                nameserver="none",
                error=last_err or "Unknown execution error",
            )

    async def scan_stream(self, domains: Sequence[str]) -> AsyncIterator[DNSResponse]:
        """Asynchronously streams scan results as queries complete."""
        tasks = [asyncio.create_task(self.query(d)) for d in domains]
        for task in asyncio.as_completed(tasks):
            yield await task

    async def scan_batch(
        self,
        domains: Sequence[str],
        on_result: Optional[Callable[[DNSResponse], None]] = None
    ) -> List[DNSResponse]:
        """Scans a batch of domains concurrently, optionally triggering a callback per result."""
        results = []
        async for resp in self.scan_stream(domains):
            results.append(resp)
            if on_result:
                on_result(resp)
        return results

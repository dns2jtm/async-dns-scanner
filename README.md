# Async DNS Scanner & Linguistic Domain Valuator

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Clean](https://img.shields.io/badge/code%20style-pep8-green.svg)](https://pep8.org/)

A high-performance, asynchronous RFC 1035 UDP DNS scanner, linguistic brandability evaluator, and port 43 WHOIS client built with pure Python. Capable of scanning hundreds of candidate domains per second with low latency and zero external runtime dependencies.

---

## Key Features

- **Raw RFC 1035 Binary Serialization**: Constructs direct DNS wire-format UDP datagrams (`HEADER` + length-prefixed `QNAME` + `QTYPE` / `QCLASS`) and parses return flags and RCODEs (`NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED`) without relying on heavy third-party DNS libraries.
- **Asynchronous Datagram Engine**: Utilizes Python `asyncio` non-blocking socket protocols and bounded `asyncio.Semaphore` pools to execute 150+ concurrent queries with retries using exponential backoff with full jitter.
- **Multi-Resolver Round-Robin Balancing**: Distributes query load across Cloudflare (`1.1.1.1`, `1.0.0.1`), Google (`8.8.8.8`, `8.8.4.4`), and Quad9 (`9.9.9.9`) to avoid rate limiting.
- **Linguistic & Phonetic Valuation**: Analyzes candidate labels for phonetic pronounceability (optimal vowel ratios, consonant-vowel alternation scoring, cluster penalties) and dictionary frequency modeling. Ships with a small built-in lexicon; load SOWPODS or any word list via `--lexicon`.
- **Direct Port 43 WHOIS Verification**: Validates available candidate registrations against authoritative TLD registries via raw TCP streams.
- **Phonetic Domain Generator**: Generates pronounceable domain templates (e.g., CVCV, CVCVC) and morpheme combinations.
- **Zero Third-Party Dependencies**: Pure Python standard library implementation (`asyncio`, `socket`, `struct`, `re`).

---

## Architecture Overview

```
                      +-----------------------------+
                      |       Input Domain(s)       |
                      +-----------------------------+
                                     |
             +-----------------------+-----------------------+
             |                                               |
             v                                               v
+------------------------+                      +------------------------+
|  Domain Valuator       |                      |  RFC 1035 Packet       |
|  - V-C Alternation     |                      |  Serialization         |
|  - Lexicon Frequency   |                      |  - Header (12 bytes)   |
|  - Length Scaling      |                      |  - Length-prefixed QNAME|
+------------------------+                      +------------------------+
             |                                               |
             |                                               v
             |                                  +------------------------+
             |                                  | Async UDP Resolver     |
             |                                  | - asyncio.DatagramProto|
             |                                  | - Semaphore Throttling |
             |                                  | - Multi-Resolver Pool  |
             |                                  +------------------------+
             |                                               |
             |                                               v
             |                                  +------------------------+
             |                                  | Response Deserializer  |
             |                                  | - NOERROR -> Registered|
             |                                  | - NXDOMAIN -> Available|
             |                                  +------------------------+
             |                                               |
             +-----------------------+-----------------------+
                                     |
                                     v
                      +-----------------------------+
                      | Direct Port 43 WHOIS Verify |
                      +-----------------------------+
                                     |
                                     v
                      +-----------------------------+
                      | Scored & Verified Output    |
                      +-----------------------------+
```

---

## Installation

Clone the repository and install locally:

```bash
git clone https://github.com/dns2jtm/async-dns-scanner.git
cd async-dns-scanner
pip install -e .
```

---

## Command-Line Usage

The package provides a comprehensive CLI utility `dns-scanner`:

### 1. Scan Candidate Domains
Scan a single domain, a wordlist file, or a phonetic pattern:

```bash
# Query single domain
python3 -m dns_scanner.cli scan --domain example.com

# Query a batch of candidate domains across .com and .io
python3 -m dns_scanner.cli scan --file candidates.txt --tld com io -c 150

# Scan CVCV phonetic patterns and show only available domains
python3 -m dns_scanner.cli scan --pattern CVCV --tld com --available-only --min-score 50

# Output results as JSON
python3 -m dns_scanner.cli scan --domain github.com --format json
```

### 2. Phonetic & Linguistic Valuation
Score pronounceability, length efficiency, and composite brandability:

```bash
python3 -m dns_scanner.cli evaluate luna zxpr code cloud apex
```

Output:
```
[*] Evaluating phonetic and brandability metrics:
LABEL                 LENGTH    PRONOUNCE       DICTIONARY        COMPOSITE   
----------------------------------------------------------------------
luna                  4         0.92            True              70.89       
zxpr                  4         0.0             False             0.0         
code                  4         0.92            True              70.89       
cloud                 5         0.73            True              55.72       
apex                  4         0.92            True              70.89       
```

Plug in a full word list such as SOWPODS / Collins Scrabble Words (one word per line, optional frequency column):

```bash
python3 -m dns_scanner.cli --lexicon sowpods.txt evaluate luna stride apex
python3 -m dns_scanner.cli --lexicon sowpods.txt scan --file words.txt --tld com --available-only
```

### 3. Direct Port 43 WHOIS Lookup
Query the authoritative registry server directly via raw TCP socket:

```bash
python3 -m dns_scanner.cli whois github.com
```

### 4. Candidate Domain Generator
Generate brandable, pronounceable names using morphemes or phonetic templates:

```bash
# Generate top tech morpheme combinations
python3 -m dns_scanner.cli generate --type morpheme --count 10

# Generate 4-letter CVCV candidates
python3 -m dns_scanner.cli generate --type cv --pattern CVCV --count 15
```

---

## Python API Usage

### Asynchronous Scanning

```python
import asyncio
from dns_scanner import AsyncDNSScanner

async def main():
    scanner = AsyncDNSScanner(max_concurrency=100, timeout=2.0)
    domains = ["google.com", "mybrandrandom123nonexistent.com", "github.com"]
    
    results = await scanner.scan_batch(domains)
    for res in results:
        print(f"Domain: {res.domain} | Status: {res.status} | Latency: {res.latency_ms}ms")

asyncio.run(main())
```

### Linguistic Valuation

```python
from dns_scanner import DomainValuator

valuator = DomainValuator()
score_data = valuator.evaluate("stride")

print(f"Pronounceability: {score_data['pronounceability']}")
print(f"Composite Score: {score_data['composite_score']}")
```

---

## Running Unit Tests

Run the standard library test discovery suite:

```bash
python3 -m unittest discover tests
```

Output:
```
................
----------------------------------------------------------------------
Ran 19 tests in 0.001s

OK
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

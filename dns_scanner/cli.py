"""Command line interface for Async DNS Scanner."""

import sys
import argparse
import asyncio
import json
import csv
from typing import List

from .protocol import QTYPE_A
from .resolver import AsyncDNSScanner, DNSResponse
from .valuator import DomainValuator, load_lexicon
from .whois import query_whois_async
from .generator import (
    generate_cv_pattern,
    generate_morpheme_domains,
    filter_top_candidates,
)


def make_valuator(args: argparse.Namespace) -> DomainValuator:
    """Builds a DomainValuator, optionally backed by a SOWPODS/word-list file."""
    path = getattr(args, "lexicon", None)
    if not path:
        return DomainValuator()
    try:
        words, freqs = load_lexicon(path)
    except FileNotFoundError:
        print(f"[!] Error: Lexicon file '{path}' not found.", file=sys.stderr)
        sys.exit(1)
    print(f"[*] Loaded {len(words):,} words from lexicon '{path}'", file=sys.stderr)
    return DomainValuator(words, freqs)


def format_table_row(cols: List[str], widths: List[int]) -> str:
    return "  ".join(f"{str(col):<{w}}" for col, w in zip(cols, widths))


def handle_scan(args: argparse.Namespace) -> None:
    """Executes asynchronous scan command."""
    domains_to_scan = []

    if args.domain:
        domains_to_scan.append(args.domain)
    elif args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                for line in f:
                    word = line.strip().lower()
                    if word:
                        if "." in word:
                            domains_to_scan.append(word)
                        else:
                            for tld in args.tld:
                                domains_to_scan.append(f"{word}.{tld.lstrip('.')}")
        except FileNotFoundError:
            print(f"[!] Error: File '{args.file}' not found.", file=sys.stderr)
            sys.exit(1)
    elif args.pattern:
        valuator = make_valuator(args)
        generated = list(generate_cv_pattern(args.pattern))
        top_candidates = filter_top_candidates(generated, valuator, min_score=args.min_score, limit=args.limit)
        for item in top_candidates:
            for tld in args.tld:
                domains_to_scan.append(f"{item['label']}.{tld.lstrip('.')}")
    else:
        print("[!] Error: Must specify --domain, --file, or --pattern.", file=sys.stderr)
        sys.exit(1)

    if not domains_to_scan:
        print("[!] No domains to scan.", file=sys.stderr)
        return

    print(f"[*] Commencing asynchronous scan of {len(domains_to_scan)} domain(s)...", file=sys.stderr)
    print(f"[*] Concurrency limit: {args.concurrency} | Timeout: {args.timeout}s\n", file=sys.stderr)

    scanner = AsyncDNSScanner(
        timeout=args.timeout,
        max_concurrency=args.concurrency,
        retries=args.retries,
    )

    async def run_scan():
        results = []
        widths = [32, 14, 10, 10, 18]
        headers = ["DOMAIN", "STATUS", "RCODE", "LATENCY", "NAMESERVER"]

        if args.format == "table":
            print(format_table_row(headers, widths))
            print("-" * sum(widths))

        valuator = make_valuator(args)

        async for resp in scanner.scan_stream(domains_to_scan):
            if args.available_only and resp.status != "AVAILABLE":
                continue

            # Optional WHOIS verification for NXDOMAIN matches
            verified_whois = None
            if args.whois_verify and resp.status == "AVAILABLE":
                whois_res = await query_whois_async(resp.domain, timeout=3.0)
                verified_whois = not whois_res.registered

            label = resp.domain.split(".")[0]
            val = valuator.evaluate(label)

            row_dict = {
                "domain": resp.domain,
                "status": resp.status,
                "rcode": resp.rcode_name,
                "latency_ms": resp.latency_ms,
                "nameserver": resp.nameserver,
                "linguistic_score": val["composite_score"],
                "whois_verified_free": verified_whois,
            }
            results.append(row_dict)

            if args.format == "table":
                status_display = resp.status
                if resp.status == "AVAILABLE":
                    status_display = f"\033[92m{resp.status}\033[0m"
                elif resp.status == "REGISTERED":
                    status_display = f"\033[90m{resp.status}\033[0m"

                row_str = format_table_row(
                    [resp.domain, status_display, resp.rcode_name, f"{resp.latency_ms}ms", resp.nameserver],
                    widths
                )
                print(row_str)

        return results

    results = asyncio.run(run_scan())

    if args.format == "json":
        print(json.dumps(results, indent=2))
    elif args.format == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=["domain", "status", "rcode", "latency_ms", "nameserver", "linguistic_score", "whois_verified_free"])
        writer.writeheader()
        writer.writerows(results)

    avail_count = sum(1 for r in results if r["status"] == "AVAILABLE")
    print(f"\n[+] Scan complete: {len(results)} evaluated, {avail_count} available.", file=sys.stderr)


def handle_evaluate(args: argparse.Namespace) -> None:
    """Linguistic and pronounceability evaluation."""
    valuator = make_valuator(args)
    print(f"[*] Evaluating phonetic and brandability metrics:")
    widths = [20, 8, 14, 16, 12]
    print(format_table_row(["LABEL", "LENGTH", "PRONOUNCE", "DICTIONARY", "COMPOSITE"], widths))
    print("-" * sum(widths))

    for word in args.words:
        res = valuator.evaluate(word)
        print(format_table_row(
            [res["label"], str(res["length"]), str(res["pronounceability"]), str(res["is_dictionary_word"]), str(res["composite_score"])],
            widths
        ))


def handle_whois(args: argparse.Namespace) -> None:
    """Direct WHOIS lookup."""
    print(f"[*] Querying WHOIS for '{args.domain}'...")
    res = asyncio.run(query_whois_async(args.domain, server=args.server, timeout=args.timeout))
    print(f"Domain:          {res.domain}")
    print(f"Server:          {res.server}")
    print(f"Registered:      {res.registered}")
    if res.registrar:
        print(f"Registrar:       {res.registrar}")
    if res.creation_date:
        print(f"Created:         {res.creation_date}")
    if res.expiration_date:
        print(f"Expires:         {res.expiration_date}")
    if res.name_servers:
        print(f"Name Servers:    {', '.join(res.name_servers)}")


def handle_generate(args: argparse.Namespace) -> None:
    """Generate domain candidates."""
    valuator = make_valuator(args)
    if args.type == "morpheme":
        candidates = generate_morpheme_domains()
    else:
        candidates = list(generate_cv_pattern(args.pattern))

    top = filter_top_candidates(candidates, valuator, min_score=args.min_score, limit=args.count)
    print(f"[*] Generated top {len(top)} domain candidates:")
    widths = [16, 8, 14, 14]
    print(format_table_row(["CANDIDATE", "LENGTH", "PRONOUNCE", "SCORE"], widths))
    print("-" * sum(widths))
    for item in top:
        print(format_table_row([item["label"], str(item["length"]), str(item["pronounceability"]), str(item["composite_score"])], widths))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="dns-scanner",
        description="Async DNS Scanner: High-performance RFC 1035 UDP scanner and linguistic valuator."
    )
    parser.add_argument("--lexicon", "-L", help="Word list file (e.g. SOWPODS), one word per line with optional frequency")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: scan
    scan_p = subparsers.add_parser("scan", help="Scan domains asynchronously")
    scan_p.add_argument("--domain", "-d", help="Single domain to query")
    scan_p.add_argument("--file", "-f", help="Path to domain or wordlist file")
    scan_p.add_argument("--pattern", "-p", help="Phonetic template e.g. CVCV")
    scan_p.add_argument("--tld", nargs="+", default=["com"], help="Target TLDs (default: com)")
    scan_p.add_argument("--concurrency", "-c", type=int, default=150, help="Max concurrent UDP queries")
    scan_p.add_argument("--timeout", "-t", type=float, default=2.5, help="Query timeout in seconds")
    scan_p.add_argument("--retries", "-r", type=int, default=1, help="Max retry attempts")
    scan_p.add_argument("--available-only", action="store_true", help="Only output available domains")
    scan_p.add_argument("--whois-verify", action="store_true", help="Double-check available domains with WHOIS")
    scan_p.add_argument("--format", choices=["table", "json", "csv"], default="table", help="Output format")
    scan_p.add_argument("--min-score", type=float, default=40.0, help="Minimum composite score filter")
    scan_p.add_argument("--limit", type=int, default=200, help="Candidate limit when using patterns")
    scan_p.set_defaults(func=handle_scan)

    # Subcommand: evaluate
    eval_p = subparsers.add_parser("evaluate", help="Score domain pronounceability and market value")
    eval_p.add_argument("words", nargs="+", help="Word or domain labels to evaluate")
    eval_p.set_defaults(func=handle_evaluate)

    # Subcommand: whois
    whois_p = subparsers.add_parser("whois", help="Query WHOIS registry on port 43")
    whois_p.add_argument("domain", help="Domain to lookup")
    whois_p.add_argument("--server", "-s", help="Optional specific WHOIS server")
    whois_p.add_argument("--timeout", "-t", type=float, default=5.0, help="WHOIS timeout")
    whois_p.set_defaults(func=handle_whois)

    # Subcommand: generate
    gen_p = subparsers.add_parser("generate", help="Generate pronounceable candidate domains")
    gen_p.add_argument("--type", choices=["cv", "morpheme"], default="cv", help="Generator type")
    gen_p.add_argument("--pattern", default="CVCV", help="Phonetic pattern (e.g. CVCV, CVCVC)")
    gen_p.add_argument("--count", "-n", type=int, default=25, help="Number of results")
    gen_p.add_argument("--min-score", type=float, default=25.0, help="Minimum composite score")
    gen_p.set_defaults(func=handle_generate)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

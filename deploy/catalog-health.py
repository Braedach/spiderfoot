#!/usr/bin/env python3
# =============================================================================
# Script:  deploy/catalog-health.py
# Version: 1.0.0
# Created: 2026-11-14
# Updated: 2026-11-14
#
# Purpose:
#   A release check. Asks every module's own data-source website whether it still answers, so a module whose service
#   has gone away is found before a scan does. On 2026-11-14 thirteen modules were found dead by hand (names that no
#   longer resolve, parked domains, an API that answers "we joined another company"); this finds them in about a
#   minute. It does not exercise a module's API, only that its service is still there.
#
# Usage:
#   python deploy/catalog-health.py              # report; exit 1 if a module that is not deprecated is dead
#   python deploy/catalog-health.py --timeout 20 --workers 8
#
# Prerequisites:
#   The repository's Python environment (it loads modules/ the way SpiderFoot does) and outbound HTTPS. It makes one
#   GET request per module to that module's public home page, so run it from a normal connection.
#
# Notes:
#   - FAILS the check (exit 1): the name does not resolve, the certificate is invalid, or the page is a parked or
#     for-sale domain.
#   - WARNS only: the connection is refused or times out twice (can be this network rather than the service), the
#     site moved to another domain, answers 404 or 410, or blocks automated requests (403, 429, 5xx from a CDN).
#     A human should look; these are often fine.
#   - A module that is marked "deprecated" is skipped: it is already known to be gone.
#   - IGNORE lists modules whose data-source website is placeholder text rather than the real service.
# =============================================================================
from __future__ import annotations

import argparse
import concurrent.futures as cf
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# modules/ is loaded the way the application loads it
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130 Safari/537.36"
PARKED_WORDS = ("domain is for sale", "buy this domain", "this domain may be for sale", "parked free", "sedoparking",
                "hugedomains", "domain has expired")
BLOCKED_CODES = {401, 403, 429, 503, 520, 521, 522, 523, 524, 525, 999}

# Modules whose "website" metadata is not the service they call (checked 2026-11-14)
IGNORE = {
    "sfp_blockchain_analytics",   # placeholder text; the module calls BlockCypher, blockchain.info and Etherscan
}


def registrable(host: str | None) -> str:
    return ".".join((host or "").lower().split(".")[-2:])


def classify(url: str, response: dict) -> tuple[str, str]:
    """(verdict, detail) for one probe. Verdicts: ok, moved, blocked, gone, unreachable, dead, parked.

    response has: error (None, "dns", "conn", "ssl"), status (HTTP status or 0), final (the URL after redirects), body
    (the first part of the page, lower-cased).
    """
    error = response.get("error")
    if error == "dns":
        return "dead", "the name does not resolve"
    if error == "ssl":
        return "dead", "invalid certificate"
    if error == "conn":
        return "unreachable", "connection refused or timed out (may be this network, not the service: check by hand)"
    status = int(response.get("status") or 0)
    if status in BLOCKED_CODES:
        return "blocked", f"HTTP {status} (blocks automated requests, or its CDN cannot reach the server)"
    if status in (404, 410):
        return "gone", f"HTTP {status}"
    if status >= 400:
        return "gone", f"HTTP {status}"
    if any(word in (response.get("body") or "") for word in PARKED_WORDS):
        return "parked", "a parked or for-sale domain"
    final = response.get("final") or url
    if registrable(urllib.parse.urlparse(final).hostname) != registrable(urllib.parse.urlparse(url).hostname):
        return "moved", f"redirects to {urllib.parse.urlparse(final).netloc}"
    return "ok", ""


def probe(url: str, timeout: int) -> dict:
    """One GET; returns the fields classify() reads."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,*/*"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"error": None, "status": r.status, "final": r.geturl(),
                    "body": r.read(4000).decode("utf-8", "replace").lower()}
    except urllib.error.HTTPError as e:
        return {"error": None, "status": e.code, "final": url, "body": ""}
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, socket.gaierror):
            return {"error": "dns", "status": 0}
        if isinstance(reason, ssl.SSLError) or "CERTIFICATE" in str(reason) or "SSL" in str(reason):
            return {"error": "ssl", "status": 0}
        return {"error": "conn", "status": 0}
    except (TimeoutError, OSError):
        return {"error": "conn", "status": 0}


def check(item: tuple[str, str], timeout: int) -> tuple[str, str, str, str]:
    name, url = item
    verdict, detail = classify(url, probe(url, timeout))
    if verdict in ("dead", "unreachable"):       # a second try, so one slow answer does not fail a release
        time.sleep(2)
        verdict, detail = classify(url, probe(url, timeout))
    return name, url, verdict, detail


def modules_to_check() -> list[tuple[str, str]]:
    from spiderfoot import SpiderFootHelpers
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    mods = SpiderFootHelpers.loadModulesAsDict(os.path.join(root, "modules"), ["sfp_template.py"])
    rows = []
    for name, info in sorted(mods.items()):
        meta = info.get("meta") or {}
        if name in IGNORE or "deprecated" in (meta.get("flags") or []):
            continue
        site = (meta.get("dataSource") or {}).get("website")
        if isinstance(site, str) and site.startswith("http"):
            rows.append((name, site))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="Check that every module's data-source website still answers.")
    ap.add_argument("--timeout", type=int, default=12, help="seconds to wait for each site (default 12)")
    ap.add_argument("--workers", type=int, default=12, help="sites asked at once (default 12)")
    args = ap.parse_args()

    rows = modules_to_check()
    print(f"Checking {len(rows)} modules' data-source websites...", flush=True)
    with cf.ThreadPoolExecutor(max(1, args.workers)) as ex:
        results = list(ex.map(lambda r: check(r, args.timeout), rows))

    counts: dict[str, int] = {}
    for _, _, verdict, _ in results:
        counts[verdict] = counts.get(verdict, 0) + 1
    print("Result:", ", ".join(f"{v} {n}" for v, n in sorted(counts.items())))
    failing = [r for r in results if r[2] in ("dead", "parked")]
    for label, verdicts in (("FAIL", ("dead", "parked")), ("WARN", ("unreachable", "gone", "moved", "blocked"))):
        for name, url, verdict, detail in results:
            if verdict in verdicts:
                print(f"  {label}  {name:30} {url}  [{verdict}] {detail}")
    if failing:
        print(f"\n{len(failing)} module(s) point at a service that is gone. Mark each deprecated (flags, an empty "
              "useCases, a summary that starts 'Deprecated: <why>') or fix it before releasing.")
        return 1
    print("\nNo module points at a service that is gone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

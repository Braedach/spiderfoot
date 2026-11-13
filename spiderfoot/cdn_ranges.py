"""Known CDN/anycast-provider IP range lookup.

Added 2026-11-13 after a live scope-escape incident: a target's own
legitimately-owned subdomain can resolve directly to a shared, multi-tenant
CDN anycast edge IP (Cloudflare, Fastly). That IP correctly matches() the
scan target's scope (the hostname really does resolve there), so the
*reactive* shared-IP mechanism (SpiderFootTarget.markIPShared() /
isSharedIP(), see target.py) cannot catch it by design - it deliberately
never demotes an address that matches the target's own authorised scope.
There is also a second, independent problem with the reactive mechanism
alone: it depends on some discovery module noticing and reporting the
sharing *before* an invasive module dispatches to the same address, and
under concurrent scanning that race is not reliably won (confirmed live:
sfp_dnsresolve's own classification can trail nmap's dispatch by minutes).

This module is a deterministic, dispatch-time-independent alternative for
the subset of shared infrastructure that publishes its own IP ranges:
checking "is this address within a known CDN provider's published range"
needs no other module to have run first and carries no ordering risk.

It intentionally does NOT replace the reactive mechanism - shared hosting
on a provider that doesn't publish ranges (or isn't in this list yet) still
needs markIPShared(). This covers the two providers that caused measured
live harm (Cloudflare, Fastly); add others here following the same pattern
if/when they cause a real incident, rather than chasing an exhaustive list
speculatively.
"""

from __future__ import annotations

import logging

import netaddr

__all__ = ["CDN_RANGE_SOURCES", "FALLBACK_RANGES", "refreshCdnRanges", "isKnownCdnIP"]

log = logging.getLogger("spiderfoot.cdn_ranges")

# Where to fetch current ranges from. Checked by refreshCdnRanges() through
# the same sf.optValueToData()/cacheGet()/cachePut() mechanism the scanner
# already uses for the Internet TLD list (see SpiderFootScanner.__init__),
# so this gets the same automatic periodic refresh and on-disk caching for
# free, with no new runtime dependency of its own.
CDN_RANGE_SOURCES: dict[str, dict[str, str]] = {
    "Cloudflare": {
        "v4": "https://www.cloudflare.com/ips-v4",
        "v6": "https://www.cloudflare.com/ips-v6",
    },
    "Fastly": {
        # Fastly publishes both families as one JSON document.
        "json": "https://api.fastly.com/public-ip-list",
    },
}

# Bootstrap fallback only - used when a live fetch fails and no cached copy
# exists yet (first run, no network access, provider endpoint down). This
# snapshot WILL go stale; it exists purely so the dispatch-time check never
# has to block on, or be silently disabled by, a failed HTTP call. The real,
# current ranges come from refreshCdnRanges()'s periodic fetch. Snapshot
# taken 2026-11-13 from each provider's own published list.
FALLBACK_RANGES: dict[str, list[str]] = {
    "Cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
        "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
        "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
        "2c0f:f248::/32",
    ],
    "Fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
        "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
        "140.248.64.0/18", "140.248.128.0/17", "146.75.0.0/16",
        "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
        "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20",
        "172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21",
        "199.232.0.0/16",
    ],
}


def refreshCdnRanges(sf, cacheHours: int = 24) -> dict[str, list[str]]:
    """Fetch current CDN provider IP ranges, with on-disk caching and a
    static fallback.

    Mirrors SpiderFootScanner.__init__'s Internet-TLD-list pattern exactly
    (same sf.cacheGet()/optValueToData()/cachePut() calls) so a failed or
    slow provider endpoint never blocks or fails scan startup - it just
    falls back to the last good cache, or FALLBACK_RANGES if there has
    never been one.

    Args:
        sf: a SpiderFoot helper instance (for cacheGet/cachePut/optValueToData).
        cacheHours (int): how long a cached fetch stays valid before the
            next scan start re-fetches it. 0 forces a refresh every time.

    Returns:
        dict[str, list[str]]: provider name -> list of CIDR strings.
    """
    ranges: dict[str, list[str]] = {}

    for provider, sources in CDN_RANGE_SOURCES.items():
        cidrs: list[str] = []
        for part, url in sources.items():
            label = f"cdn_ranges_{provider}_{part}"
            raw = sf.cacheGet(label, cacheHours)
            if raw is None:
                raw = sf.optValueToData(url)
                if raw:
                    sf.cachePut(label, raw)
            if not raw:
                log.warning(
                    "Could not refresh %s CDN ranges (%s) - using fallback"
                    " snapshot for this provider.", provider, part
                )
                continue
            cidrs.extend(_parseCidrsFromSource(provider, raw))

        ranges[provider] = cidrs if cidrs else list(FALLBACK_RANGES.get(provider, []))

    return ranges


def _parseCidrsFromSource(provider: str, raw: str) -> list[str]:
    """Parse one provider's raw fetched document into a list of CIDR strings."""
    raw = raw.strip()
    if not raw:
        return []

    if provider == "Fastly":
        import json
        try:
            data = json.loads(raw)
            return list(data.get("addresses", [])) + list(data.get("ipv6_addresses", []))
        except (ValueError, AttributeError) as e:
            log.warning("Could not parse Fastly IP list JSON: %s", e)
            return []

    # Cloudflare's ips-v4/ips-v6 endpoints are plain newline-separated CIDRs.
    return [line.strip() for line in raw.splitlines() if line.strip()]


def isKnownCdnIP(ip: str, ranges: dict[str, list[str]] | None = None) -> str | None:
    """Return the provider name if ip falls within a known CDN/anycast
    provider's IP ranges, else None.

    Args:
        ip (str): the IPv4 or IPv6 address to check.
        ranges (dict[str, list[str]] | None): provider -> CIDR list, as
            returned by refreshCdnRanges(). Defaults to FALLBACK_RANGES if
            not supplied (e.g. in isolated unit tests).

    Returns:
        str | None: the matching provider's name, or None.
    """
    if not ip or not isinstance(ip, str):
        return None

    try:
        addr = netaddr.IPAddress(ip)
    except netaddr.AddrFormatError:
        return None

    for provider, cidrs in (ranges if ranges is not None else FALLBACK_RANGES).items():
        for cidr in cidrs:
            try:
                if addr in netaddr.IPNetwork(cidr):
                    return provider
            except netaddr.AddrFormatError:
                continue

    return None

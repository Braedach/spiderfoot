# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         spiderfoot.scan.scope_policy
# Purpose:      One definition of "what may an active module contact" for every search case,
#               used by the dispatch gate and by the egress check. See docs/scope-guard-design.md.
# Created:      2026-11-16
# Licence:      MIT
# -------------------------------------------------------------------------------
"""Scope policy for active contact.

Only *contact with a host* is restricted. Passive lookups (vendor APIs, parsers) and the identity tools are never
blocked by this module: the guard exists to stop active modules (port scanners, web and TLS probes, crawlers) from
touching hosts the owner did not authorise.

Modes (setting ``_scope_guard_mode``):

* ``off``     - the policy is not consulted.
* ``log``     - decisions are made and recorded ("would block"), nothing extra is blocked.
* ``enforce`` - blocked contact is refused.
"""

from __future__ import annotations

import ipaddress
import threading
import urllib.parse
from dataclasses import dataclass
from typing import Callable, Iterable

# Modules that connect to the host named in an event (web, TLS, ports, crawling, scanners). Reviewed 2026-11-16 from
# the module code and the rc.39 IP-scan evidence. A module that contacts event hosts and is not listed here fails
# test_scope_policy.py::test_every_invasive_module_is_active (the flag and this list must agree).
ACTIVE_MODULES: frozenset[str] = frozenset({
    # flagged "invasive": already gated before this policy
    "sfp_junkfiles", "sfp_nmap", "sfp_nuclei", "sfp_portscan_tcp", "sfp_tool_arjun", "sfp_tool_dalfox",
    "sfp_tool_ffuf", "sfp_tool_gobuster", "sfp_tool_katana", "sfp_tool_masscan", "sfp_tool_naabu",
    "sfp_tool_nikto",
    # contact event hosts but were never gated (found in the rc.39 IP scan: 193 and 80 third-party hosts)
    "sfp_sslcert", "sfp_httpx", "sfp_filemeta", "sfp_tool_gowitness", "sfp_tool_nbtscan",
    "sfp_tool_onesixtyone", "sfp_tool_snallygaster", "sfp_tool_sslscan", "sfp_tool_sslyze",
    "sfp_tool_testsslsh", "sfp_tool_tlsx", "sfp_tool_wafw00f", "sfp_tool_whatweb", "sfp_spider",
    "sfp_cloudfront", "sfp_subdomain_takeover", "sfp_dnszonexfer",
})

# Send a person's identifiers to many sites. Bounded by their own options (person_targets_only and caps), not by
# host scope; listed so the tests and the documentation can name them.
IDENTITY_MODULES: frozenset[str] = frozenset({"sfp_accounts", "sfp_tool_maigret", "sfp_tool_user_scanner"})

# A scan about a person (or a wallet) gives no host any authorisation for active contact.
PERSON_TARGETS = frozenset({"HUMAN_NAME", "PHONE_NUMBER", "USERNAME", "EMAILADDR", "BITCOIN_ADDRESS"})

# Event types whose data names a host, address or URL. Only these are judged at dispatch: other types carry text
# (a banner, a technology name) that must never be misread as a hostname.
HOST_EVENT_TYPES = frozenset({
    "IP_ADDRESS", "IPV6_ADDRESS", "INTERNET_NAME", "INTERNET_NAME_UNRESOLVED", "DOMAIN_NAME", "DOMAIN_NAME_PARENT",
    "LINKED_URL_INTERNAL", "LINKED_URL_EXTERNAL", "URL_FORM", "URL_STATIC", "URL_JAVASCRIPT", "URL_UPLOAD",
    "URL_PASSWORD", "TCP_PORT_OPEN", "UDP_PORT_OPEN", "AFFILIATE_INTERNET_NAME", "AFFILIATE_IPADDR",
    "AFFILIATE_IPV6_ADDRESS", "AFFILIATE_DOMAIN_NAME", "CO_HOSTED_SITE", "CO_HOSTED_SITE_DOMAIN", "SIMILARDOMAIN",
    "NETBLOCK_OWNER", "NETBLOCK_MEMBER", "NETBLOCKV6_OWNER", "NETBLOCKV6_MEMBER",
})

MODES = ("off", "log", "enforce")

# Second-level public suffixes, enough to compare a vendor's domain (not a full public-suffix list)
_SLD = {"com.au", "net.au", "org.au", "edu.au", "gov.au", "co.uk", "org.uk", "ac.uk", "gov.uk", "co.nz", "co.jp",
        "com.br", "com.cn", "co.in", "co.za", "com.sg", "com.hk"}


@dataclass(frozen=True)
class Decision:
    """Result of one scope check."""

    allowed: bool
    reason: str


def host_of(value: object) -> str | None:
    """The bare host or IP in event data or a URL, lowercased; None when the data does not name a host.

    Handles ``host``, ``ip``, ``ip:port``, ``ip:port/proto (service)``, ``[v6]:port`` and URLs.
    """
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text:
        return None
    if "://" in text:
        try:
            return urllib.parse.urlparse(text).hostname or None
        except ValueError:
            return None
    text = text.split(" ", 1)[0].split("/", 1)[0]
    try:
        ipaddress.ip_address(text)
        return text
    except ValueError:
        pass
    if text.startswith("[") and "]" in text:
        return text[1:text.index("]")] or None
    if text.count(":") == 1:
        text = text.split(":", 1)[0]
    if not text or " " in text:
        return None
    return text


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def registrable(host: str) -> str:
    """The registrable domain of a host (a close-enough comparison key; IPs are returned unchanged)."""
    if _is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _SLD:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


class ScopePolicy:
    """What an active module may contact, for one scan's target."""

    def __init__(self, target, mode: str = "log", *, asn_authorised: bool = False, asn_max_addresses: int = 256,
                 cdn_lookup: Callable[[str], str | None] | None = None,
                 resolver: Callable[[str], Iterable[str]] | None = None) -> None:
        """Create the policy.

        Args:
            target: the scan's SpiderFootTarget (read live, so aliases added at scan start are seen).
            mode (str): off, log or enforce.
            asn_authorised (bool): the owner explicitly authorised active contact for an ASN target.
            asn_max_addresses (int): hard cap on distinct addresses contacted for an ASN target.
            cdn_lookup: ip -> provider name when the address is a known shared edge, else None.
            resolver: name -> list of addresses; used to verify that a hostname resolves to an IP target now.
        """
        self.target = target
        self.mode = mode if mode in MODES else "log"
        self.asn_authorised = asn_authorised
        self.asn_max_addresses = asn_max_addresses
        self._cdn_lookup = cdn_lookup
        self._resolver = resolver
        self._lock = threading.Lock()
        self._resolved: dict[str, frozenset[str]] = {}
        self._discovered: set[str] = set()
        self._asn_contacted: set[str] = set()
        self.counts: dict[tuple[str, str], int] = {}
        self.examples: dict[tuple[str, str], str] = {}

    # ----------------------------------------------------------------------------------------- discovery

    def observe(self, value: object) -> None:
        """Remember a host or address this scan has seen in event data (for the egress check)."""
        host = host_of(value)
        if host:
            with self._lock:
                self._discovered.add(host)
                self._discovered.add(registrable(host))

    def was_discovered(self, host: str) -> bool:
        """True when the scan has seen this host (or its registrable domain) in event data."""
        with self._lock:
            return host in self._discovered or registrable(host) in self._discovered

    # ----------------------------------------------------------------------------------------- decisions

    def _resolves_to_target(self, name: str) -> bool:
        """A hostname is the IP target's own only if it resolves to the target's address now."""
        if self._resolver is None:
            return False
        with self._lock:
            cached = self._resolved.get(name)
        if cached is None:
            try:
                cached = frozenset(str(a).lower() for a in (self._resolver(name) or []))
            except Exception:
                cached = frozenset()
            with self._lock:
                self._resolved[name] = cached
        return any(self._ip_in_authorised_scope(a) for a in cached)

    def _ip_in_authorised_scope(self, ip: str) -> bool:
        """The literal authorised address or block for IP and netblock targets."""
        ttype = self.target.targetType
        if ttype in ("IP_ADDRESS", "IPV6_ADDRESS"):
            return ip == self.target.targetValue.lower()
        if ttype in ("NETBLOCK_OWNER", "NETBLOCKV6_OWNER"):
            try:
                return ipaddress.ip_address(ip) in ipaddress.ip_network(self.target.targetValue, strict=False)
            except ValueError:
                return False
        return False

    def decide(self, value: object) -> Decision:
        """May an active module contact this host, address or URL?"""
        host = host_of(value)
        if host is None:
            return Decision(True, "no host in the data (not judged)")
        ttype = self.target.targetType

        if ttype in PERSON_TARGETS:
            return Decision(False, "person scan: no active contact with any host")

        if ttype == "BGP_AS_OWNER":
            if not self.asn_authorised:
                return Decision(False, "ASN scan: active contact needs explicit authorisation")
            if not _is_ip(host) or host not in self.target.getAddresses():
                return Decision(False, "ASN scan: not a registered address of the ASN")
            with self._lock:
                if host not in self._asn_contacted and len(self._asn_contacted) >= self.asn_max_addresses:
                    return Decision(False, f"ASN scan: the {self.asn_max_addresses}-address cap is reached")
                self._asn_contacted.add(host)
            return Decision(True, "ASN scan: authorised registered address")

        if _is_ip(host):
            if self._ip_in_authorised_scope(host):
                return Decision(True, "the authorised address or block")
            if host in self.target.getAddresses():
                provider = self._cdn_lookup(host) if self._cdn_lookup else None
                if provider:
                    return Decision(False, f"{provider} shared edge address")
                if self.target.isSharedIP(host):
                    return Decision(False, "address proven shared with a non-target host")
                return Decision(True, "a resolved address of the target")
            return Decision(False, "address is not the target's")

        # a hostname
        if ttype in ("IP_ADDRESS", "IPV6_ADDRESS", "NETBLOCK_OWNER", "NETBLOCKV6_OWNER"):
            # an IP or block target authorises the address, plus names that verifiably point at it NOW. The
            # reverse-DNS name set at scan start counts; its parent domain does not (that is the ISP's).
            if self.target.matches(host, includeParents=False, includeChildren=True):
                return Decision(True, "the target's own reverse-DNS name")
            if self._resolves_to_target(host):
                return Decision(True, "resolves to the authorised address now")
            return Decision(False, "name does not resolve to the authorised address")
        if self.target.matches(host, includeParents=True, includeChildren=True):
            return Decision(True, "the target's own name or subdomain")
        return Decision(False, "name is not the target's")

    def decide_event(self, event_type: str, data: object) -> Decision:
        """Judge dispatching an event to an active module. Only host-carrying event types are judged."""
        if event_type not in HOST_EVENT_TYPES:
            return Decision(True, "event type does not name a host (not judged)")
        return self.decide(data)

    def egress(self, module_name: str, value: object, vendor_domains: Iterable[str] = ()) -> Decision:
        """Check one outbound request by a module.

        Active modules must stay in scope. Any other module is only noted when it contacts a host this scan
        discovered that is out of scope (log-only: a vendor whose own address was merely discovered is allowed).
        """
        host = host_of(value)
        if host is None:
            return Decision(True, "no host")
        verdict = self.decide(host)
        if module_name in ACTIVE_MODULES:
            return verdict
        if verdict.allowed or not self.was_discovered(host):
            return Decision(True, "not an active module, or not a discovered host")
        if registrable(host) in {registrable(host_of(d) or str(d)) for d in vendor_domains if d}:
            return Decision(True, "the module's own declared data source")
        return Decision(False, "non-active module contacting a discovered out-of-scope host (log only)")

    # ----------------------------------------------------------------------------------------- reporting

    def record(self, module_name: str, value: object, decision: Decision, layer: str) -> None:
        """Count a blocked decision for the scan log."""
        key = (module_name, f"{layer}: {decision.reason}")
        with self._lock:
            self.counts[key] = self.counts.get(key, 0) + 1
            self.examples.setdefault(key, str(host_of(value) or value)[:80])

    def summary(self) -> list[str]:
        """One line per module and reason, most frequent first, for the scan log."""
        with self._lock:
            items = sorted(self.counts.items(), key=lambda kv: -kv[1])
            return [f"{n} x {mod}: {why} (first: {self.examples.get((mod, why), '')})"
                    for (mod, why), n in items]

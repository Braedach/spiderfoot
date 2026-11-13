from __future__ import annotations

"""Tests for SpiderFootScanner.shouldDispatchToModule() - the central
strict-scope gate used by waitForThreads() to decide whether an event may
reach an "invasive" tool module.

Covers the scope-escape issue documented in README.md: discovery modules can
produce events for third-party hosts/addresses that are not actually related
to the scan target, and active ("invasive") tool modules must not act on
them.
"""

import uuid

from spiderfoot import SpiderFootEvent, cdn_ranges
from spiderfoot.scan.scanner import SpiderFootScanner
from test.unit.utils.test_scanner_base import TestScannerBase


class _FakeModule:
    """Just enough of a module for shouldDispatchToModule()'s own checks."""

    def __init__(self, name, flags=None):
        self.__name__ = name
        self.meta = {"flags": flags or []}


class TestStrictScopeGate(TestScannerBase):

    def _build_scanner(self, target_value, target_type, strict_scope=True):
        opts = self.default_options.copy()
        scan_id = str(uuid.uuid4())
        scanner = SpiderFootScanner(
            "scope gate test", scan_id, target_value, target_type,
            ["sfp_example"], opts, start=False,
        )
        scanner._SpiderFootScanner__config["_strict_scope"] = strict_scope
        return scanner

    def test_invasive_module_rejects_out_of_scope_ip(self):
        scanner = self._build_scanner("example.com", "INTERNET_NAME")
        invasive = _FakeModule("sfp_nmap", flags=["invasive"])
        event = SpiderFootEvent("IP_ADDRESS", "198.51.100.9", "sfp_hackertarget", None)

        self.assertFalse(scanner.shouldDispatchToModule(invasive, event))

    def test_non_invasive_module_still_gets_out_of_scope_ip(self):
        scanner = self._build_scanner("example.com", "INTERNET_NAME")
        passive = _FakeModule("sfp_passive_lookup", flags=[])
        event = SpiderFootEvent("IP_ADDRESS", "198.51.100.9", "sfp_hackertarget", None)

        self.assertTrue(scanner.shouldDispatchToModule(passive, event))

    def test_invasive_module_accepts_in_scope_ip(self):
        scanner = self._build_scanner("203.0.113.5", "IP_ADDRESS")
        invasive = _FakeModule("sfp_nmap", flags=["invasive"])
        event = SpiderFootEvent("IP_ADDRESS", "203.0.113.5", "sfp_hackertarget", None)

        self.assertTrue(scanner.shouldDispatchToModule(invasive, event))

    def test_invasive_module_accepts_hostname_resolved_from_domain_target(self):
        # Mirrors sfp_dnsresolve registering a resolved host as a target alias.
        scanner = self._build_scanner("example.com", "INTERNET_NAME")
        scanner._SpiderFootScanner__target.setAlias("203.0.113.5", "IP_ADDRESS")
        invasive = _FakeModule("sfp_nmap", flags=["invasive"])
        event = SpiderFootEvent("IP_ADDRESS", "203.0.113.5", "sfp_dnsresolve", None)

        self.assertTrue(scanner.shouldDispatchToModule(invasive, event))

    def test_invasive_module_rejects_cohosted_ip_not_an_alias(self):
        # The domain's own resolved IP is an alias, but a third party that
        # merely shares that IP (CO_HOSTED_SITE-style discovery) is not.
        scanner = self._build_scanner("example.com", "INTERNET_NAME")
        scanner._SpiderFootScanner__target.setAlias("203.0.113.5", "IP_ADDRESS")
        invasive = _FakeModule("sfp_nmap", flags=["invasive"])
        event = SpiderFootEvent("IP_ADDRESS", "203.0.113.200", "sfp_hackertarget", None)

        self.assertFalse(scanner.shouldDispatchToModule(invasive, event))

    def test_strict_scope_disabled_lets_invasive_module_see_everything(self):
        scanner = self._build_scanner("example.com", "INTERNET_NAME", strict_scope=False)
        invasive = _FakeModule("sfp_nmap", flags=["invasive"])
        event = SpiderFootEvent("IP_ADDRESS", "198.51.100.9", "sfp_hackertarget", None)

        self.assertTrue(scanner.shouldDispatchToModule(invasive, event))

    def test_name_phone_username_targets_are_unrestricted(self):
        # matches() always returns True for these target types - scope has no
        # natural meaning for a name/phone/username search.
        scanner = self._build_scanner("+15551234567", "PHONE_NUMBER")
        invasive = _FakeModule("sfp_nmap", flags=["invasive"])
        event = SpiderFootEvent("IP_ADDRESS", "198.51.100.9", "sfp_phone", None)

        self.assertTrue(scanner.shouldDispatchToModule(invasive, event))

    # -- Shared/CDN IP gate (found 2026-11-13: a legitimately-registered --
    # -- alias IP can still be a shared CDN edge serving unrelated sites --

    def test_invasive_module_rejects_shared_ip_even_if_aliased(self):
        # www.example.com (a real alias) resolves to a Fastly edge IP that
        # also serves an unrelated site - a discovery module proved that by
        # calling markIPShared(). The IP is still a registered alias (so
        # matches() is True, discovery/passive modules are unaffected), but
        # invasive modules must not act on the bare address directly.
        scanner = self._build_scanner("example.com", "INTERNET_NAME")
        scanner._SpiderFootScanner__target.setAlias("151.101.3.7", "IP_ADDRESS")
        scanner._SpiderFootScanner__target.markIPShared("151.101.3.7")
        invasive = _FakeModule("sfp_nmap", flags=["invasive"])
        event = SpiderFootEvent("IP_ADDRESS", "151.101.3.7", "sfp_dnsresolve", None)

        self.assertFalse(scanner.shouldDispatchToModule(invasive, event))

    def test_non_invasive_module_still_gets_shared_ip(self):
        # Discovery must still see it - only action is blocked.
        scanner = self._build_scanner("example.com", "INTERNET_NAME")
        scanner._SpiderFootScanner__target.setAlias("151.101.3.7", "IP_ADDRESS")
        scanner._SpiderFootScanner__target.markIPShared("151.101.3.7")
        passive = _FakeModule("sfp_passive_lookup", flags=[])
        event = SpiderFootEvent("IP_ADDRESS", "151.101.3.7", "sfp_dnsresolve", None)

        self.assertTrue(scanner.shouldDispatchToModule(passive, event))

    def test_invasive_module_rejects_shared_ip_with_port_suffix(self):
        # TCP_PORT_OPEN-style "ip:port" data must also be caught, not just
        # the bare IP_ADDRESS event.
        scanner = self._build_scanner("example.com", "INTERNET_NAME")
        scanner._SpiderFootScanner__target.setAlias("151.101.3.7", "IP_ADDRESS")
        scanner._SpiderFootScanner__target.markIPShared("151.101.3.7")
        invasive = _FakeModule("sfp_httpx", flags=["invasive"])
        event = SpiderFootEvent("TCP_PORT_OPEN", "151.101.3.7:443", "sfp_internetdb", None)

        self.assertFalse(scanner.shouldDispatchToModule(invasive, event))

    def test_invasive_module_accepts_aliased_ip_not_marked_shared(self):
        # Baseline: a dedicated, single-tenant alias IP (never marked
        # shared, since nothing ever found a non-matching co-tenant on it)
        # is completely unaffected - this is the common case the original
        # scope guard already validated and must not regress.
        scanner = self._build_scanner("example.com", "INTERNET_NAME")
        scanner._SpiderFootScanner__target.setAlias("203.0.113.5", "IP_ADDRESS")
        invasive = _FakeModule("sfp_nmap", flags=["invasive"])
        event = SpiderFootEvent("IP_ADDRESS", "203.0.113.5", "sfp_dnsresolve", None)

        self.assertTrue(scanner.shouldDispatchToModule(invasive, event))

    def test_extract_ip_for_shared_check(self):
        extract = SpiderFootScanner._extractIPForSharedCheck
        self.assertEqual(extract("151.101.3.7"), "151.101.3.7")
        self.assertEqual(extract("151.101.3.7:443"), "151.101.3.7")
        self.assertEqual(extract("151.101.3.7:443/tcp (https)"), "151.101.3.7")
        self.assertIsNone(extract("example.com"))
        self.assertIsNone(extract("2606:4700:3037::ac43:ac5f"))

    def test_invasive_module_rejects_owned_subdomain_on_shared_cdn_edge(self):
        # The structural gap found live 2026-11-13, distinct from the
        # markIPShared() race above: the target's own subdomain resolves
        # DIRECTLY to a Cloudflare anycast edge. matches() is correctly
        # True (it's a real alias) and markIPShared() is NEVER called -
        # there is no affiliate hop, no co-hosted-site discovery, nothing
        # for the reactive mechanism to key off at all. Only the static
        # CDN-range check (independent of any other module having run)
        # can catch this.
        scanner = self._build_scanner("braedach.com", "INTERNET_NAME")
        scanner._SpiderFootScanner__target.setAlias("104.21.71.238", "IP_ADDRESS")
        scanner._SpiderFootScanner__cdnRanges = dict(cdn_ranges.FALLBACK_RANGES)
        invasive = _FakeModule("sfp_nmap", flags=["invasive"])
        event = SpiderFootEvent("IP_ADDRESS", "104.21.71.238", "sfp_dnsresolve", None)

        self.assertFalse(scanner.shouldDispatchToModule(invasive, event))
        # Confirms it really was the static check, not the reactive one.
        self.assertFalse(scanner._SpiderFootScanner__target.isSharedIP("104.21.71.238"))

    def test_invasive_module_rejects_shared_cdn_ip_with_port_suffix(self):
        scanner = self._build_scanner("braedach.com", "INTERNET_NAME")
        scanner._SpiderFootScanner__target.setAlias("151.101.3.7", "IP_ADDRESS")
        scanner._SpiderFootScanner__cdnRanges = dict(cdn_ranges.FALLBACK_RANGES)
        invasive = _FakeModule("sfp_httpx", flags=["invasive"])
        event = SpiderFootEvent("TCP_PORT_OPEN", "151.101.3.7:443", "sfp_internetdb", None)

        self.assertFalse(scanner.shouldDispatchToModule(invasive, event))

    def test_invasive_module_accepts_own_literal_ip_target_even_if_in_cdn_range(self):
        # The exemption must hold: if the user's own directly-authorised
        # target IP genuinely falls within a published CDN range, the
        # static check must never block their own authorised scan.
        scanner = self._build_scanner("151.101.3.7", "IP_ADDRESS")
        scanner._SpiderFootScanner__cdnRanges = dict(cdn_ranges.FALLBACK_RANGES)
        invasive = _FakeModule("sfp_nmap", flags=["invasive"])
        event = SpiderFootEvent("IP_ADDRESS", "151.101.3.7", "sfp_hackertarget", None)

        self.assertTrue(scanner.shouldDispatchToModule(invasive, event))

    def test_invasive_module_accepts_ip_not_in_any_cdn_range(self):
        # Baseline: an ordinary dedicated IP, not in any known CDN range
        # and never marked shared, is unaffected by either check.
        scanner = self._build_scanner("example.com", "INTERNET_NAME")
        scanner._SpiderFootScanner__target.setAlias("203.0.113.5", "IP_ADDRESS")
        scanner._SpiderFootScanner__cdnRanges = dict(cdn_ranges.FALLBACK_RANGES)
        invasive = _FakeModule("sfp_nmap", flags=["invasive"])
        event = SpiderFootEvent("IP_ADDRESS", "203.0.113.5", "sfp_dnsresolve", None)

        self.assertTrue(scanner.shouldDispatchToModule(invasive, event))

    def test_invasive_module_accepts_full_url_on_target_own_domain(self):
        # The bug found live 2026-11-13: matches() has no URL parsing, so a
        # full LINKED_URL_INTERNAL/URL_FORM-style URL for the target's own
        # page was always rejected outright as "out of target scope" -
        # every invasive URL-fuzzing module (dalfox/ffuf/arjun/katana/
        # gobuster) had silently never been able to dispatch on any domain
        # scan since this gate shipped.
        scanner = self._build_scanner("example.com", "INTERNET_NAME")
        invasive = _FakeModule("sfp_tool_dalfox", flags=["invasive"])
        event = SpiderFootEvent(
            "URL_FORM", "https://example.com/login.jsp?user=x", "sfp_spider", None)

        self.assertTrue(scanner.shouldDispatchToModule(invasive, event))

    def test_invasive_module_accepts_full_url_with_port_on_target_subdomain(self):
        scanner = self._build_scanner("example.com", "INTERNET_NAME")
        scanner._SpiderFootScanner__target.setAlias("www.example.com", "INTERNET_NAME")
        invasive = _FakeModule("sfp_tool_ffuf", flags=["invasive"])
        event = SpiderFootEvent(
            "LINKED_URL_INTERNAL", "http://www.example.com:8080/admin", "sfp_spider", None)

        self.assertTrue(scanner.shouldDispatchToModule(invasive, event))

    def test_invasive_module_still_rejects_full_url_on_unrelated_domain(self):
        # The fix must not become a bypass - an out-of-scope URL is still
        # correctly rejected, just via its extracted hostname instead of
        # the full URL string.
        scanner = self._build_scanner("example.com", "INTERNET_NAME")
        invasive = _FakeModule("sfp_tool_dalfox", flags=["invasive"])
        event = SpiderFootEvent(
            "URL_FORM", "https://unrelated-third-party.com/login", "sfp_spider", None)

        self.assertFalse(scanner.shouldDispatchToModule(invasive, event))

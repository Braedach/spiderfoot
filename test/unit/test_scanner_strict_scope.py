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

from spiderfoot import SpiderFootEvent
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

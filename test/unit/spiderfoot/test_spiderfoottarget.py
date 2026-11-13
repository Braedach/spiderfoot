from __future__ import annotations

"""Tests for spiderfoottarget module."""

import unittest
from test.unit.utils.test_module_base import TestModuleBase
from spiderfoot.target import SpiderFootTarget
from test.unit.utils.test_base import TestModuleBase
from test.unit.utils.resource_manager import get_test_resource_manager
from test.unit.utils.thread_registry import get_test_thread_registry
from test.unit.utils.test_helpers import safe_recursion


class TestSpiderFootTarget(TestModuleBase):

    def setUp(self):
        super().setUp()
        self.target_value = "example.com"
        self.target_type = "INTERNET_NAME"
        self.target = SpiderFootTarget(self.target_value, self.target_type)
        # Register event emitters if they exist
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def test_init(self):
        self.assertEqual(self.target.targetType, self.target_type)
        self.assertEqual(self.target.targetValue, self.target_value)
        self.assertEqual(self.target.targetAliases, [])

    def test_targetType_setter_invalid_type(self):
        with self.assertRaises(TypeError):
            self.target.targetType = 123

    def test_targetType_setter_invalid_value(self):
        with self.assertRaises(ValueError):
            self.target.targetType = "INVALID_TYPE"

    def test_targetValue_setter_invalid_type(self):
        with self.assertRaises(TypeError):
            self.target.targetValue = 123

    def test_targetValue_setter_empty_value(self):
        with self.assertRaises(ValueError):
            self.target.targetValue = ""

    def test_setAlias(self):
        alias_value = "alias.com"
        alias_type = "INTERNET_NAME"
        self.target.setAlias(alias_value, alias_type)
        self.assertIn({"type": alias_type, "value": alias_value},
                      self.target.targetAliases)

    def test_setAlias_invalid_value_type(self):
        self.target.setAlias(123, "INTERNET_NAME")
        self.assertNotIn({"type": "INTERNET_NAME", "value": 123},
                         self.target.targetAliases)

    def test_setAlias_empty_value(self):
        self.target.setAlias("", "INTERNET_NAME")
        self.assertNotIn({"type": "INTERNET_NAME", "value": ""},
                         self.target.targetAliases)

    def test_setAlias_invalid_typeName_type(self):
        self.target.setAlias("alias.com", 123)
        self.assertNotIn({"type": 123, "value": "alias.com"},
                         self.target.targetAliases)

    def test_setAlias_empty_typeName(self):
        self.target.setAlias("alias.com", "")
        self.assertNotIn({"type": "", "value": "alias.com"},
                         self.target.targetAliases)

    def test_getEquivalents(self):
        alias_value = "alias.com"
        alias_type = "INTERNET_NAME"
        self.target.setAlias(alias_value, alias_type)
        equivalents = self.target._getEquivalents(alias_type)
        self.assertIn(alias_value, equivalents)

    def test_getNames(self):
        alias_value = "alias.com"
        alias_type = "INTERNET_NAME"
        self.target.setAlias(alias_value, alias_type)
        names = self.target.getNames()
        self.assertIn(alias_value, names)
        self.assertIn(self.target_value, names)

    def test_getAddresses(self):
        alias_value = "192.168.1.1"
        alias_type = "IP_ADDRESS"
        self.target.setAlias(alias_value, alias_type)
        addresses = self.target.getAddresses()
        self.assertIn(alias_value, addresses)

    def test_matches(self):
        alias_value = "alias.com"
        alias_type = "INTERNET_NAME"
        self.target.setAlias(alias_value, alias_type)
        self.assertTrue(self.target.matches(alias_value))
        self.assertTrue(self.target.matches(self.target_value))
        self.assertFalse(self.target.matches("nonexistent.com"))

    def test_matches_case_insensitive(self):
        # DNS is case-insensitive — mixed-case in-scope hosts must match
        # (regression: matches() compared raw value against lowercased names).
        self.assertTrue(self.target.matches("EXAMPLE.COM"))
        self.assertTrue(self.target.matches("Sub.Example.COM"))
        self.assertTrue(self.target.matches("WWW.EXAMPLE.COM", includeChildren=True))

    def test_matches_suffix_bypass_blocked(self):
        # A look-alike domain sharing the suffix (without the dot boundary)
        # must NOT be considered in scope, regardless of case.
        self.assertFalse(self.target.matches("evilexample.com"))
        self.assertFalse(self.target.matches("EvilExample.com"))
        self.assertFalse(self.target.matches("notexample.com"))

    def test_matches_ip(self):
        alias_value = "192.168.1.1"
        alias_type = "IP_ADDRESS"
        self.target.setAlias(alias_value, alias_type)
        self.assertTrue(self.target.matches(alias_value))
        self.assertFalse(self.target.matches("10.0.0.1"))

    def test_matches_subnet(self):
        self.target.targetType = "NETBLOCK_OWNER"
        self.target.targetValue = "192.168.1.0/24"
        self.assertTrue(self.target.matches("192.168.1.1"))
        self.assertFalse(self.target.matches("10.0.0.1"))
        
    def test_matches_parent_domain(self):
        # Use a different target that doesn't match the parent domain directly
        target = SpiderFootTarget("sub.example.com", "INTERNET_NAME")
        target.setAlias("www.sub.example.com", "INTERNET_NAME")
        self.assertTrue(target.matches(
            "example.com", includeParents=True))
        self.assertFalse(target.matches(
            "example.com", includeParents=False))

    def test_matches_child_domain(self):
        alias_value = "example.com"
        alias_type = "INTERNET_NAME"
        self.target.setAlias(alias_value, alias_type)
        self.assertTrue(self.target.matches(
            "sub.example.com", includeChildren=True))
        self.assertFalse(self.target.matches(
            "sub.example.com", includeChildren=False))

    def test_mark_ip_shared_does_not_affect_matches(self):
        # markIPShared() must leave matches() entirely alone - it's a
        # separate, invasive-dispatch-only signal (see
        # SpiderFootScanner.shouldDispatchToModule() and its own tests).
        self.target.setAlias("151.101.3.7", "IP_ADDRESS")
        self.assertTrue(self.target.matches("151.101.3.7"))
        self.target.markIPShared("151.101.3.7")
        self.assertTrue(self.target.matches("151.101.3.7"))

    def test_is_shared_ip(self):
        self.assertFalse(self.target.isSharedIP("151.101.3.7"))
        self.target.markIPShared("151.101.3.7")
        self.assertTrue(self.target.isSharedIP("151.101.3.7"))
        # Case-insensitive, consistent with alias storage.
        self.target.markIPShared("2606:4700::1")
        self.assertTrue(self.target.isSharedIP("2606:4700::1"))

    def test_mark_ip_shared_invalid_input_ignored(self):
        self.target.markIPShared("")
        self.target.markIPShared(None)
        self.assertFalse(self.target.isSharedIP(""))
        self.assertFalse(self.target.isSharedIP(None))

    def test_is_shared_ip_unmarked_dedicated_ip_unaffected(self):
        # Baseline: an alias never marked shared (the common, single-tenant
        # case) must never be reported as shared.
        self.target.setAlias("203.0.113.5", "IP_ADDRESS")
        self.assertFalse(self.target.isSharedIP("203.0.113.5"))

    def test_mark_ip_shared_never_demotes_the_literal_ip_target(self):
        # The exact use case this must never break: a user explicitly
        # searches an IP address (e.g. the scope-guard validation's own
        # 101.189.0.149) and a historical/passive-DNS-style discovery
        # module reports a stale prior-occupant hostname for it - common
        # on residential/dynamic IPs. That must never block scanning the
        # address the user actually authorised.
        target = SpiderFootTarget("101.189.0.149", "IP_ADDRESS")
        target.markIPShared("101.189.0.149")
        self.assertFalse(target.isSharedIP("101.189.0.149"))

    def test_mark_ip_shared_never_demotes_an_address_in_the_owned_netblock(self):
        target = SpiderFootTarget("203.0.113.0/24", "NETBLOCK_OWNER")
        target.markIPShared("203.0.113.42")
        self.assertFalse(target.isSharedIP("203.0.113.42"))
        # An address genuinely outside the owned block is unaffected by
        # the exemption and can still be marked.
        target.markIPShared("198.51.100.1")
        self.assertTrue(target.isSharedIP("198.51.100.1"))

    def test_mark_ip_shared_is_a_noop_for_asn_targets(self):
        # BGP_AS_OWNER has no netblock-membership check in matches() at
        # all - an ASN's scope is entirely its registered aliases, by
        # construction. Exempted for the same reason as NETBLOCK_OWNER.
        # UNTESTED against a real ASN scan - no authorised ASN scope
        # exists to validate this against (2026-11-13).
        target = SpiderFootTarget("AS64512", "BGP_AS_OWNER")
        target.markIPShared("203.0.113.5")
        self.assertFalse(target.isSharedIP("203.0.113.5"))

    def test_mark_ip_shared_still_works_for_a_secondary_ip_on_a_domain_target(self):
        # The actual bug this fix addresses: a domain target's subdomain
        # resolves to a secondary (non-literal-target) IP that turns out
        # to be a shared CDN edge. This must still work.
        target = SpiderFootTarget("example.com", "INTERNET_NAME")
        target.setAlias("151.101.3.7", "IP_ADDRESS")
        target.markIPShared("151.101.3.7")
        self.assertTrue(target.isSharedIP("151.101.3.7"))

    def test_is_directly_authorised_scope_ip_target(self):
        target = SpiderFootTarget("101.189.0.149", "IP_ADDRESS")
        self.assertTrue(target.isDirectlyAuthorisedScope("101.189.0.149"))
        self.assertFalse(target.isDirectlyAuthorisedScope("101.189.0.150"))

    def test_is_directly_authorised_scope_netblock_target(self):
        target = SpiderFootTarget("203.0.113.0/24", "NETBLOCK_OWNER")
        self.assertTrue(target.isDirectlyAuthorisedScope("203.0.113.42"))
        self.assertFalse(target.isDirectlyAuthorisedScope("198.51.100.1"))

    def test_is_directly_authorised_scope_asn_target_is_always_true(self):
        target = SpiderFootTarget("AS64512", "BGP_AS_OWNER")
        self.assertTrue(target.isDirectlyAuthorisedScope("203.0.113.5"))

    def test_is_directly_authorised_scope_domain_target_is_always_false(self):
        # A domain target has no literal IP/netblock/ASN scope of its own -
        # every address reaches it only via alias, never direct authorisation.
        target = SpiderFootTarget("example.com", "INTERNET_NAME")
        self.assertFalse(target.isDirectlyAuthorisedScope("151.101.3.7"))

    def test_is_known_cdn_ip_detects_published_range(self):
        # Real braedach.com incident IP (Fastly/Ghost.io edge).
        target = SpiderFootTarget("example.com", "INTERNET_NAME")
        self.assertEqual(target.isKnownCdnIP("151.101.3.7"), "Fastly")
        # Real incident IP (Cloudflare anycast edge).
        self.assertEqual(target.isKnownCdnIP("104.21.71.238"), "Cloudflare")

    def test_is_known_cdn_ip_returns_none_for_non_cdn_address(self):
        target = SpiderFootTarget("example.com", "INTERNET_NAME")
        self.assertIsNone(target.isKnownCdnIP("203.0.113.5"))

    def test_is_known_cdn_ip_never_overridden_by_own_scope(self):
        # This is the whole point of the exemption: even if the user's own
        # directly-authorised IP genuinely falls within a published CDN
        # range (e.g. they run infrastructure behind Cloudflare/Fastly
        # themselves), the static check must never block their own target.
        target = SpiderFootTarget("151.101.3.7", "IP_ADDRESS")
        self.assertIsNone(target.isKnownCdnIP("151.101.3.7"))

        netblock_target = SpiderFootTarget("104.21.71.0/24", "NETBLOCK_OWNER")
        self.assertIsNone(netblock_target.isKnownCdnIP("104.21.71.238"))

    def test_is_known_cdn_ip_still_works_for_an_owned_subdomain_on_a_shared_edge(self):
        # The exact structural gap found live 2026-11-13: a domain
        # target's OWN subdomain correctly matches() scope and resolves
        # directly to a CDN anycast edge, with no affiliate hop and no
        # markIPShared() call ever involved. isKnownCdnIP() must catch
        # this independently of the reactive mechanism.
        target = SpiderFootTarget("braedach.com", "INTERNET_NAME")
        target.setAlias("104.21.71.238", "IP_ADDRESS")
        self.assertFalse(target.isSharedIP("104.21.71.238"))
        self.assertEqual(target.isKnownCdnIP("104.21.71.238"), "Cloudflare")

    def tearDown(self):
        """Clean up after each test."""
        super().tearDown()

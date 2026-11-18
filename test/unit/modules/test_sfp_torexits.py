from __future__ import annotations

"""Tests for sfp_torexits module."""

import pytest
import unittest

from modules.sfp_torexits import sfp_torexits
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleTorexits(TestModuleBase):

    def test_opts(self):
        module = sfp_torexits()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_torexits()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_torexits()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_torexits()
        self.assertIsInstance(module.producedEvents(), list)

    def setUp(self):
        """Set up before each test."""
        super().setUp()
        # Register event emitters if they exist
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        """Clean up after each test."""
        super().tearDown()


class TestTorexitsNetblocks(unittest.TestCase):
    """A netblock must be checked against the exit list, never enumerated."""

    EXITS = ["101.160.5.9", "203.0.113.7", "2001:db8::1"]

    def _module(self):
        from spiderfoot import SpiderFootEvent
        sf = SpiderFoot({"_useragent": "x", "_fetchtimeout": 5, "__logging": False})
        mod = sfp_torexits()
        mod.setup(sf, {})
        mod.__name__ = "sfp_torexits"
        mod.checkForStop = lambda: False
        mod.calls = 0

        def fake_retrieve():
            mod.calls += 1
            return list(self.EXITS)
        mod.retrieveExitNodes = fake_retrieve
        mod.out = []
        mod.notifyListeners = lambda e: mod.out.append((e.eventType, e.data))
        root = SpiderFootEvent("ROOT", "x", "", "")
        return mod, root, SpiderFootEvent

    def test_huge_netblock_is_fast_and_parses_once(self):
        import time
        mod, root, Evt = self._module()
        t = time.time()
        mod.handleEvent(Evt("NETBLOCK_OWNER", "101.160.0.0/11", "sfp_ripe", root))
        self.assertLess(time.time() - t, 2)
        self.assertEqual(mod.calls, 1)
        self.assertEqual(mod.out, [("IP_ADDRESS", "101.160.5.9"), ("TOR_EXIT_NODE", "101.160.5.9")])

    def test_ip_events_reuse_the_parsed_list(self):
        mod, root, Evt = self._module()
        for ip in ("1.1.1.1", "203.0.113.7", "8.8.8.8"):
            mod.handleEvent(Evt("IP_ADDRESS", ip, "sfp_x", root))
        self.assertEqual(mod.calls, 1)
        self.assertEqual(mod.out, [("TOR_EXIT_NODE", "203.0.113.7")])

    def test_ipv6_netblock(self):
        mod, root, Evt = self._module()
        mod.handleEvent(Evt("NETBLOCKV6_OWNER", "2001:db8::/32", "sfp_ripe", root))
        self.assertEqual(mod.out, [("IPV6_ADDRESS", "2001:db8::1"), ("TOR_EXIT_NODE", "2001:db8::1")])

    def test_netblock_without_exit_nodes_emits_nothing(self):
        mod, root, Evt = self._module()
        mod.handleEvent(Evt("NETBLOCK_OWNER", "10.0.0.0/8", "sfp_ripe", root))
        self.assertEqual(mod.out, [])

    def test_checknetblocks_off_skips_netblock(self):
        mod, root, Evt = self._module()
        mod.opts["checknetblocks"] = False
        mod.handleEvent(Evt("NETBLOCK_OWNER", "101.160.0.0/11", "sfp_ripe", root))
        self.assertEqual(mod.calls, 0)
        self.assertEqual(mod.out, [])

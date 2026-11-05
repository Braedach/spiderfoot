from __future__ import annotations

"""Tests for sfp_hackertarget module."""

import pytest
import unittest
from unittest.mock import MagicMock, patch

from modules.sfp_hackertarget import sfp_hackertarget
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleHackertarget(TestModuleBase):

    def test_opts(self):
        module = sfp_hackertarget()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_hackertarget()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_hackertarget()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_hackertarget()
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

    def _make_module(self, target):
        """Build a module wired to a real target, with network calls stubbed out."""
        sf = SpiderFoot(self.default_options)
        module = sfp_hackertarget()
        module.__name__ = "sfp_hackertarget"
        module.setup(sf, dict())
        module.setTarget(target)
        module.notifyListeners = MagicMock()
        # Every address "resolves" to some host, so the netblock-wide
        # IP_ADDRESS/CO_HOSTED_SITE emission path (reached only when
        # reverseIpLookup finds something) actually runs for each address
        # considered - this is what happens on a real, densely-populated /24.
        module.reverseIpLookup = MagicMock(
            side_effect=lambda ip: [f"host-{ip}.example.net"])
        module.httpHeaders = MagicMock(return_value=None)
        return module

    def test_handleEvent_netblock_owner_only_expands_in_scope_ips(self):
        # Target is a single IP within 203.0.113.0/24: matches() only matches
        # that one address, so the netblock must not be fanned out to the
        # other 253 addresses in it.
        target = SpiderFootTarget("203.0.113.5", "IP_ADDRESS")
        module = self._make_module(target)

        event = SpiderFootEvent("ROOT", "203.0.113.5", "sfp_hackertarget", None)
        netblock_event = SpiderFootEvent(
            "NETBLOCK_OWNER", "203.0.113.0/24", "sfp_ripe", event)

        module.handleEvent(netblock_event)

        emitted_ips = {
            call.args[0].data
            for call in module.notifyListeners.call_args_list
            if call.args[0].eventType == "IP_ADDRESS"
        }
        self.assertEqual(emitted_ips, {"203.0.113.5"})

    def test_handleEvent_netblock_owner_expands_full_block_for_netblock_target(self):
        # When the user's own target IS the netblock, scanning every address
        # in it is exactly what was asked for, so it is not restricted.
        target = SpiderFootTarget("203.0.113.0/30", "NETBLOCK_OWNER")
        module = self._make_module(target)

        event = SpiderFootEvent("ROOT", "203.0.113.0/30", "sfp_hackertarget", None)
        netblock_event = SpiderFootEvent(
            "NETBLOCK_OWNER", "203.0.113.0/30", "sfp_ripe", event)

        module.handleEvent(netblock_event)

        emitted_ips = {
            call.args[0].data
            for call in module.notifyListeners.call_args_list
            if call.args[0].eventType == "IP_ADDRESS"
        }
        self.assertEqual(
            emitted_ips,
            {"203.0.113.0", "203.0.113.1", "203.0.113.2", "203.0.113.3"},
        )

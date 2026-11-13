from __future__ import annotations

"""Tests for sfp_dnsresolve module."""

import pytest
import unittest

from modules.sfp_dnsresolve import sfp_dnsresolve
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleDnsResolve(TestModuleBase):

    def test_opts(self):
        module = sfp_dnsresolve()
        self.assertTrue(set(module.optdescs.keys()).issubset(set(module.opts.keys())))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_dnsresolve()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_dnsresolve()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_dnsresolve()
        self.assertIsInstance(module.producedEvents(), list)

    def test_max_threads_raised_above_the_shared_default(self):
        # This module is the single highest-fan-in module in the catalog -
        # see the class attribute's own comment for the live incident
        # (28+ minute scan stall, 2026-11-13) that justified raising it
        # above plugin.py's generic default of 10.
        module = sfp_dnsresolve()
        self.assertGreater(module.maxThreads, 10)

    def setUp(self):
        """Set up before each test."""
        super().setUp()
        # Register event emitters if they exist
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        """Clean up after each test."""
        super().tearDown()

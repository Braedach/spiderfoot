from __future__ import annotations

"""Tests for sfp_accounts module."""

import pytest
import unittest

from modules.sfp_accounts import sfp_accounts
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleAccounts(TestModuleBase):

    def test_opts(self):
        module = sfp_accounts()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_accounts()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_accounts()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_accounts()
        self.assertIsInstance(module.producedEvents(), list)

    def test_checkSites_normal_case_still_works(self):
        """Baseline regression check: checkSites()'s new overall deadline
        (added 2026-11-13 - see sfp_s3bucket's test for the full incident
        this guards against, the same pattern applied via sequential
        thread.join() here instead of a threading.enumerate() busy-wait)
        must not change behaviour for the common case where every check
        returns quickly.
        """
        sf = SpiderFoot(self.default_options)
        module = sfp_accounts()
        module.setup(sf, {'_fetchtimeout': 5, 'batch_size': 2})

        module.checkSite = lambda name, site: None  # returns immediately

        result = module.checkSites(
            'testuser', sites=[{'name': 'site-a'}, {'name': 'site-b'}])

        self.assertEqual(result, [])

    def setUp(self):
        """Set up before each test."""
        super().setUp()
        # Register event emitters if they exist
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        """Clean up after each test."""
        super().tearDown()

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

    def test_checkSites_slow_but_progressing_run_is_not_cut_short(self):
        """20 threads legitimately take longer than a flat total deadline to work through hundreds of
        sites; the old 30 s total deadline cut every username short and skipped the rest. As long as
        checks keep completing, the run must finish."""
        import time
        sf = SpiderFoot(self.default_options)
        module = sfp_accounts()
        module.setup(sf, {'_fetchtimeout': 0, 'batch_size': 2})
        module.STALL_FLOOR = 1
        done = []

        def slow_check(name, site):
            time.sleep(0.3)           # each check is quick, but 8 of them over 2 threads take ~1.2 s > STALL_FLOOR
            done.append(site['name'])

        module.checkSite = slow_check
        module.error = lambda *a, **k: self.fail("a progressing run must not be abandoned")
        module.checkSites('testuser', sites=[{'name': f's{i}'} for i in range(8)])
        self.assertEqual(len(done), 8)

    def test_checkSites_abandons_when_nothing_makes_progress(self):
        """A genuinely hung check must still not block the scan forever."""
        import threading
        import time
        sf = SpiderFoot(self.default_options)
        module = sfp_accounts()
        module.setup(sf, {'_fetchtimeout': 0, 'batch_size': 1})
        module.STALL_FLOOR = 1
        release = threading.Event()
        module.checkSite = lambda name, site: release.wait(30)
        errors = []
        module.error = lambda msg, *a, **k: errors.append(msg)
        start = time.monotonic()
        module.checkSites('testuser', sites=[{'name': 'hung'}])
        release.set()
        self.assertLess(time.monotonic() - start, 5)
        self.assertEqual(len(errors), 1)
        self.assertIn('stopped making progress', errors[0])

    def setUp(self):
        """Set up before each test."""
        super().setUp()
        # Register event emitters if they exist
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        """Clean up after each test."""
        super().tearDown()

from __future__ import annotations

"""Tests for sfp_s3bucket module."""

import pytest
import unittest

from modules.sfp_s3bucket import sfp_s3bucket
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleS3bucket(TestModuleBase):

    def test_opts(self):
        module = sfp_s3bucket()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_s3bucket()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_s3bucket()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_s3bucket()
        self.assertIsInstance(module.producedEvents(), list)

    def test_threadSites_does_not_hang_forever_on_a_stuck_checkSite(self):
        """Regression test for a real live incident (2026-11-13): a single
        hung bucket check (checkSite() never returning - no response, a
        firewall drop, a slow-loris stall) used to block threadSites()
        forever, which blocks handleEvent() forever, which stalls the
        WHOLE SCAN forever with no error and no crash. threadSites() must
        give up after its deadline instead of waiting unconditionally for
        a thread that will never finish.
        """
        import threading
        import time as time_module
        from unittest.mock import patch

        sf = SpiderFoot(self.default_options)
        module = sfp_s3bucket()
        module.setup(sf, {'_fetchtimeout': 1})

        never_set = threading.Event()
        module.checkSite = lambda url: never_set.wait()  # never returns

        # Fast-forward virtual time so the test doesn't actually wait out
        # the real deadline (max(30, _fetchtimeout*4) seconds).
        start = time_module.monotonic()
        fake_now = [start]

        def fake_monotonic():
            fake_now[0] += 5
            return fake_now[0]

        with patch('time.monotonic', side_effect=fake_monotonic):
            result = module.threadSites(['http://stuck-bucket.example.com'])

        # Must return (not hang the test), and the stuck checkSite() call
        # simply produced no result rather than wedging the module.
        self.assertEqual(result, {})

    def setUp(self):
        """Set up before each test."""
        super().setUp()
        # Register event emitters if they exist
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        """Clean up after each test."""
        super().tearDown()

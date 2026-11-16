from __future__ import annotations

"""Tests for sfp_crt module."""

import pytest
import unittest

from modules.sfp_crt import sfp_crt
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleCrt(TestModuleBase):


    def setUp(self):
        """Enhanced setUp with ThreadReaper module tracking."""
        super().setUp()
        # ThreadReaper infrastructure is automatically initialized
        
    def tearDown(self):
        """Enhanced tearDown with ThreadReaper cleanup."""
        # ThreadReaper infrastructure automatically cleans up
        super().tearDown()
    def test_opts(self):
        module = sfp_crt()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_crt()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_crt()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_crt()
        self.assertIsInstance(module.producedEvents(), list)

    def test_parseApiResponse_nonfatal_http_response_code_should_not_set_errorState(self):
        sf = SpiderFoot(self.default_options)

        http_codes = ["200", "404"]
        for code in http_codes:
            with self.subTest(code=code):
                module = sfp_crt()
                module.setup(sf, dict())
                result = module.parseApiResponse(
                    {"code": code, "content": None})
                self.assertIsNone(result)
                self.assertFalse(module.errorState)

    def test_parseApiResponse_fatal_http_response_error_code_should_set_errorState(self):
        sf = SpiderFoot(self.default_options)

        http_codes = ["401", "403", "429", "500", "502", "503"]
        for code in http_codes:
            with self.subTest(code=code):
                module = sfp_crt()
                module.setup(sf, dict())
                result = module.parseApiResponse(
                    {"code": code, "content": None})
                self.assertIsNone(result)
                self.assertTrue(module.errorState)

    def setUp(self):
        """Set up before each test."""
        super().setUp()
        # Register event emitters if they exist
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        """Clean up after each test."""
        super().tearDown()


# ---------------------------------------------------------------------------------------------------------------
# crt.sh is often slow or overloaded. A live scan logged "No response from crt.sh" 40 times and its certificate
# history stopped a year short of the live certificate.

from unittest import mock as _mock


class TestCrtRetries(TestModuleBase):

    def _module(self, answers, **opts):
        m = sfp_crt()
        m.__name__ = "sfp_crt"
        m.setup(SpiderFoot(self.default_options), {"_useragent": "SpiderFoot", "retrywait": 0, **opts})
        self.calls = []
        queue = list(answers)

        def fake_fetch(url, **kw):
            self.calls.append(url)
            return queue.pop(0) if queue else None
        m.fetch_url = fake_fetch
        m.checkForStop = lambda: False
        return m

    def test_a_missing_answer_is_retried_and_a_later_success_is_used(self):
        ok = {"code": "200", "content": '[{"id": 1}]'}
        with _mock.patch("modules.sfp_crt.time.sleep"):
            res = self._module([None, None, ok])._fetch_with_retry("https://crt.sh/?q=x")
        assert res is ok and len(self.calls) == 3

    def test_a_server_error_or_rate_limit_is_retried(self):
        ok = {"code": "200", "content": "x"}
        with _mock.patch("modules.sfp_crt.time.sleep"):
            res = self._module([{"code": "503", "content": ""}, {"code": "429", "content": ""}, ok])._fetch_with_retry("u")
        assert res is ok

    def test_a_clean_answer_including_not_found_is_not_retried(self):
        for answer in ({"code": "200", "content": "[]"}, {"code": "404", "content": ""}):
            with _mock.patch("modules.sfp_crt.time.sleep"):
                m = self._module([answer])
                assert m._fetch_with_retry("u") is answer and len(self.calls) == 1

    def test_it_gives_up_after_the_configured_retries(self):
        with _mock.patch("modules.sfp_crt.time.sleep"):
            m = self._module([None] * 10, retries=1)
            assert m._fetch_with_retry("u") is None
        assert len(self.calls) == 2

    def test_the_pause_grows_with_each_retry(self):
        with _mock.patch("modules.sfp_crt.time.sleep") as sleep:
            self._module([None] * 5, retries=3, retrywait=2)._fetch_with_retry("u")
        assert [c.args[0] for c in sleep.call_args_list] == [2.0, 4.0, 6.0]

    def test_zero_retries_means_one_attempt(self):
        with _mock.patch("modules.sfp_crt.time.sleep"):
            m = self._module([None, None], retries=0)
            m._fetch_with_retry("u")
        assert len(self.calls) == 1

    def test_the_options_are_documented(self):
        assert set(sfp_crt.opts) == set(sfp_crt.optdescs)

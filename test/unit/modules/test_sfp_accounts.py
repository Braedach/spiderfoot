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


# ---------------------------------------------------------------------------------------------------------------
# Name-scan false positives (2026-11-16): a site's search page was reported as an account ("Scribd ... /search?query=
# leon.marcus.scott&verbatim=true"), and a dotted name produced impossible nested subdomains.

from spiderfoot.sflib import SpiderFoot as _SF
from modules.sfp_accounts import sfp_accounts as _Accounts

_SEARCH_SITE = {"name": "ExampleDocs", "cat": "hobby", "uri_check": "https://docs.example/search?query={account}&verbatim=true",
                "e_code": 200, "e_string": "results", "m_code": 404, "m_string": "no results"}
_SUBDOMAIN_SITE = {"name": "ExampleBlogs", "cat": "blog", "uri_check": "https://{account}.blogs.example/",
                   "e_code": 200, "e_string": "welcome", "m_code": 404, "m_string": "gone"}
_PROFILE_SITE = {"name": "ExampleSocial", "cat": "social", "uri_check": "https://social.example/u/{account}",
                 "e_code": 200, "e_string": "profile", "m_code": 404, "m_string": "gone"}


class TestAccountsFalsePositives(TestModuleBase):

    def _module(self, content="profile results welcome"):
        m = _Accounts()
        m.__name__ = "sfp_accounts"
        m.opts = dict(_Accounts.opts, _fetchtimeout=5, _useragent="t", musthavename=False)
        m.siteResults = {}
        import threading
        m.lock = threading.Lock()
        self.fetched = []

        def fake(url, **kw):
            self.fetched.append(url)
            return {"code": "200", "content": content}
        m.fetch_url = fake
        m.debug = lambda *a, **k: None
        return m

    def test_a_dotted_name_is_not_checked_as_a_subdomain(self):
        m = self._module()
        m.checkSite("leon.marcus.scott", _SUBDOMAIN_SITE)
        assert not self.fetched and not m.siteResults                       # no request, no result

    def test_a_plain_name_is_still_checked_as_a_subdomain(self):
        m = self._module()
        m.checkSite("leonscott", _SUBDOMAIN_SITE)
        assert self.fetched == ["https://leonscott.blogs.example/"]
        assert list(m.siteResults.values()) == [True]

    def test_a_dotted_name_is_still_checked_on_ordinary_profile_urls(self):
        m = self._module()
        m.checkSite("leon.scott", _PROFILE_SITE)
        assert self.fetched == ["https://social.example/u/leon.scott"]

    def test_a_search_page_check_still_reports_but_says_how_weak_the_evidence_is(self):
        m = self._module()
        m.checkSite("leon.marcus.scott", _SEARCH_SITE)
        (text, found), = m.siteResults.items()
        assert found is True
        assert "ExampleDocs (Category: hobby)" in text and "<SFURL>" in text
        assert "weak evidence" in text and "search page" in text

    def test_a_profile_check_carries_no_weakness_note(self):
        m = self._module()
        m.checkSite("leonscott", _PROFILE_SITE)
        (text, found), = m.siteResults.items()
        assert found is True and "weak evidence" not in text

    def test_the_weak_check_pattern_matches_search_urls_only(self):
        weak = _Accounts.WEAK_CHECK
        for url in ("https://x.example/search?query={account}", "https://x.example/?q={account}",
                    "https://x.example/find?search={account}", "https://x.example/search/{account}"):
            assert weak.search(url), url
        for url in ("https://x.example/u/{account}", "https://{account}.x.example/", "https://x.example/research/{account}",
                    "https://x.example/profile?id={account}"):
            assert not weak.search(url), url

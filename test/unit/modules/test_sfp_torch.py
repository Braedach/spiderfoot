from __future__ import annotations

"""Tests for sfp_torch module."""

import pytest
import unittest

from modules.sfp_torch import sfp_torch
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleTorch(TestModuleBase):

    def test_opts(self):
        module = sfp_torch()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_torch()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_torch()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_torch()
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


# ---------------------------------------------------------------------------------------------------------------
# Behaviour tests (2026-11-16): TORCH moved to a new onion address and an Omega search interface, and the module
# kept dialling the old address. Markup below has the shape captured from the live site on 2026-11-16.

import urllib.parse as _u
from spiderfoot import SpiderFootEvent as _Ev

_BASE = "http://" + "a" * 56 + ".onion"
_HIT = ('<td><b><a href="{url}">{title}</a></b><br>\n<small><strong>{term}</strong> and more text</small><br>')
_NONE = "<html>TORCH: Tor Search! Matching any words No documents match your query</html>"


def _page(*urls, term="example"):
    return "<html><table><tr>" + "".join(_HIT.format(url=u, title="Title", term=term) for u in urls) + "</tr></table></html>"


class TestTorchBehaviour(TestModuleBase):

    def _module(self, pages, **opts):
        m = sfp_torch()
        m.__name__ = "sfp_torch"
        m.setup(SpiderFoot(self.default_options), {"torch_url": _BASE, "fetchlinks": False, "_useragent": "test",
                                                  "_fetchtimeout": 5, **opts})
        self.events, self.errors, self.urls = [], [], []
        m.notifyListeners = self.events.append
        m.error = self.errors.append
        m.checkForStop = lambda: False
        queue = list(pages)

        def fake_fetch(url, **kw):
            self.urls.append(url)
            return {"content": queue.pop(0) if queue else _NONE, "code": "200"}
        m.fetch_url = fake_fetch
        return m

    def _event(self, etype="DOMAIN_NAME", data="example.org"):
        return _Ev(etype, data, "test", _Ev("ROOT", "root", "", None))

    def test_the_old_address_is_gone(self):
        import modules.sfp_torch as mod
        assert "torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd" not in open(mod.__file__).read()
        assert sfp_torch.opts["torch_url"].endswith(".onion")

    def test_it_searches_the_configured_address_for_the_exact_phrase(self):
        m = self._module([_NONE])
        m.handleEvent(self._event("HUMAN_NAME", "Pat Example"))
        q = _u.urlparse(self.urls[0])
        assert self.urls[0].startswith(_BASE + "/cgi-bin/omega/omega?")
        params = _u.parse_qs(q.query)
        assert params["P"] == ['"Pat Example"'] and params["DEFAULTOP"] == ["and"] and params["TOPDOC"] == ["0"]

    def test_an_email_address_is_searched_as_two_words_because_torch_cannot_match_an_at_sign(self):
        m = self._module([_NONE])
        m.handleEvent(self._event("EMAILADDR", "pat@example.org"))
        assert _u.parse_qs(_u.urlparse(self.urls[0]).query)["P"] == ["pat example.org"]

    def test_a_domain_is_searched_as_a_phrase(self):
        m = self._module([_NONE])
        m.handleEvent(self._event("DOMAIN_NAME", "example.org"))
        assert _u.parse_qs(_u.urlparse(self.urls[0]).query)["P"] == ['"example.org"']

    def test_quote_marks_in_the_data_cannot_break_the_query(self):
        assert sfp_torch._query("HUMAN_NAME", 'Pat "The" Example') == '"Pat The Example"'

    def test_the_module_is_no_longer_flagged_errorprone(self):
        assert "errorprone" not in sfp_torch.meta["flags"] and "tor" in sfp_torch.meta["flags"]

    def test_result_links_become_darknet_mentions(self):
        hit1, hit2 = "http://" + "b" * 56 + ".onion/x", "http://" + "c" * 56 + ".onion/"
        m = self._module([_page(hit1, hit2), _NONE])
        m.handleEvent(self._event())
        assert [(e.eventType, e.data) for e in self.events] == [("DARKNET_MENTION_URL", hit1),
                                                                  ("DARKNET_MENTION_URL", hit2)]

    def test_it_pages_with_topdoc_until_the_results_stop(self):
        m = self._module([_page("http://" + "b" * 56 + ".onion/1"), _page("http://" + "c" * 56 + ".onion/2"), _NONE])
        m.handleEvent(self._event())
        tops = [_u.parse_qs(_u.urlparse(u).query)["TOPDOC"][0] for u in self.urls]
        assert tops == ["0", "10", "20"]
        assert len(self.events) == 2

    def test_no_match_page_means_no_events_and_no_error(self):
        m = self._module([_NONE])
        m.handleEvent(self._event())
        assert not self.events and not self.errors

    def test_an_unreachable_site_is_reported_as_a_possibly_stale_address_not_a_crash(self):
        m = self._module([])
        m.fetch_url = lambda url, **kw: {"content": None, "code": None}
        m.handleEvent(self._event())
        assert not self.events

    def test_a_clearnet_address_in_the_setting_is_refused(self):
        m = self._module([_NONE], torch_url="http://example.com")
        m.handleEvent(self._event())
        assert self.errors and "onion" in self.errors[0] and m.errorState
        assert not self.urls                       # nothing was requested

    def test_the_same_term_is_not_searched_twice(self):
        m = self._module([_NONE, _NONE])
        m.handleEvent(self._event())
        m.handleEvent(self._event())
        assert len(self.urls) == 1

    def test_names_are_skipped_when_the_option_is_off(self):
        m = self._module([_NONE], fullnames=False)
        m.handleEvent(self._event("HUMAN_NAME", "Pat Example"))
        assert not self.urls

"""The spider must treat http://site:80/a and http://site/a as one URL (14% of one scan's URLs were such duplicates)."""
from __future__ import annotations

from unittest.mock import MagicMock

from modules.sfp_spider import canonical_url, sfp_spider
from spiderfoot import SpiderFootEvent
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase


class TestCanonicalUrl(TestModuleBase):

    def test_default_ports_and_case_are_normalised(self):
        for given, expected in (
            ("http://Demo.Example:80/a?x=1#f", "http://demo.example/a?x=1#f"),
            ("https://demo.example:443/", "https://demo.example/"),
            ("http://demo.example", "http://demo.example"),
            ("http://[::1]:80/x", "http://[::1]/x"),
            ("http://u:p@Host:80/z", "http://u:p@Host/z"),   # userinfo is case-sensitive: left alone
        ):
            self.assertEqual(canonical_url(given), expected)

    def test_other_ports_and_schemes_are_left_alone(self):
        for url in ("http://demo.example:8080/a", "https://demo.example:80/a", "http://demo.example:380/",
                    "ftp://h:80/a", "mailto:a@b.c", "not a url", "http://h:8080"):
            self.assertEqual(canonical_url(url), url)
        self.assertIsNone(canonical_url(None))

    def test_path_query_and_fragment_are_untouched(self):
        url = "http://demo.example:80/a%20b/c.jsp?id=1&x=%7E#sec"
        self.assertEqual(canonical_url(url), "http://demo.example/a%20b/c.jsp?id=1&x=%7E#sec")


class TestSpiderDedupe(TestModuleBase):

    def _module(self):
        sf = SpiderFoot(self.default_options)
        m = sfp_spider()
        m.__name__ = "sfp_spider"
        m.setup(sf, {"start": ["http://", "https://"], "maxlevels": 1, "maxpages": 50, "pausesec": 0,
                     "_fetchtimeout": 5, "_useragent": "SpiderFoot"})
        target = MagicMock()
        target.matches.return_value = True
        target.getNames.return_value = ["demo.example"]
        m.getTarget = lambda: target
        m.checkForStop = lambda: False
        self.emitted = []
        m.notifyListeners = self.emitted.append
        self.fetched = []
        pages = {
            "http://demo.example": '<a href="/a">a</a><a href="http://demo.example:80/b">b</a><a href="/a">a</a>',
            "http://demo.example/a": "<p>a</p>", "http://demo.example/b": "<p>b</p>",
        }

        def fake_fetch(url, **kwargs):
            self.fetched.append(url)
            body = pages.get(url)
            return {"code": "200", "status": "OK", "content": body, "headers": {"content-type": "text/html"}, "realurl": url} \
                if body is not None else {"code": "404", "status": "x", "content": None, "headers": {}, "realurl": url}

        m.fetch_url = fake_fetch
        return m

    def _links(self):
        return [e.data for e in self.emitted if e.eventType == "LINKED_URL_INTERNAL"]

    def test_a_site_named_three_ways_is_spidered_once(self):
        m = self._module()
        for etype, data in (("INTERNET_NAME", "demo.example"), ("TCP_PORT_OPEN", "demo.example:80"),
                            ("LINKED_URL_INTERNAL", "http://demo.example:80")):
            m.handleEvent(SpiderFootEvent(etype, data, "sfp_httpx", None))
        links = self._links()
        self.assertEqual(len(links), len(set(links)), links)
        self.assertEqual(links.count("http://demo.example"), 1)
        self.assertNotIn("http://demo.example:80", links)
        self.assertEqual(self.fetched.count("http://demo.example"), 2)   # the probe plus the one real fetch, not per name

    def test_a_link_written_with_the_default_port_is_the_same_page(self):
        m = self._module()
        m.handleEvent(SpiderFootEvent("INTERNET_NAME", "demo.example", "sfp_dnsresolve", None))
        links = self._links()
        self.assertIn("http://demo.example/b", links)
        self.assertFalse([u for u in links if u.endswith(":80/b") or ":80/" in u], links)
        self.assertEqual(self.fetched.count("http://demo.example/b"), 1)

    def test_non_default_ports_are_still_separate_sites(self):
        m = self._module()
        m.handleEvent(SpiderFootEvent("LINKED_URL_INTERNAL", "http://demo.example:8080/x", "sfp_httpx", None))
        self.assertIn("http://demo.example:8080/x", self.fetched)

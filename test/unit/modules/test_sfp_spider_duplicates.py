"""The spider must not fetch-and-store the same site again for every origin (http and https, name and IP, port 8080).
One live scan of a 108-page test site produced 7,050 events from 6 origins; only 20 distinct page contents were stored
for 1,642 pages."""
from __future__ import annotations

from unittest.mock import MagicMock

from modules.sfp_spider import sfp_spider
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase

HOME = '<html><a href="/a.jsp">a</a><a href="/b.jsp">b</a><p>Welcome   to   Example   Bank</p></html>'


class TestSpiderDuplicatePages(TestModuleBase):

    def _module(self, pages, **opts):
        m = sfp_spider()
        m.__name__ = "sfp_spider"
        m.setup(SpiderFoot(self.default_options), {"maxlevels": 2, "maxpages": 50, "pausesec": 0, "_fetchtimeout": 5,
                                                   "_useragent": "SpiderFoot", **opts})
        target = MagicMock()
        target.matches.return_value = True
        target.getNames.return_value = ["demo.example", "203.0.113.10"]
        m.getTarget = lambda: target
        m.checkForStop = lambda: False
        self.emitted = []
        m.notifyListeners = self.emitted.append

        def fake_fetch(url, **kw):
            body = pages(url) if callable(pages) else pages.get(url)
            return {"code": "200", "status": "OK", "content": body, "headers": {"content-type": "text/html", "server": "x"},
                    "realurl": url}
        m.fetch_url = fake_fetch
        return m

    def _count(self, etype):
        return len([e for e in self.emitted if e.eventType == etype])

    def _process(self, m, url):
        m.urlEvents[url] = None
        return m.processUrl(url)

    def test_the_same_page_on_another_origin_is_recorded_but_not_stored_or_followed(self):
        pages = {"http://demo.example/": HOME,
                 "https://demo.example/": HOME.replace('href="/a.jsp"', 'href="https://demo.example/a.jsp"'),
                 "https://203.0.113.10/": HOME}
        m = self._module(pages)
        first = self._process(m, "http://demo.example/")
        assert first and any(u.endswith("/a.jsp") for u in first)
        assert self._process(m, "https://demo.example/") is None          # links not followed again
        assert self._process(m, "https://203.0.113.10/") is None
        assert self._count("TARGET_WEB_CONTENT") == 1                      # the content was stored once
        assert self._count("HTTP_CODE") == 3                               # but every origin's status is still recorded
        assert self._count("WEBSERVER_HTTPHEADERS") == 3                   # and its headers (they can differ per origin)

    def test_different_pages_are_all_processed(self):
        m = self._module(lambda u: f"<html><a href='/x'>x</a>page for {u.rsplit('/', 1)[-1]}</html>")
        for path in ("a.jsp", "b.jsp", "c.jsp"):
            self._process(m, f"http://demo.example/{path}")
        assert self._count("TARGET_WEB_CONTENT") == 3

    def test_a_catch_all_server_is_not_crawled_into_a_trap(self):
        m = self._module(lambda u: '<html><a href="/next1">n</a><a href="/next2">n</a>same shell</html>')
        results = [self._process(m, f"http://demo.example/p{i}") for i in range(20)]
        assert results[0] is not None and all(r is None for r in results[1:])
        assert self._count("TARGET_WEB_CONTENT") == 1

    def test_with_the_option_off_every_page_is_processed_as_before(self):
        m = self._module({"http://demo.example/": HOME, "https://demo.example/": HOME}, skipduplicatepages=False)
        assert self._process(m, "http://demo.example/") and self._process(m, "https://demo.example/")
        assert self._count("TARGET_WEB_CONTENT") == 2

    def test_empty_pages_are_never_treated_as_duplicates(self):
        m = self._module({"http://demo.example/a": "", "http://demo.example/b": "   "})
        for url in ("http://demo.example/a", "http://demo.example/b"):
            self._process(m, url)
        assert self._count("HTTP_CODE") == 2

    def test_the_fingerprint_ignores_hosts_and_whitespace_only(self):
        fp = sfp_spider._page_fingerprint
        assert fp('<a href="http://a.example/x">x</a>  hi') == fp('<a href="https://203.0.113.10:8080/x">x</a> hi')
        assert fp("<p>one</p>") != fp("<p>two</p>")
        assert fp(b"<p>one</p>") == fp("<p>one</p>")
        assert fp("") is None and fp(None) is None

    def test_a_failure_in_the_check_never_stops_the_crawl(self):
        m = self._module({"http://demo.example/": HOME})
        m.pageHashes = None                                               # break the store
        assert self._process(m, "http://demo.example/")                   # still processed (treated as not a duplicate)

    def test_the_options_are_documented(self):
        assert set(sfp_spider.opts) == set(sfp_spider.optdescs)

"""Tests for sfp_onionsearch (multi-engine dark-web search)."""
from __future__ import annotations

from modules.sfp_onionsearch import DEFAULT_ENGINES, sfp_onionsearch
from spiderfoot import SpiderFootEvent
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase

A = "a" * 56
B = "b" * 56
C = "c" * 56
ENGINE = f"http://{A}.onion/search?q={{q}}"


def _page(*items):
    """Markup shaped like the engines' result lists: a link, then its snippet."""
    return "<html><nav><a href='http://%s.onion/'>home</a></nav>" % A + "".join(
        f"<div><a href='{u}'>Title</a><p>{s}</p></div>" for u, s in items) + "</html>"


class TestOnionSearch(TestModuleBase):

    def _module(self, pages, engines=None, **opts):
        m = sfp_onionsearch()
        m.__name__ = "sfp_onionsearch"
        m.setup(SpiderFoot(self.default_options), {"engines": engines or f"one = {ENGINE}", "delay": 0,
                                                  "_useragent": "t", "_fetchtimeout": 5, **opts})
        self.events, self.urls = [], []
        m.notifyListeners = self.events.append
        m.checkForStop = lambda: False
        m.getTarget = lambda: type("T", (), {"targetValue": "Pat Example"})()
        queue = dict(pages)

        def fake(url, **kw):
            self.urls.append(url)
            for key, body in queue.items():
                if url.startswith(key):
                    return {"content": body, "code": "200"}
            return {"content": None, "code": None}
        m.fetch_url = fake
        return m

    def _event(self, etype="HUMAN_NAME", data="Pat Example"):
        return SpiderFootEvent(etype, data, "test", SpiderFootEvent("ROOT", "root", "", None))

    # -- configuration
    def test_opts_and_descriptions_match(self):
        assert set(sfp_onionsearch.opts) == set(sfp_onionsearch.optdescs)

    def test_default_engines_are_all_valid_onion_addresses(self):
        engines = sfp_onionsearch.parse_engines(DEFAULT_ENGINES)
        assert len(engines) == 6 and all(u.endswith(("{q}",)) or "{q}" in u for _, u in engines)

    def test_bad_engine_lines_are_ignored(self):
        text = "\n".join(["a = http://example.com/?q={q}", "b = " + ENGINE, "c = http://" + B + ".onion/", "no equals",
                          "d = ftp://" + C + ".onion/?q={q}"])
        assert [n for n, _ in sfp_onionsearch.parse_engines(text)] == ["b"]

    def test_no_usable_engine_stops_the_module(self):
        m = sfp_onionsearch()
        m.__name__ = "sfp_onionsearch"
        m.setup(SpiderFoot(self.default_options), {"engines": "x = http://example.com/{q}"})
        assert m.errorState

    def test_flagged_tor_and_slow(self):
        assert {"tor", "slow"} <= set(sfp_onionsearch.meta["flags"])

    # -- link extraction
    def test_links_to_the_engines_own_address_are_skipped_and_each_link_once(self):
        m = self._module({})
        page = _page((f"http://{B}.onion/x", "one"), (f"http://{B}.onion/x", "dup"), (f"http://{C}.onion/", "two"))
        got = [u for u, _ in m.extract_links(page, ENGINE)]
        assert got == [f"http://{B}.onion/x", f"http://{C}.onion/"]

    def test_clearnet_links_are_never_taken(self):
        m = self._module({})
        assert m.extract_links("<a href='http://example.com/x'>x</a>", ENGINE) == []

    # -- searching
    def test_a_name_is_searched_as_a_quoted_phrase_url_encoded(self):
        m = self._module({f"http://{A}.onion/search": _page()})
        m.handleEvent(self._event())
        assert self.urls == [f"http://{A}.onion/search?q=%22Pat+Example%22"]

    def test_a_snippet_that_holds_the_term_is_reported_without_fetching_the_page(self):
        page = _page((f"http://{B}.onion/p", "posted by Pat Example yesterday"))
        m = self._module({f"http://{A}.onion/search": page})
        m.handleEvent(self._event())
        assert [(e.eventType, e.data) for e in self.events[:1]] == [("DARKNET_MENTION_URL", f"http://{B}.onion/p")]
        assert "Pat Example" in self.events[1].data and "found through one" in self.events[1].data
        assert len(self.urls) == 1

    def test_other_results_are_verified_by_fetching_and_kept_only_if_they_mention_the_term(self):
        page = _page((f"http://{B}.onion/yes", "unrelated"), (f"http://{C}.onion/no", "unrelated"))
        m = self._module({f"http://{A}.onion/search": page,
                          f"http://{B}.onion/yes": "<p>dump: Pat Example, 1 High St</p>",
                          f"http://{C}.onion/no": "<p>nothing here</p>"}, verify=True)
        m.handleEvent(self._event())
        assert [e.data for e in self.events if e.eventType == "DARKNET_MENTION_URL"] == [f"http://{B}.onion/yes"]

    def test_by_default_no_hidden_service_page_is_ever_opened(self):
        page = _page((f"http://{B}.onion/a", "no mention"), (f"http://{C}.onion/b", "none either"))
        m = self._module({f"http://{A}.onion/search": page})
        m.handleEvent(self._event())
        assert self.urls == [f"http://{A}.onion/search?q=%22Pat+Example%22"] and not self.events
        assert sfp_onionsearch.opts["verify"] is False

    def test_sponsored_adverts_are_never_results_and_never_followed(self):
        page = (f"<a href='http://{B}.onion/ad' rel='nofollow sponsored noopener'>Ad Pat Example</a><p>Pat Example</p>"
                f"<a href='http://{C}.onion/real'>r</a><p>Pat Example is here</p>")
        m = self._module({f"http://{A}.onion/search": page}, verify=True)
        m.handleEvent(self._event())
        assert [e.data for e in self.events if e.eventType == "DARKNET_MENTION_URL"] == [f"http://{C}.onion/real"]
        assert not any(f"{B}" in u for u in self.urls)

    def test_the_verification_budget_is_respected(self):
        page = _page(*[(f"http://{c * 56}.onion/", "x") for c in "bcdef"])
        m = self._module({f"http://{A}.onion/search": page}, max_verify=2, verify=True)
        m.handleEvent(self._event())
        assert len(self.urls) == 3                      # the search plus two verification fetches

    def test_a_dead_engine_does_not_stop_the_others(self):
        engines = f"dead = http://{B}.onion/s?q={{q}}\none = {ENGINE}"
        page = _page((f"http://{C}.onion/p", "Pat Example here"))
        m = self._module({f"http://{A}.onion/search": page}, engines=engines)
        m.handleEvent(self._event())
        assert any(e.eventType == "DARKNET_MENTION_URL" for e in self.events)

    def test_a_link_two_engines_return_is_reported_once(self):
        engines = f"one = {ENGINE}\ntwo = http://{B}.onion/s?q={{q}}"
        page = _page((f"http://{C}.onion/p", "Pat Example here"))
        m = self._module({f"http://{A}.onion/search": page, f"http://{B}.onion/s": page}, engines=engines)
        m.handleEvent(self._event())
        assert [e.data for e in self.events if e.eventType == "DARKNET_MENTION_URL" and C in e.data] == [f"http://{C}.onion/p"]

    # -- target-only
    def test_only_the_scan_target_is_searched_by_default(self):
        m = self._module({})
        m.handleEvent(self._event("HUMAN_NAME", "Someone Else"))
        assert self.urls == []

    def test_with_target_only_off_other_names_are_searched(self):
        m = self._module({f"http://{A}.onion/search": _page()}, target_only=False)
        m.handleEvent(self._event("HUMAN_NAME", "Someone Else"))
        assert len(self.urls) == 1

    def test_the_same_term_is_searched_once(self):
        m = self._module({f"http://{A}.onion/search": _page()})
        m.handleEvent(self._event())
        m.handleEvent(self._event())
        assert len(self.urls) == 1

    # -- phone numbers
    def test_a_phone_number_is_searched_in_several_written_forms_and_matched_by_digits(self):
        m = self._module({f"http://{A}.onion/search": _page((f"http://{B}.onion/p", "call 0459 053 405 now"))})
        m.getTarget = lambda: type("T", (), {"targetValue": "+61459053405"})()
        m.handleEvent(self._event("PHONE_NUMBER", "+61459053405"))
        assert len(self.urls) >= 2
        assert any(e.eventType == "DARKNET_MENTION_URL" for e in self.events)

    def test_quotes_in_the_data_cannot_break_the_query(self):
        m = self._module({f"http://{A}.onion/search": _page()})
        m.getTarget = lambda: type("T", (), {"targetValue": 'Pat "X" Example'})()
        m.handleEvent(self._event("HUMAN_NAME", 'Pat "X" Example'))
        assert "%22Pat+X+Example%22" in self.urls[0]

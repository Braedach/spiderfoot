"""sfp_searxng: web search through the administrator's own SearXNG server. Off, with no address, by default; acts only on
person scans; every result is reported and marked with whether the searched term really appears in it. Hosts and people
below are examples."""
from __future__ import annotations

import json
import os
from unittest import mock

from modules.sfp_searxng import sfp_searxng
from spiderfoot import SpiderFootEvent
from spiderfoot.config.app_config import NetworkConfig
from spiderfoot.core.config import ConfigManager
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase

BASE = "https://search.example.org"


def answer(results=None, code="200", unresponsive=None, raw=None):
    body = raw if raw is not None else json.dumps({"results": results or [], "unresponsive_engines": unresponsive or []})
    return {"code": code, "content": body}


def hit(title="Pat Example - Profile", url="https://site.example/pat", content="Pat Example lives in Perth", engines=("duckduckgo",)):
    return {"title": title, "url": url, "content": content, "engines": list(engines)}


class TestDefaults(TestModuleBase):

    def test_it_is_off_with_no_address_by_default_everywhere(self):
        net = NetworkConfig()
        assert net.searxng_enabled is False and net.searxng_url == ""
        cfg = ConfigManager.DEFAULT_CONFIG
        assert cfg['_searxng_enabled'] is False and cfg['_searxng_url'] == ""
        for key in ("_searxng_enabled", "_searxng_url", "_searxng_max_queries", "_searxng_delay", "_searxng_timeout",
                    "_searxng_results"):
            assert key in ConfigManager.CONFIG_DESCRIPTIONS, key         # every setting is described

    def test_the_limits_are_modest(self):
        net = NetworkConfig()
        assert net.searxng_max_queries <= 10 and net.searxng_delay >= 1 and net.searxng_results <= 20

    def test_the_settings_page_has_a_web_search_section_and_every_setting_is_documented(self):
        meta = open(os.path.join(os.path.dirname(__file__), "..", "..", "..", "frontend", "src", "lib", "settingsMeta.ts")).read()
        assert "websearch: { tab: 'system', label: 'Web Search'" in meta
        for key in ("_searxng_enabled", "_searxng_url", "_searxng_max_queries", "_searxng_delay", "_searxng_timeout",
                    "_searxng_results"):
            assert f"{key}: {{ group: 'websearch'" in meta, key
        assert "governed by the SearXNG server" in meta or "decided by the SearXNG server" in meta   # the rate note

    def test_no_real_address_is_in_the_module_or_in_any_searxng_setting(self):
        """The owner's address is entered in Settings, never shipped in the repository."""
        root = os.path.join(os.path.dirname(__file__), "..", "..", "..")
        module = open(os.path.join(root, "modules", "sfp_searxng.py")).read().lower()
        assert "braedach" not in module and "baden" not in module
        for rel in ("spiderfoot/core/config.py", "spiderfoot/config/app_config.py", "frontend/src/lib/settingsMeta.ts"):
            for line in open(os.path.join(root, rel)).read().splitlines():
                if "searxng" in line.lower():
                    assert "braedach" not in line.lower() and "baden" not in line.lower(), (rel, line)


class TestModule(TestModuleBase):

    def _module(self, answers=None, target_type="HUMAN_NAME", **opts):
        m = sfp_searxng()
        m.__name__ = "sfp_searxng"
        base = {"_searxng_enabled": True, "_searxng_url": BASE, "_searxng_max_queries": 6, "_searxng_delay": 0,
                "_searxng_timeout": 5, "_searxng_results": 10, "_useragent": "SpiderFoot"}
        self.infos, self.errors, self.events, self.urls = [], [], [], []
        m.info = self.infos.append
        m.error = self.errors.append
        m.setup(SpiderFoot(self.default_options), {**base, **opts})
        m.notifyListeners = self.events.append
        m.checkForStop = lambda: False
        m.getTarget = lambda: mock.MagicMock(targetType=target_type)
        queue = list(answers or [])

        def fake_fetch(url, **kw):
            self.urls.append(url)
            return queue.pop(0) if queue else answer([])
        m.fetch_url = fake_fetch
        return m

    def _send(self, m, etype="HUMAN_NAME", data="Pat Example"):
        m.handleEvent(SpiderFootEvent(etype, data, "test", SpiderFootEvent("ROOT", "root", "", None)))

    # --- off by default
    def test_unconfigured_it_stands_down_quietly_and_sends_nothing(self):
        for opts in ({"_searxng_enabled": False}, {"_searxng_url": ""}, {"_searxng_enabled": "false"},
                     {"_searxng_url": "ftp://x.example"}, {"_searxng_url": "javascript:alert(1)"}, {"_searxng_url": "not a url"}):
            m = self._module(**opts)
            assert m.errorState and any("not configured" in i for i in self.infos) and not self.errors
            self._send(m)
            assert not self.urls and not self.events

    def test_the_address_is_cleaned_of_a_trailing_slash_and_may_have_a_path(self):
        m = self._module([answer([])], _searxng_url=BASE + "/searx/")
        self._send(m)
        assert self.urls[0].startswith(BASE + "/searx/search?")

    def test_the_enable_switch_may_arrive_as_a_string_from_the_database(self):
        assert not self._module(_searxng_enabled="0").errorState is False
        assert self._module(_searxng_enabled="true").errorState is False

    # --- person scans only
    def test_it_acts_only_on_person_scans_unless_told_otherwise(self):
        m = self._module([answer([hit()])], target_type="INTERNET_NAME")
        self._send(m)
        assert not self.urls
        m = self._module([answer([hit()])], target_type="INTERNET_NAME", person_targets_only=False)
        self._send(m)
        assert self.urls

    # --- queries
    def test_a_name_an_email_and_a_username_are_searched_as_exact_phrases(self):
        m = self._module([answer([]), answer([]), answer([])])
        self._send(m, "HUMAN_NAME", 'Pat "The" Example')
        self._send(m, "EMAILADDR", "pat@example.com")
        self._send(m, "USERNAME", "patexample")
        from urllib.parse import parse_qs, urlsplit
        qs = [parse_qs(urlsplit(u).query) for u in self.urls]
        assert [q["q"][0] for q in qs] == ['"Pat The Example"', '"pat@example.com"', '"patexample"']
        assert all(q["format"] == ["json"] for q in qs)

    def test_a_short_or_odd_username_is_not_searched(self):
        m = self._module()
        self._send(m, "USERNAME", "ab")
        self._send(m, "USERNAME", "--drop table")
        assert not self.urls

    def test_a_phone_number_is_searched_in_the_ways_it_is_written(self):
        m = self._module([answer([])] * 4)
        self._send(m, "PHONE_NUMBER", "+61892345678")
        from urllib.parse import parse_qs, urlsplit
        asked = [parse_qs(urlsplit(u).query)["q"][0] for u in self.urls]
        assert '"+61892345678"' in asked and any("8 9234 5678" in q for q in asked) and any("(08) 9234 5678" in q for q in asked)
        assert len(asked) == len(set(asked)) <= 4

    # --- results
    def test_every_result_is_reported_and_marked_by_whether_the_term_is_in_it(self):
        m = self._module([answer([hit(), hit(title="Unrelated page", url="https://other.example/x", content="nothing here")])])
        self._send(m)
        bodies = [e.data for e in self.events]
        assert [e.eventType for e in self.events] == ["SEARCH_ENGINE_WEB_CONTENT"] * 2
        assert "<SFURL>https://site.example/pat</SFURL>" in bodies[0] and "appears in this result" in bodies[0]
        assert "does NOT appear" in bodies[1]                                  # still provided: the model decides
        assert "engines: duckduckgo" in bodies[0] and '[search: "Pat Example"' in bodies[0]

    def test_a_phone_number_is_matched_by_its_digits_however_the_page_writes_it(self):
        m = self._module([answer([hit(content="Call us on (08) 9234-5678 today")])] + [answer([])] * 3)
        self._send(m, "PHONE_NUMBER", "+61892345678")
        assert "appears in this result" in self.events[0].data

    def test_only_the_configured_number_of_results_is_kept(self):
        m = self._module([answer([hit(url=f"https://site.example/{i}") for i in range(30)])], _searxng_results=5)
        self._send(m)
        assert len(self.events) == 5

    def test_the_same_term_is_searched_once_and_the_same_page_reported_once(self):
        m = self._module([answer([hit(), hit()]), answer([hit()])])
        self._send(m)
        self._send(m)
        assert len(self.urls) == 1 and len(self.events) == 1

    def test_unresponsive_engines_are_noted_not_treated_as_an_error(self):
        m = self._module([answer([hit()], unresponsive=[["duckduckgo", "CAPTCHA"]])])
        self._send(m)
        assert not self.errors and any("duckduckgo (CAPTCHA)" in i for i in self.infos) and self.events

    # --- limits
    def test_it_never_sends_more_searches_than_the_limit_and_says_so_once(self):
        m = self._module([answer([])] * 10, _searxng_max_queries=2)
        for name in ("Alpha One", "Beta Two", "Gamma Three"):
            self._send(m, "HUMAN_NAME", name)
        assert len(self.urls) == 2 and len([i for i in self.infos if "limit of 2 searches" in i]) == 1

    def test_it_waits_between_searches_but_not_before_the_first(self):
        m = self._module([answer([])] * 3, _searxng_delay=2)
        with mock.patch("modules.sfp_searxng.time.sleep") as sleep:
            self._send(m, "HUMAN_NAME", "Alpha One")
            self._send(m, "HUMAN_NAME", "Beta Two")
            self._send(m, "HUMAN_NAME", "Gamma Three")
        assert [c.args[0] for c in sleep.call_args_list] == [2.0, 2.0]

    # --- failures say what to do, and never leak the full address
    def test_a_refusal_points_at_the_json_setting_and_stops_the_module(self):
        m = self._module([answer(code="403")])
        self._send(m)
        assert m.errorState and "json" in self.errors[0] and "settings.yml" in self.errors[0]
        assert BASE + "/search" not in self.errors[0]                         # host only, no query

    def test_rate_limiting_stops_the_module_and_names_where_it_is_configured(self):
        m = self._module([answer(code="429")])
        self._send(m)
        assert m.errorState and "rate" in self.errors[0] and "server" in self.errors[0]

    def test_other_failures_are_reported_without_stopping(self):
        for res in (None, answer(code="500"), answer(raw="<html>not json</html>")):
            m = self._module([res])
            self._send(m)
            assert self.errors and not m.errorState, res

    def test_the_options_are_documented(self):
        assert set(sfp_searxng.opts) == set(sfp_searxng.optdescs)
        assert "SEARCH_ENGINE_WEB_CONTENT" in sfp_searxng().producedEvents()

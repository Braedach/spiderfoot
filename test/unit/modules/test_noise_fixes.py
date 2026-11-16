"""Log-noise fixes from the 2026-11-16 scans: an invalid OpenCorporates key logged an error on every event (10 times in
one scan) and the free-tier note as an error each time; three WiFi modules logged an error in every All Modules run
because they need a search term the user supplies."""
from __future__ import annotations

from modules.sfp_opencorporates import sfp_opencorporates
from modules.sfp_openwifimap import sfp_openwifimap
from modules.sfp_wificafespots import sfp_wificafespots
from modules.sfp_wifimapio import sfp_wifimapio
from spiderfoot import SpiderFootEvent
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase


class TestOpenCorporatesNoise(TestModuleBase):

    def _module(self, code, api_key=""):
        m = sfp_opencorporates()
        m.__name__ = "sfp_opencorporates"
        m.setup(SpiderFoot(self.default_options), {"api_key": api_key, "_useragent": "SpiderFoot", "_fetchtimeout": 5})
        self.errors, self.infos, self.fetches = [], [], []
        m.error = self.errors.append
        m.info = self.infos.append
        m.notifyListeners = lambda e: None

        def fake_fetch(url, **kw):
            self.fetches.append(url)
            return {"code": code, "content": "{}"}
        m.fetch_url = fake_fetch
        return m

    def _event(self, name):
        return SpiderFootEvent("COMPANY_NAME", name, "sfp_company", SpiderFootEvent("ROOT", "root", "", None))

    def test_an_invalid_key_is_reported_once_and_the_module_stops(self):
        m = self._module("401", api_key="placeholder")
        for name in ("Alpha Pty Ltd", "Beta Pty Ltd", "Gamma Pty Ltd"):
            m.handleEvent(self._event(name))
        assert len(self.errors) == 1 and "refused" in self.errors[0]
        assert len(self.fetches) == 1                          # it did not keep calling with a key that is refused
        assert m.errorState

    def test_the_no_key_note_is_an_info_line_and_appears_once(self):
        m = self._module("404")
        for name in ("Alpha Pty Ltd", "Beta Pty Ltd"):
            m.handleEvent(self._event(name))
        assert not self.errors
        assert len([i for i in self.infos if "no API key" in i]) == 1

    def test_no_answer_at_all_does_not_crash(self):
        m = self._module("200")
        m.fetch_url = lambda url, **kw: None
        m.handleEvent(self._event("Alpha Pty Ltd"))
        assert not self.errors

    def test_a_rate_limit_is_still_an_error(self):
        m = self._module("403")
        m.handleEvent(self._event("Alpha Pty Ltd"))
        assert any("rate-limited" in e for e in self.errors)


class TestWifiModulesAreQuietWhenNotConfigured(TestModuleBase):

    def test_no_error_is_logged_but_the_module_still_stands_down(self):
        for cls in (sfp_openwifimap, sfp_wifimapio, sfp_wificafespots):
            m = cls()
            m.__name__ = cls.__name__
            errors, infos = [], []
            m.error = errors.append
            m.info = infos.append
            m.setup(SpiderFoot(self.default_options), {})
            assert not errors, cls.__name__
            assert any("Not configured" in i for i in infos), cls.__name__
            assert m.errorState, cls.__name__

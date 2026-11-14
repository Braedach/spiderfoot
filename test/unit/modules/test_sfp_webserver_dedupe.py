"""sfp_webserver reported the same banner once per page (280 events, 2 distinct, in one scan)."""
from __future__ import annotations

import json
from unittest.mock import MagicMock

from modules.sfp_webserver import sfp_webserver
from spiderfoot import SpiderFootEvent
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase


class TestWebserverDedupe(TestModuleBase):

    def _module(self):
        sf = SpiderFoot(self.default_options)
        m = sfp_webserver()
        m.__name__ = "sfp_webserver"
        m.setup(sf, dict())
        m.sf = sf
        target = MagicMock()
        target.matches.return_value = True
        m.getTarget = lambda: target
        self.events = []
        m.notifyListeners = self.events.append
        return m

    def _headers(self, m, url, headers):
        ev = SpiderFootEvent("WEBSERVER_HTTPHEADERS", json.dumps(headers), "sfp_spider", None)
        ev.actualSource = url
        m.handleEvent(ev)

    def _data(self, etype):
        return [e.data for e in self.events if e.eventType == etype]

    def test_one_banner_and_technology_per_host(self):
        m = self._module()
        for i in range(200):
            self._headers(m, f"http://demo.example/page{i}.jsp",
                          {"server": "Apache-Coyote/1.1", "set-cookie": "JSESSIONID=abc"})
        self.assertEqual(self._data("WEBSERVER_BANNER"), ["Apache-Coyote/1.1"])
        self.assertEqual(self._data("WEBSERVER_TECHNOLOGY"), ["Java/JSP"])

    def test_a_different_host_or_value_is_still_reported(self):
        m = self._module()
        self._headers(m, "http://demo.example/a", {"server": "Apache-Coyote/1.1"})
        self._headers(m, "http://other.example/a", {"server": "Apache-Coyote/1.1"})
        self._headers(m, "http://demo.example/b", {"server": "nginx", "x-powered-by": "PHP/8.3"})
        self.assertEqual(self._data("WEBSERVER_BANNER"), ["Apache-Coyote/1.1", "Apache-Coyote/1.1", "nginx"])
        self.assertEqual(self._data("WEBSERVER_TECHNOLOGY"), ["PHP/8.3"])

    def test_redirect_links_are_still_reported_per_page(self):
        m = self._module()
        self._headers(m, "http://demo.example/a", {"location": "http://demo.example/login"})
        self._headers(m, "http://demo.example/b", {"location": "http://demo.example/home"})
        self.assertEqual(len(self._data("LINKED_URL_INTERNAL")), 2)

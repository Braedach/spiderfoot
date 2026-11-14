"""Shodan's "no information available" answer is a normal result, not an error."""
from __future__ import annotations

import json

from modules.sfp_shodan import sfp_shodan
from spiderfoot import SpiderFootEvent
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase


class TestShodanNotFound(TestModuleBase):

    def _module(self, answer):
        sf = SpiderFoot(self.default_options)
        m = sfp_shodan()
        m.__name__ = "sfp_shodan"
        m.setup(sf, {"api_key": "k", "_fetchtimeout": 5})
        self.errors, self.events = [], []
        m.error = self.errors.append
        m.notifyListeners = self.events.append
        m.fetch_url = lambda *a, **k: {"code": "404", "content": json.dumps(answer)}
        import modules.sfp_shodan as mod
        mod.time.sleep = lambda s: None
        return m

    def test_not_found_is_not_an_error(self):
        m = self._module({"error": "No information available for that IP."})
        for ip in ("198.51.100.7", "198.51.100.8"):
            m.handleEvent(SpiderFootEvent("IP_ADDRESS", ip, "sfp_dnsresolve", None))
        self.assertEqual(self.errors, [])
        self.assertEqual(self.events, [])
        self.assertFalse(m.errorState)

    def test_other_error_answers_are_still_errors(self):
        m = self._module({"error": "Invalid IP"})
        m.handleEvent(SpiderFootEvent("IP_ADDRESS", "198.51.100.7", "sfp_dnsresolve", None))
        self.assertEqual(self.errors, ["Error returned from SHODAN: Invalid IP"])

    def test_the_predicate(self):
        self.assertTrue(sfp_shodan._is_not_found("No information available for that IP."))
        self.assertTrue(sfp_shodan._is_not_found("no information available for that domain"))
        self.assertFalse(sfp_shodan._is_not_found("Invalid IP"))
        self.assertFalse(sfp_shodan._is_not_found(None))

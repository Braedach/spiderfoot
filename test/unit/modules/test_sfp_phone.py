from __future__ import annotations

"""Tests for sfp_phone module."""

import pytest
import unittest

from modules.sfp_phone import sfp_phone
from spiderfoot.sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from test.unit.utils.test_module_base import TestModuleBase
from test.unit.utils.test_helpers import safe_recursion


class TestModulePhone(TestModuleBase):

    def setUp(self):
        super().setUp()

    def test_opts(self):
        module = sfp_phone()
        module.__name__ = "sfp_phone"
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_phone()
        module.__name__ = "sfp_phone"
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_phone()
        module.__name__ = "sfp_phone"
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_phone()
        module.__name__ = "sfp_phone"
        self.assertIsInstance(module.producedEvents(), list)

    @safe_recursion(max_depth=5)
    def test_handleEvent_domain_whois_event_data_containing_phone_string_should_create_phone_number_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_phone()
        module.__name__ = "sfp_phone"
        module.setup(sf, dict())

        target_value = 'van1shland.io'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            expected = 'PHONE_NUMBER'
            if str(event.eventType) != expected:
                raise Exception(f"{event.eventType} != {expected}")

            expected = "+12025550111"
            if str(event.data) != expected:
                raise Exception(f"{event.data} != {expected}")

            raise Exception("OK")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_phone)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data,
                              event_module, source_event)

        event_type = 'DOMAIN_WHOIS'
        event_data = 'example data +1 202 555 0111 example data'
        event_module = 'example module'
        source_event = evt
        evt = SpiderFootEvent(event_type, event_data,
                              event_module, source_event)

        with self.assertRaises(Exception) as cm:
            module.handleEvent(evt)

        self.assertEqual("OK", str(cm.exception))

    @safe_recursion(max_depth=5)
    def test_handleEvent_domain_whois_event_data_not_containing_phone_string_should_not_create_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_phone()
        module.__name__ = "sfp_phone"
        module.setup(sf, dict())

        target_value = 'van1shland.io'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_phone)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data,
                              event_module, source_event)

        event_type = 'DOMAIN_WHOIS'
        event_data = 'example data'
        event_module = 'example module'
        source_event = evt
        evt = SpiderFootEvent(event_type, event_data,
                              event_module, source_event)

        result = module.handleEvent(evt)

        self.assertIsNone(result)

    @safe_recursion(max_depth=5)
    def test_handleEvent_phone_number_event_data_containing_phone_string_should_return_provider_telco_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_phone()
        module.__name__ = "sfp_phone"
        module.setup(sf, dict())

        target_value = 'van1shland.io'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            expected = 'PROVIDER_TELCO'
            if str(event.eventType) != expected:
                raise Exception(f"{event.eventType} != {expected}")

            expected = "Swisscom"
            if str(event.data) != expected:
                raise Exception(f"{event.data} != {expected}")

            raise Exception("OK")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_phone)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data,
                              event_module, source_event)

        event_type = 'PHONE_NUMBER'
        event_data = '+41798765432'
        event_module = 'example module'
        source_event = evt
        evt = SpiderFootEvent(event_type, event_data,
                              event_module, source_event)

        with self.assertRaises(Exception) as cm:
            module.handleEvent(evt)

        self.assertEqual("OK", str(cm.exception))


if __name__ == '__main__':
    unittest.main()


# ---------------------------------------------------------------------------------------------------------------
# Behaviour tests (2026-11-16): the module used to report only the carrier and returned early when there was none.
# Numbers are libphonenumber's own example numbers, not real people's.

import json as _json

from spiderfoot import SpiderFootEvent as _Ev

MOBILE = "+61412345678"          # an Australian mobile range
FIXED = "+61892345678"           # an Australian fixed line (Perth area)
GARBAGE = "+999"


class TestPhoneDescribe(TestModuleBase):

    def _module(self):
        m = sfp_phone()
        m.__name__ = "sfp_phone"
        m.setup(SpiderFoot(self.default_options), {})
        self.events = []
        m.notifyListeners = self.events.append
        return m

    def _run(self, number):
        m = self._module()
        m.handleEvent(_Ev("PHONE_NUMBER", number, "test", _Ev("ROOT", "root", "", None)))
        return {e.eventType: e.data for e in self.events}

    def test_a_mobile_is_described_even_when_the_carrier_is_unknown(self):
        out = self._run(MOBILE)
        assert out["PHONE_NUMBER_TYPE"] == "Mobile"
        assert "RAW_RIR_DATA" in out                       # the old code returned early and emitted nothing here

    def test_the_raw_record_has_every_fact_and_the_porting_caveat(self):
        raw = _json.loads(self._run(MOBILE)["RAW_RIR_DATA"])
        for key in ("number", "international", "national", "country_calling_code", "region_code", "valid", "possible",
                    "line_type", "location", "carrier", "time_zones", "note"):
            assert key in raw, key
        assert raw["number"] == MOBILE and raw["valid"] is True and raw["region_code"] == "AU"
        assert raw["national"].startswith("0412") and raw["international"].startswith("+61")
        assert "ported" in raw["note"] and "original" in raw["note"]

    def test_a_fixed_line_gets_a_location(self):
        out = self._run(FIXED)
        assert out["PHONE_NUMBER_TYPE"] == "Fixed line"
        assert out["GEOINFO"] == "Armadale"                # the geocoder lookup was commented out before

    def test_an_invalid_number_is_reported_as_invalid_and_not_typed(self):
        out = self._run(GARBAGE)
        if "RAW_RIR_DATA" in out:
            assert _json.loads(out["RAW_RIR_DATA"])["valid"] is False
        assert "PHONE_NUMBER_TYPE" not in out

    def test_an_unparseable_value_is_ignored_quietly(self):
        assert self._run("not a number") == {}

    def test_one_failing_lookup_never_hides_the_others(self):
        from unittest import mock
        m = self._module()
        with mock.patch("modules.sfp_phone.geocoder.description_for_number", side_effect=RuntimeError("boom")):
            m.handleEvent(_Ev("PHONE_NUMBER", MOBILE, "test", _Ev("ROOT", "root", "", None)))
        types = {e.eventType for e in self.events}
        assert "PHONE_NUMBER_TYPE" in types and "RAW_RIR_DATA" in types

    def test_extraction_from_web_content_still_works(self):
        m = self._module()
        m.handleEvent(_Ev("TARGET_WEB_CONTENT", "Call us on +61 8 9234 5678 today", "test",
                          _Ev("ROOT", "root", "", None)))
        assert [e.data for e in self.events if e.eventType == "PHONE_NUMBER"] == [FIXED]

    def test_produced_events_are_declared(self):
        produced = sfp_phone().producedEvents()
        for etype in ("PHONE_NUMBER", "PROVIDER_TELCO", "PHONE_NUMBER_TYPE", "GEOINFO", "RAW_RIR_DATA"):
            assert etype in produced

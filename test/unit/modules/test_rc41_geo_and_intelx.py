from __future__ import annotations

"""rc.41: coordinates reach the map, phone numbers say which country they belong to, IntelX accepts a pasted URL."""

import pytest

from modules.sfp_intelx import sfp_intelx
from modules.sfp_ipapico_modern import sfp_ipapico_modern, _coordinates
from modules.sfp_ipinfo_modern import sfp_ipinfo_modern
from spiderfoot import SpiderFootEvent
from spiderfoot.sflib import SpiderFoot


def _ip_event():
    root = SpiderFootEvent("ROOT", "1.2.3.4", "", "")
    return SpiderFootEvent("IP_ADDRESS", "1.2.3.4", "test", root)


def _run(module_cls, payload, query_attr):
    mod = module_cls()
    mod.setup(SpiderFoot({"_useragent": "t", "_fetchtimeout": 5, "__logging": False}), {"api_key": "test-key"})
    mod.__name__ = module_cls.__name__
    seen = []
    mod.notifyListeners = lambda evt: seen.append((evt.eventType, evt.data))
    setattr(mod, query_attr, lambda ip: payload)
    mod.handleEvent(_ip_event())
    return seen


class TestIpapicoCoordinates:
    def test_coordinates_are_emitted_with_the_location(self):
        seen = _run(sfp_ipapico_modern, {"country": "AU", "country_name": "Australia", "city": "Perth",
                                         "region": "Western Australia", "latitude": -31.95, "longitude": 115.86}, "query")
        assert ("PHYSICAL_COORDINATES", "-31.9500,115.8600") in seen
        assert any(t == "GEOINFO" for t, _ in seen)

    def test_missing_or_invalid_coordinates_are_not_emitted(self):
        for lat, lon in ((None, None), ("x", "y"), (95, 10), (10, 200), (0, 0)):
            seen = _run(sfp_ipapico_modern, {"country": "AU", "latitude": lat, "longitude": lon}, "query")
            assert not any(t == "PHYSICAL_COORDINATES" for t, _ in seen), (lat, lon)

    def test_coordinates_helper(self):
        assert _coordinates("1", "2") == "1.0000,2.0000"
        assert _coordinates(None, 2) is None

    def test_it_declares_the_event(self):
        assert "PHYSICAL_COORDINATES" in sfp_ipapico_modern().producedEvents()


class TestIpinfoCoordinates:
    def test_loc_becomes_coordinates(self):
        seen = _run(sfp_ipinfo_modern, {"country": "AU", "city": "Perth", "region": "WA", "loc": "-31.9522,115.8614"}, "queryIP")
        assert ("PHYSICAL_COORDINATES", "-31.9522,115.8614") in seen

    @pytest.mark.parametrize("loc", ["", "bad", "1,2,3", "95,10", "0,0", None])
    def test_a_bad_loc_is_ignored(self, loc):
        seen = _run(sfp_ipinfo_modern, {"country": "AU", "loc": loc}, "queryIP")
        assert not any(t == "PHYSICAL_COORDINATES" for t, _ in seen)

    def test_it_declares_the_event(self):
        assert "PHYSICAL_COORDINATES" in sfp_ipinfo_modern().producedEvents()


class TestIntelxHost:
    @pytest.mark.parametrize("typed,host", [
        ("free.intelx.io", "free.intelx.io"),
        ("https://free.intelx.io/", "free.intelx.io"),
        ("https://free.intelx.io", "free.intelx.io"),
        ("  2.intelx.io/ ", "2.intelx.io"),
        ("HTTPS://Public.IntelX.io/intelligent", "public.intelx.io"),
        ("", ""),
    ])
    def test_the_host_is_taken_from_however_it_was_typed(self, typed, host):
        mod = sfp_intelx()
        mod.opts["base_url"] = typed
        assert mod.host() == host

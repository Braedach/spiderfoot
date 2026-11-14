"""The profile listing reports what a scan started now would run, including keyed modules whose key is saved."""
from unittest import mock

from spiderfoot.api.routers import scan as scan_router
from spiderfoot.scan.scan_profile import ScanProfile


def _profile():
    return ScanProfile(name="t", display_name="T", include_modules=["sfp_a"], optional_modules=["sfp_b", "sfp_c", "sfp_gone"])


ALL = {n: {"meta": {"flags": []}} for n in ("sfp_a", "sfp_b", "sfp_c")}


def test_listing_without_keys():
    d = scan_router._profile_to_dict(_profile(), ALL, set())
    assert d["modules"] == ["sfp_a"] and d["module_count"] == 1
    assert d["optional_total"] == 2                       # a module missing from this build is not counted
    assert d["optional_active"] == [] and d["optional_inactive"] == ["sfp_b", "sfp_c"]


def test_listing_with_a_key_saved():
    d = scan_router._profile_to_dict(_profile(), ALL, {"sfp_b"})
    assert d["modules"] == ["sfp_a", "sfp_b"] and d["module_count"] == 2
    assert d["optional_active"] == ["sfp_b"] and d["optional_inactive"] == ["sfp_c"]


def test_configured_modules_come_from_the_live_configuration():
    cfg = mock.Mock()
    cfg.get_config.return_value = {"__modules__": {"sfp_b": {"opts": {"api_key": "k"}}, "sfp_c": {"opts": {"api_key": ""}}}}
    with mock.patch.object(scan_router, "get_app_config", return_value=cfg):
        assert scan_router._configured_modules() == {"sfp_b"}
    cfg.get_config.side_effect = RuntimeError("db down")
    with mock.patch.object(scan_router, "get_app_config", return_value=cfg):
        assert scan_router._configured_modules() == set()

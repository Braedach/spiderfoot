"""The New Scan page's searches (domain, IP, email, phone, name, ASN): each maps to a profile that suits it, the IP and
ASN profiles keep a scan to its target, and a profile's per-module options really reach the scan (they used to be
ignored by the scan router)."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi import FastAPI
from fastapi.testclient import TestClient

from spiderfoot import SpiderFootHelpers, SpiderFootTarget
from spiderfoot.api.dependencies import get_api_key, get_app_config
from spiderfoot.api.routers import scan as scan_router
from spiderfoot.scan.scan_profile import (
    EXPANSION_OPTION_KEYS, SEARCH_TYPES, ScanProfile, get_profile_manager, search_type_for_target_type,
)


@pytest.fixture(scope="module")
def catalog():
    return SpiderFootHelpers.loadModulesAsDict("modules", ["sfp_template.py"])


def flags(catalog, name):
    return set((catalog[name].get("meta") or {}).get("flags") or [])


# ------------------------------------------------------------------------------------------------ the map


def test_there_is_one_search_for_each_kind_of_target():
    assert [s["key"] for s in SEARCH_TYPES] == ["domain", "ip", "email", "phone", "name", "asn"]


def test_every_search_runs_a_real_profile():
    pm = get_profile_manager()
    for st in SEARCH_TYPES:
        assert pm.get(st["profile"]) is not None, st


def test_every_target_type_but_bitcoin_belongs_to_exactly_one_search():
    seen = {}
    for st in SEARCH_TYPES:
        for tt in st["target_types"]:
            assert tt not in seen, f"{tt} is claimed by {seen[tt]} and {st['key']}"
            seen[tt] = st["key"]
    for tt in SpiderFootTarget._validTypes - {"BITCOIN_ADDRESS"}:
        assert tt in seen, f"no search accepts target type {tt}"


@pytest.mark.parametrize("target_type,key", [
    ("INTERNET_NAME", "domain"), ("IP_ADDRESS", "ip"), ("IPV6_ADDRESS", "ip"), ("NETBLOCK_OWNER", "ip"),
    ("EMAILADDR", "email"), ("PHONE_NUMBER", "phone"), ("HUMAN_NAME", "name"), ("USERNAME", "name"),
    ("BGP_AS_OWNER", "asn"),
])
def test_a_target_type_finds_its_search(target_type, key):
    assert search_type_for_target_type(target_type)["key"] == key


def test_an_unknown_target_type_has_no_search():
    assert search_type_for_target_type("BITCOIN_ADDRESS") is None and search_type_for_target_type("nonsense") is None


# ------------------------------------------------------------------------------------------------ the new profiles


@pytest.mark.parametrize("name", ["ip-address", "asn"])
def test_every_listed_module_exists_and_is_reliable(catalog, name):
    p = get_profile_manager().get(name)
    for m in p.include_modules + p.optional_modules:
        assert m in catalog, f"{name} lists {m}, which is not in the catalog"
        assert not flags(catalog, m) & {"deprecated", "errorprone"}, (name, m)


def test_the_ip_profile_runs_without_keys_and_leaves_out_what_would_wander(catalog):
    p = get_profile_manager().get("ip-address")
    assert not [m for m in p.include_modules if "apikey" in flags(catalog, m)]
    for wandering in ("sfp_dnsneighbor", "sfp_tool_nbtscan", "sfp_tool_onesixtyone", "sfp_tool_massdns",
                      "sfp_accounts", "sfp_tool_maigret", "sfp_tool_user_scanner", "sfp_phone", "sfp_tldsearch"):
        assert wandering not in p.include_modules, wandering
    assert p.disable_expansion
    for core in ("sfp_nmap", "sfp_httpx", "sfp_sslcert", "sfp_nuclei", "sfp_internetdb", "sfp_ripe", "sfp_dnsresolve"):
        assert core in p.include_modules


def test_the_ip_profile_resolves_to_a_working_set(catalog):
    p = get_profile_manager().get("ip-address")
    chosen = p.resolve_modules(catalog, set())
    assert 45 <= len(chosen) <= 70 and "sfp__stor_db" in chosen
    with_keys = p.resolve_modules(catalog, set(catalog))
    assert {"sfp_shodan", "sfp_greynoise", "sfp_abuseipdb"} <= set(with_keys) and len(with_keys) > len(chosen)


def test_the_asn_profile_is_registry_only_with_no_active_or_tool_module(catalog):
    p = get_profile_manager().get("asn")
    chosen = p.resolve_modules(catalog, set())
    assert set(chosen) >= {"sfp_ripe", "sfp_whois", "sfp__stor_db"}
    for m in chosen:
        assert not flags(catalog, m) & {"invasive", "tool", "tor"}, m
    for active in ("sfp_nmap", "sfp_httpx", "sfp_spider", "sfp_sslcert", "sfp_tool_naabu"):
        assert active not in chosen
    assert p.disable_expansion


def test_the_existing_profiles_do_not_switch_expansion_off():
    pm = get_profile_manager()
    for name in ("full-footprint", "email-address", "person-name", "phone-number", "dark-web", "infrastructure"):
        assert not pm.get(name).disable_expansion, name


# ------------------------------------------------------------------------------------------------ the options


def _modules():
    return {"sfp_a": {"opts": {"netblocklookup": True, "subnetlookup": True, "other": 5}},
            "sfp_b": {"opts": {"netblockscan": True, "scan_netblocks": 1}},
            "sfp_c": {"opts": {"nothing": 1}},
            "sfp_unselected": {"opts": {"netblocklookup": True}}}


def test_expansion_options_are_switched_off_only_where_a_module_has_them():
    p = ScanProfile(name="t", display_name="T", disable_expansion=True)
    out = p.module_option_overrides(_modules(), ["sfp_a", "sfp_b", "sfp_c"])
    assert out == {"sfp_a": {"netblocklookup": False, "subnetlookup": False},
                   "sfp_b": {"netblockscan": False, "scan_netblocks": False}}
    assert set(EXPANSION_OPTION_KEYS) == {"netblocklookup", "subnetlookup", "netblockscan", "scan_netblocks", "expandasnetblocks"}


def test_without_the_flag_nothing_is_switched_off():
    assert ScanProfile(name="t", display_name="T").module_option_overrides(_modules(), ["sfp_a"]) == {}


def test_a_profiles_own_module_options_apply_to_selected_modules_only():
    p = ScanProfile(name="t", display_name="T", module_options={"sfp_a": {"other": 9}, "sfp_unselected": {"x": 1}})
    assert p.module_option_overrides(_modules(), ["sfp_a"]) == {"sfp_a": {"other": 9}}


def test_the_profiles_own_value_wins_over_the_expansion_default():
    p = ScanProfile(name="t", display_name="T", disable_expansion=True, module_options={"sfp_a": {"netblocklookup": True}})
    assert p.module_option_overrides(_modules(), ["sfp_a"])["sfp_a"]["netblocklookup"] is True


def test_the_flag_survives_saving_and_loading():
    p = ScanProfile(name="t", display_name="T", disable_expansion=True)
    assert ScanProfile.from_dict(p.to_dict()).disable_expansion is True
    assert ScanProfile.from_dict({"name": "old"}).disable_expansion is False


def test_the_scan_configuration_gets_the_overrides_and_the_original_is_untouched():
    config = {"__modules__": {"sfp_a": {"opts": {"netblocklookup": True, "keep": 1}}, "sfp_x": {"opts": {}}}}
    out = scan_router._with_module_option_overrides(config, {"sfp_a": {"netblocklookup": False}, "sfp_missing": {"a": 1}})
    assert out["__modules__"]["sfp_a"]["opts"] == {"netblocklookup": False, "keep": 1}
    assert config["__modules__"]["sfp_a"]["opts"]["netblocklookup"] is True          # a copy, not the live settings
    assert "sfp_missing" not in out["__modules__"]


# ------------------------------------------------------------------------------------------------ the endpoint


@pytest.fixture
def client(monkeypatch):
    app = FastAPI()
    app.dependency_overrides[get_api_key] = lambda: "test-key"
    app.dependency_overrides[get_app_config] = lambda: type("C", (), {"get_config": lambda self: {}})()
    cat = SpiderFootHelpers.loadModulesAsDict("modules", ["sfp_template.py"])
    monkeypatch.setattr(scan_router, "_get_all_modules_dict", lambda: cat)
    monkeypatch.setattr(scan_router, "_configured_modules", lambda: set())
    app.include_router(scan_router.router)
    return TestClient(app)


def test_the_endpoint_lists_the_six_searches_with_what_each_runs(client):
    body = client.get("/search-types").json()
    assert body["total"] == 6
    by = {s["key"]: s for s in body["search_types"]}
    assert by["ip"]["profile"] == "ip-address" and by["ip"]["profile_info"]["disable_expansion"] is True
    assert by["asn"]["profile_info"]["module_count"] < by["ip"]["profile_info"]["module_count"]
    assert by["phone"]["target_types"] == ["PHONE_NUMBER"] and by["phone"]["example"].startswith("+")
    assert all(s["profile_info"]["module_count"] >= 1 for s in body["search_types"])


# ------------------------------------------------------------------------------------------------ nothing dead weight

from test.unit.test_scan_profiles_chain import _reachable_types


@pytest.mark.parametrize("name,seed", [("ip-address", "IP_ADDRESS"), ("asn", "BGP_AS_OWNER")])
def test_every_module_in_the_new_profiles_can_fire_from_its_target(catalog, name, seed):
    """A module that only watches event types the profile can never produce is dead weight (a profile once listed a
    module for a phone number that only reads email addresses)."""
    p = get_profile_manager().get(name)
    names = [m for m in p.include_modules + p.optional_modules if m in catalog]
    reachable = _reachable_types(catalog, names, seed)
    dead = [m for m in names if not ({"*"} & set(catalog[m].get("consumes") or []))
            and not (set(catalog[m].get("consumes") or []) & reachable)]
    assert not dead, f"{name}: these modules can never fire from a {seed} target: {dead}"


# ------------------------------------------------------------------------------------------------ subject context


def test_the_subject_context_is_stored_with_the_scan_only_when_given():
    req = scan_router.ScanRequest(name="n", target="pat@example.com", subject_country="  Australia ", subject_region="Perth")
    assert scan_router._subject_context(req) == {"_subject_country": "Australia", "_subject_region": "Perth"}
    assert scan_router._subject_context(scan_router.ScanRequest(name="n", target="x")) == {}
    partial = scan_router.ScanRequest(name="n", target="x", subject_country="Australia", subject_region="   ")
    assert scan_router._subject_context(partial) == {"_subject_country": "Australia"}


def test_the_subject_context_is_cleaned_and_bounded():
    req = scan_router.ScanRequest(name="n", target="x", subject_country="Aus\ntralia\t", subject_region="a" * 120)
    ctx = scan_router._subject_context(req)
    assert ctx["_subject_country"] == "Aus tralia" and len(ctx["_subject_region"]) == 120


def test_an_over_long_subject_context_is_refused_by_the_request_model():
    import pydantic
    with pytest.raises(pydantic.ValidationError):
        scan_router.ScanRequest(name="n", target="x", subject_country="a" * 81)
    with pytest.raises(pydantic.ValidationError):
        scan_router.ScanRequest(name="n", target="x", subject_region="a" * 121)

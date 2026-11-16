"""The Web Application Test profile: active testing only with a stated authorisation, scope guard enforced."""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from spiderfoot import SpiderFootHelpers
from spiderfoot.api.routers.scan import ScanRequest, _authorisation_record, _profile_to_dict, _require_test_authorisation
from spiderfoot.scan.scan_profile import ScanProfile, get_profile_manager
from spiderfoot.scan.scope_policy import ACTIVE_MODULES


@pytest.fixture(scope="module")
def catalog():
    return SpiderFootHelpers.loadModulesAsDict("modules", ["sfp_template.py"])


@pytest.fixture()
def profile():
    return get_profile_manager().get("web-app-test")


def req(**kw):
    return ScanRequest(name="s", target=kw.pop("target", "example.com"), **kw)


def test_the_profile_exists_and_requires_authorisation(profile):
    assert profile is not None and profile.requires_authorisation is True
    assert get_profile_manager().get("full-footprint").requires_authorisation is False


def test_every_module_exists_and_is_resolved(profile, catalog):
    missing = [m for m in profile.include_modules if m not in catalog]
    assert not missing, missing
    all_modules = {n: {"meta": catalog[n].get("meta", {})} for n in catalog}
    resolved = set(profile.resolve_modules(all_modules))
    assert set(profile.include_modules) <= resolved


def test_no_passive_person_or_dark_web_module_is_in_it(profile, catalog):
    assert not [m for m in profile.include_modules if "tor" in set((catalog[m].get("meta") or {}).get("flags") or [])]
    assert not [m for m in profile.include_modules if m in {"sfp_accounts", "sfp_tool_maigret", "sfp_searxng", "sfp_torch"}]


def test_every_active_module_in_it_is_governed_by_the_scope_guard(profile):
    tools = [m for m in profile.include_modules if m.startswith("sfp_tool_") or m in {"sfp_nuclei", "sfp_httpx", "sfp_spider"}]
    ungoverned = [m for m in tools if m not in ACTIVE_MODULES and m not in {"sfp_tool_katana"}]
    assert not ungoverned, ungoverned
    assert "sfp_tool_katana" in ACTIVE_MODULES


def test_it_enforces_the_scope_guard(profile):
    assert profile.option_overrides.get("_scope_guard_mode") == "enforce"
    assert profile.apply_overrides({"_scope_guard_mode": "log"})["_scope_guard_mode"] == "enforce"


def test_sql_injection_tools_and_exploit_frameworks_are_not_in_it(profile):
    assert not [m for m in profile.include_modules if "sqlmap" in m or "metasploit" in m or "exploit" in m]


def test_it_is_in_the_api_listing(profile, catalog):
    all_modules = {n: {"meta": catalog[n].get("meta", {})} for n in catalog}
    assert _profile_to_dict(profile, all_modules)["requires_authorisation"] is True


def test_the_flag_survives_serialisation(profile):
    assert ScanProfile.from_dict(profile.to_dict()).requires_authorisation is True
    assert ScanProfile.from_dict({"name": "x"}).requires_authorisation is False


# --- the gate ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("value", [None, False])
def test_a_scan_without_the_statement_is_refused(profile, value):
    with pytest.raises(HTTPException) as e:
        _require_test_authorisation(profile, req(authorised_to_test=value))
    assert e.value.status_code == 422 and "authorised" in e.value.detail


def test_a_stated_authorisation_for_a_domain_or_ip_is_accepted(profile):
    for target in ("example.com", "203.0.113.10"):
        _require_test_authorisation(profile, req(target=target, authorised_to_test=True))


@pytest.mark.parametrize("target", ["pat@example.com", "+61400000000", "Pat Example", "AS64496"])
def test_it_will_not_run_against_a_person_or_an_asn(profile, target):
    with pytest.raises(HTTPException) as e:
        _require_test_authorisation(profile, req(target=target, authorised_to_test=True))
    assert e.value.status_code == 422 and "domain name or an IP" in e.value.detail


def test_an_ordinary_profile_needs_no_statement():
    _require_test_authorisation(get_profile_manager().get("full-footprint"), req())
    _require_test_authorisation(get_profile_manager().get("person-name"), req(target="Pat Example"))


def test_the_statement_is_recorded_with_the_scan_and_only_when_made():
    rec = _authorisation_record(req(authorised_to_test=True))
    assert rec["_authorised_to_test"] is True and rec["_authorised_to_test_at"].endswith("+00:00")
    assert _authorisation_record(req()) == {} and _authorisation_record(req(authorised_to_test=False)) == {}


def test_other_profiles_do_not_require_authorisation():
    pm = get_profile_manager()
    assert [p.name for p in pm.list_profiles() if p.requires_authorisation] == ["web-app-test"]

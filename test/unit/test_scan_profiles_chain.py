"""The phone, email and name profiles must name real modules, and every one of them must be able to fire.

A profile once listed sfp_gravatar for a phone number: the module only watches email addresses, so on a phone target
it could never run. Each module is checked against the event types the profile can really produce, starting from the
target type and following what each included module emits.
"""
from __future__ import annotations

import pytest

from spiderfoot import SpiderFootHelpers
from spiderfoot.scan.scan_profile import ScanProfile, get_profile_manager, modules_with_credentials

SEEDS = {"phone-number": "PHONE_NUMBER", "email-address": "EMAILADDR", "person-name": "HUMAN_NAME"}


@pytest.fixture(scope="module")
def catalog():
    return SpiderFootHelpers.loadModulesAsDict("modules", ["sfp_template.py"])


def _flags(catalog, name):
    return set((catalog[name].get("meta") or {}).get("flags") or [])


def _reachable_types(catalog, names, seed):
    """Event types that can occur in a scan of ``names`` started from a ``seed`` event."""
    types = {seed, "ROOT"}
    changed = True
    while changed:
        changed = False
        for n in names:
            consumes = set(catalog[n].get("consumes") or [])
            if "*" in consumes or consumes & types:
                new = set(catalog[n].get("provides") or []) - types
                if new:
                    types |= new
                    changed = True
    return types


@pytest.mark.parametrize("profile_name", sorted(SEEDS))
def test_every_named_module_exists(catalog, profile_name):
    p = get_profile_manager().get(profile_name)
    missing = [m for m in p.include_modules + p.optional_modules if m not in catalog]
    assert not missing, f"{profile_name} names modules that do not exist: {missing}"


@pytest.mark.parametrize("profile_name", sorted(SEEDS))
def test_no_module_is_dead_weight(catalog, profile_name):
    p = get_profile_manager().get(profile_name)
    names = [m for m in p.include_modules + p.optional_modules if m in catalog]
    reachable = _reachable_types(catalog, names, SEEDS[profile_name])
    dead = [m for m in names if not ({"*"} & set(catalog[m].get("consumes") or []))
            and not (set(catalog[m].get("consumes") or []) & reachable)]
    assert not dead, f"{profile_name}: these modules can never fire from a {SEEDS[profile_name]} target: {dead}"


@pytest.mark.parametrize("profile_name", sorted(SEEDS))
def test_always_on_modules_are_key_free_and_safe(catalog, profile_name):
    p = get_profile_manager().get(profile_name)
    for m in p.include_modules:
        flags = _flags(catalog, m)
        assert not flags & {"apikey", "invasive", "tool", "tor", "errorprone", "deprecated"}, (profile_name, m, flags)


@pytest.mark.parametrize("profile_name", sorted(SEEDS))
def test_optional_modules_are_not_in_the_always_on_list(profile_name):
    p = get_profile_manager().get(profile_name)
    assert not set(p.include_modules) & set(p.optional_modules)


def test_the_phone_profile_no_longer_lists_gravatar():
    assert "sfp_gravatar" not in get_profile_manager().get("phone-number").include_modules


def test_the_name_profile_follows_the_usernames_it_finds(catalog):
    p = get_profile_manager().get("person-name")
    username_readers = {m for m in p.include_modules if "USERNAME" in (catalog[m].get("consumes") or [])}
    assert {"sfp_github", "sfp_keybase", "sfp_venmo"} <= username_readers


def test_optional_modules_run_only_when_their_key_is_saved(catalog):
    p = get_profile_manager().get("phone-number")
    all_modules = {n: {"meta": catalog[n].get("meta", {})} for n in catalog}
    base = p.resolve_modules(all_modules)
    with_key = p.resolve_modules(all_modules, {"sfp_numverify"})
    assert "sfp_numverify" not in base and "sfp_numverify" in with_key
    assert set(with_key) - set(base) == {"sfp_numverify"}
    assert "sfp_twilio" not in with_key                        # a key for one module does not enable another
    assert p.resolve_modules(all_modules, {"sfp_nonexistent"}) == base


def test_credentials_detection_matches_the_modules_page():
    cfg = {"a": {"opts": {"api_key": "x"}}, "b": {"opts": {"api_key": ""}}, "c": {"opts": {"timeout": 5}},
           "d": {"opts": {"account_sid": "a", "auth_token": "t"}}, "e": {"opts": {"access_token": "t", "api_secret": ""}},
           "f": {"opts": {"remote_password": "x"}}, "g": {"opts": {"api_key": None}}}
    assert modules_with_credentials(cfg) == {"a", "d"}
    assert modules_with_credentials(None) == set()


def test_optional_modules_round_trip_through_serialisation():
    p = ScanProfile(name="t", display_name="T", include_modules=["a"], optional_modules=["b"])
    assert ScanProfile.from_dict(p.to_dict()).optional_modules == ["b"]


# Modules whose service was found dead, parked or login-walled on 2026-11-14 (see CHANGELOG, rc.37). A profile must not
# list them: they cost time and add errors without ever returning data.
KNOWN_DEAD = {"sfp_callername", "sfp_trumail", "sfp_searchcode", "sfp_twitter", "sfp_duckduckgo", "sfp_sublist3r",
              "sfp_bgpview", "sfp_sorbs", "sfp_onionsearchengine", "sfp_tool_wappalyzer", "sfp_tool_phoneinfoga"}


@pytest.mark.parametrize("profile_name", sorted(SEEDS))
def test_no_known_dead_module_is_listed(profile_name):
    p = get_profile_manager().get(profile_name)
    assert not KNOWN_DEAD & set(p.include_modules + p.optional_modules), profile_name


def test_the_dark_web_profile_excludes_the_dead_search_engine(catalog):
    p = get_profile_manager().get("dark-web")
    all_modules = {n: {"meta": catalog[n].get("meta", {})} for n in catalog}
    resolved = p.resolve_modules(all_modules)
    assert "sfp_onionsearchengine" not in resolved and "sfp_ahmia" in resolved

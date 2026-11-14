"""Modules whose service is gone are marked deprecated, so no profile, "All Modules" or use case runs them.

Each was checked against its real service on 2026-11-14 (see CHANGELOG, rc.38). A deprecated module can still be picked
explicitly on the By Module tab; it is just never chosen for the user.
"""
import pytest

from spiderfoot import SpiderFootHelpers
from spiderfoot.api.routers import scan as scan_router
from spiderfoot.scan.scan_profile import get_profile_manager

DEAD = ["sfp_sublist3r", "sfp_duckduckgo", "sfp_bgpview", "sfp_sorbs", "sfp_zonefiles", "sfp_onionsearchengine",
        "sfp_callername", "sfp_trumail", "sfp_searchcode", "sfp_twitter", "sfp_threatminer", "sfp_tool_wappalyzer",
        "sfp_tool_phoneinfoga"]


@pytest.fixture(scope="module")
def catalog():
    return SpiderFootHelpers.loadModulesAsDict("modules", ["sfp_template.py"])


@pytest.mark.parametrize("name", DEAD)
def test_the_module_is_marked_deprecated_and_out_of_the_use_case_tabs(catalog, name):
    meta = catalog[name]["meta"]
    assert "deprecated" in meta["flags"]
    assert meta["summary"].startswith("Deprecated: ")                 # the Modules page shows why
    assert not meta["useCases"] and not catalog[name].get("group")


# phone-number and email-address are checked by test_scan_profiles_chain.py (rc.37): they list modules by name, and a
# profile's own list overrides deprecation.
@pytest.mark.parametrize("profile", ["full-footprint", "quick-recon", "passive-only", "infrastructure", "dark-web",
                                     "person-name", "api-powered", "investigate"])
def test_no_profile_selects_a_deprecated_module(catalog, profile):
    p = get_profile_manager().get(profile)
    all_modules = {n: {"meta": catalog[n].get("meta", {})} for n in catalog}
    try:                                                               # keyed (optional) modules, with every key saved
        chosen = set(p.resolve_modules(all_modules, set(catalog)))
    except TypeError:                                                  # a build without optional profile modules
        chosen = set(p.resolve_modules(all_modules))
    assert not chosen & set(DEAD), sorted(chosen & set(DEAD))


def test_all_modules_leaves_them_out(catalog):
    class Sf:
        opts = {"__modules__": catalog}

    chosen = set(scan_router._reliable_modules(Sf(), list(catalog)))
    assert not chosen & set(DEAD)
    assert "sfp_shodan" in chosen and "sfp_nuclei" in chosen          # working modules are untouched

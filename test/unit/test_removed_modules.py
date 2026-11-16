"""A module whose service is gone is removed, not deprecated. Thirteen were deleted on 2026-11-16 (and sfp_onioncity
with the dark-web fixes); this keeps them out, and keeps the catalog free of modules marked deprecated."""
from __future__ import annotations

import os

import pytest

from spiderfoot import SpiderFootHelpers
from spiderfoot.api.routers import scan as scan_router
from spiderfoot.scan.scan_profile import get_profile_manager

REMOVED = ["sfp_sublist3r", "sfp_duckduckgo", "sfp_bgpview", "sfp_sorbs", "sfp_zonefiles", "sfp_onionsearchengine",
           "sfp_callername", "sfp_trumail", "sfp_searchcode", "sfp_twitter", "sfp_threatminer", "sfp_tool_wappalyzer",
           "sfp_tool_phoneinfoga"]


@pytest.fixture(scope="module")
def catalog():
    return SpiderFootHelpers.loadModulesAsDict("modules", ["sfp_template.py"])


@pytest.mark.parametrize("name", REMOVED)
def test_the_module_is_gone(catalog, name):
    assert name not in catalog
    assert not os.path.exists(f"modules/{name}.py")


def test_no_module_is_marked_deprecated(catalog):
    """A module that does not work is removed. If one must be kept for a reason, give this test an exception with the
    reason next to it."""
    deprecated = sorted(n for n, i in catalog.items() if "deprecated" in ((i.get("meta") or {}).get("flags") or []))
    assert not deprecated, f"remove these instead of deprecating them: {deprecated}"


def test_no_profile_names_a_module_that_does_not_exist(catalog):
    for p in get_profile_manager().list_profiles():
        named = list(p.include_modules) + list(p.optional_modules) + list(p.exclude_modules)
        missing = sorted(m for m in named if m not in catalog)
        assert not missing, f"profile {p.name} names modules that do not exist: {missing}"


def test_all_modules_selects_only_modules_that_exist(catalog):
    class Sf:
        opts = {"__modules__": catalog}

    chosen = set(scan_router._reliable_modules(Sf(), list(catalog)))
    assert chosen <= set(catalog) and not chosen & set(REMOVED)
    assert "sfp_shodan" in chosen and "sfp_nuclei" in chosen          # working modules are untouched

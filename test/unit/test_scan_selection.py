"""How POST /api/scans turns a New Scan selection into a module list (rc.35)."""
import pytest

from spiderfoot.api.routers import scan as scan_router
from spiderfoot.scan.scan_profile import get_profile_manager


class FakeSf:
    """Just the module lookups the selection helpers use."""

    def __init__(self, modules):
        self.opts = {"__modules__": modules}

    def modulesProducing(self, events):
        return [m for m, i in self.opts["__modules__"].items()
                if "*" in events or set(i.get("provides", [])) & set(events)]

    def eventsToModules(self, modules):
        return [e for m in modules for e in self.opts["__modules__"][m].get("consumes", [])]


MODULES = {
    "sfp_phone": {"provides": ["PHONE_NUMBER"], "consumes": ["EMAILADDR"], "meta": {"flags": []}},
    "sfp_email": {"provides": ["EMAILADDR"], "consumes": ["DOMAIN_NAME"], "meta": {"flags": []}},
    "sfp_dns": {"provides": ["DOMAIN_NAME"], "consumes": ["ROOT"], "meta": {"flags": []}},
    "sfp_unrelated": {"provides": ["BITCOIN_ADDRESS"], "consumes": ["TARGET_WEB_CONTENT"], "meta": {"flags": []}},
    "sfp_flaky": {"provides": ["PHONE_NUMBER"], "consumes": ["ROOT"], "meta": {"flags": ["errorprone"]}},
    "sfp_old": {"provides": ["EMAILADDR"], "consumes": ["ROOT"], "meta": {"flags": ["deprecated"]}},
    "sfp_onion": {"provides": ["DARKNET_MENTION_URL"], "consumes": ["DOMAIN_NAME"], "meta": {"flags": ["tor"]}},
    "sfp__stor_db": {"provides": [], "consumes": ["*"], "meta": {"flags": []}},
}


def test_required_data_selects_producers_and_what_feeds_them():
    mods = scan_router._modules_for_required_data(FakeSf(MODULES), ["PHONE_NUMBER"])
    assert mods == ["sfp_dns", "sfp_email", "sfp_phone"]


def test_required_data_with_no_producer_is_empty():
    assert scan_router._modules_for_required_data(FakeSf(MODULES), ["NO_SUCH_TYPE"]) == []


def test_all_modules_keeps_tor_and_drops_unreliable():
    sf = FakeSf(MODULES)
    mods = scan_router._reliable_modules(sf, sf.modulesProducing(["*"]))
    assert "sfp_onion" in mods
    assert "sfp_flaky" not in mods and "sfp_old" not in mods


def test_dark_web_profile_no_longer_overrides_the_general_proxy():
    profile = get_profile_manager().get("dark-web")
    assert not any(k.startswith("_socks") for k in (profile.option_overrides or {}))


@pytest.mark.parametrize("name", ["phone-number", "email-address", "person-name", "full-footprint", "dark-web"])
def test_builtin_profiles_exist_with_a_display_name(name):
    profile = get_profile_manager().get(name)
    assert profile is not None and profile.display_name

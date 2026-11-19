from __future__ import annotations

"""An address scan must stay with the address: it followed 958 netblocks (and harvested 4,937 third-party emails)
because the one module that turns an AS into netblocks (sfp_ripe) had no switch for it."""

from modules.sfp_ripe import sfp_ripe
from spiderfoot import SpiderFootEvent
from spiderfoot.scan.scan_profile import EXPANSION_OPTION_KEYS, get_profile_manager
from spiderfoot.sflib import SpiderFoot


def _module(expand: bool):
    mod = sfp_ripe()
    mod.setup(SpiderFoot({"_useragent": "t", "_fetchtimeout": 5, "__logging": False}), {"expandasnetblocks": expand})
    mod.__name__ = "sfp_ripe"
    mod.asNetblocks = lambda asn: ["203.0.113.0/24", "198.51.100.0/24", "2001:db8::/32"]
    mod.lastContent = "{}"
    seen = []
    mod.notifyListeners = lambda e: seen.append((e.eventType, e.data))
    return mod, seen


def _as_owner_event():
    root = SpiderFootEvent("ROOT", "192.0.2.1", "", "")
    return SpiderFootEvent("BGP_AS_OWNER", "64500", "sfp_ripe", root)


def test_with_expansion_on_every_netblock_of_the_as_is_followed():
    mod, seen = _module(True)
    mod.handleEvent(_as_owner_event())
    assert [d for t, d in seen if t.startswith("NETBLOCK")] == ["203.0.113.0/24", "198.51.100.0/24", "2001:db8::/32"]


def test_with_expansion_off_none_is_followed():
    mod, seen = _module(False)
    mod.handleEvent(_as_owner_event())
    assert seen == []


def test_the_default_keeps_the_old_behaviour_for_other_scans():
    assert sfp_ripe.opts["expandasnetblocks"] is True
    assert "expandasnetblocks" in sfp_ripe.optdescs


def test_the_switch_is_one_the_profiles_turn_off():
    assert "expandasnetblocks" in EXPANSION_OPTION_KEYS


def test_the_ip_profile_switches_it_off_and_the_asn_profile_keeps_it_for_its_own_as():
    mods = {"sfp_ripe": {"opts": dict(sfp_ripe.opts)}}
    pm = get_profile_manager()
    ip = pm.get("ip-address")
    assert ip.disable_expansion
    assert ip.module_option_overrides(mods, ["sfp_ripe"]) == {"sfp_ripe": {"expandasnetblocks": False}}
    # The ASN scan's target is the AS, so listing the netblocks it announces is the point of that scan.
    asn = pm.get("asn")
    assert asn.module_option_overrides(mods, ["sfp_ripe"]) == {"sfp_ripe": {"expandasnetblocks": True}}


def test_the_person_and_domain_profiles_are_untouched():
    mods = {"sfp_ripe": {"opts": dict(sfp_ripe.opts)}}
    for name in ("person-name", "email-address", "phone-number", "full-footprint"):
        p = get_profile_manager().get(name)
        assert p.module_option_overrides(mods, ["sfp_ripe"]) == {}, name


def test_netblock_reputation_sweep_is_an_expansion_switch():
    """The owning /11 of a single address must not be swept address by address."""
    from modules.sfp_torexits import sfp_torexits
    assert "checknetblocks" in EXPANSION_OPTION_KEYS
    assert "checknetblocks" in sfp_torexits.opts


def test_web_app_test_profile_widens_nuclei_but_stays_detection_only():
    prof = get_profile_manager().get("web-app-test")
    tags = set(prof.module_options["sfp_nuclei"]["baseline_tags"].split(","))
    assert {"ssl", "graphql", "swagger", "openapi", "cors", "jwt", "redirect", "crlf", "exposure", "misconfig"} <= tags
    assert not tags & {"default-login", "intrusive", "dos", "fuzz", "bruteforce"}
    # the module's own exclusion of dos, fuzz and intrusive templates must not be overridden by the profile
    assert "template_exclude_tags" not in prof.module_options["sfp_nuclei"]
    assert "template_exclude_tags" in __import__("modules.sfp_nuclei", fromlist=["x"]).sfp_nuclei.opts

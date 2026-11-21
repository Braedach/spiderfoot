"""A saved module value that is only an old default must not beat the current default (nikto/nuclei 20, naabu 50, arjun)."""
from __future__ import annotations

import importlib

import pytest

from spiderfoot.sflib import config as sfconfig
from spiderfoot.sflib.superseded_defaults import SUPERSEDED_DEFAULTS, drop_superseded, is_superseded


def reference(**modules):
    return {"__modules__": {name: {"opts": dict(opts)} for name, opts in modules.items()}}


def test_every_retired_default_is_really_retired():
    """Listing a value that is still the current default would make a saved copy of it vanish for nothing."""
    for module, opts in SUPERSEDED_DEFAULTS.items():
        cls = getattr(importlib.import_module(f"modules.{module}"), module)
        for opt, old in opts.items():
            assert opt in cls.opts, (module, opt)
            current = cls.opts[opt]
            current = "1" if current is True else "0" if current is False else str(current)
            assert current not in old, (module, opt, current)


@pytest.mark.parametrize("module,opt,old,default", [
    ("sfp_tool_nikto", "max_targets", "20", 0),
    ("sfp_nuclei", "max_targets", "20", 0),
    ("sfp_tool_naabu", "max_targets", "50", 0),
    ("sfp_tool_arjun", "run_timeout", "180", 300),
])
def test_a_saved_old_default_gives_way_to_the_current_one(module, opt, old, default):
    ref = reference(**{module: {opt: default}})
    out = sfconfig.configUnserialize({f"{module}:{opt}": old}, ref)
    assert out["__modules__"][module]["opts"][opt] == default


def test_a_saved_old_boolean_default_gives_way():
    ref = reference(sfp_tool_arjun={"stable": False})
    out = sfconfig.configUnserialize({"sfp_tool_arjun:stable": "1"}, ref)
    assert out["__modules__"]["sfp_tool_arjun"]["opts"]["stable"] is False


def test_a_value_chosen_on_purpose_still_applies():
    ref = reference(sfp_tool_nikto={"max_targets": 0})
    out = sfconfig.configUnserialize({"sfp_tool_nikto:max_targets": "35"}, ref)
    assert out["__modules__"]["sfp_tool_nikto"]["opts"]["max_targets"] == 35


def test_other_modules_and_global_settings_are_untouched():
    ref = {"_maxthreads": 24, **reference(sfp_other={"max_targets": 0})}
    out = sfconfig.configUnserialize({"_maxthreads": "20", "sfp_other:max_targets": "20"}, ref)
    assert out["_maxthreads"] == 20 and out["__modules__"]["sfp_other"]["opts"]["max_targets"] == 20


def test_the_stored_dict_is_not_changed():
    stored = {"sfp_nuclei:max_targets": "20", "x": "1"}
    assert drop_superseded(stored) == {"x": "1"} and len(stored) == 2


def test_values_compare_as_the_database_holds_them():
    assert is_superseded("sfp_tool_nikto", "max_targets", 20) and is_superseded("sfp_tool_nikto", "max_targets", " 20 ")
    assert is_superseded("sfp_tool_arjun", "stable", True) and not is_superseded("sfp_tool_arjun", "stable", False)
    assert not is_superseded("sfp_tool_nikto", "max_targets", 21) and not is_superseded("sfp_nope", "max_targets", 20)


def test_settings_screen_does_not_show_an_old_default_as_if_in_force(monkeypatch):
    from spiderfoot.api import dependencies

    class Db:
        def __init__(self, *a, **k): pass
        def close(self): pass
        def configGet(self): return {"sfp_tool_nikto:max_targets": "20", "sfp_tool_nikto:timeout": "300"}

    monkeypatch.setattr(dependencies, "SpiderFootDb", Db)
    monkeypatch.setattr(dependencies, "get_app_config", lambda: type("C", (), {"get_config": lambda self: {}})())
    assert dependencies.get_fresh_config_values() == {"sfp_tool_nikto:timeout": "300"}


def test_every_profile_that_runs_nuclei_pins_the_excluded_tags_too():
    from spiderfoot.scan.scan_profile import NUCLEI_SAFETY, ProfileManager
    mgr = ProfileManager()
    for name in ("tools-only", "web-app-test", "ip-address"):
        opts = mgr.get(name).module_options["sfp_nuclei"]
        assert opts["template_exclude_tags"] == NUCLEI_SAFETY["template_exclude_tags"] == "dos,fuzz,intrusive", name

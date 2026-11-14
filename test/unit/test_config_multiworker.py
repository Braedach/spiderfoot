"""Config saved through one API worker must survive a save through another (lost-update bug).

The API runs several worker processes, each holding its own copy of the config. Saving used to
write the whole config from that worker's memory, so entering API keys one after another could
leave only the last one in the database.
"""
from __future__ import annotations

import copy

import pytest

from spiderfoot.api import dependencies
from spiderfoot.api.dependencies import Config
from spiderfoot.config.app_config import AppConfig

MODULES = {
    "sfp_shodan": {"opts": {"api_key": "", "maxnetblock": 24}, "optdescs": {}},
    "sfp_virustotal": {"opts": {"api_key": "", "verify": True}, "optdescs": {}},
    "sfp_alienvault": {"opts": {"api_key": ""}, "optdescs": {}},
    "sfp_ipinfo": {"opts": {"api_key": ""}, "optdescs": {}},
}


class FakeStore:
    """Stands in for tbl_config; shared by every fake worker."""
    rows: dict = {}


class FakeDb:
    open_handles = 0  # every handle the config code opens must be closed again (pool leak guard)
    def __init__(self, *a, **k): FakeDb.open_handles += 1
    def close(self): FakeDb.open_handles -= 1
    def configSet(self, m):
        assert m, "configSet must not be called with nothing to write"
        FakeStore.rows.update(m)
        FakeStore.writes.append(dict(m))
        return True
    def configGet(self): return dict(FakeStore.rows)


class FakeSf:
    def __init__(self, *a, **k): pass
    def configUnserialize(self, stored, flat):
        out = copy.deepcopy(flat)
        for key, val in stored.items():
            if ":" in key:
                mod, opt = key.split(":", 1)
                if mod in out["__modules__"]:
                    out["__modules__"][mod]["opts"][opt] = val
            else:
                out[key] = val
        return out


@pytest.fixture(autouse=True)
def fake_db(monkeypatch):
    FakeStore.rows = {}
    FakeStore.writes = []
    monkeypatch.setattr(dependencies, "SpiderFootDb", FakeDb)
    monkeypatch.setattr(dependencies, "SpiderFoot", FakeSf)


def worker() -> Config:
    flat = {"__modules__": copy.deepcopy(MODULES), "_maxthreads": 16}
    return Config(_app_config=AppConfig.from_dict(flat))


def stored_key(module: str) -> str | None:
    return FakeStore.rows.get(f"{module}:api_key")


def test_keys_entered_through_different_workers_all_survive():
    """The reported bug: shodan, virustotal, alienvault and ipinfo entered one after another."""
    workers = [worker() for _ in range(4)]
    for w, (mod, key) in zip(workers, [("sfp_virustotal", "vt-key"), ("sfp_alienvault", "av-key"),
                                       ("sfp_ipinfo", "ip-key"), ("sfp_shodan", "sh-key")]):
        assert w.set_module_options(mod, {"api_key": key})
    assert stored_key("sfp_virustotal") == "vt-key"
    assert stored_key("sfp_alienvault") == "av-key"
    assert stored_key("sfp_ipinfo") == "ip-key"
    assert stored_key("sfp_shodan") == "sh-key"


def test_save_writes_only_the_changed_key():
    w = worker()
    w.set_module_options("sfp_shodan", {"api_key": "sh-key"})
    assert FakeStore.writes == [{"sfp_shodan:api_key": "sh-key"}]


def test_a_stale_worker_does_not_overwrite_a_newer_value():
    a, b = worker(), worker()
    a.set_module_options("sfp_virustotal", {"api_key": "vt-key"})
    b.set_module_options("sfp_shodan", {"api_key": "sh-key"})   # b never saw a's change
    assert stored_key("sfp_virustotal") == "vt-key"


def test_a_save_picks_up_other_workers_changes():
    a, b = worker(), worker()
    a.set_module_options("sfp_virustotal", {"api_key": "vt-key"})
    b.set_module_options("sfp_shodan", {"api_key": "sh-key"})
    assert b.get_config()["__modules__"]["sfp_virustotal"]["opts"]["api_key"] == "vt-key"


def test_a_stale_copy_is_refreshed_at_the_start_of_a_request(monkeypatch):
    a, b = worker(), worker()
    a.set_module_options("sfp_virustotal", {"api_key": "vt-key"})
    b._synced_at -= 10          # b has not refreshed for 10 s
    b.refresh_if_stale()
    assert b.get_config()["__modules__"]["sfp_virustotal"]["opts"]["api_key"] == "vt-key"


def test_a_fresh_copy_is_not_reloaded():
    w = worker()
    called = []
    w.reload = lambda: called.append(1)
    w.refresh_if_stale()
    assert not called


def test_unknown_module_returns_false_and_writes_nothing():
    assert worker().set_module_options("sfp_nope", {"api_key": "x"}) is False
    assert FakeStore.writes == []


def test_global_setting_change_does_not_clobber_module_keys():
    a, b = worker(), worker()
    a.set_module_options("sfp_virustotal", {"api_key": "vt-key"})
    b.update_config({"_maxthreads": 24})
    b.save_config()
    assert stored_key("sfp_virustotal") == "vt-key"
    assert FakeStore.rows.get("_maxthreads") == 24


def test_changed_keys_helper():
    assert Config._changed_keys({"a": 1, "b": 2, "c": 3}, {"a": 1, "b": 9}) == {"b": 2, "c": 3}



def test_config_code_closes_every_db_handle():
    """Saving and reloading must not leave a pooled connection checked out (rc.33 leaked one per call)."""
    FakeDb.open_handles = 0
    a, b = worker(), worker()
    a.set_module_options("sfp_virustotal", {"api_key": "vt-key"})
    b.reload()
    b.refresh_if_stale(max_age=0)
    assert dependencies.get_fresh_config_values().get("sfp_virustotal:api_key") == "vt-key"
    assert FakeDb.open_handles == 0

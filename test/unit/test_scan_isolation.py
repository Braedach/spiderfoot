"""Scans must never run inside an API worker, and dead scans must not stay RUNNING."""
from __future__ import annotations

import sys
import types

import pytest

from spiderfoot.scan import liveness


class FakeRedis:
    def __init__(self, alive=(), lock_free=True):
        self.alive = set(alive)
        self.lock_free = lock_free

    def set(self, key, value, nx=False, ex=None):
        return self.lock_free if nx else True

    def exists(self, key):
        return key.rsplit(":", 1)[1] in self.alive


class FakeDb:
    def __init__(self, rows):
        self.rows = rows
        self.updates = {}

    def scanInstanceList(self):
        return self.rows

    def scanInstanceSet(self, guid, ended=None, status=None, started=None):
        self.updates[guid] = status


NOW = 1_000_000.0


def row(guid, status, age):
    t = NOW - age
    return (guid, "n", "t", t, t, 0, status, 5)


@pytest.fixture
def with_redis(monkeypatch):
    def install(client):
        monkeypatch.setattr(liveness, "_redis", lambda: client)
    return install


def test_dead_running_scan_is_failed(with_redis):
    with_redis(FakeRedis())
    db = FakeDb([row("DEAD0001", "RUNNING", 600)])
    assert liveness.reap_orphaned_scans(db, now=NOW) == ["DEAD0001"]
    assert db.updates == {"DEAD0001": "ERROR-FAILED"}


def test_dead_abort_requested_scan_becomes_aborted(with_redis):
    with_redis(FakeRedis())
    db = FakeDb([row("DEAD0002", "ABORT-REQUESTED", 600)])
    liveness.reap_orphaned_scans(db, now=NOW)
    assert db.updates == {"DEAD0002": "ABORTED"}


def test_live_scan_is_left_alone(with_redis):
    with_redis(FakeRedis(alive={"LIVE0001"}))
    db = FakeDb([row("LIVE0001", "RUNNING", 600)])
    assert liveness.reap_orphaned_scans(db, now=NOW) == []
    assert db.updates == {}


def test_young_running_scan_is_within_grace(with_redis):
    with_redis(FakeRedis())
    db = FakeDb([row("NEW00001", "RUNNING", 30)])
    assert liveness.reap_orphaned_scans(db, now=NOW) == []


def test_queued_starting_scan_is_not_reaped(with_redis):
    with_redis(FakeRedis())
    db = FakeDb([row("QUEUED01", "STARTING", 3600)])
    assert liveness.reap_orphaned_scans(db, now=NOW) == []


def test_finished_scans_ignored(with_redis):
    with_redis(FakeRedis())
    db = FakeDb([row("DONE0001", "FINISHED", 99999)])
    assert liveness.reap_orphaned_scans(db, now=NOW) == []


def test_no_redis_never_reaps_blind(with_redis):
    with_redis(None)
    db = FakeDb([row("DEAD0003", "RUNNING", 600)])
    assert liveness.reap_orphaned_scans(db, now=NOW) == []
    assert db.updates == {}


def test_reaper_lock_held_by_another_worker(with_redis):
    with_redis(FakeRedis(lock_free=False))
    db = FakeDb([row("DEAD0004", "RUNNING", 600)])
    assert liveness.reap_orphaned_scans(db, now=NOW) == []


def _args():
    return ("SCAN0001", "name", "example.com", "INTERNET_NAME", ["sfp_x"], {"k": "v"})


def test_dispatch_prefers_celery(monkeypatch):
    from spiderfoot.api.routers import scan as router
    sent = {}
    celery_mod = types.SimpleNamespace(is_celery_available=lambda: True)
    task_mod = types.SimpleNamespace(run_scan=types.SimpleNamespace(
        apply_async=lambda **kw: sent.update(kw)))
    monkeypatch.setitem(sys.modules, "spiderfoot.celery_app", celery_mod)
    monkeypatch.setitem(sys.modules, "spiderfoot.tasks.scan", task_mod)
    monkeypatch.setattr(router, "_spawn_isolated_scan", lambda *a: pytest.fail("must not spawn"))
    assert router.dispatch_scan(*_args()) == "celery"
    assert sent["queue"] == "scan" and sent["task_id"] == "SCAN0001"
    assert sent["kwargs"]["target_value"] == "example.com"
    assert sent["kwargs"]["scan_id"] == "SCAN0001"


@pytest.mark.parametrize("available", [False, "raises"])
def test_fallback_is_detached_process_never_in_worker(monkeypatch, available):
    from spiderfoot.api.routers import scan as router

    def avail():
        if available == "raises":
            raise RuntimeError("boom")
        return False

    monkeypatch.setitem(sys.modules, "spiderfoot.celery_app",
                        types.SimpleNamespace(is_celery_available=avail))
    spawned = []
    monkeypatch.setattr(router, "_spawn_isolated_scan", lambda *a: spawned.append(a))
    monkeypatch.setattr(router, "startSpiderFootScanner",
                        lambda *a, **k: pytest.fail("scan ran inside the API worker"))
    assert router.dispatch_scan(*_args(), stealth_level="low") == "process"
    assert spawned and spawned[0][5]["_stealth_level"] == "low"


def test_uvicorn_gets_generous_worker_healthcheck(monkeypatch):
    import uvicorn
    from spiderfoot import service_runner
    captured = {}
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: captured.update(kw))
    monkeypatch.delenv("SF_API_WORKER_HEALTHCHECK_TIMEOUT", raising=False)
    service_runner._run_api(8001, {})
    assert captured["timeout_worker_healthcheck"] == 120
    monkeypatch.setenv("SF_API_WORKER_HEALTHCHECK_TIMEOUT", "45")
    service_runner._run_api(8001, {})
    assert captured["timeout_worker_healthcheck"] == 45


def test_scanner_entry_holds_heartbeat_for_whole_scan(monkeypatch):
    from spiderfoot.scan import scanner
    events = []

    class HB:
        def __init__(self, scan_id): events.append(("init", scan_id))
        def __enter__(self): events.append("enter"); return self
        def __exit__(self, *a): events.append("exit")

    class FakeScanner:
        def __init__(self, *a, **k): events.append("scan-ran")

    monkeypatch.setattr(liveness, "ScanHeartbeat", HB)
    monkeypatch.setattr(scanner, "logWorkerSetup", lambda q: None)
    monkeypatch.setattr(scanner, "SpiderFootScanner", FakeScanner)
    scanner.startSpiderFootScanner(None, "name", "SCAN0002", "t", "INTERNET_NAME", [], {})
    assert events == [("init", "SCAN0002"), "enter", "scan-ran", "exit"]

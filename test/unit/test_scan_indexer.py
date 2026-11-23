"""Indexing finished scans in the background: queue, progress, completion markers, resume and failure."""
from __future__ import annotations

import asyncio
import threading
import time

import pytest
from fastapi import HTTPException

from spiderfoot.agents import service
from spiderfoot.agents.indexer import STATE_COLLECTION, ScanIndexer


class FakeQdrant:
    def __init__(self):
        self.points = {}
        self.collections = set()

    def ensure_collection(self, name, vector_size=1): self.collections.add(name)
    def upsert(self, name, pts):
        for p in pts:
            self.points[(name, p.id)] = p
        return len(pts)
    def get(self, name, ids): return [self.points[(name, i)] for i in ids if (name, i) in self.points]


class FakeEngine:
    def __init__(self):
        self.batches = []
        self.fail = None
        self.gate = None
        self.entered = threading.Event()

    def index_events(self, events):
        self.entered.set()
        if self.gate is not None:
            assert self.gate.wait(5)
        if self.fail:
            raise self.fail
        self.batches.append(len(events))
        return len(events)


def make(n=25, batch=10, candidates=None):
    engine, qd = FakeEngine(), FakeQdrant()
    idx = ScanIndexer(lambda sid: [f"{sid}-{i}" for i in range(n)], engine, qd, candidates=candidates, batch=batch, pause_s=0)
    return idx, engine, qd


def wait(cond, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.01)
    return False


def test_a_scan_is_indexed_in_batches_then_marked_done():
    idx, engine, qd = make()
    assert idx.request("S1")["status"] in ("queued", "indexing", "done")
    assert wait(lambda: idx.status("S1")["status"] == "done")
    idx.stop()
    assert engine.batches == [10, 10, 5]
    st = idx.status("S1")
    assert st["indexed"] == 25 and st["total"] == 25 and st["percent"] == 100.0
    assert (STATE_COLLECTION, next(k[1] for k in qd.points if k[0] == STATE_COLLECTION)) in qd.points      # the marker is stored


def test_progress_is_visible_while_it_runs():
    idx, engine, _ = make(n=20, batch=10)
    engine.gate = threading.Event()
    idx.request("S1")
    assert engine.entered.wait(5)
    mid = idx.status("S1")
    assert mid["status"] == "indexing" and mid["total"] == 20 and mid["percent"] == 0.0
    engine.gate.set()
    assert wait(lambda: idx.status("S1")["status"] == "done")
    idx.stop()


def test_a_scan_is_never_queued_twice_and_an_on_demand_request_goes_to_the_front():
    idx, engine, _ = make()
    engine.gate = threading.Event()
    idx.request("A")                                   # starts at once, held by the gate
    assert engine.entered.wait(5)
    idx.request("B"); idx.request("C"); idx.request("B"); idx.request("C", front=True)
    assert idx.overview()["queue"] == ["C", "B"]
    engine.gate.set()
    assert wait(lambda: all(idx.status(s)["status"] == "done" for s in "ABC"))
    idx.stop()


def test_a_marked_scan_is_not_indexed_again_even_by_a_new_indexer():
    idx, engine, qd = make()
    idx.request("S1")
    assert wait(lambda: idx.status("S1")["status"] == "done")
    idx.stop()
    fresh = ScanIndexer(lambda sid: ["x"], FakeEngine(), qd, pause_s=0)         # the same Qdrant, as after a restart
    assert fresh.status("S1")["status"] == "done"
    fresh.request("S1")
    assert fresh._engine.batches == [] and fresh.overview()["queue"] == []


def test_a_failure_is_reported_and_a_new_request_retries():
    idx, engine, _ = make()
    engine.fail = RuntimeError("qdrant down")
    idx.request("S1")
    assert wait(lambda: idx.status("S1")["status"] == "error")
    assert "qdrant down" in idx.status("S1")["error"]
    engine.fail = None
    idx.request("S1")
    assert wait(lambda: idx.status("S1")["status"] == "done")
    idx.stop()


def test_unknown_scan_has_status_none_and_no_scan_id_is_rejected():
    idx, _, _ = make()
    assert idx.status("nope")["status"] == "none"
    with pytest.raises(ValueError):
        idx.request("")


def test_the_poller_queues_only_scans_that_are_not_indexed():
    idx, engine, qd = make(candidates=lambda: ["A", "B", "C"])
    idx.request("A")
    assert wait(lambda: idx.status("A")["status"] == "done")
    assert idx.enqueue_candidates() == 2               # B and C; A has its marker
    assert wait(lambda: all(idx.status(s)["status"] == "done" for s in "BC"))
    assert idx.enqueue_candidates() == 0
    idx.stop()


def test_a_broken_candidate_list_never_raises():
    def boom(): raise RuntimeError("db down")
    idx, _, _ = make(candidates=boom)
    assert idx.enqueue_candidates() == 0


def test_stopping_mid_scan_leaves_no_marker_so_it_resumes_later():
    idx, engine, qd = make(n=50, batch=10)
    engine.gate = threading.Event()
    idx.request("S1")
    assert engine.entered.wait(5)
    idx.stop()
    engine.gate.set()
    assert wait(lambda: idx.status("S1")["status"] == "queued")
    assert not any(k[0] == STATE_COLLECTION for k in qd.points)


# ---- the service endpoints
def run(coro):
    return asyncio.run(coro)


def test_endpoints_request_report_and_overview(monkeypatch):
    idx, _, _ = make()
    monkeypatch.setattr(service, "_indexer", idx)
    first = run(service.index_scan("S1"))
    assert first["scan_id"] == "S1"
    assert wait(lambda: run(service.index_status("S1"))["status"] == "done")
    assert "queue" in run(service.index_overview())
    idx.stop()


def test_endpoints_say_503_when_indexing_is_not_available(monkeypatch):
    def broken(): raise RuntimeError("no qdrant")
    monkeypatch.setattr(service, "_indexer", None)
    monkeypatch.setattr(service, "_build_indexer", broken)
    for call in (lambda: service.index_scan("S1"), lambda: service.index_status("S1"), service.index_overview):
        with pytest.raises(HTTPException) as e:
            run(call())
        assert e.value.status_code == 503


def test_the_event_loader_skips_root_and_needs_a_database(monkeypatch):
    from spiderfoot.agents import report_generator as rg
    monkeypatch.delenv("SF_POSTGRES_DSN", raising=False)
    with pytest.raises(RuntimeError):
        rg._load_scan_events("S1")
    monkeypatch.setenv("SF_POSTGRES_DSN", "postgresql://x")

    class Db:
        def __init__(self, *a, **k): pass
        def scanResultEvent(self, sid):
            return [(1.0, "example.org", "sfp_x", "h0", "ROOT", "", 100, 100, 0),
                    (2.0, "www.example.org", "sfp_dns", "h1", "INTERNET_NAME", "h0", 100, 100, 0),
                    ("short",)]
        def close(self): pass
    monkeypatch.setattr("spiderfoot.db.SpiderFootDb", Db)
    events = rg._load_scan_events("S1")
    assert [e.event_type for e in events] == ["INTERNET_NAME"] and events[0].data == "www.example.org"

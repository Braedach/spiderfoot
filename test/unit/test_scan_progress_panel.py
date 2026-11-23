"""The scan progress panel: what is running, how much is queued, the rate, and how long the scan has been quiet."""
from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock, patch

from spiderfoot.api.routers import scan_progress as sp
from spiderfoot.scan.scan_progress import ProgressSnapshot
from spiderfoot.scan.scanner import module_progress_text


def snap(**kw):
    base = dict(timestamp=1.0, overall_pct=40.0, modules_completed=4, modules_total=10, events_total=500, throughput_eps=0.0,
                eta_seconds=None, modules_running=2)
    return ProgressSnapshot(**{**base, **kw})


def test_the_snapshot_uses_the_names_the_page_reads_as_well_as_the_old_ones():
    d = snap().to_dict()
    assert d["overall_percent"] == 40.0 and d["modules_finished"] == 4       # the page read these and found nothing: 0%
    assert d["overall_pct"] == 40.0 and d["modules_completed"] == 4          # existing callers keep theirs


def test_the_snapshot_carries_what_the_scan_is_doing():
    d = snap(running=[{"name": "sfp_tool_nikto", "progress": "55 of 118 servers tested so far"}], queued_events=1234,
             events_per_min=17.46, quiet_for_s=62.04).to_dict()
    assert d["running"][0]["progress"].startswith("55 of 118") and d["queued_events"] == 1234
    assert d["events_per_min"] == 17.5 and d["quiet_for_s"] == 62.0
    assert snap().to_dict()["running"] == []                                  # nothing known: empty, never missing


def test_the_redis_snapshot_reads_the_new_fields_and_survives_damaged_ones():
    redis = MagicMock()
    redis.hgetall.return_value = {"progress": "40", "modules_completed": "4", "modules_total": "10", "modules_running": "2",
                                  "events_produced": "500", "updated_at": "1.0",
                                  "running_modules": json.dumps([{"name": "sfp_nuclei", "progress": "3 of 9 targets scanned so far"}]),
                                  "queued_events": "77", "events_per_min": "12.5", "quiet_for_s": "9"}
    with patch("redis.from_url", return_value=redis), patch.object(sp, "HAS_TRACKER", True):
        s = sp._redis_snapshot("S1")
        assert s.running[0]["name"] == "sfp_nuclei" and s.queued_events == 77 and s.events_per_min == 12.5 and s.quiet_for_s == 9.0
        redis.hgetall.return_value = {**redis.hgetall.return_value, "running_modules": "{not json"}
        assert sp._redis_snapshot("S1").running == []
        redis.hgetall.return_value = {"progress": "40"}                       # an older worker that wrote none of the new fields
        old = sp._redis_snapshot("S1")
        assert old.running == [] and old.queued_events == 0


def test_a_module_progress_line_is_read_safely():
    class A: progress_text = "5 of 9 done"
    class B:
        def progress_text(self): return "3 of 7 done"
    class C:
        def progress_text(self): raise RuntimeError("module bug")
    class D: pass
    assert module_progress_text(A()) == "5 of 9 done" and module_progress_text(B()) == "3 of 7 done"
    assert module_progress_text(C()) == "" and module_progress_text(D()) == ""
    assert len(module_progress_text(type("E", (), {"progress_text": "x" * 500})())) == 120


def test_the_stream_sends_an_update_when_anything_changes_not_only_the_percentage():
    snaps = iter([snap(running=[{"name": "a", "progress": "1 of 9"}]), snap(running=[{"name": "a", "progress": "2 of 9"}]),
                  snap(running=[{"name": "a", "progress": "2 of 9"}])])
    last = {"s": None}

    def fake_snapshot(scan_id):
        try:
            last["s"] = next(snaps)
        except StopIteration:
            pass
        return last["s"]

    async def collect():
        out = []
        with patch.object(sp, "_redis_snapshot", fake_snapshot), patch.object(sp, "get_tracker", lambda sid: None):
            async for chunk in sp._sse_generator("S1", interval=0.01, timeout=1):
                out.append(chunk)
                if len(out) >= 3:
                    break
        return out
    chunks = asyncio.run(collect())
    kinds = [c.split("\n", 1)[0] for c in chunks]
    assert kinds[:2] == ["event: progress", "event: progress"]               # the percentage did not change; the text did

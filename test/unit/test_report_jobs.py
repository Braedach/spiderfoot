"""AI reports as background jobs: the page gets a job id at once and can show which step the report is on."""
from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException

from spiderfoot.agents import service
from spiderfoot.agents.base import AgentResult
from spiderfoot.agents.report_generator import REPORT_PHASES, _phase


class SlowAgent:
    """Reports its phases like the real agent, then waits (so a status call can look at it half way)."""
    def __init__(self, result_type="scan_report", fail=None):
        self.release = None
        self.result_type = result_type
        self.fail = fail
        self.seen = []

    async def handle_event(self, event):
        for key, _ in REPORT_PHASES[:3]:
            _phase(event, key)
            self.seen.append(key)
        if self.release is not None:
            await self.release.wait()
        if self.fail:
            raise self.fail
        _phase(event, "finish")
        return AgentResult(agent_name="report_generator", event_id="e", scan_id=event["scan_id"], result_type=self.result_type,
                           data={"report": "# R", "target": event["target"]} if self.result_type == "scan_report" else {"error": "no key"})


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    service._report_jobs.clear()
    monkeypatch.setattr(service, "_persist_report", lambda *a, **k: None)
    yield
    service._report_jobs.clear()


def req(**kw):
    return service.ReportRequest(scan_id="S1", target="example.org", **kw)


def run(coro):
    return asyncio.run(coro)


def test_a_job_starts_at_once_and_reports_its_steps_while_running(monkeypatch):
    async def go():
        agent = SlowAgent(); agent.release = asyncio.Event()
        monkeypatch.setattr(service, "_agents", {"report_generator": agent})
        started = await service.start_report(req())
        assert started["status"] == "running" and len(started["steps"]) == len(REPORT_PHASES)
        await asyncio.sleep(0.05)
        mid = await service.report_status(started["job_id"])
        assert mid["status"] == "running" and mid["phase"] == "model"
        states = {s["key"]: s["state"] for s in mid["steps"]}
        assert states == {"digest": "done", "context": "done", "model": "running", "finish": "waiting"}
        with pytest.raises(HTTPException) as e:                       # the result is not ready: 409, not an empty report
            await service.report_result(started["job_id"])
        assert e.value.status_code == 409
        agent.release.set()
        await service._report_jobs[started["job_id"]]["task"]
        done = await service.report_status(started["job_id"])
        assert done["status"] == "done" and all(s["state"] == "done" for s in done["steps"])
        assert (await service.report_result(started["job_id"]))["data"]["report"] == "# R"
    run(go())


def test_a_failed_report_says_why(monkeypatch):
    async def go():
        monkeypatch.setattr(service, "_agents", {"report_generator": SlowAgent(fail=RuntimeError("model said no"))})
        job = await service.start_report(req())
        await service._report_jobs[job["job_id"]]["task"]
        st = await service.report_status(job["job_id"])
        assert st["status"] == "error" and "model said no" in st["error"]
        with pytest.raises(HTTPException) as e:
            await service.report_result(job["job_id"])
        assert e.value.status_code == 500 and "model said no" in e.value.detail
    run(go())


def test_an_agent_error_result_is_a_failed_job_not_a_report(monkeypatch):
    async def go():
        monkeypatch.setattr(service, "_agents", {"report_generator": SlowAgent(result_type="error")})
        job = await service.start_report(req())
        await service._report_jobs[job["job_id"]]["task"]
        assert (await service.report_status(job["job_id"]))["status"] == "error"
    run(go())


def test_an_unknown_job_is_404_and_a_missing_agent_is_503(monkeypatch):
    async def go():
        with pytest.raises(HTTPException) as e:
            await service.report_status("nope")
        assert e.value.status_code == 404
        monkeypatch.setattr(service, "_agents", {})
        with pytest.raises(HTTPException) as e2:
            await service.start_report(req())
        assert e2.value.status_code == 503
    run(go())


def test_only_the_newest_jobs_are_kept(monkeypatch):
    async def go():
        monkeypatch.setattr(service, "_agents", {"report_generator": SlowAgent()})
        monkeypatch.setattr(service, "_MAX_REPORT_JOBS", 3)
        ids = []
        for _ in range(5):
            j = await service.start_report(req())
            await service._report_jobs[j["job_id"]]["task"]
            ids.append(j["job_id"])
        assert len(service._report_jobs) == 3 and ids[-1] in service._report_jobs and ids[0] not in service._report_jobs
    run(go())


def test_a_progress_callback_that_raises_never_stops_the_report():
    _phase({"_progress": lambda key: 1 / 0}, "model")          # no exception
    _phase({}, "model")
    _phase({"_progress": "not callable"}, "model")

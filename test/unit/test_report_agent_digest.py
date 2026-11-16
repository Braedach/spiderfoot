"""Wiring of the scan digest into the AI report agent: it is ADDED to what the model already receives (the vector
context is untouched), the appendix is appended by code, and a digest failure never stops a report."""
from __future__ import annotations

import asyncio

import pytest

import spiderfoot.agents.report_generator as rg
from spiderfoot.agents.base import AgentConfig

DIGEST = {"text": "SCAN DIGEST (authoritative)\nIN-SCOPE FINDINGS: expired certificate on www.example.com",
          "appendix": "## Appendix A: Complete inventory\n- www.example.com [sfp_test]",
          "digests": [{"target": "example.com", "target_type": "INTERNET_NAME", "total_events": 10,
                       "accounting": {"in-scope finding": 10}}]}
QDRANT = {"available": True, "scan_events": {}, "semantic_hits": [], "infra_hits": [], "attack_surface": {},
          "event_stats": {"total_indexed": 500, "scans_queried": 1, "type_breakdown": {}, "risk_breakdown": {}},
          "geo": {}}


class FakeAgent(rg.ReportGeneratorAgent):
    def __init__(self, reply="# Cyber Threat Intelligence Report: example.com\n\nBody.\n"):
        super().__init__(AgentConfig(name="report_generator", llm_model="test-model"))
        self.calls = []
        self.reply = reply

    async def call_llm(self, messages, **kwargs):
        self.calls.append(messages)
        return self.reply


def run(agent, **event):
    base = {"scan_id": "S1", "target": "example.com", "scan_name": "t"}
    return asyncio.run(agent.process_event({**base, **event}))


@pytest.fixture
def patched(monkeypatch):
    monkeypatch.setattr(rg, "_get_qdrant_context", lambda scan_ids, target: dict(QDRANT))
    monkeypatch.setattr(rg, "_load_digest", lambda scan_ids, target: dict(DIGEST))


def test_the_digest_is_added_to_the_prompt_and_the_vector_context_is_still_there(patched, monkeypatch):
    marker = "VECTOR-CONTEXT-MARKER"
    monkeypatch.setattr(rg.ReportGeneratorAgent, "_format_qdrant_context", lambda self, ctx: marker)
    agent = FakeAgent()
    run(agent)
    user = agent.calls[0][1]["content"]
    assert "SCAN DIGEST (authoritative)" in user and marker in user          # added, not replaced
    assert user.index("SCAN DIGEST") < user.index(marker)                    # the digest comes first
    assert "EVIDENCE RULES" in user                                          # the instruction line points at the rules


def test_the_system_prompt_keeps_everything_it_had_and_adds_the_evidence_rules():
    assert "REPORT FORMAT" in rg.SYSTEM_PROMPT and "IMPORTANT INSTRUCTIONS" in rg.SYSTEM_PROMPT
    assert "EVIDENCE RULES" in rg.SYSTEM_PROMPT
    for search in ("Domain or hostname", "IP address or netblock", "ASN:", "Email address:", "Phone number:", "Person name:"):
        assert search in rg.SYSTEM_PROMPT, search                            # guidance for every search type
    for rule in ("UNVERIFIED", "RELATED CONTEXT", "Coverage and Limitations", "What This Scan Did Not", "Appendix A"):
        assert rule in rg.SYSTEM_PROMPT, rule


def test_the_appendix_is_appended_after_the_report_by_code(patched):
    result = run(FakeAgent())
    report = result.data["report"]
    assert report.startswith("# Cyber Threat Intelligence Report")
    assert report.index("Body.") < report.index("## Appendix A: Complete inventory")
    assert "www.example.com [sfp_test]" in report
    assert result.data["digest"][0]["total_events"] == 10


def test_without_a_digest_the_report_is_produced_as_before(monkeypatch):
    monkeypatch.setattr(rg, "_get_qdrant_context", lambda scan_ids, target: dict(QDRANT))
    monkeypatch.setattr(rg, "_load_digest", lambda scan_ids, target: {"text": "", "appendix": "", "digests": []})
    agent = FakeAgent()
    result = run(agent)
    assert result.result_type == "scan_report" and "Appendix A" not in result.data["report"]
    assert result.data["report"].startswith("# Cyber Threat Intelligence Report")


def test_a_failing_digest_loader_never_stops_a_report(monkeypatch):
    monkeypatch.delenv("SF_POSTGRES_DSN", raising=False)
    assert rg._load_digest(["S1"], "example.com") == {"text": "", "appendix": "", "digests": []}
    monkeypatch.setenv("SF_POSTGRES_DSN", "postgresql://nobody:x@127.0.0.1:1/none")      # unreachable
    assert rg._load_digest(["S1"], "example.com")["text"] == ""


def test_the_digest_size_budget_can_be_set(monkeypatch):
    import spiderfoot.agents.report_digest as dg
    calls = {}
    monkeypatch.setenv("SF_POSTGRES_DSN", "postgresql://x")
    monkeypatch.setenv("SF_REPORT_DIGEST_MAX_CHARS", "12345")

    class Db:
        def __init__(self, cfg): pass
        def scanResultEvent(self, sid): return []
        def scanLogs(self, sid, limit=None): return []
        def close(self): pass
    import spiderfoot.db as dbmod
    monkeypatch.setattr(dbmod, "SpiderFootDb", Db)
    real = dg.render_digest
    monkeypatch.setattr(dg, "render_digest", lambda d, max_chars=None: calls.setdefault("max", max_chars) and real(d, max_chars=max_chars))
    rg._load_digest(["S1"], "example.com")
    assert calls["max"] == 12345

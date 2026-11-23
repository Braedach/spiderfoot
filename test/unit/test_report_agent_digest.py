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
    monkeypatch.setattr(rg, "_get_qdrant_context", lambda scan_ids, target, **kw: dict(QDRANT))
    monkeypatch.setattr(rg, "_load_digest", lambda scan_ids, target: dict(DIGEST))


def test_the_digest_is_added_to_the_prompt_and_the_vector_context_is_still_there(patched, monkeypatch):
    marker = "VECTOR-CONTEXT-MARKER"
    monkeypatch.setattr(rg.ReportGeneratorAgent, "_format_qdrant_context", lambda self, ctx, compact=False: marker)
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
    monkeypatch.setattr(rg, "_get_qdrant_context", lambda scan_ids, target, **kw: dict(QDRANT))
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


# ------------------------------------------------------------------------------------------------ efficiency


def test_the_vector_section_drops_its_sampled_counts_and_listing_when_a_digest_exists_but_keeps_the_ranked_matches():
    ctx = dict(QDRANT)
    ctx["event_stats"] = {"total_indexed": 500, "scans_queried": 1, "type_breakdown": {"HTTP_CODE": 400},
                          "risk_breakdown": {"info": 500}}
    ctx["attack_surface"] = {"domains": 3, "hosts": 4}
    ctx["scan_events"] = {"HTTP_CODE": [{"data": "SAMPLED-EVENT", "source": "sfp_spider", "risk": 0}]}
    ctx["semantic_hits"] = [{"type": "VULNERABILITY_GENERAL", "score": 0.91, "risk": 1, "data": "RANKED-HIT"}]
    ctx["infra_hits"] = [{"type": "TCP_PORT_OPEN", "score": 0.8, "data": "INFRA-HIT"}]
    agent = FakeAgent()
    full = agent._format_qdrant_context(ctx)
    compact = agent._format_qdrant_context(ctx, compact=True)
    assert "SAMPLED-EVENT" in full and "RANKED-HIT" in full                # unchanged without a digest
    assert "SAMPLED-EVENT" not in compact and "EVENT TYPE DISTRIBUTION" not in compact      # no conflicting sampled counts
    assert "ATTACK SURFACE METRICS" not in compact
    assert "RANKED-HIT" in compact and "INFRA-HIT" in compact                # what only the vector store adds is kept
    assert "authoritative" in compact


def test_the_prompt_uses_the_compact_vector_section_only_when_there_is_a_digest(monkeypatch):
    seen = []
    monkeypatch.setattr(rg, "_get_qdrant_context", lambda scan_ids, target, **kw: dict(QDRANT))
    monkeypatch.setattr(rg.ReportGeneratorAgent, "_format_qdrant_context",
                        lambda self, ctx, compact=False: seen.append(compact) or "VEC")
    monkeypatch.setattr(rg, "_load_digest", lambda scan_ids, target: dict(DIGEST))
    run(FakeAgent())
    monkeypatch.setattr(rg, "_load_digest", lambda scan_ids, target: {"text": "", "appendix": "", "digests": []})
    run(FakeAgent())
    assert seen == [True, False]


def test_the_report_records_how_big_the_prompt_was(patched):
    result = run(FakeAgent())
    assert result.data["prompt_chars"] > len(rg.SYSTEM_PROMPT)
    assert result.data["prompt_tokens_estimate"] == result.data["prompt_chars"] // 4


def test_the_report_asks_for_prompt_caching_because_it_retries_the_same_prompt(patched):
    class Spy(FakeAgent):
        async def call_llm(self, messages, **kwargs):
            self.kwargs = kwargs
            return self.reply
    agent = Spy()
    run(agent)
    assert agent.kwargs.get("cache_prompt") is True


def test_prompt_caching_marks_the_system_prompt_and_the_last_user_message_and_is_off_by_default():
    from spiderfoot.ai import anthropic_chat
    messages = [{"role": "system", "content": "SYS"}, {"role": "user", "content": "first"},
                {"role": "assistant", "content": "ok"}, {"role": "user", "content": "LAST"}]
    plain = anthropic_chat.build_request(messages, "m", 4096)
    assert plain["system"] == "SYS" and plain["messages"][-1]["content"] == "LAST"          # unchanged by default
    cached = anthropic_chat.build_request(messages, "m", 4096, cache_prompt=True)
    assert cached["system"] == [{"type": "text", "text": "SYS", "cache_control": {"type": "ephemeral"}}]
    assert cached["messages"][-1]["content"] == [{"type": "text", "text": "LAST", "cache_control": {"type": "ephemeral"}}]
    assert cached["messages"][0]["content"] == "first"                                        # only the last user turn
    assert messages[-1]["content"] == "LAST"                                                  # the caller's list is untouched


# ---- a big scan's first report used to time out while every event was embedded (42,000 events took 16 minutes)
def test_with_a_digest_the_report_does_not_index_the_scan_first(monkeypatch):
    seen = {}
    monkeypatch.setattr(rg, "_get_qdrant_context", lambda scan_ids, target, **kw: seen.update(kw) or dict(QDRANT))
    monkeypatch.setattr(rg, "_load_digest", lambda scan_ids, target: dict(DIGEST))
    monkeypatch.delenv("SF_REPORT_BACKFILL", raising=False)
    run(FakeAgent())
    assert seen == {"backfill": False}


def test_without_a_digest_the_scan_is_still_indexed_as_before(monkeypatch):
    seen = {}
    monkeypatch.setattr(rg, "_get_qdrant_context", lambda scan_ids, target, **kw: seen.update(kw) or dict(QDRANT))
    monkeypatch.setattr(rg, "_load_digest", lambda scan_ids, target: {"text": "", "appendix": "", "digests": []})
    monkeypatch.delenv("SF_REPORT_BACKFILL", raising=False)
    run(FakeAgent())
    assert seen == {"backfill": True}


@pytest.mark.parametrize("mode,has_digest,expected", [
    ("auto", True, False), ("auto", False, True), ("", True, False), ("AUTO", False, True),
    ("always", True, True), ("always", False, True), ("never", True, False), ("never", False, False),
])
def test_backfill_modes(monkeypatch, mode, has_digest, expected):
    monkeypatch.setenv("SF_REPORT_BACKFILL", mode)
    assert rg._backfill_wanted(has_digest) is expected


def test_a_scan_not_in_qdrant_is_not_embedded_when_backfill_is_off(monkeypatch):
    """The real function, with only the Qdrant client faked: nothing is indexed when backfill is off."""
    calls = []

    class Q:
        def ensure_collection(self, *a, **k): pass
        def scroll(self, *a, **k): return [], None

    monkeypatch.setattr("spiderfoot.ai.qdrant_client.get_qdrant_client", lambda: Q())
    monkeypatch.setattr("spiderfoot.services.embedding_service.get_embedding_service", lambda: object())
    monkeypatch.setattr(rg, "_backfill_scan_into_qdrant", lambda *a, **k: calls.append(a) or 0)
    rg._get_qdrant_context(["S1"], "example.com", backfill=False)
    assert calls == []
    rg._get_qdrant_context(["S1"], "example.com", backfill=True)
    assert len(calls) == 1


# ---- correlations come from the database, with their risk and size, not from whatever the page sent
class FakeDb:
    rows = []
    closed = 0

    def __init__(self, *a, **k): pass
    def scanCorrelationList(self, sid): return list(FakeDb.rows)
    def close(self): FakeDb.closed += 1


def _corr(rid, risk, count, name=None):
    return (1, f"title {rid}", rid, risk, name or f"rule {rid}", f"description {rid}", "logic", count)


def test_correlations_are_read_from_the_database_highest_risk_first(monkeypatch):
    monkeypatch.setenv("SF_POSTGRES_DSN", "postgresql://x")
    monkeypatch.setattr("spiderfoot.db.SpiderFootDb", FakeDb)
    FakeDb.rows = [_corr("a", "LOW", 3), _corr("b", "HIGH", 5), _corr("c", "HIGH", 9), _corr("d", "INFO", 1)]
    FakeDb.closed = 0
    got = rg._load_correlations(["S1"])
    assert [c["rule_id"] for c in got] == ["c", "b", "a", "d"]               # risk first, then the bigger result
    assert got[0]["risk"] == "HIGH" and got[0]["event_count"] == 9
    assert FakeDb.closed == 1


def test_correlation_loading_never_raises_and_needs_a_database(monkeypatch):
    monkeypatch.delenv("SF_POSTGRES_DSN", raising=False)
    assert rg._load_correlations(["S1"]) == []
    monkeypatch.setenv("SF_POSTGRES_DSN", "postgresql://x")

    class Broken(FakeDb):
        def scanCorrelationList(self, sid): raise RuntimeError("db down")
    monkeypatch.setattr("spiderfoot.db.SpiderFootDb", Broken)
    assert rg._load_correlations(["S1"]) == []


def test_the_correlation_list_is_capped(monkeypatch):
    monkeypatch.setenv("SF_POSTGRES_DSN", "postgresql://x")
    monkeypatch.setattr("spiderfoot.db.SpiderFootDb", FakeDb)
    FakeDb.rows = [_corr(str(i), "LOW", i) for i in range(250)]
    assert len(rg._load_correlations(["S1"])) == rg.MAX_CORRELATIONS


def test_the_prompt_shows_each_correlations_risk_and_size(patched):
    agent = FakeAgent()
    text = agent._format_correlations([{"rule_name": "Shared certificate", "risk": "high", "event_count": 7, "description": "d"}])
    assert text == "- [HIGH] Shared certificate (7 events): d"
    assert agent._format_correlations([{"type": "x", "description": "y"}]) == "- x: y"       # the old shape still works


def test_database_correlations_replace_the_ones_the_page_sent_and_the_page_list_is_the_fallback(patched, monkeypatch):
    monkeypatch.setattr(rg, "_load_correlations", lambda ids: [{"rule_name": "FROM-DB", "risk": "HIGH", "event_count": 2, "description": "x"}])
    agent = FakeAgent()
    run(agent, correlations=[{"rule_name": "FROM-PAGE", "description": "y"}])
    user = agent.calls[0][1]["content"]
    assert "FROM-DB" in user and "FROM-PAGE" not in user
    monkeypatch.setattr(rg, "_load_correlations", lambda ids: [])
    agent2 = FakeAgent()
    run(agent2, correlations=[{"rule_name": "FROM-PAGE", "description": "y"}])
    assert "FROM-PAGE" in agent2.calls[0][1]["content"]

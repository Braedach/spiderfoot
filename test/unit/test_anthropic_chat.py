"""Tests for the direct Anthropic path (replaces the LiteLLM proxy)."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import anthropic
import httpx2
import pytest

from spiderfoot.agents.base import AgentConfig, BaseAgent
from spiderfoot.ai import anthropic_chat
from spiderfoot.ai.llm_client import LLMClient, LLMConfig, LLMError, LLMProvider


@pytest.fixture(autouse=True)
def _no_fallback_by_default(monkeypatch):
    """Existing tests exercise the plain endpoint; the fallback tests opt in."""
    monkeypatch.setenv("SF_LLM_FALLBACK", "")


def _reply(text="ok", stop_reason="end_turn"):
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text=text)],
        stop_reason=stop_reason,
        stop_details=None,
        model="claude-sonnet-5",
        usage=SimpleNamespace(input_tokens=10, output_tokens=5),
        to_dict=lambda: {},
    )


def _bad_request():
    req = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    return anthropic.BadRequestError(
        "bad schema", response=httpx2.Response(400, request=req), body=None
    )


class TestBuildRequest:
    def test_lifts_system_messages_and_never_sends_temperature(self):
        req = anthropic_chat.build_request(
            [{"role": "system", "content": "be terse"}, {"role": "user", "content": "hi"}],
            "claude-sonnet-5", 2048,
        )
        assert req["system"] == "be terse"
        assert req["messages"] == [{"role": "user", "content": "hi"}]
        assert not {"temperature", "top_p", "top_k"} & set(req)

    def test_max_tokens_has_room_for_thinking(self):
        req = anthropic_chat.build_request([{"role": "user", "content": "x"}], "m", 256)
        assert req["max_tokens"] == anthropic_chat.MIN_MAX_TOKENS
        big = anthropic_chat.build_request([{"role": "user", "content": "x"}], "m", 20000)
        assert big["max_tokens"] == 20000

    def test_json_schema_becomes_output_config_format(self):
        schema = {"type": "object", "properties": {"a": {"type": "string"}}}
        req = anthropic_chat.build_request(
            [{"role": "user", "content": "x"}], "m", 100,
            response_format={"type": "json_schema", "json_schema": {"name": "n", "schema": schema}},
        )
        assert req["output_config"]["format"] == {"type": "json_schema", "schema": schema}
        assert anthropic_chat.without_schema(req)["output_config"] == {"effort": "medium"}

    def test_json_object_adds_no_constraint(self):
        req = anthropic_chat.build_request(
            [{"role": "user", "content": "x"}], "m", 100, response_format={"type": "json_object"}
        )
        assert "format" not in req["output_config"]

    def test_effort_can_be_disabled(self, monkeypatch):
        monkeypatch.setenv("SF_LLM_EFFORT", "")
        req = anthropic_chat.build_request([{"role": "user", "content": "x"}], "m", 100)
        assert "output_config" not in req


class TestResponseText:
    def test_joins_text_blocks(self):
        msg = SimpleNamespace(
            content=[SimpleNamespace(type="thinking", thinking=""), SimpleNamespace(type="text", text="a"),
                     SimpleNamespace(type="text", text="b")],
            stop_reason="end_turn",
        )
        assert anthropic_chat.response_text(msg) == "ab"

    def test_refusal_raises(self):
        msg = SimpleNamespace(content=[], stop_reason="refusal", stop_details=SimpleNamespace(category="cyber"))
        with pytest.raises(RuntimeError, match="cyber"):
            anthropic_chat.response_text(msg)

    def test_max_tokens_without_text_raises(self):
        with pytest.raises(RuntimeError, match="max_tokens"):
            anthropic_chat.response_text(SimpleNamespace(content=[], stop_reason="max_tokens"))


class TestLLMClientAnthropic:
    def _client(self):
        return LLMClient(LLMConfig(model="claude-sonnet-5", provider=LLMProvider.ANTHROPIC, max_retries=1))

    def test_chat_returns_text_and_usage(self):
        with patch("anthropic.Anthropic") as sdk:
            sdk.return_value.messages.create.return_value = _reply("hello")
            resp = self._client().chat_messages([{"role": "user", "content": "hi"}])
        assert resp.content == "hello"
        assert resp.usage.total_tokens == 15
        sent = sdk.return_value.messages.create.call_args.kwargs
        assert sent["model"] == "claude-sonnet-5" and "temperature" not in sent

    def test_rejected_schema_is_retried_without_it(self):
        fmt = {"type": "json_schema", "json_schema": {"schema": {"type": "object"}}}
        with patch("anthropic.Anthropic") as sdk:
            create = sdk.return_value.messages.create
            create.side_effect = [_bad_request(), _reply("{}")]
            resp = self._client().chat_messages([{"role": "user", "content": "hi"}], response_format=fmt)
        assert resp.content == "{}"
        assert "format" not in create.call_args_list[1].kwargs.get("output_config", {})

    def test_refusal_is_an_llm_error(self):
        with patch("anthropic.Anthropic") as sdk:
            sdk.return_value.messages.create.return_value = SimpleNamespace(
                content=[], stop_reason="refusal", stop_details=None
            )
            with pytest.raises(LLMError):
                self._client().chat_messages([{"role": "user", "content": "hi"}])


class _Agent(BaseAgent):
    event_types = []

    async def process_event(self, *a, **k):  # pragma: no cover - not used
        return None


@pytest.mark.asyncio
async def test_agent_calls_claude_directly_when_provider_is_anthropic():
    agent = _Agent(AgentConfig(name="t", llm_provider="anthropic", llm_model="claude-sonnet-5"))
    client = MagicMock()
    client.messages.create = AsyncMock(return_value=_reply("answer"))
    client.close = AsyncMock()
    with patch("anthropic.AsyncAnthropic", return_value=client) as ctor:
        text = await agent.call_llm([{"role": "user", "content": "q"}], temperature=0.3)
    assert text == "answer"
    assert "temperature" not in client.messages.create.call_args.kwargs
    assert ctor.call_args.kwargs["max_retries"] == agent.config.llm_max_retries
    await agent.close()
    client.close.assert_awaited()


def test_agent_config_reads_provider_from_env(monkeypatch):
    monkeypatch.setenv("SF_LLM_PROVIDER", "Anthropic")
    monkeypatch.delenv("SF_LLM_API_BASE", raising=False)
    cfg = AgentConfig.from_env("x")
    assert cfg.llm_provider == "anthropic" and cfg.llm_endpoint == ""


class TestFallback:
    def test_default_asks_the_api_to_retry_a_refusal_on_another_model(self, monkeypatch):
        monkeypatch.delenv("SF_LLM_FALLBACK", raising=False)
        assert anthropic_chat.fallback_kwargs() == {
            "betas": [anthropic_chat.FALLBACK_BETA], "fallbacks": "default"}

    def test_can_be_turned_off(self, monkeypatch):
        monkeypatch.setenv("SF_LLM_FALLBACK", "")
        assert anthropic_chat.fallback_kwargs() == {}

    def test_sync_client_uses_the_beta_endpoint_when_on(self, monkeypatch):
        monkeypatch.delenv("SF_LLM_FALLBACK", raising=False)
        with patch("anthropic.Anthropic") as sdk:
            beta_create = sdk.return_value.beta.messages.create
            beta_create.return_value = _reply("rescued")
            resp = LLMClient(LLMConfig(model="claude-sonnet-5-5", provider=LLMProvider.ANTHROPIC,
                                       max_retries=1)).chat_messages([{"role": "user", "content": "x"}])
        assert resp.content == "rescued"
        sent = beta_create.call_args.kwargs
        assert sent["fallbacks"] == "default" and sent["betas"] == [anthropic_chat.FALLBACK_BETA]
        sdk.return_value.messages.create.assert_not_called()

    @pytest.mark.asyncio
    async def test_agent_uses_the_beta_endpoint_when_on(self, monkeypatch):
        monkeypatch.delenv("SF_LLM_FALLBACK", raising=False)
        agent = _Agent(AgentConfig(name="t", llm_provider="anthropic", llm_model="claude-sonnet-5-5"))
        client = MagicMock()
        client.beta.messages.create = AsyncMock(return_value=_reply("rescued"))
        client.close = AsyncMock()
        with patch("anthropic.AsyncAnthropic", return_value=client):
            assert await agent.call_llm([{"role": "user", "content": "q"}]) == "rescued"
        assert client.beta.messages.create.call_args.kwargs["fallbacks"] == "default"
        await agent.close()

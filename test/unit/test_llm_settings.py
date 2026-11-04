"""Tests for GUI-managed LLM provider settings (spiderfoot.ai.llm_settings)."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from spiderfoot.ai import llm_settings


@pytest.fixture(autouse=True)
def store(monkeypatch):
    """An in-memory stand-in for the tbl_config rows in scope LLM."""
    rows: dict[str, str] = {}

    def fake_write(items):
        for k, v in items.items():
            if v is None:
                rows.pop(k, None)
            else:
                rows[k] = v

    monkeypatch.setenv("SF_JWT_SECRET", "unit-test-secret")
    monkeypatch.delenv("SF_JWT_SECRET_KEY", raising=False)
    monkeypatch.setattr(llm_settings, "_read_all", lambda: dict(rows))
    monkeypatch.setattr(llm_settings, "_write", fake_write)
    llm_settings._invalidate()
    yield rows
    llm_settings._invalidate()


def test_encrypt_round_trip_and_not_plaintext():
    token = llm_settings.encrypt_secret("sk-live-123")
    assert token.startswith("enc:v1:")
    assert "sk-live-123" not in token
    assert llm_settings.decrypt_secret(token) == "sk-live-123"


def test_rotated_secret_reads_as_unset(monkeypatch):
    token = llm_settings.encrypt_secret("sk-live-123")
    monkeypatch.setenv("SF_JWT_SECRET", "a-different-secret")
    assert llm_settings.decrypt_secret(token) is None


def test_no_secret_means_cannot_encrypt(monkeypatch):
    monkeypatch.delenv("SF_JWT_SECRET", raising=False)
    with pytest.raises(llm_settings.SettingsUnavailable):
        llm_settings.encrypt_secret("x")


def test_key_is_stored_encrypted(store):
    llm_settings.set_provider("anthropic", api_key="sk-ant-secret")
    assert store["anthropic.api_key"].startswith("enc:v1:")
    assert "sk-ant-secret" not in store["anthropic.api_key"]


def test_status_never_contains_the_key(store):
    llm_settings.set_provider("openai", api_key="sk-openai-secret", model="gpt-x")
    status = llm_settings.provider_status()
    assert "sk-openai-secret" not in repr(status)
    openai = next(p for p in status["providers"] if p["id"] == "openai")
    assert openai["key_set"] is True and openai["model"] == "gpt-x"
    assert next(p for p in status["providers"] if p["id"] == "anthropic")["key_set"] is False


def test_omitted_key_is_kept_and_empty_key_clears(store):
    llm_settings.set_provider("openai", api_key="sk-1")
    llm_settings.set_provider("openai", model="m")  # key omitted: unchanged
    assert "openai.api_key" in store
    llm_settings.set_provider("openai", api_key="")  # empty: cleared
    assert "openai.api_key" not in store


def test_no_active_provider_means_use_environment():
    assert llm_settings.resolve() is None


def test_active_provider_resolves_with_its_own_key_and_defaults():
    llm_settings.set_provider("anthropic", api_key="sk-ant")
    llm_settings.set_provider("openai", api_key="sk-oa", model="gpt-x")
    llm_settings.set_active("openai")
    eff = llm_settings.resolve()
    assert (eff.provider, eff.api_key, eff.model, eff.source) == ("openai", "sk-oa", "gpt-x", "gui")
    llm_settings.set_active("anthropic")
    eff = llm_settings.resolve()
    assert (eff.provider, eff.api_key, eff.model) == ("anthropic", "sk-ant", "claude-sonnet-5-5")


def test_deepseek_is_openai_provider_with_its_own_base():
    llm_settings.set_provider("deepseek", api_key="sk-ds")
    llm_settings.set_active("deepseek")
    eff = llm_settings.resolve()
    assert eff.provider == "openai"
    assert eff.api_base == "https://api.deepseek.com/v1"
    assert eff.model == "deepseek-chat"


def test_unknown_provider_is_rejected():
    with pytest.raises(ValueError):
        llm_settings.set_active("skynet")
    with pytest.raises(ValueError):
        llm_settings.set_provider("skynet", api_key="x")


def test_undecryptable_key_resolves_blank_not_error(monkeypatch):
    llm_settings.set_provider("anthropic", api_key="sk-ant")
    llm_settings.set_active("anthropic")
    monkeypatch.setenv("SF_JWT_SECRET", "rotated")
    llm_settings._invalidate()
    assert llm_settings.resolve().api_key == ""


def test_unreadable_store_falls_back_to_environment(monkeypatch):
    def boom():
        raise llm_settings.SettingsUnavailable("no database")

    monkeypatch.setattr(llm_settings, "_read_all", boom)
    llm_settings._invalidate()
    assert llm_settings.resolve() is None


def test_llmconfig_from_env_is_overridden_by_gui(monkeypatch):
    from spiderfoot.ai.llm_client import LLMConfig, LLMProvider

    monkeypatch.setenv("SF_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("SF_LLM_API_KEY", "env-key")
    assert LLMConfig.from_env().api_key == "env-key"  # nothing chosen in the GUI

    llm_settings.set_provider("openai", api_key="gui-key", model="gpt-x")
    llm_settings.set_active("openai")
    cfg = LLMConfig.from_env()
    assert (cfg.provider, cfg.api_key, cfg.model) == (LLMProvider.OPENAI, "gui-key", "gpt-x")


def test_agent_picks_up_gui_change_and_drops_stale_client(monkeypatch):
    from spiderfoot.agents.base import AgentConfig, BaseAgent

    closed = []

    class FakeClient:
        async def close(self):
            closed.append(True)

    agent = SimpleNamespace(
        config=AgentConfig(name="t", llm_provider="anthropic", llm_model="claude-sonnet-5-5", llm_api_key="env"),
        _anthropic_client=FakeClient(),
    )
    refresh = BaseAgent._refresh_llm_settings

    asyncio.run(refresh(agent))  # nothing chosen: untouched
    assert agent.config.llm_api_key == "env" and not closed

    llm_settings.set_provider("openai", api_key="gui-key", model="gpt-x")
    llm_settings.set_active("openai")
    asyncio.run(refresh(agent))
    assert (agent.config.llm_provider, agent.config.llm_api_key, agent.config.llm_model) == ("openai", "gui-key", "gpt-x")
    assert agent._anthropic_client is None and closed == [True]


def test_anthropic_without_any_key_points_at_ai_connections(monkeypatch):
    from spiderfoot.agents.base import AgentConfig, BaseAgent

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    agent = SimpleNamespace(
        config=AgentConfig(name="t", llm_provider="anthropic", llm_api_key=""),
        _anthropic_client=None,
    )
    with pytest.raises(RuntimeError, match="AI Connections"):
        asyncio.run(BaseAgent._call_anthropic(agent, [{"role": "user", "content": "hi"}], "m", 10, None))

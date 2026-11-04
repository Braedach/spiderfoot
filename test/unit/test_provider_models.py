"""Tests for listing the models each provider offers."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
import requests

from spiderfoot.ai import llm_settings, provider_models


@pytest.fixture(autouse=True)
def store(monkeypatch):
    rows: dict[str, str] = {}

    def fake_write(items):
        for k, v in items.items():
            rows.pop(k, None) if v is None else rows.__setitem__(k, v)

    monkeypatch.setenv("SF_JWT_SECRET", "unit-test-secret")
    monkeypatch.setattr(llm_settings, "_read_all", lambda: dict(rows))
    monkeypatch.setattr(llm_settings, "_write", fake_write)
    llm_settings._invalidate()
    yield rows
    llm_settings._invalidate()


def test_unknown_provider_raises():
    with pytest.raises(ValueError):
        provider_models.list_models("skynet")


def test_mock_has_no_models():
    assert provider_models.list_models("mock") == {"models": [], "error": None}


def test_key_needed_before_listing_openai():
    out = provider_models.list_models("openai")
    assert out["models"] == [] and "Save an API key first" in out["error"]


def test_anthropic_lists_models_with_the_stored_key(monkeypatch):
    llm_settings.set_provider("anthropic", api_key="sk-ant-secret")
    seen = {}

    class FakeClient:
        def __init__(self, api_key=None, **kw):
            seen["key"] = api_key
            self.models = SimpleNamespace(list=lambda limit=100: SimpleNamespace(data=[
                SimpleNamespace(id="claude-a", display_name="Claude A"),
                SimpleNamespace(id="claude-b", display_name=None),
            ]))

    import anthropic
    monkeypatch.setattr(anthropic, "Anthropic", FakeClient)
    out = provider_models.list_models("anthropic")
    assert seen["key"] == "sk-ant-secret"
    assert out["models"] == [{"id": "claude-a", "label": "Claude A"}, {"id": "claude-b", "label": "claude-b"}]
    assert out["error"] is None and "sk-ant-secret" not in repr(out)


def test_openai_filters_non_chat_models_but_deepseek_does_not(monkeypatch):
    payload = {"data": [{"id": "gpt-4o"}, {"id": "text-embedding-3-small"}, {"id": "whisper-1"}, {"id": "gpt-4o-mini"}]}
    monkeypatch.setattr(provider_models, "_http_json", lambda url, key: payload)
    llm_settings.set_provider("openai", api_key="sk-oa")
    assert [m["id"] for m in provider_models.list_models("openai")["models"]] == ["gpt-4o", "gpt-4o-mini"]
    llm_settings.set_provider("deepseek", api_key="sk-ds")
    assert len(provider_models.list_models("deepseek")["models"]) == 4


def test_openai_compatible_uses_the_provider_base(monkeypatch):
    urls = []
    monkeypatch.setattr(provider_models, "_http_json", lambda url, key: urls.append(url) or {"data": []})
    llm_settings.set_provider("deepseek", api_key="sk-ds")
    provider_models.list_models("deepseek")
    assert urls == ["https://api.deepseek.com/v1/models"]


def test_provider_errors_become_safe_messages(monkeypatch):
    llm_settings.set_provider("openai", api_key="sk-oa-secret")

    def rejected(url, key):
        raise requests.HTTPError(response=SimpleNamespace(status_code=401))

    monkeypatch.setattr(provider_models, "_http_json", rejected)
    out = provider_models.list_models("openai")
    assert out["models"] == [] and "rejected the API key" in out["error"]

    def down(url, key):
        raise requests.ConnectionError("boom sk-oa-secret")

    monkeypatch.setattr(provider_models, "_http_json", down)
    out = provider_models.list_models("openai")
    assert out["error"] == "Could not reach the provider." and "sk-oa-secret" not in repr(out)


def test_ollama_lists_pulled_models_and_needs_no_key(monkeypatch):
    urls = []
    monkeypatch.setattr(provider_models, "_http_json",
                        lambda url, key: urls.append((url, key)) or {"models": [{"name": "llama3:8b"}, {"name": "mistral"}]})
    out = provider_models.list_models("ollama")
    assert [m["id"] for m in out["models"]] == ["llama3:8b", "mistral"]
    assert urls == [("http://localhost:11434/api/tags", "")]


def test_non_http_base_is_refused():
    llm_settings.set_provider("openai", api_key="sk", api_base="file:///etc/passwd")
    out = provider_models.list_models("openai")
    assert out["models"] == [] and "http" in out["error"]


def test_login_page_instead_of_json_gives_a_clear_message(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            raise ValueError("Expecting value: line 1 column 1 (char 0)")

    monkeypatch.setattr("requests.get", lambda *a, **k: FakeResponse())
    llm_settings.set_provider("ollama", api_base="https://ollama.example.com")
    out = provider_models.list_models("ollama")
    assert out["models"] == []
    assert "did not return a model list" in out["error"] and "Expecting value" not in out["error"]

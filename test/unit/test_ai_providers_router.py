"""API tests for the AI Connections router: admin-only, keys are write-only."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from spiderfoot.ai import llm_settings
from spiderfoot.api.dependencies import get_api_key
from spiderfoot.api.routers import ai_providers


def _client(role: str | None) -> TestClient:
    app = FastAPI()
    app.include_router(ai_providers.router, prefix="/api")
    app.dependency_overrides[get_api_key] = lambda: None

    @app.middleware("http")
    async def set_user(request: Request, call_next):
        request.state.user = SimpleNamespace(role=SimpleNamespace(value=role)) if role else None
        return await call_next(request)

    return TestClient(app)


@pytest.fixture(autouse=True)
def memory_store(monkeypatch):
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


@pytest.mark.parametrize("role", [None, "viewer", "analyst", "operator"])
def test_non_admins_are_refused(role):
    client = _client(role)
    assert client.get("/api/ai/providers").status_code == 403
    assert client.put("/api/ai/providers/openai", json={"api_key": "x"}).status_code == 403
    assert client.delete("/api/ai/providers/openai/key").status_code == 403


def test_admin_flow_never_returns_the_key():
    client = _client("admin")
    r = client.put("/api/ai/providers/openai", json={"api_key": "sk-secret-value", "model": "gpt-x"})
    assert r.status_code == 200
    assert "sk-secret-value" not in r.text
    assert client.get("/api/ai/providers").json()["source"] == "environment"

    r = client.put("/api/ai/providers/active", json={"provider": "openai"})
    body = r.json()
    assert body["active"] == "openai" and body["source"] == "gui"
    assert next(p for p in body["providers"] if p["id"] == "openai")["key_set"] is True
    assert "sk-secret-value" not in r.text

    r = client.delete("/api/ai/providers/openai/key")
    assert next(p for p in r.json()["providers"] if p["id"] == "openai")["key_set"] is False


def test_unknown_provider_is_404():
    client = _client("admin")
    assert client.put("/api/ai/providers/skynet", json={}).status_code == 404
    assert client.put("/api/ai/providers/active", json={"provider": "skynet"}).status_code == 404


def test_models_endpoint_is_admin_only_and_404s_unknown(monkeypatch):
    from spiderfoot.ai import provider_models
    monkeypatch.setattr(provider_models, "list_models",
                        lambda pid: {"models": [{"id": "m1", "label": "M1"}], "error": None})
    assert _client("viewer").get("/api/ai/providers/openai/models").status_code == 403
    r = _client("admin").get("/api/ai/providers/openai/models")
    assert r.status_code == 200 and r.json()["models"][0]["id"] == "m1"

    def boom(pid):
        raise ValueError("unknown provider")

    monkeypatch.setattr(provider_models, "list_models", boom)
    assert _client("admin").get("/api/ai/providers/skynet/models").status_code == 404

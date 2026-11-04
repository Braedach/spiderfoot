"""
AI Connections API: per-provider LLM settings managed from the GUI.

API keys are write-only: they are encrypted at rest and never returned, only
whether one is set. Reads and writes are limited to administrators.
"""
from __future__ import annotations

import logging
import os

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from spiderfoot.ai import llm_settings
from ..dependencies import get_api_key

log = logging.getLogger(__name__)


def require_admin(request: Request) -> None:
    user = getattr(request.state, "user", None)
    role = getattr(getattr(user, "role", None), "value", getattr(user, "role", None))
    if role != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required")


router = APIRouter(dependencies=[Depends(get_api_key), Depends(require_admin)])


class ProviderUpdate(BaseModel):
    api_key: str | None = Field(None, description="Omit to keep the stored key; empty string clears it")
    model: str | None = None
    api_base: str | None = None


class ActiveProvider(BaseModel):
    provider: str = Field("", description="Provider id, or empty to use the stack environment")


def _environment_fallback() -> dict:
    return {
        "provider": os.environ.get("SF_LLM_PROVIDER", ""),
        "model": os.environ.get("SF_LLM_MODEL", ""),
        "key_set": bool(os.environ.get("SF_LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")),
    }


@router.get("/ai/providers")
def list_providers() -> dict:
    status = llm_settings.provider_status()
    status["source"] = "gui" if status["active"] else "environment"
    status["environment"] = _environment_fallback()
    return status


@router.put("/ai/providers/active")
def set_active_provider(body: ActiveProvider) -> dict:
    try:
        llm_settings.set_active(body.provider)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except llm_settings.SettingsUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return list_providers()


@router.put("/ai/providers/{provider_id}")
def update_provider(provider_id: str, body: ProviderUpdate) -> dict:
    try:
        llm_settings.set_provider(
            provider_id, api_key=body.api_key, model=body.model, api_base=body.api_base
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except llm_settings.SettingsUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    log.info("LLM provider '%s' updated (key changed: %s)", provider_id, body.api_key is not None)
    return list_providers()


@router.delete("/ai/providers/{provider_id}/key")
def clear_provider_key(provider_id: str) -> dict:
    try:
        llm_settings.clear_key(provider_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except llm_settings.SettingsUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return list_providers()

"""List the models a provider offers, using the key saved in AI Connections.

Never raises: a failure comes back as ``{"models": [], "error": "<safe message>"}`` so the
page can fall back to typing a model name. Error text never includes the key.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from spiderfoot.ai import llm_settings

log = logging.getLogger("sf.ai.provider_models")

_TIMEOUT = 10
_OPENAI_BASE = "https://api.openai.com/v1"
# The OpenAI models endpoint also lists embedding, audio and image models, which cannot answer reports.
_NOT_CHAT = re.compile(r"embedding|whisper|tts|dall-e|moderation|audio|realtime|transcribe|image|davinci|babbage", re.I)


def _result(models: list[dict[str, str]], error: str | None = None) -> dict[str, Any]:
    return {"models": models, "error": error}


def _anthropic(key: str) -> dict[str, Any]:
    import anthropic

    client = anthropic.Anthropic(api_key=key or None, timeout=_TIMEOUT, max_retries=0)
    try:
        page = client.models.list(limit=100)
    except anthropic.AuthenticationError:
        return _result([], "Anthropic rejected the API key.")
    except anthropic.APIConnectionError:
        return _result([], "Could not reach Anthropic.")
    except anthropic.APIError as exc:
        return _result([], f"Anthropic returned an error ({getattr(exc, 'status_code', 'unknown')}).")
    models = [{"id": m.id, "label": getattr(m, "display_name", None) or m.id} for m in page.data]
    return _result(models)


def _http_json(url: str, key: str) -> Any:
    import requests

    if not re.match(r"^https?://", url):
        raise ValueError("The API base URL must start with http:// or https://")
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    response = requests.get(url, headers=headers, timeout=_TIMEOUT)
    response.raise_for_status()
    return response.json()


def _openai_compatible(preset: str, key: str, base: str) -> dict[str, Any]:
    import requests

    base = (base or _OPENAI_BASE).rstrip("/")
    try:
        data = _http_json(f"{base}/models", key)
    except ValueError as exc:
        return _result([], str(exc))
    except requests.HTTPError as exc:
        code = exc.response.status_code if exc.response is not None else "unknown"
        return _result([], "The provider rejected the API key." if code in (401, 403) else f"The provider returned an error ({code}).")
    except requests.RequestException:
        return _result([], "Could not reach the provider.")
    ids = sorted({m["id"] for m in data.get("data", []) if isinstance(m, dict) and "id" in m})
    if preset == "openai":
        ids = [i for i in ids if not _NOT_CHAT.search(i)]
    return _result([{"id": i, "label": i} for i in ids])


def _ollama(base: str) -> dict[str, Any]:
    import requests

    try:
        data = _http_json(f"{base.rstrip('/')}/api/tags", "")
    except ValueError as exc:
        return _result([], str(exc))
    except requests.RequestException:
        return _result([], "Could not reach Ollama at that address.")
    names = sorted({m["name"] for m in data.get("models", []) if isinstance(m, dict) and "name" in m})
    return _result([{"id": n, "label": n} for n in names])


def list_models(preset: str) -> dict[str, Any]:
    """Models offered by ``preset``. Raises ValueError only for an unknown preset."""
    if preset not in llm_settings.PRESETS:
        raise ValueError(f"unknown provider '{preset}'")
    if preset == "mock":
        return _result([])
    try:
        key, base = llm_settings.credentials(preset)
    except Exception as exc:
        log.debug("LLM settings unavailable: %s", exc)
        return _result([], "Saved settings could not be read.")
    needs_key = llm_settings.PRESETS[preset]["needs_key"]
    if needs_key and not key and preset != "anthropic":
        return _result([], "Save an API key first to list this provider's models.")
    try:
        if preset == "anthropic":
            return _anthropic(key)
        if preset == "ollama":
            return _ollama(base)
        return _openai_compatible(preset, key, base)
    except Exception:
        log.warning("Listing models for %s failed", preset, exc_info=True)
        return _result([], "Could not list models.")

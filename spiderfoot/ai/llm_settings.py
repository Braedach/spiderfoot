"""
GUI-managed LLM provider settings.

Each provider the AI Connections page offers (Anthropic, OpenAI, DeepSeek,
Ollama, Mock) keeps its own API key, model and base URL, plus one setting for
which provider is active. They live in ``tbl_config`` under their own scope
(``LLM``) so they never mix with the global options, and API keys are
encrypted at rest.

Precedence, resolved on every request so a change in the GUI takes effect
without a restart: **GUI setting, then the stack environment** (``SF_LLM_*`` /
``ANTHROPIC_API_KEY``), so an environment-only deployment keeps working.

Encryption: Fernet, with a key derived (HKDF-SHA256) from the JWT secret (``SF_JWT_SECRET``),
a secret every service already has. Rotating that secret makes stored keys
undecryptable; they then read as "not set" and must be entered again.
"""
from __future__ import annotations

import base64
import logging
import os
import time
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("sf.ai.llm_settings")

SCOPE = "LLM"
ACTIVE_OPT = "active"
_ENC_PREFIX = "enc:v1:"
_CACHE_TTL_SECONDS = 5.0

# Preset id -> how it maps onto the backend's provider types. DeepSeek is not
# its own provider type: its API is wire-compatible with OpenAI's, so it is the
# "openai" provider with DeepSeek's base URL.
PRESETS: dict[str, dict[str, Any]] = {
    "anthropic": {"label": "Anthropic", "provider": "anthropic", "api_base": "",
                  "default_model": "claude-sonnet-5-5", "needs_key": True},
    "openai": {"label": "OpenAI", "provider": "openai", "api_base": "",
               "default_model": "gpt-4o-mini", "needs_key": True},
    "deepseek": {"label": "DeepSeek", "provider": "openai",
                 "api_base": "https://api.deepseek.com/v1",
                 "default_model": "deepseek-chat", "needs_key": True},
    "ollama": {"label": "Ollama", "provider": "ollama",
               "api_base": "http://localhost:11434",
               "default_model": "llama3", "needs_key": False},
    "mock": {"label": "Mock", "provider": "mock", "api_base": "",
             "default_model": "", "needs_key": False},
}


class SettingsUnavailable(RuntimeError):
    """The settings store cannot be used (no database or no secret)."""


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

def _fernet() -> Any:
    # The stacks hand services the stack's SF_JWT_SECRET_KEY as SF_JWT_SECRET.
    secret = os.environ.get("SF_JWT_SECRET", "") or os.environ.get("SF_JWT_SECRET_KEY", "")
    if not secret:
        raise SettingsUnavailable("SF_JWT_SECRET is not set; cannot encrypt provider keys")
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"spiderfoot-llm-provider-keys-v1").derive(secret.encode())
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_secret(plain: str) -> str:
    return _ENC_PREFIX + _fernet().encrypt(plain.encode()).decode()


def decrypt_secret(stored: str) -> str | None:
    """Return the plaintext, or None if it cannot be decrypted (e.g. the secret rotated)."""
    if not stored.startswith(_ENC_PREFIX):
        return None
    try:
        return _fernet().decrypt(stored[len(_ENC_PREFIX):].encode()).decode()
    except Exception:
        log.warning("A stored LLM provider key could not be decrypted; enter it again in AI Connections")
        return None


# ---------------------------------------------------------------------------
# Storage (tbl_config, scope LLM)
# ---------------------------------------------------------------------------

def _connect() -> Any:
    dsn = os.environ.get("SF_POSTGRES_DSN", "")
    if not dsn:
        raise SettingsUnavailable("SF_POSTGRES_DSN is not set")
    import psycopg2
    return psycopg2.connect(dsn, connect_timeout=5)


def _read_all() -> dict[str, str]:
    conn = _connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT opt, val FROM tbl_config WHERE scope = %s", (SCOPE,))
            rows = {opt: val for opt, val in cur.fetchall()}
        conn.commit()
        return rows
    finally:
        conn.close()


def _write(items: dict[str, str | None]) -> None:
    """Upsert values; a None value deletes the row."""
    conn = _connect()
    try:
        with conn.cursor() as cur:
            for opt, val in items.items():
                if val is None:
                    cur.execute("DELETE FROM tbl_config WHERE scope = %s AND opt = %s", (SCOPE, opt))
                else:
                    cur.execute(
                        "INSERT INTO tbl_config (scope, opt, val) VALUES (%s, %s, %s) "
                        "ON CONFLICT (scope, opt) DO UPDATE SET val = EXCLUDED.val",
                        (SCOPE, opt, val),
                    )
        conn.commit()
    finally:
        conn.close()


_cache: tuple[float, dict[str, str]] | None = None


def _rows(force: bool = False) -> dict[str, str]:
    global _cache
    now = time.monotonic()
    if not force and _cache and now - _cache[0] < _CACHE_TTL_SECONDS:
        return _cache[1]
    rows = _read_all()
    _cache = (now, rows)
    return rows


def _invalidate() -> None:
    global _cache
    _cache = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class EffectiveLLM:
    provider: str          # backend provider type: anthropic / openai / ollama / mock
    model: str
    api_key: str
    api_base: str
    source: str            # "gui" or "environment"
    preset: str = ""


def _check_preset(preset: str) -> None:
    if preset not in PRESETS:
        raise ValueError(f"unknown provider '{preset}'")


def provider_status() -> dict[str, Any]:
    """Safe-to-return view: never includes a key, only whether one is set."""
    try:
        rows = _rows(force=True)
    except Exception as exc:
        log.warning("LLM settings unavailable: %s", exc)
        rows = {}
    active = rows.get(ACTIVE_OPT, "")
    providers = []
    for pid, preset in PRESETS.items():
        stored = rows.get(f"{pid}.api_key", "")
        providers.append({
            "id": pid,
            "label": preset["label"],
            "needs_key": preset["needs_key"],
            "key_set": bool(stored) and decrypt_secret(stored) is not None,
            "model": rows.get(f"{pid}.model", ""),
            "api_base": rows.get(f"{pid}.api_base", ""),
            "default_model": preset["default_model"],
            "default_api_base": preset["api_base"],
        })
    return {"active": active if active in PRESETS else "", "providers": providers}


def set_provider(preset: str, *, api_key: str | None = None, model: str | None = None,
                 api_base: str | None = None) -> None:
    """Save changes for one provider. ``api_key=None`` leaves the stored key alone."""
    _check_preset(preset)
    items: dict[str, str | None] = {}
    if api_key is not None:
        items[f"{preset}.api_key"] = encrypt_secret(api_key) if api_key else None
    if model is not None:
        items[f"{preset}.model"] = model or None
    if api_base is not None:
        items[f"{preset}.api_base"] = api_base or None
    if items:
        _write(items)
        _invalidate()


def clear_key(preset: str) -> None:
    _check_preset(preset)
    _write({f"{preset}.api_key": None})
    _invalidate()


def set_active(preset: str) -> None:
    if preset:
        _check_preset(preset)
    _write({ACTIVE_OPT: preset or None})
    _invalidate()


def credentials(preset: str) -> tuple[str, str]:
    """Server-side only: the stored (key, api_base) for a provider, never sent to a client.

    The key is "" when none is stored or it cannot be decrypted.
    """
    _check_preset(preset)
    rows = _rows(force=True)
    stored = rows.get(f"{preset}.api_key", "")
    key = (decrypt_secret(stored) or "") if stored else ""
    base = rows.get(f"{preset}.api_base") or PRESETS[preset]["api_base"]
    return key, base


def resolve() -> EffectiveLLM | None:
    """The settings to use right now, or None when the GUI has not chosen a provider.

    None means "use the environment", so callers fall back to the values they
    already read from ``SF_LLM_*``. Never raises: an unreadable store falls back
    to the environment rather than breaking report generation.
    """
    try:
        rows = _rows()
    except Exception as exc:
        log.debug("LLM settings unavailable, using environment: %s", exc)
        return None
    pid = rows.get(ACTIVE_OPT, "")
    if pid not in PRESETS:
        return None
    preset = PRESETS[pid]
    key = ""
    stored = rows.get(f"{pid}.api_key", "")
    if stored:
        key = decrypt_secret(stored) or ""
    return EffectiveLLM(
        provider=preset["provider"],
        model=rows.get(f"{pid}.model") or preset["default_model"],
        api_key=key,
        api_base=rows.get(f"{pid}.api_base") or preset["api_base"],
        source="gui",
        preset=pid,
    )

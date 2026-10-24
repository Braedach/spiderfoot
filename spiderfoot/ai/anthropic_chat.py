"""Map SpiderFoot's OpenAI-style chat calls onto Anthropic's Messages API.

SpiderFoot's LLM callers speak the OpenAI chat shape (a list of role/content
messages, an optional ``response_format``). This module turns that into
arguments for the official ``anthropic`` SDK and turns the reply back into
text, so the callers can talk to Claude directly instead of through a proxy
(the LiteLLM gateway this replaces).

API facts this relies on (Claude Sonnet 5 / 5.5):
  * ``temperature``, ``top_p`` and ``top_k`` are rejected (HTTP 400), so none is
    sent.
  * Structured output is ``output_config.format`` with a ``json_schema``.
  * Thinking tokens count against ``max_tokens``, so a small cap can return no
    text at all; ``MIN_MAX_TOKENS`` keeps room for the answer.
  * A request can end with ``stop_reason == "refusal"``.
"""

from __future__ import annotations

import os
from typing import Any

# Thinking shares this budget with the visible answer; callers that ask for
# 1-2k tokens would otherwise be cut off before any text.
MIN_MAX_TOKENS = 8192

DEFAULT_EFFORT = "medium"


def build_request(
    messages: list[dict[str, Any]],
    model: str,
    max_tokens: int,
    response_format: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return keyword arguments for ``client.messages.create``.

    Args:
        messages: OpenAI-style chat messages; ``system`` messages are lifted
            into the top-level ``system`` field.
        model: Claude model id, e.g. ``claude-sonnet-5``.
        max_tokens: requested output cap (raised to ``MIN_MAX_TOKENS``).
        response_format: OpenAI-style ``{"type": "json_schema", ...}`` or
            ``{"type": "json_object"}``.
    """
    system_parts: list[str] = []
    chat: list[dict[str, Any]] = []
    for m in messages:
        role = m.get("role")
        content = m.get("content", "")
        if role == "system":
            system_parts.append(str(content))
        elif role in ("user", "assistant"):
            chat.append({"role": role, "content": content})

    request: dict[str, Any] = {
        "model": model,
        "max_tokens": max(int(max_tokens or 0), MIN_MAX_TOKENS),
        "messages": chat,
    }
    if system_parts:
        request["system"] = "\n\n".join(system_parts)

    output_config: dict[str, Any] = {}
    effort = os.environ.get("SF_LLM_EFFORT", DEFAULT_EFFORT).strip().lower()
    if effort:
        output_config["effort"] = effort

    schema = _json_schema(response_format)
    if schema is not None:
        output_config["format"] = {"type": "json_schema", "schema": schema}
    if output_config:
        request["output_config"] = output_config

    return request


def without_schema(request: dict[str, Any]) -> dict[str, Any]:
    """Copy of ``request`` with the structured-output constraint removed.

    Used to retry once when the API rejects a schema that uses keywords the
    constrained decoder does not support; the callers already parse JSON
    defensively.
    """
    retry = dict(request)
    cfg = dict(retry.get("output_config", {}))
    cfg.pop("format", None)
    if cfg:
        retry["output_config"] = cfg
    else:
        retry.pop("output_config", None)
    return retry


def response_text(message: Any) -> str:
    """Concatenate the text blocks of a Messages API reply.

    Raises:
        RuntimeError: the model refused the request, or hit ``max_tokens``
            before writing any text.
    """
    if getattr(message, "stop_reason", None) == "refusal":
        details = getattr(message, "stop_details", None)
        category = getattr(details, "category", None)
        raise RuntimeError(f"Claude declined the request (category: {category})")

    text = "".join(
        block.text for block in getattr(message, "content", []) if getattr(block, "type", "") == "text"
    )
    if not text and getattr(message, "stop_reason", None) == "max_tokens":
        raise RuntimeError("Claude hit max_tokens before writing any text")
    return text


def _json_schema(response_format: dict[str, Any] | None) -> dict[str, Any] | None:
    """Extract the JSON schema from an OpenAI-style ``response_format``."""
    if not response_format or response_format.get("type") != "json_schema":
        return None
    spec = response_format.get("json_schema") or {}
    schema = spec.get("schema")
    return schema if isinstance(schema, dict) else None

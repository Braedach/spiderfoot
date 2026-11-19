"""Request headers for an authenticated application test (a session cookie or an Authorization header).

The value is a credential, so it is handled differently from every other scan option:
  * it is validated here and accepted only for a profile that requires the authorisation statement;
  * it is held in Redis for a few hours under the scan id, taken out of Redis (and deleted) by the process that runs the
    scan, and never written to the database (``scanConfigSet`` skips it), to Celery's task arguments or to the log;
  * the active tools receive it as command-line headers for requests to the target only (the scope guard decides which
    hosts those are), and modules never log a command line.
"""

from __future__ import annotations

import json
import re

OPT_KEY = "_request_headers"          # in a scan's global options; list of "Name: value" strings
SECRET_SCAN_OPTS = frozenset({OPT_KEY})
MAX_HEADERS = 5
MAX_VALUE_CHARS = 2048
STASH_TTL_SECONDS = 6 * 3600

_NAME = re.compile(r"^[A-Za-z0-9\-]{1,64}$")
# Headers a person must not set: they would change how the request is framed or routed, not authenticate it.
_REFUSED_NAMES = frozenset({"host", "content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer",
                            "proxy-authorization", "proxy-connection", "keep-alive", "expect"})


class HeaderError(ValueError):
    """A header the scan cannot accept; ``safe_message`` is safe to show (it never contains the value)."""

    @property
    def safe_message(self) -> str:
        return self.args[0] if self.args else "invalid request header"


def parse_headers(raw) -> list[str]:
    """Validate ``["Name: value", ...]`` and return it normalised (``Name: value``)."""
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        raise HeaderError("request_headers must be a list of 'Name: value' strings")
    cleaned = []
    for item in raw:
        if not isinstance(item, str) or ":" not in item:
            raise HeaderError("each request header must look like 'Name: value'")
        name, value = item.split(":", 1)
        name, value = name.strip(), value.strip()
        if not _NAME.match(name):
            raise HeaderError("a request header name has characters that are not allowed")
        if name.lower() in _REFUSED_NAMES:
            raise HeaderError(f"the '{name}' header cannot be set")
        if not value or len(value) > MAX_VALUE_CHARS:
            raise HeaderError(f"the '{name}' header value is empty or longer than {MAX_VALUE_CHARS} characters")
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise HeaderError(f"the '{name}' header value has control characters")
        cleaned.append(f"{name}: {value}")
    if len(cleaned) > MAX_HEADERS:
        raise HeaderError(f"at most {MAX_HEADERS} request headers are accepted")
    return cleaned


def _key(scan_id: str) -> str:
    return f"sf:scan-secret:{scan_id}"


def _redis():
    from spiderfoot.scan.liveness import _redis as connect
    return connect()


def stash(scan_id: str, headers: list[str]) -> bool:
    """Hold the headers for the process that will run the scan. False when Redis is not there to hold them safely."""
    client = _redis()
    if client is None:
        return False
    try:
        client.set(_key(scan_id), json.dumps(headers), ex=STASH_TTL_SECONDS)
        return True
    except Exception:
        return False


def take(scan_id: str) -> list[str]:
    """The headers stashed for this scan, removed from Redis as they are read. Empty when there are none."""
    client = _redis()
    if client is None:
        return []
    try:
        raw = client.getdel(_key(scan_id)) if hasattr(client, "getdel") else None
        if raw is None and not hasattr(client, "getdel"):
            raw = client.get(_key(scan_id))
            client.delete(_key(scan_id))
        return parse_headers(json.loads(raw)) if raw else []
    except Exception:
        return []


def from_opts(opts) -> list[str]:
    """The validated headers in a module's options (empty when none were given)."""
    try:
        return parse_headers((opts or {}).get(OPT_KEY))
    except HeaderError:
        return []


def flag_args(opts, flag: str = "-H") -> list[str]:
    """``[flag, 'Name: value', ...]`` for tools that take one flag per header (katana, nuclei, httpx, ffuf, dalfox)."""
    out: list[str] = []
    for h in from_opts(opts):
        out.extend([flag, h])
    return out


def joined(opts) -> str:
    """The headers as one newline-separated string (arjun and sqlmap take them that way)."""
    return "\n".join(from_opts(opts))

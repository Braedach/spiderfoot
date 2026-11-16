# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         spiderfoot.sflib.catchall
# Purpose:      Tell a real "this file exists" answer from a server that answers every path the same way.
# Created:      2026-11-16
# Licence:      MIT
# -------------------------------------------------------------------------------
"""Catch-all detection for web probe findings.

Some servers (single-page apps, load balancers, custom error handling) answer *every* path with the same page and
HTTP 200. A scanner that reports "path X exists because the server answered" then reports hundreds of files that are
not there. In a live scan of a single address, Nikto reported ``/.htpasswd``, ``/.bash_history`` and others as exposed
because the server returned the same 1,523-byte page for every path, and an AI report told the owner to rotate
credentials that were never exposed.

The test: ask the same server for a path that cannot exist (a random name, with the same file extension) and compare.
A reported path whose answer is the same as the answer for the impossible path is not evidence of anything.
"""

from __future__ import annotations

import hashlib
import re
import threading
import uuid
from typing import Callable
from urllib.parse import urlsplit

# A reported path's answer counts as "the same page" when its status and content type match and its length is within
# this share of the baseline's (dynamic pages carry timestamps, a reflected path and the like), or its first 4 KB are identical
LENGTH_TOLERANCE = 0.03
MIN_TOLERANCE_BYTES = 32


def origin_of(url: str) -> str | None:
    """``scheme://host[:port]`` of a URL, or None."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    return f"{parts.scheme}://{parts.netloc}"


def _extension(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    return name[name.rfind("."):] if "." in name and not name.startswith(".") else ""


def fingerprint(response: dict | None) -> tuple[str, str, int, str] | None:
    """(status, content type, length, hash of the first 4 KB) for a fetch result, or None when there was no answer."""
    if not response:
        return None
    code = str(response.get("code") or "")
    if not code:
        return None
    content = response.get("content")
    body = content if isinstance(content, (bytes, str)) else ""
    raw = body if isinstance(body, bytes) else body.encode("utf-8", "replace")
    ctype = ""
    for k, v in (response.get("headers") or {}).items():
        if str(k).lower() == "content-type":
            ctype = str(v).lower().split(";", 1)[0].strip()
    return code, ctype, len(raw), hashlib.sha1(raw[:4096]).hexdigest()


def content_fingerprint(content) -> str | None:
    """Fingerprint of a page's content that ignores which host it was fetched from, and whitespace.

    Absolute URLs are reduced to their path, so the same page reached as http://name/, https://name/ or
    https://203.0.113.10:8080/ gets the same fingerprint. None for empty content.
    """
    if not content:
        return None
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")
    text = re.sub(r"https?://[^/\s\"'<>]+", "", str(content))
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return None
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()


class CatchAllBaseline:
    """Remembers, per server, how it answers a path that cannot exist.

    Args:
        fetch: ``fetch(url) -> dict`` returning ``{"code", "content", ...}`` (a module's ``fetch_url`` wrapper).
    """

    def __init__(self, fetch: Callable[[str], dict | None]) -> None:
        self._fetch = fetch
        self._cache: dict[tuple[str, str], tuple[str, str, int, str] | None] = {}
        self._lock = threading.Lock()

    def baseline(self, origin: str, extension: str = "") -> tuple[str, str, int, str] | None:
        """How ``origin`` answers a random path (ending in ``extension``): its fingerprint, or None if unknown."""
        key = (origin, extension)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        try:
            result = fingerprint(self._fetch(f"{origin}/{uuid.uuid4().hex[:16]}{extension}"))
        except Exception:
            result = None
        with self._lock:
            self._cache[key] = result
        return result

    def is_catch_all(self, url: str, response: dict | None = None) -> bool:
        """True when ``url`` is answered exactly as a path that cannot exist would be.

        Args:
            url: the path a scanner says exists.
            response: the answer already in hand; fetched when omitted.
        """
        origin = origin_of(url)
        if origin is None:
            return False
        path = urlsplit(url).path or "/"
        if path == "/":
            return False                       # the site's front page is not a path claim
        base = self.baseline(origin, _extension(path))
        if base is None:
            return False                       # cannot tell: do not discard on a guess
        if response is None:
            try:
                response = self._fetch(url)
            except Exception:
                return False
        got = fingerprint(response)
        if got is None:
            return False
        if got[0] != base[0] or got[1] != base[1]:
            return False                       # a different status or content type: not the catch-all page
        if got[3] == base[3]:
            return True
        tolerance = max(MIN_TOLERANCE_BYTES, int(base[2] * LENGTH_TOLERANCE))
        return abs(got[2] - base[2]) <= tolerance

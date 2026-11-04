"""Turn discovered URLs into the unit a scan tool should run against.

A crawl can find thousands of URLs that are really a handful of hosts, directories and endpoints
(``page.jsp?id=1`` and ``page.jsp?id=2`` are one endpoint). Tools that fan out per URL use these
keys to run once per real target instead of once per string.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit


def _split(url: str):
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    return parts


def host_key(url: str) -> str | None:
    """``scheme://host[:port]``: one key per web server."""
    parts = _split(url)
    return None if parts is None else f"{parts.scheme}://{parts.netloc.lower()}"


def directory_base(url: str) -> str | None:
    """The directory a URL lives in, always ending in ``/``; query, fragment and file name are dropped.

    ``http://h/a/b.html?x=1`` -> ``http://h/a/``; ``http://h/index.jsp?c=1`` -> ``http://h/``.
    """
    parts = _split(url)
    if parts is None:
        return None
    path = parts.path or "/"
    if not path.endswith("/"):
        path = path.rsplit("/", 1)[0] + "/"
    return f"{parts.scheme}://{parts.netloc.lower()}{path}"


def endpoint_key(url: str, with_param_names: bool = False) -> str | None:
    """``scheme://host/path`` with the query dropped, so only the parameter *values* are ignored.

    With ``with_param_names`` the sorted parameter names are kept, so ``?id=1`` and ``?id=2`` match but
    ``?id=1`` and ``?name=x`` do not.
    """
    parts = _split(url)
    if parts is None:
        return None
    key = f"{parts.scheme}://{parts.netloc.lower()}{parts.path or '/'}"
    if with_param_names:
        names = sorted({name for name, _ in parse_qsl(parts.query, keep_blank_values=True)})
        if names:
            key += "?" + "&".join(names)
    return key

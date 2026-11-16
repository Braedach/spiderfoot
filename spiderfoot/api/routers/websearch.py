"""Web Search settings: a connection test for the administrator's own SearXNG server.

POST /api/websearch/test checks that an address answers a SearXNG search in JSON and says what is wrong when it does not.
It exists so Settings > Web Search can show the problem next to the address (the usual one: the json format is not enabled
in the server's settings.yml).

The request is made by the SpiderFoot server to an address an authenticated user typed, so it is narrow on purpose: http
or https only, cloud metadata addresses refused, at most three redirects, a short timeout, and the answer is reduced to a
verdict and counts: the body of whatever answered is never returned.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
from urllib.parse import urlsplit

import requests
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..dependencies import get_api_key, get_app_config

log = logging.getLogger("spiderfoot.api.websearch")
router = APIRouter()

TIMEOUT_SECONDS = 10
MAX_REDIRECTS = 3
_METADATA_NET = ipaddress.ip_network("169.254.0.0/16")     # link-local: the cloud metadata service lives here


class WebSearchTest(BaseModel):
    url: str | None = Field(None, max_length=2048, description="Address to test; the saved setting when omitted")


def normalise(url: str) -> tuple[str | None, str | None]:
    """The address cleaned of a trailing slash, or (None, why it cannot be used)."""
    text = (url or "").strip()
    if not text:
        return None, "No address entered."
    try:
        parts = urlsplit(text)
    except ValueError:
        return None, "That is not a valid address."
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None, "The address must start with http:// or https://."
    return f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}", None


def _refused_target(host: str) -> str | None:
    """A reason to refuse this host (it resolves to a cloud metadata address), else None."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return None                                 # the request itself will report that the name does not resolve
    for info in infos:
        try:
            if ipaddress.ip_address(info[4][0]) in _METADATA_NET:
                return "That address points at a cloud metadata service, which is not a search server."
        except ValueError:
            continue
    return None


def run_test(url: str, session: "requests.Session | None" = None) -> dict:
    """Test an address. ``session`` is injectable for tests."""
    base, problem = normalise(url)
    if base is None:
        return {"ok": False, "message": problem}
    refused = _refused_target(urlsplit(base).hostname or "")
    if refused:
        return {"ok": False, "message": refused}

    session = session or requests.Session()
    session.max_redirects = MAX_REDIRECTS
    try:
        res = session.get(f"{base}/search", params={"q": "test", "format": "json"}, timeout=TIMEOUT_SECONDS,
                          headers={"User-Agent": "SpiderFoot connection test"})
    except requests.exceptions.SSLError:
        return {"ok": False, "message": "The server's certificate was not accepted (expired, self-signed or for another name)."}
    except requests.exceptions.TooManyRedirects:
        return {"ok": False, "message": f"The address redirected more than {MAX_REDIRECTS} times."}
    except requests.exceptions.Timeout:
        return {"ok": False, "message": f"No answer within {TIMEOUT_SECONDS} seconds."}
    except requests.exceptions.ConnectionError:
        return {"ok": False, "message": "Could not connect (the name did not resolve, or the server refused the connection)."}
    except requests.exceptions.RequestException:
        return {"ok": False, "message": "The request failed."}

    code = res.status_code
    if code == 403:
        return {"ok": False, "message": "The server refused the search. The json format is probably not enabled: add 'json' "
                                         "under search.formats in the server's settings.yml."}
    if code == 429:
        return {"ok": False, "message": "The server is rate-limiting this request. Its rate limiter is configured on the server."}
    if code != 200:
        return {"ok": False, "message": f"The server answered HTTP {code}; that does not look like a SearXNG server."}
    try:
        data = json.loads(res.text)
    except ValueError:
        return {"ok": False, "message": "The server answered, but not with JSON. Is the json format enabled in its settings.yml?"}
    if not isinstance(data, dict) or "results" not in data:
        return {"ok": False, "message": "The server answered JSON, but not a SearXNG search result."}

    results = data.get("results") or []
    engines = {r.get("engine") for r in results if isinstance(r, dict) and r.get("engine")}
    unresponsive = [e[0] for e in (data.get("unresponsive_engines") or []) if isinstance(e, (list, tuple)) and e]
    note = f" {len(unresponsive)} engine(s) did not answer: {', '.join(map(str, unresponsive[:6]))}." if unresponsive else ""
    return {"ok": True, "message": f"Connected. A test search returned {len(results)} results from {len(engines)} engine(s)." + note,
            "results": len(results), "engines": sorted(map(str, engines)), "unresponsive": [str(u) for u in unresponsive]}


@router.post("/websearch/test", summary="Test the connection to a SearXNG server")
def test_websearch(body: WebSearchTest, api_key: str | None = Depends(get_api_key), config=Depends(get_app_config)):
    """Test the given address, or the saved one when none is given. Returns ``{ok, message, ...}``."""
    url = body.url
    if not url:
        try:
            url = str(config.get_config().get("_searxng_url") or "")
        except Exception:
            url = ""
    return run_test(url)

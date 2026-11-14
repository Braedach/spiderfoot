#  -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         spiderfoot.sflib.proxy
# Purpose:      One place that decides which proxy (if any) an outbound HTTP request uses.
# Created:      2026-11-14
# Updated:      2026-11-14
# Licence:      MIT
# -------------------------------------------------------------------------------
"""Outbound proxy selection.

Two independent settings exist:

* The general proxy (``_socks1type`` / ``_socks2addr`` / ``_socks3port`` / ``_socks4user`` /
  ``_socks5pwd``): for sites that must leave the network through a proxy. Applies to every
  request except local and private addresses.
* Tor (``_tor_enabled`` / ``_tor_host`` / ``_tor_port``): used ONLY for ``.onion`` addresses.
  Ordinary sites never go through Tor, so data sources that block Tor exits keep working and the
  general proxy stays whatever the administrator set.

An ``.onion`` address is never fetched directly: without Tor it cannot resolve, and trying would
only leak the name to the local DNS resolver. :func:`proxies_for_url` reports that as an error
instead.
"""

from __future__ import annotations

import ipaddress
import urllib.parse
from typing import Any

# Setting value (upper-cased) -> URL scheme understood by requests/PySocks.
# socks5h/socks4a resolve names at the proxy, which a proxy-only network needs.
_SCHEMES = {
    "4": "socks4a", "SOCKS4": "socks4a", "SOCKS4A": "socks4a",
    "5": "socks5h", "SOCKS5": "socks5h", "SOCKS5H": "socks5h",
    "TOR": "socks5h",
    "HTTP": "http", "HTTPS": "http",
}

TOR_DEFAULT_HOST = "sf-tor"
TOR_DEFAULT_PORT = 9050


def as_bool(value: Any) -> bool:
    """Settings arrive as real booleans or as the strings the database stores."""
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def _port(value: Any) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return 0
    return port if 0 < port < 65536 else 0


def _host_of(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except (ValueError, AttributeError):
        return ""


def is_onion(url: str) -> bool:
    """True when the URL's host is a Tor hidden service."""
    return _host_of(url).endswith(".onion")


def _is_local(host: str) -> bool:
    if host in ("localhost", ""):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified


def tor_proxy_url(opts: dict | None) -> str | None:
    """``socks5h://host:port`` for the Tor setting, or None when Tor is off or incomplete."""
    if not opts or not as_bool(opts.get("_tor_enabled", False)):
        return None
    host = str(opts.get("_tor_host") or "").strip()
    port = _port(opts.get("_tor_port"))
    if not host or not port:
        return None
    return f"socks5h://{host}:{port}"


def general_proxy_url(opts: dict | None) -> str | None:
    """URL for the general outbound proxy, or None when it is not (fully) configured."""
    if not opts:
        return None
    scheme = _SCHEMES.get(str(opts.get("_socks1type") or "").strip().upper())
    host = str(opts.get("_socks2addr") or "").strip()
    port = _port(opts.get("_socks3port"))
    if not scheme or not host or not port:
        return None
    auth = ""
    user = str(opts.get("_socks4user") or "")
    if user:
        auth = urllib.parse.quote(user, safe="")
        pwd = str(opts.get("_socks5pwd") or "")
        if pwd:
            auth += ":" + urllib.parse.quote(pwd, safe="")
        auth += "@"
    return f"{scheme}://{auth}{host}:{port}"


def proxies_for_url(url: str, opts: dict | None) -> tuple[dict[str, str] | None, str | None]:
    """Decide how ``url`` leaves the network.

    Returns:
        ``(proxies, error)``. ``proxies`` is a requests-style dict or None for a direct
        connection. ``error`` is set (and ``proxies`` is None) when the request must not be
        made at all: an ``.onion`` address with Tor off.
    """
    host = _host_of(url)
    if host.endswith(".onion"):
        tor = tor_proxy_url(opts)
        if not tor:
            return None, "Tor is not enabled (Settings > Tor), so .onion addresses cannot be fetched"
        return {"http": tor, "https": tor}, None

    proxy = general_proxy_url(opts)
    if not proxy or _is_local(host):
        return None, None
    if host == str((opts or {}).get("_socks2addr") or "").strip().lower():
        return None, None
    return {"http": proxy, "https": proxy}, None

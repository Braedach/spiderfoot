# -*- coding: utf-8 -*-
"""Route scan lookups through the configured DNS server without breaking internal names.

dnspython's ``override_system_resolver()`` replaces ``socket.getaddrinfo`` and
friends for the whole process. Applied naively, every internal name (``sf-redis``,
``sf-qdrant``, anything on the container network) stops resolving, because the
external server has never heard of it. The API builds a ``SpiderFoot`` object on
every scan request, so the API worker lost its Redis connection to Celery and
every scan silently fell back to running in-process.

This wraps the override: internal names go to the system resolver, everything
else to the configured server.
"""

from __future__ import annotations

import ipaddress
import socket

import dns.resolver

INTERNAL_SUFFIXES = (".podman", ".local", ".internal", ".lan", ".localdomain", ".svc", ".cluster.local")
_WRAPPED = ("getaddrinfo", "gethostbyname", "gethostbyname_ex")


def is_internal_name(host: object) -> bool:
    """True for names that must use the system resolver."""
    if isinstance(host, bytes):
        host = host.decode("ascii", "ignore")
    if not isinstance(host, str):
        return True
    h = host.rstrip(".").lower()
    if not h or "." not in h or h.endswith(INTERNAL_SUFFIXES):
        return True
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def install_external_resolver(nameserver: str) -> None:
    """Resolve public names via ``nameserver``; keep internal names on the system resolver."""
    dns.resolver.restore_system_resolver()
    system = {n: getattr(socket, n) for n in _WRAPPED}

    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    dns.resolver.override_system_resolver(resolver)
    external = {n: getattr(socket, n) for n in _WRAPPED}

    def _route(name: str):
        sys_fn, ext_fn = system[name], external[name]

        def routed(host, *args, **kwargs):
            if is_internal_name(host):
                return sys_fn(host, *args, **kwargs)
            return ext_fn(host, *args, **kwargs)

        routed.__name__ = name
        return routed

    for n in _WRAPPED:
        setattr(socket, n, _route(n))

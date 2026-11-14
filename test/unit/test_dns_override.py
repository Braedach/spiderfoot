"""The external-DNS override must not break resolution of internal service names."""
from __future__ import annotations

import socket

import dns.resolver
import pytest

from spiderfoot.sflib import dns_override
from spiderfoot.sflib.dns_override import install_external_resolver, is_internal_name


@pytest.fixture(autouse=True)
def restore_sockets():
    saved = {n: getattr(socket, n) for n in dns_override._WRAPPED}
    yield
    for n, fn in saved.items():
        setattr(socket, n, fn)
    dns.resolver.restore_system_resolver()


@pytest.mark.parametrize("host", [
    "sf-redis", "sf-postgres", "localhost", "redis.dns.podman", "x.internal", "printer.local",
    "10.89.3.66", "::1", b"sf-qdrant", "", None, "sf-api.",
])
def test_internal_names_are_recognised(host):
    assert is_internal_name(host)


@pytest.mark.parametrize("host", ["example.com", "braedach.com", "WWW.Demo.Testfire.NET", "a.b.c.d.io"])
def test_public_names_are_not_internal(host):
    assert not is_internal_name(host)


def _install_with_fakes(monkeypatch):
    calls = []

    def fake_system(name):
        def fn(host, *a, **k):
            calls.append(("system", name, host))
            return [("sys", host)]
        return fn

    def fake_external(name):
        def fn(host, *a, **k):
            calls.append(("external", name, host))
            return [("ext", host)]
        return fn

    for n in dns_override._WRAPPED:
        monkeypatch.setattr(socket, n, fake_system(n))

    def fake_override(resolver):
        assert resolver.nameservers == ["1.1.1.1"]
        for n in dns_override._WRAPPED:
            setattr(socket, n, fake_external(n))

    monkeypatch.setattr(dns.resolver, "override_system_resolver", fake_override)
    monkeypatch.setattr(dns.resolver, "restore_system_resolver", lambda: None)
    install_external_resolver("1.1.1.1")
    return calls


def test_internal_names_still_use_system_resolver(monkeypatch):
    calls = _install_with_fakes(monkeypatch)
    assert socket.getaddrinfo("sf-redis", 6379) == [("sys", "sf-redis")]
    assert socket.gethostbyname("sf-qdrant") == [("sys", "sf-qdrant")]
    assert calls == [("system", "getaddrinfo", "sf-redis"), ("system", "gethostbyname", "sf-qdrant")]


def test_public_names_use_the_configured_server(monkeypatch):
    calls = _install_with_fakes(monkeypatch)
    assert socket.getaddrinfo("braedach.com", 443) == [("ext", "braedach.com")]
    assert calls == [("external", "getaddrinfo", "braedach.com")]


def test_real_override_keeps_internal_names_resolving():
    """End to end with the real dnspython: 'localhost' must still resolve after the override."""
    install_external_resolver("127.0.0.1")
    assert socket.getaddrinfo("localhost", 80)
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo("no-such-host.invalid", 80)

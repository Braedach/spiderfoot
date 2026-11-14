"""Outbound proxy selection: the general proxy and the Tor setting are independent."""
from unittest import mock

import pytest

from spiderfoot.sflib import network
from spiderfoot.sflib.proxy import general_proxy_url, proxies_for_url, tor_proxy_url
from spiderfoot.services.http_service import HttpService, HttpServiceConfig

TOR = {"_tor_enabled": True, "_tor_host": "sf-tor", "_tor_port": 9050}
SOCKS = {"_socks1type": "5", "_socks2addr": "proxy.example", "_socks3port": "1080"}


def test_onion_goes_through_tor_and_nothing_else_does():
    proxies, err = proxies_for_url("http://abcdefgh.onion/page", TOR)
    assert err is None and proxies == {"http": "socks5h://sf-tor:9050", "https": "socks5h://sf-tor:9050"}
    assert proxies_for_url("https://example.com/", TOR) == (None, None)


def test_onion_is_never_fetched_directly_when_tor_is_off():
    for opts in ({}, None, {**TOR, "_tor_enabled": False}, {**TOR, "_tor_enabled": "false"}, {**TOR, "_tor_host": ""}):
        proxies, err = proxies_for_url("http://abcdefgh.onion/", opts)
        assert proxies is None and err


def test_onion_uses_tor_even_when_a_general_proxy_is_set():
    proxies, _ = proxies_for_url("http://abcdefgh.onion/", {**TOR, **SOCKS})
    assert proxies["http"] == "socks5h://sf-tor:9050"
    proxies, _ = proxies_for_url("https://example.com/", {**TOR, **SOCKS})
    assert proxies["https"] == "socks5h://proxy.example:1080"


@pytest.mark.parametrize("kind,scheme", [("4", "socks4a"), ("5", "socks5h"), ("HTTP", "http"), ("TOR", "socks5h"),
                                         ("http", "http")])
def test_proxy_type_becomes_a_scheme_requests_understands(kind, scheme):
    url = general_proxy_url({"_socks1type": kind, "_socks2addr": "p", "_socks3port": 8080})
    assert url == f"{scheme}://p:8080"


def test_incomplete_or_unknown_proxy_is_ignored():
    assert general_proxy_url({"_socks1type": "5", "_socks2addr": "p", "_socks3port": ""}) is None
    assert general_proxy_url({"_socks1type": "bogus", "_socks2addr": "p", "_socks3port": 1}) is None
    assert tor_proxy_url({"_tor_enabled": True, "_tor_host": "sf-tor", "_tor_port": "99999"}) is None


def test_credentials_are_url_encoded():
    url = general_proxy_url({**SOCKS, "_socks4user": "me", "_socks5pwd": "p@ss:w/rd"})
    assert url == "socks5h://me:p%40ss%3Aw%2Frd@proxy.example:1080"


@pytest.mark.parametrize("url", ["http://127.0.0.1:8001/x", "http://localhost/x", "http://10.1.2.3/", "http://192.168.1.5/",
                                 "http://proxy.example/"])
def test_local_addresses_and_the_proxy_itself_are_direct(url):
    assert proxies_for_url(url, SOCKS) == (None, None)


def test_legacy_fetch_applies_the_settings():
    session = mock.Mock()
    session.get.return_value = mock.Mock(status_code=200, reason="OK", content=b"ok", headers={}, url="u")
    with mock.patch.object(network, "getSession", return_value=session):
        network.fetchUrl("http://abcdefgh.onion/", opts=TOR)
        assert session.get.call_args.kwargs["proxies"]["http"] == "socks5h://sf-tor:9050"
        network.fetchUrl("https://example.com/", opts=TOR)
        assert "proxies" not in session.get.call_args.kwargs
        session.get.reset_mock()
        res = network.fetchUrl("http://abcdefgh.onion/", opts={})
        assert not session.get.called and res["code"] is None and "Tor" in res["status"]


def test_http_service_applies_the_settings():
    svc = HttpService(HttpServiceConfig.from_sf_config({**TOR, **SOCKS}))
    session = mock.Mock()
    session.get.return_value = mock.Mock(status_code=200, reason="OK", content=b"ok", headers={}, url="u",
                                         iter_content=lambda **k: [b"ok"], encoding="utf-8", text="ok")
    with mock.patch.object(svc, "get_session", return_value=session):
        svc.fetch_url("http://abcdefgh.onion/")
        assert session.get.call_args.kwargs["proxies"]["http"] == "socks5h://sf-tor:9050"
        svc.fetch_url("https://example.com/")
        assert session.get.call_args.kwargs["proxies"]["https"] == "socks5h://proxy.example:1080"
    off = HttpService(HttpServiceConfig.from_sf_config({}))
    with mock.patch.object(off, "get_session", return_value=session):
        session.get.reset_mock()
        res = off.fetch_url("http://abcdefgh.onion/")
        assert not session.get.called and "Tor" in str(res.get("status"))

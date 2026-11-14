"""network.fetchBytes returns a body unchanged (fetchUrl decodes it as text and destroys binary files)."""
from unittest import mock

from spiderfoot.sflib import network

BINARY = bytes(range(256)) * 8


def _session(body=BINARY, status=200, headers=None):
    resp = mock.MagicMock(status_code=status, headers=headers or {})
    resp.iter_content.return_value = [body[i:i + 500] for i in range(0, len(body), 500)]
    resp.__enter__.return_value = resp
    session = mock.Mock()
    session.get.return_value = resp
    return session


def test_binary_body_is_returned_byte_for_byte():
    session = _session()
    with mock.patch.object(network, "getSession", return_value=session):
        assert network.fetchBytes("http://e.com/a.jpg") == BINARY
    assert session.get.call_args.kwargs["stream"] is True


def test_size_limit_stops_the_download():
    with mock.patch.object(network, "getSession", return_value=_session()):
        assert network.fetchBytes("http://e.com/a.jpg", sizeLimit=1000) is None
    with mock.patch.object(network, "getSession", return_value=_session(headers={"Content-Length": "999999"})):
        assert network.fetchBytes("http://e.com/a.jpg", sizeLimit=1000) is None


def test_errors_and_bad_urls_return_none():
    with mock.patch.object(network, "getSession", return_value=_session(status=404)):
        assert network.fetchBytes("http://e.com/missing.pdf") is None
    session = mock.Mock()
    session.get.side_effect = OSError("refused")
    with mock.patch.object(network, "getSession", return_value=session):
        assert network.fetchBytes("http://e.com/a.pdf") is None
        for bad in ("file:///etc/passwd", "ftp://e.com/a", "", None):
            assert network.fetchBytes(bad) is None


def test_proxy_settings_apply():
    session = _session()
    with mock.patch.object(network, "getSession", return_value=session):
        network.fetchBytes("http://abcdefgh.onion/a.pdf", opts={"_tor_enabled": True, "_tor_host": "sf-tor", "_tor_port": 9050})
        assert session.get.call_args.kwargs["proxies"]["http"] == "socks5h://sf-tor:9050"
        session.get.reset_mock()
        assert network.fetchBytes("http://abcdefgh.onion/a.pdf", opts={}) is None
        assert not session.get.called

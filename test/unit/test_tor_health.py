"""Dashboard Tor status: working, not working, or not configured."""
import socket
import threading
from unittest import mock

from spiderfoot.api.routers import health


def _socks_listener():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def serve():
        conn, _ = srv.accept()
        conn.recv(3)
        conn.sendall(b"\x05\x00")
        conn.close()
        srv.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1]


def test_unreachable_proxy_is_down():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    assert health._probe_tor("127.0.0.1", port)["status"] == "down"


def test_proxy_answers_and_exit_check_confirms_tor():
    resp = mock.Mock(ok=True)
    resp.json.return_value = {"IsTor": True, "IP": "198.51.100.7"}
    with mock.patch("requests.get", return_value=resp) as get:
        result = health._probe_tor("127.0.0.1", _socks_listener())
    assert result["status"] == "up"
    assert get.call_args.kwargs["proxies"]["https"].startswith("socks5h://127.0.0.1:")
    assert "198.51.100.7" not in str(result)


def test_proxy_answers_but_no_circuit_is_degraded():
    with mock.patch("requests.get", side_effect=OSError("no circuit")):
        assert health._probe_tor("127.0.0.1", _socks_listener())["status"] == "degraded"


def test_turned_off_reports_not_configured_without_probing():
    cfg = mock.Mock()
    cfg.get_config.return_value = {"_tor_enabled": False, "_tor_host": "sf-tor", "_tor_port": 9050}
    with mock.patch("spiderfoot.api.dependencies.get_app_config", return_value=cfg), \
         mock.patch.object(health, "_probe_tor") as probe:
        result = health._check_tor()
    assert result["status"] == "unknown" and "Not configured" in result["message"]
    assert not probe.called


def test_first_call_answers_at_once_and_probes_in_the_background():
    cfg = mock.Mock()
    cfg.get_config.return_value = {"_tor_enabled": True, "_tor_host": "tor.test", "_tor_port": 9050}
    done = threading.Event()

    def probe(host, port):
        done.set()
        return {"status": "up", "message": "Working"}

    health._tor_state.update(result=None, at=0.0, key="", running=False)
    with mock.patch("spiderfoot.api.dependencies.get_app_config", return_value=cfg), \
         mock.patch.object(health, "_probe_tor", side_effect=probe):
        assert health._check_tor()["message"] == "Checking..."
        assert done.wait(5)
        for _ in range(50):
            if not health._tor_state["running"]:
                break
            threading.Event().wait(0.05)
        assert health._check_tor()["status"] == "up"
    health._tor_state.update(result=None, at=0.0, key="", running=False)


def test_tor_and_unconfigured_minio_are_in_the_dashboard(monkeypatch):
    monkeypatch.delenv("SF_MINIO_ENDPOINT", raising=False)
    assert "tor" in health._SUBSYSTEM_CHECKS
    assert health._check_minio() == {"status": "unknown", "message": "Not configured"}

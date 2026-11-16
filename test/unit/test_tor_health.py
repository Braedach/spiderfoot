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


class _FakeRedis:
    """Just the calls the shared Tor check makes."""

    def __init__(self):
        self.store, self.ttls = {}, {}

    def get(self, k):
        return self.store.get(k)

    def set(self, k, v, nx=False, ex=None):
        if nx and k in self.store:
            return None
        self.store[k] = v
        return True

    def setex(self, k, ttl, v):
        self.store[k] = v
        self.ttls[k] = ttl

    def delete(self, k):
        self.store.pop(k, None)


def test_tor_result_is_shared_between_processes_through_redis():
    """Two API processes must give the same answer: one probes, the other reads what it stored."""
    cfg = mock.Mock()
    cfg.get_config.return_value = {"_tor_enabled": True, "_tor_host": "tor.test", "_tor_port": 9050}
    r = _FakeRedis()
    probes = []
    done, release = threading.Event(), threading.Event()

    def probe(host, port):
        probes.append((host, port))
        done.set()
        release.wait(5)                                   # hold the probe open while the second process asks
        return {"status": "up", "message": "Working"}

    with mock.patch("spiderfoot.api.dependencies.get_app_config", return_value=cfg), \
         mock.patch.object(health, "_tor_redis", return_value=r), \
         mock.patch.object(health, "_probe_tor", side_effect=probe):
        first = health._check_tor()                       # process A: nothing stored yet
        second = health._check_tor()                      # process B, at the same moment
        assert first["message"] == "Checking..." and second["message"] == "Checking..."
        assert done.wait(5)
        release.set()
        for _ in range(100):
            if "sf:health:tor:result:tor.test:9050" in r.store:
                break
            threading.Event().wait(0.05)
        a, b = health._check_tor(), health._check_tor()   # any process now reads the one stored answer
    assert a["status"] == b["status"] == "up"
    assert len(probes) == 1                               # the lock kept the second process from probing
    assert r.ttls["sf:health:tor:result:tor.test:9050"] == 300


def test_a_failed_tor_probe_is_stored_for_a_short_time():
    cfg = mock.Mock()
    cfg.get_config.return_value = {"_tor_enabled": True, "_tor_host": "tor.test", "_tor_port": 9050}
    r = _FakeRedis()
    with mock.patch("spiderfoot.api.dependencies.get_app_config", return_value=cfg), \
         mock.patch.object(health, "_tor_redis", return_value=r), \
         mock.patch.object(health, "_probe_tor", return_value={"status": "down", "message": "x"}):
        health._check_tor()
        for _ in range(100):
            if "sf:health:tor:result:tor.test:9050" in r.store:
                break
            threading.Event().wait(0.05)
    assert r.ttls["sf:health:tor:result:tor.test:9050"] == 60


def test_broken_redis_falls_back_to_the_per_process_state():
    cfg = mock.Mock()
    cfg.get_config.return_value = {"_tor_enabled": True, "_tor_host": "tor.test", "_tor_port": 9050}
    broken = mock.Mock()
    broken.get.side_effect = OSError("redis down")
    health._tor_state.update(result={"status": "up", "message": "Working"}, at=__import__("time").monotonic(),
                             key="tor.test:9050", running=False)
    with mock.patch("spiderfoot.api.dependencies.get_app_config", return_value=cfg), \
         mock.patch.object(health, "_tor_redis", return_value=broken):
        assert health._check_tor()["status"] == "up"
    health._tor_state.update(result=None, at=0.0, key="", running=False)


def test_vector_and_qdrant_rows(monkeypatch):
    monkeypatch.delenv("VECTOR_API_URL", raising=False)
    assert health._check_vector()["status"] == "unknown"          # not deployed: not "down"
    assert "qdrant" in health._SUBSYSTEM_CHECKS
    monkeypatch.setenv("SF_QDRANT_URL", "http://qdrant.test:6333")
    ok = mock.MagicMock()
    ok.__enter__.return_value.status = 200
    with mock.patch("urllib.request.urlopen", return_value=ok) as op:
        assert health._check_qdrant() == {"status": "up"}
    assert op.call_args[0][0] == "http://qdrant.test:6333/healthz"
    with mock.patch("urllib.request.urlopen", side_effect=OSError("refused")):
        assert health._check_qdrant()["status"] == "down"

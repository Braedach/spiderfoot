"""Egress health monitor (spiderfoot.scan.egress_health)."""
from __future__ import annotations

from spiderfoot.scan import egress_health as eh

NO = {"content": None, "code": None}
OK = {"content": "x", "code": "200"}


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def monitor(**kw):
    msgs = []
    c = Clock()
    return eh.EgressHealth(notify=msgs.append, clock=c, **kw), msgs, c


def feed(m, n, result, host="a.example.org"):
    for i in range(n):
        m.record(f"https://{host}/{i}", result)


def test_an_answer_of_any_kind_counts_as_reaching_the_network():
    assert eh.answered({"code": "404"}) and eh.answered({"code": 500}) and eh.answered(OK)
    assert not eh.answered(None) and not eh.answered(NO) and not eh.answered({"code": "0"}) and not eh.answered({"code": 0})
    assert eh.answered({"code": None, "status": "scope-guard"})       # we refused to send it: not a network fault


def test_a_healthy_scan_says_nothing():
    m, msgs, _ = monitor()
    feed(m, 50, OK)
    assert m.state() == eh.OK and msgs == [] and m.summary() == []


def test_too_few_requests_prove_nothing():
    m, msgs, _ = monitor()
    feed(m, eh.MIN_REQUESTS - 1, NO)
    assert m.state() == eh.OK and msgs == []


def test_a_dead_network_is_reported_once_with_the_empty_is_not_clean_warning():
    m, msgs, _ = monitor()
    for i in range(40):
        m.record(f"https://h{i}.example.org/", NO)
    assert m.state() == eh.FAILING
    assert len(msgs) >= 1 and "FAILING" in msgs[-1] and "NOT a clean result" in msgs[-1]
    n = len(msgs)
    feed(m, 20, NO, host="zz.example.org")
    assert len(msgs) == n or msgs[-1].startswith("Egress health")      # no repeated warning while the state is unchanged


def test_one_failing_host_is_named_instead_of_blaming_the_network():
    m, msgs, _ = monitor()
    feed(m, 30, OK, host="fine.example.org")
    feed(m, 60, NO, host="down.example.org")
    assert m.state() in (eh.DEGRADED, eh.FAILING)
    assert any("down.example.org" in x and "probably down" in x for x in msgs)


def test_recovery_is_announced():
    m, msgs, c = monitor()
    for i in range(30):
        m.record(f"https://h{i}.example.org/", NO)
    c.t += 10_000                                          # the failures age out of the window
    feed(m, 30, OK)
    assert m.state() == eh.OK and "answered again" in msgs[-1]


def test_degraded_is_between_the_two_thresholds():
    m, _, _ = monitor()
    feed(m, 14, OK)
    for i in range(26):
        m.record(f"https://h{i}.example.org/", NO)
    assert m.state() == eh.DEGRADED                        # 65% of 40 got no answer


def test_onion_requests_are_tracked_apart_and_never_trip_the_alarm():
    m, msgs, _ = monitor()
    for i in range(100):
        m.record(f"http://{'a' * 56}.onion/{i}", NO)
    assert m.state() == eh.OK and msgs == [] and m.total == 0


def test_the_summary_lists_canary_failures_and_the_scan_wide_share():
    m, _, _ = monitor()
    m.canaries = [("DNS lookup", False, "example.com did not resolve (gaierror)"), ("Tor proxy", True, "ok")]
    for i in range(30):
        m.record(f"https://h{i}.example.org/", NO)
    text = " | ".join(m.summary())
    assert "DNS lookup" in text and "Tor proxy" not in text and "30 of 30" in text and "failing" in text


def test_recording_never_raises():
    m, _, _ = monitor()
    m.record(None, None)                                   # type: ignore[arg-type]
    m.record("not a url", {"code": object()})
    assert m.total >= 0


def test_a_broken_notifier_never_breaks_a_scan():
    def boom(msg):
        raise RuntimeError("log down")
    m = eh.EgressHealth(notify=boom)
    for i in range(40):
        m.record(f"https://h{i}.example.org/", NO)         # must not raise


# --- canaries ------------------------------------------------------------------------------------------------------
def test_canaries_pass_when_dns_and_the_proxy_work():
    r = eh.run_canaries({"_socks1type": "TOR", "_socks2addr": "tor.local", "_socks3port": 9050},
                        resolve=lambda n: ["1.2.3.4"], connect=lambda h, p: None)
    assert r == [("DNS lookup", True, "ok"), ("TOR proxy", True, "ok")]


def test_canaries_report_a_dead_resolver_and_a_dead_proxy():
    def no_dns(name):
        raise OSError("no resolver")

    def no_conn(h, p):
        raise ConnectionRefusedError()
    r = eh.run_canaries({"_socks1type": "5", "_socks2addr": "h", "_socks3port": "1080"}, resolve=no_dns, connect=no_conn)
    assert [(n, ok) for n, ok, _ in r] == [("DNS lookup", False), ("5 proxy", False)]
    assert "OSError" in r[0][2] and "ConnectionRefusedError" in r[1][2]


def test_with_no_proxy_configured_only_dns_is_checked_and_nothing_else_is_contacted():
    seen = []
    r = eh.run_canaries({"_socks1type": ""}, resolve=lambda n: seen.append(n), connect=lambda h, p: seen.append(h))
    assert len(r) == 1 and seen == ["example.com"]


def test_a_bad_proxy_port_is_not_a_crash():
    r = eh.run_canaries({"_socks1type": "5", "_socks2addr": "h", "_socks3port": "abc"}, resolve=lambda n: None)
    assert len(r) == 1


def test_modules_report_to_the_targets_monitor_without_changing_the_result():
    from spiderfoot.plugins.modern_plugin import SpiderFootModernPlugin
    mon = eh.EgressHealth()
    p = SpiderFootModernPlugin.__new__(SpiderFootModernPlugin)
    p.getTarget = lambda: type("T", (), {"egressHealth": mon})()
    p._fetch_url_unrecorded = lambda *a, **k: {"content": None, "code": None}
    p._scope_egress_blocked = lambda url: None
    out = p.fetch_url("https://example.org/x")
    assert out == {"content": None, "code": None} and mon.total == 1 and mon.failures == 1

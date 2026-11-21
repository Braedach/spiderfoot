"""sfp_tool_naabu: every host found is scanned; a spent time budget is reported, never silent."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from modules.sfp_tool_naabu import sfp_tool_naabu
from spiderfoot import SpiderFootEvent


def make(**opts):
    m = sfp_tool_naabu()
    m.sf = MagicMock()
    m.opts = dict(sfp_tool_naabu.opts, **opts)
    m.results = {}
    m._runs = 0
    m._spent = 0.0
    m._skipped = []
    m.errorState = False
    m.notifyListeners = MagicMock()
    m._find_binary = MagicMock(return_value="/usr/bin/naabu")
    m.error = MagicMock()
    m.info = MagicMock()
    m.__name__ = "sfp_tool_naabu"
    return m


def ev(host):
    return SpiderFootEvent("INTERNET_NAME", host, "sfp_dnsresolve", None)


def run_hosts(m, hosts):
    with patch("modules.sfp_tool_naabu.subprocess.run", return_value=MagicMock(returncode=0, stdout="", stderr="")) as run:
        for h in hosts:
            m.handleEvent(ev(h))
    return run


def test_default_has_no_count_limit_and_a_time_budget():
    assert sfp_tool_naabu.opts["max_targets"] == 0 and sfp_tool_naabu.opts["total_budget"] > 0


def test_all_hosts_are_scanned_beyond_the_old_limit_of_50():
    m = make()
    run = run_hosts(m, [f"h{i}.example.org" for i in range(120)])
    assert run.call_count == 120 and m._skipped == []


def test_same_host_is_scanned_once():
    m = make()
    assert run_hosts(m, ["a.example.org", "a.example.org"]).call_count == 1


def test_count_limit_still_works_when_set_and_skips_are_reported():
    m = make(max_targets=2)
    run = run_hosts(m, [f"h{i}.example.org" for i in range(5)])
    assert run.call_count == 2 and len(m._skipped) == 3
    m.error.assert_called_once()
    m.finished()
    assert "did not scan 3 host(s)" in m.error.call_args.args[0] and "h2.example.org" in m.error.call_args.args[0]


def test_time_budget_stops_new_runs_and_reports_the_rest():
    m = make(total_budget=100)
    m._spent = 150.0
    run = run_hosts(m, ["a.example.org", "b.example.org"])
    assert run.call_count == 0 and m._skipped == ["a.example.org", "b.example.org"]
    assert "time budget" in m.error.call_args.args[0]


def test_budget_zero_means_no_time_limit():
    m = make(total_budget=0)
    m._spent = 10 ** 9
    assert run_hosts(m, ["a.example.org"]).call_count == 1


def test_every_profile_that_runs_naabu_pins_full_coverage():
    from spiderfoot.scan.scan_profile import ProfileManager, NAABU_COVERAGE
    mgr = ProfileManager()
    for name in ("full-footprint", "tools-only", "network-service-test", "ip-address"):
        opts = mgr.get(name).module_options.get("sfp_tool_naabu")
        assert opts == NAABU_COVERAGE and opts["max_targets"] == 0, name

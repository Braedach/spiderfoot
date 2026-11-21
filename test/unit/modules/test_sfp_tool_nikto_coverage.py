"""sfp_tool_nikto: every web server found is tested; a spent time budget is reported, never silent; one slow server cannot hold the scan."""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

from modules.sfp_tool_nikto import sfp_tool_nikto
from spiderfoot import SpiderFootEvent


def make(**opts):
    m = sfp_tool_nikto()
    m.sf = MagicMock()
    m.opts = dict(sfp_tool_nikto.opts, **opts)
    m.results = {}
    m._runs = 0
    m._spent = 0.0
    m._skipped = []
    m._catchall = None
    m.errorState = False
    m.notifyListeners = MagicMock()
    m.checkForStop = MagicMock(return_value=False)
    m._find_binary = MagicMock(return_value="/usr/bin/nikto")
    m.error = MagicMock()
    m.info = MagicMock()
    m.__name__ = "sfp_tool_nikto"
    return m


def ev(url):
    return SpiderFootEvent("LINKED_URL_INTERNAL", url, "sfp_spider", None)


def run_hosts(m, hosts):
    done = MagicMock(returncode=0, stdout="", stderr="")
    with patch("modules.sfp_tool_nikto.subprocess.run", return_value=done) as run:
        for h in hosts:
            m.handleEvent(ev(h))
    return run


def test_default_has_no_count_limit_and_a_time_budget():
    assert sfp_tool_nikto.opts["max_targets"] == 0 and sfp_tool_nikto.opts["total_budget"] > 0


def test_all_servers_are_tested_beyond_the_old_limit_of_20():
    m = make()
    run = run_hosts(m, [f"https://host{i}.example.org/" for i in range(90)])
    assert run.call_count == 90 and m._skipped == []


def test_nikto_gets_a_short_request_timeout_and_a_per_server_maxtime():
    m = make(timeout=240, request_timeout=7)
    cmd = run_hosts(m, ["https://a.example.org/"]).call_args.args[0]
    assert cmd[cmd.index("-timeout") + 1] == "7"
    assert cmd[cmd.index("-maxtime") + 1] == "240s"


def test_count_limit_still_works_when_set_and_the_skip_is_reported():
    m = make(max_targets=2)
    run = run_hosts(m, [f"https://h{i}.example.org/" for i in range(5)])
    assert run.call_count == 2 and len(m._skipped) == 3
    m.error.assert_called_once()                       # said when the first server is skipped
    m.finished()
    assert "did not test 3 web server(s)" in m.error.call_args.args[0]
    assert "https://h2.example.org" in m.error.call_args.args[0]


def test_time_budget_stops_new_runs_and_reports_the_rest():
    m = make(total_budget=100)
    m._spent = 150.0                                   # already used up
    run = run_hosts(m, ["https://a.example.org/", "https://b.example.org/"])
    assert run.call_count == 0 and m._skipped == ["https://a.example.org", "https://b.example.org"]
    assert "time budget" in m.error.call_args.args[0]


def test_time_spent_is_counted_even_when_a_run_times_out():
    import subprocess
    m = make(total_budget=3600)
    with patch("modules.sfp_tool_nikto.subprocess.run", side_effect=subprocess.TimeoutExpired("nikto", 1)), \
            patch("modules.sfp_tool_nikto.time.monotonic", side_effect=[100.0, 160.0]):
        m.handleEvent(ev("https://slow.example.org/"))
    assert m._spent == 60.0


def test_budget_zero_means_no_time_limit():
    m = make(total_budget=0)
    m._spent = 10 ** 9
    run = run_hosts(m, ["https://a.example.org/"])
    assert run.call_count == 1


def test_every_profile_that_runs_nikto_pins_full_coverage():
    from spiderfoot.scan.scan_profile import ProfileManager, NIKTO_COVERAGE
    mgr = ProfileManager()
    for name in ("full-footprint", "tools-only", "web-app-test", "ip-address"):
        opts = mgr.get(name).module_options.get("sfp_tool_nikto")
        assert opts == NIKTO_COVERAGE and opts["max_targets"] == 0, name

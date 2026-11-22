"""sfp_tool_nikto: every web server found is tested; a spent time budget is reported, never silent; one slow server cannot hold the scan."""
from __future__ import annotations

import threading
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
    m._reported = 0
    m._lock = threading.Lock()
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


def test_default_has_no_count_limit_and_no_total_time_limit():
    # each server is bounded by "timeout"; a scan-wide budget is an opt-in
    assert sfp_tool_nikto.opts["max_targets"] == 0 and sfp_tool_nikto.opts["total_budget"] == 0


def test_the_long_scan_profiles_leave_room_for_the_tools():
    # the 120-minute profile limit ended a 50-server scan while nikto was still working through its queue
    from spiderfoot.scan.scan_profile import ProfileManager
    for name in ("tools-only", "web-app-test", "network-service-test"):
        assert ProfileManager().get(name).timeout_minutes >= 240, name


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
    m.finish()
    assert "did not test 3 web server(s)" in m.error.call_args.args[0]
    assert "https://h2.example.org" in m.error.call_args.args[0]


def test_time_budget_stops_new_runs_and_reports_the_rest():
    m = make(total_budget=100)
    m._spent = 200.0                                   # past the hard share (150%) of the budget
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


def cmd_of(run, i=0):
    return run.call_args_list[i].args[0]


def test_summary_hook_is_the_one_the_framework_calls():
    # the scanner calls finish() when a scan wraps up; finished() is never called (rc.50's summary used that name)
    from spiderfoot.plugins.plugin import SpiderFootPlugin
    assert sfp_tool_nikto.finish is not SpiderFootPlugin.finish
    assert "finished" not in sfp_tool_nikto.__dict__


def test_finish_can_be_called_again_and_lists_each_skip_once():
    m = make(max_targets=1)
    run_hosts(m, ["https://a.example.org/", "https://b.example.org/"])
    m.finish()
    assert m.error.call_count == 2                     # the first skip, then the summary
    m.finish()
    assert m.error.call_count == 2                     # nothing new to list
    run_hosts(m, ["https://c.example.org/"])
    m.finish()
    assert "https://c.example.org" in m.error.call_args.args[0] and "https://b.example.org" not in m.error.call_args.args[0]


def test_every_skipped_server_is_logged_when_it_is_skipped():
    m = make(max_targets=1)
    run_hosts(m, [f"https://h{i}.example.org/" for i in range(4)])
    said = [c.args[0] for c in m.error.call_args_list + m.info.call_args_list]
    for i in (1, 2, 3):
        assert any(f"https://h{i}.example.org" in t for t in said), i


def test_plain_http_on_a_tls_port_is_the_https_server_and_is_tested_once():
    m = make()
    run = run_hosts(m, ["http://a.example.org:443", "https://a.example.org:443", "https://a.example.org/",
                        "http://a.example.org:8443", "https://a.example.org:8443"])
    targets = [cmd_of(run, i)[2] for i in range(run.call_count)]
    assert targets == ["https://a.example.org", "https://a.example.org:8443"]


def test_plain_http_on_other_ports_is_kept_as_it_is():
    m = make()
    run = run_hosts(m, ["http://a.example.org/", "http://a.example.org:8080", "http://a.example.org:81"])
    assert [cmd_of(run, i)[2] for i in range(3)] == ["http://a.example.org", "http://a.example.org:8080",
                                                      "http://a.example.org:81"]


def test_odd_addresses_do_not_raise():
    m = make()
    run = run_hosts(m, ["http://", "http://[::1", "https://host:notaport/", "ftp://a.example.org"])
    assert run.call_count == 0 and m._skipped == []


def test_past_the_soft_share_runs_are_shortened_so_later_servers_still_get_tested():
    m = make(total_budget=1000, timeout=300)
    m._spent = 800.0                                   # 80%: past the soft share, before the hard one
    run = run_hosts(m, ["https://a.example.org/"])
    assert run.call_count == 1 and cmd_of(run)[cmd_of(run).index("-maxtime") + 1] == "90s"
    assert m._skipped == []


def test_before_the_soft_share_runs_get_the_full_allowance():
    m = make(total_budget=1000, timeout=300)
    run = run_hosts(m, ["https://a.example.org/"])
    assert cmd_of(run)[cmd_of(run).index("-maxtime") + 1] == "300s"


def test_a_short_timeout_option_is_never_lengthened_by_the_shortening():
    m = make(total_budget=1000, timeout=45)
    m._spent = 800.0
    run = run_hosts(m, ["https://a.example.org/"])
    assert cmd_of(run)[cmd_of(run).index("-maxtime") + 1] == "45s"


def test_concurrent_events_run_each_server_once_and_account_every_second():
    # handleEvent runs in a thread pool: duplicates must not both run, and no run's time may be lost
    m = make(total_budget=0)
    hosts = [f"https://h{i % 20}.example.org/" for i in range(200)]
    clock = {"n": 0}

    def fake_run(*a, **k):
        time.sleep(0.001)
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("modules.sfp_tool_nikto.subprocess.run", side_effect=fake_run) as run:
        threads = [threading.Thread(target=lambda hs=hosts[i::8]: [m.handleEvent(ev(h)) for h in hs]) for i in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
    assert run.call_count == 20 and m._runs == 20 and clock["n"] == 0
    assert m._spent > 0.0

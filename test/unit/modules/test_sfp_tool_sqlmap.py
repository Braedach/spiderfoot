"""sfp_tool_sqlmap: detection only, one run per endpoint, a command line that event data cannot change."""
from unittest.mock import MagicMock, patch

import pytest

from spiderfoot import SpiderFootEvent
from modules.sfp_tool_sqlmap import sfp_tool_sqlmap

OUTPUT = """\
[12:17:06] [INFO] GET parameter 'id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
sqlmap identified the following injection point(s) with a total of 16 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 6214=6214

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=1 UNION ALL SELECT NULL,NULL,NULL-- -
---
[12:17:06] [INFO] the back-end DBMS is SQLite
web application technology: Express
back-end DBMS: SQLite
"""
CLEAN = "[12:00:00] [WARNING] GET parameter 'id' does not seem to be injectable\n"


def make(**opts):
    m = sfp_tool_sqlmap()
    m.sf = MagicMock()
    m.opts = dict(sfp_tool_sqlmap.opts, **dict({"test_forms": False}, **opts))   # forms off unless a test turns them on
    m.results = {}
    m._runs = 0
    m._form_runs = 0
    m.errorState = False
    m.notifyListeners = MagicMock()
    m.checkForStop = MagicMock(return_value=False)
    m.__name__ = "sfp_tool_sqlmap"
    return m


def ev(url, etype="LINKED_URL_INTERNAL"):
    return SpiderFootEvent(etype, url, "sfp_spider", None)


def run_with(m, stdout, urls):
    done = MagicMock(returncode=0, stdout=stdout, stderr="")
    with patch.object(sfp_tool_sqlmap, "_find_binary", return_value="/tools/sqlmap/sqlmap.py"), \
            patch("modules.sfp_tool_sqlmap.subprocess.run", return_value=done) as run:
        for u in urls:
            m.handleEvent(ev(u))
    return run


def test_parse_reads_parameter_techniques_and_dbms():
    findings, dbms = sfp_tool_sqlmap.parse(OUTPUT)
    assert dbms == "SQLite"
    assert findings == [{
        "param": "id", "place": "GET",
        "techniques": [("boolean-based blind", "AND boolean-based blind - WHERE or HAVING clause"),
                       ("UNION query", "Generic UNION query (NULL) - 3 columns")],
    }]


def test_parse_clean_output_has_no_findings():
    assert sfp_tool_sqlmap.parse(CLEAN) == ([], None)


def test_a_finding_is_reported_as_critical_with_evidence():
    m = make()
    run_with(m, OUTPUT, ["http://h/item.php?id=1"])
    kinds = [c.args[0].eventType for c in m.notifyListeners.call_args_list]
    assert kinds == ["VULNERABILITY_CVE_CRITICAL", "RAW_RIR_DATA"]
    text = m.notifyListeners.call_args_list[0].args[0].data
    assert "parameter 'id'" in text and "SQLite" in text and "boolean-based blind" in text


def test_nothing_found_emits_nothing():
    m = make()
    run_with(m, CLEAN, ["http://h/item.php?id=1"])
    m.notifyListeners.assert_not_called()


def test_command_is_detection_only_whatever_the_options_say():
    m = make(level=99, techniques="BEUSTQ")
    run = run_with(m, CLEAN, ["http://h/item.php?id=1"])
    cmd = run.call_args.args[0]
    assert cmd[cmd.index("--risk") + 1] == "1"
    assert cmd[cmd.index("--level") + 1] == "3"                      # capped
    assert cmd[cmd.index("--technique") + 1] == "BEUT"              # no stacked queries
    assert "--batch" in cmd and "--flush-session" in cmd
    forbidden = ("--dump", "--dump-all", "--dbs", "--tables", "--passwords", "--os-shell", "--os-cmd", "--file-read",
                 "--file-write", "--sql-shell", "--sql-query", "--udf-inject", "--priv-esc")
    assert not [a for a in cmd if a in forbidden]
    assert run.call_args.kwargs.get("shell") is not True


def test_the_url_is_only_the_value_of_dash_u():
    m = make()
    nasty = "http://h/x.php?a=1&b=--os-shell"
    run = run_with(m, CLEAN, [nasty])
    cmd = run.call_args.args[0]
    assert cmd[cmd.index("-u") + 1] == nasty
    assert cmd.count("--os-shell") == 0


def test_one_run_per_endpoint_and_parameter_set():
    m = make()
    run = run_with(m, CLEAN, [f"http://h/item.php?id={i}" for i in range(50)] + ["http://h/item.php?name=x"])
    assert run.call_count == 2


def test_the_cap_counts_runs_not_urls():
    m = make(max_targets=2)
    run = run_with(m, CLEAN, ["http://h/a.php?x=1", "http://h/b.php?x=1", "http://h/c.php?x=1", "http://h/d.php"])
    assert run.call_count == 2


@pytest.mark.parametrize("url", ["http://h/page", "ftp://h/x?a=1", "javascript:alert(1)?a=1", "http:///x?a=1", "http://h/x?novalue"])
def test_urls_without_a_testable_parameter_are_skipped(url):
    m = make()
    run = run_with(m, CLEAN, [url])
    run.assert_not_called()


def test_missing_binary_switches_the_module_off():
    m = make()
    with patch.object(sfp_tool_sqlmap, "_find_binary", return_value=None), \
            patch("modules.sfp_tool_sqlmap.subprocess.run") as run:
        m.handleEvent(ev("http://h/a.php?x=1"))
    run.assert_not_called()
    assert m.errorState is True
    assert m.sf.error.called or m.error is not None
    m.notifyListeners.assert_not_called()


def test_it_is_an_active_invasive_module_and_registered_everywhere_that_matters():
    from spiderfoot.scan.scope_policy import ACTIVE_MODULES
    from spiderfoot.scan.scan_profile import get_profile_manager
    from spiderfoot.agents.report_digest import APPLICATION_TEST_MODULES
    assert "invasive" in sfp_tool_sqlmap.meta["flags"]
    assert "sfp_tool_sqlmap" in ACTIVE_MODULES
    assert "sfp_tool_sqlmap" in APPLICATION_TEST_MODULES
    web = next(p for p in get_profile_manager().list_profiles() if getattr(p, "name", None) == "web-app-test"
               or (isinstance(p, dict) and p.get("name") == "web-app-test"))
    mods = web["include_modules"] if isinstance(web, dict) else web.include_modules
    assert "sfp_tool_sqlmap" in mods
    # and in no other profile: it is for authorised application tests only
    for p in get_profile_manager().list_profiles():
        name = p["name"] if isinstance(p, dict) else p.name
        inc = p["include_modules"] if isinstance(p, dict) else p.include_modules
        if name != "web-app-test":
            assert "sfp_tool_sqlmap" not in (inc or [])


FORMS_OUTPUT = """\
[INFO] found a total of 2 targets
#1/2 POST http://h/doLogin
POST data: uid=&passw=&btnSubmit=Login
do you want to test this form? [Y/n/q]
sqlmap identified the following injection point(s) with a total of 40 HTTP(s) requests:
---
Parameter: uid (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: uid=x' OR 1=1-- -&passw=&btnSubmit=Login
---
#2/2 GET http://h/search.jsp?q=
sqlmap identified the following injection point(s) with a total of 12 HTTP(s) requests:
---
Parameter: q (GET)
    Type: error-based
    Title: MySQL error-based
    Payload: q=1 AND 1=1
---
back-end DBMS: MySQL
"""


def test_parse_reads_several_blocks_and_their_form_urls():
    findings, dbms = sfp_tool_sqlmap.parse(FORMS_OUTPUT)
    assert dbms == "MySQL"
    assert [(f["place"], f["param"], f["url"]) for f in findings] == [
        ("POST", "uid", "http://h/doLogin"), ("GET", "q", "http://h/search.jsp?q=")]


def test_a_form_page_is_tested_with_forms_and_the_post_finding_names_the_form_url():
    m = make(test_forms=True)
    done = MagicMock(returncode=0, stdout=FORMS_OUTPUT, stderr="")
    with patch.object(sfp_tool_sqlmap, "_find_binary", return_value="/tools/sqlmap/sqlmap.py"), \
            patch("modules.sfp_tool_sqlmap.subprocess.run", return_value=done) as run:
        m.handleEvent(ev("http://h/login.jsp", "URL_FORM"))
    cmd = run.call_args.args[0]
    assert "--forms" in cmd and cmd[cmd.index("-u") + 1] == "http://h/login.jsp"
    assert cmd[cmd.index("--risk") + 1] == "1" and "--dump" not in cmd and "--technique" in cmd
    texts = [c.args[0].data for c in m.notifyListeners.call_args_list if c.args[0].eventType == "VULNERABILITY_CVE_CRITICAL"]
    assert len(texts) == 2 and "POST parameter 'uid' at http://h/doLogin" in texts[0]


def test_a_plain_linked_page_is_form_tested_but_a_script_is_not():
    m = make(test_forms=True)
    run = run_with(m, CLEAN, ["http://h/login.jsp", "http://h/app.js", "http://h/logo.gif"])
    assert run.call_count == 1
    cmd = run.call_args.args[0]
    assert "--forms" in cmd and cmd[cmd.index("-u") + 1] == "http://h/login.jsp"


def test_forms_are_tested_once_per_page():
    m = make(test_forms=True)
    done = MagicMock(returncode=0, stdout=CLEAN, stderr="")
    with patch.object(sfp_tool_sqlmap, "_find_binary", return_value="/x"), \
            patch("modules.sfp_tool_sqlmap.subprocess.run", return_value=done) as run:
        for _ in range(3):
            m.handleEvent(ev("http://h/login.jsp", "URL_FORM"))
    assert run.call_count == 1


def test_parameter_runs_cannot_use_up_the_form_page_budget():
    m = make(test_forms=True, max_targets=1, max_form_pages=5)
    urls = ["http://h/a.jsp?x=1", "http://h/b.jsp?y=1", "http://h/login.jsp"]
    run = run_with(m, CLEAN, urls)
    cmds = [c.args[0] for c in run.call_args_list]
    assert any("--forms" in c and c[c.index("-u") + 1] == "http://h/login.jsp" for c in cmds)
    assert sum("--forms" not in c for c in cmds) == 1             # parameter cap still holds


def test_form_testing_can_be_switched_off():
    m = make(test_forms=False)
    done = MagicMock(returncode=0, stdout=CLEAN, stderr="")
    with patch.object(sfp_tool_sqlmap, "_find_binary", return_value="/x"), \
            patch("modules.sfp_tool_sqlmap.subprocess.run", return_value=done) as run:
        m.handleEvent(ev("http://h/login.jsp", "URL_FORM"))
    run.assert_not_called()

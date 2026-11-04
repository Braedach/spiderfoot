"""A crawl finds thousands of URLs; the per-URL tools must run once per real target, not once per string."""
import os
import subprocess
import tempfile
from unittest.mock import MagicMock, patch

from spiderfoot import SpiderFootEvent
from modules.sfp_tool_arjun import sfp_tool_arjun
from modules.sfp_tool_dalfox import sfp_tool_dalfox
from modules.sfp_tool_ffuf import sfp_tool_ffuf
from modules.sfp_tool_gobuster import sfp_tool_gobuster
from modules.sfp_tool_nikto import sfp_tool_nikto

OK = MagicMock(returncode=0, stdout="", stderr="")


def make(cls, **opts):
    m = cls()
    m.sf = MagicMock()
    m.opts = dict(cls.opts, **opts)
    m.results = {}
    m._runs = 0
    m.errorState = False
    m.notifyListeners = MagicMock()
    m.__name__ = cls.__name__
    return m


def feed(module, etype, urls):
    for u in urls:
        module.handleEvent(SpiderFootEvent(etype, u, "sfp_spider", None))


def variants(n, base="http://h/index.jsp?content=page{}.htm"):
    return [base.format(i) for i in range(n)]


def test_gobuster_runs_once_per_directory_not_once_per_url():
    m = make(sfp_tool_gobuster, soft_404_detection=False)
    urls = variants(1000) + ["http://h/a/x.html", "http://h/a/y.html?q=1", "http://h/b/", "http://h/c/d/e.js"]
    with patch("modules.sfp_tool_gobuster.subprocess.run", return_value=OK) as run, \
            patch("modules.sfp_tool_gobuster.os.path.isfile", return_value=True), \
            patch("modules.sfp_tool_gobuster.tempfile.NamedTemporaryFile") as tmp, \
            patch("modules.sfp_tool_gobuster.open", create=True) as op, \
            patch("modules.sfp_tool_gobuster.os.unlink"), \
            patch("modules.sfp_tool_gobuster.os.path.getsize", return_value=0):
        tmp.return_value.name = "/tmp/g.json"
        op.return_value.__enter__.return_value.read.return_value = '{"results": []}'
        feed(m, "LINKED_URL_INTERNAL", urls)
    assert run.call_count == 4  # /, /a/, /b/, /c/d/


def test_gobuster_cap_counts_runs_and_stops_there():
    m = make(sfp_tool_gobuster, soft_404_detection=False, max_targets=5)
    urls = [f"http://h/dir{i}/file.html" for i in range(40)]
    with patch("modules.sfp_tool_gobuster.subprocess.run", return_value=OK) as run, \
            patch("modules.sfp_tool_gobuster.os.path.isfile", return_value=True), \
            patch("modules.sfp_tool_gobuster.tempfile.NamedTemporaryFile") as tmp, \
            patch("modules.sfp_tool_gobuster.open", create=True) as op, \
            patch("modules.sfp_tool_gobuster.os.unlink"), \
            patch("modules.sfp_tool_gobuster.os.path.getsize", return_value=0):
        tmp.return_value.name = "/tmp/g.json"
        op.return_value.__enter__.return_value.read.return_value = '{"results": []}'
        feed(m, "LINKED_URL_INTERNAL", urls)
    assert run.call_count == 5


def test_gobuster_keeps_partial_results_when_a_run_times_out():
    m = make(sfp_tool_gobuster)

    def write_then_time_out(cmd, **kw):
        with open(cmd[-1], "w") as f:  # gobuster writes each hit to -o as it finds it
            f.write("admin                (Status: 301) [Size: 0] [--> http://h/admin/]\n")
        raise subprocess.TimeoutExpired(cmd, 300)

    with patch("modules.sfp_tool_gobuster.subprocess.run", side_effect=write_then_time_out):
        path = m.execute_command(["gobuster", "dir"])
    try:
        assert path and os.path.getsize(path) > 0
        assert m._parse_output(open(path).read())["results"][0]["path"].startswith("/admin")
    finally:
        if path:
            os.unlink(path)


def test_gobuster_timeout_with_nothing_found_returns_none_and_leaves_no_temp_file():
    m = make(sfp_tool_gobuster)
    created = []
    real = tempfile.NamedTemporaryFile

    def spy(*a, **kw):
        f = real(*a, **kw)
        created.append(f.name)
        return f

    with patch("modules.sfp_tool_gobuster.subprocess.run", side_effect=subprocess.TimeoutExpired(["g"], 1)), \
            patch("modules.sfp_tool_gobuster.tempfile.NamedTemporaryFile", side_effect=spy):
        assert m.execute_command(["gobuster", "dir"]) is None
    assert created and not os.path.exists(created[0])


def test_nikto_runs_once_per_web_server():
    m = make(sfp_tool_nikto)
    with patch.object(sfp_tool_nikto, "_find_binary", return_value="/bin/nikto"), \
            patch("modules.sfp_tool_nikto.subprocess.run", return_value=OK) as run:
        feed(m, "LINKED_URL_INTERNAL", variants(500, "http://a/p{}.jsp?x=1") + variants(300, "http://b/p{}.php"))
        feed(m, "DOMAIN_NAME", ["a"])  # the same server as http://a: no second run
    assert run.call_count == 2


def test_arjun_runs_once_per_endpoint():
    m = make(sfp_tool_arjun)
    with patch.object(sfp_tool_arjun, "_find_binary", return_value="/bin/arjun"), \
            patch("modules.sfp_tool_arjun.subprocess.run", return_value=OK) as run:
        feed(m, "LINKED_URL_INTERNAL", variants(1000) + ["http://h/other.jsp?a=1", "http://h/third.jsp"])
    assert run.call_count == 3


def test_dalfox_one_run_per_parameter_set_and_paramless_urls_do_not_use_the_cap():
    m = make(sfp_tool_dalfox, max_targets=2)
    urls = [f"http://h/static{i}.html" for i in range(200)] + variants(300, "http://h/p.jsp?id={}") + ["http://h/p.jsp?name=x"]
    with patch.object(sfp_tool_dalfox, "_find_binary", return_value="/bin/dalfox"), \
            patch("modules.sfp_tool_dalfox.subprocess.run", return_value=OK) as run:
        feed(m, "LINKED_URL_INTERNAL", urls)
    assert run.call_count == 2  # ?id and ?name; the 200 parameterless pages cost nothing


def test_ffuf_runs_once_per_directory_and_a_domain_matches_its_root():
    m = make(sfp_tool_ffuf)
    with patch.object(sfp_tool_ffuf, "_find_binary", return_value="/bin/ffuf"), \
            patch("modules.sfp_tool_ffuf.os.path.isfile", return_value=True), \
            patch("modules.sfp_tool_ffuf.subprocess.run", return_value=OK) as run:
        feed(m, "LINKED_URL_INTERNAL", variants(1000, "https://h/index.jsp?x={}") + ["https://h/a/b.html"])
        feed(m, "DOMAIN_NAME", ["h"])  # same as https://h/ already done
    assert run.call_count == 2  # https://h/ and https://h/a/

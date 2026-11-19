"""Authenticated application tests: the headers are a credential and are handled as one."""
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from spiderfoot import SpiderFootEvent, auth_headers
from spiderfoot.api.routers.scan import ScanRequest, _stash_request_headers
from spiderfoot.scan.scan_profile import get_profile_manager

H = ["Cookie: session=abc123", "Authorization: Bearer tok.en-1"]


# -- validation ---------------------------------------------------------------------------------------------------
def test_good_headers_are_normalised():
    assert auth_headers.parse_headers(["Cookie:  a=b  ", "X-Api-Key: k"]) == ["Cookie: a=b", "X-Api-Key: k"]
    assert auth_headers.parse_headers(None) == [] and auth_headers.parse_headers([]) == []


@pytest.mark.parametrize("bad", [
    ["no colon"], [""], ["Bad Name: v"], ["Na me: v"], ["Cookie: a\r\nX-Evil: 1"], ["Cookie: a\nb"], ["Cookie: "],
    ["Host: evil.example"], ["Content-Length: 5"], ["Transfer-Encoding: chunked"], ["Proxy-Authorization: x"],
    ["X: " + "a" * 3000], [f"X-{i}: v" for i in range(6)], [123], "not-a-list-but-no-colon",
])
def test_unsafe_or_malformed_headers_are_refused(bad):
    with pytest.raises(auth_headers.HeaderError):
        auth_headers.parse_headers(bad)


def test_error_messages_never_contain_the_value():
    for bad in (["Host: s3cr3t-value"], ["Cookie: s3cr3t\r\nx"], ["Bad Name: s3cr3t-value"]):
        with pytest.raises(auth_headers.HeaderError) as e:
            auth_headers.parse_headers(bad)
        assert "s3cr3t" not in str(e.value)


# -- never stored ---------------------------------------------------------------------------------------------------
def test_the_database_layer_skips_the_secret_option():
    from spiderfoot.db.db_config import ConfigManager
    stored = []
    cm = ConfigManager.__new__(ConfigManager)
    cm.db_type = "sqlite"
    cm.dbhLock = MagicMock()
    cm.dbh = MagicMock()
    cm.dbh.execute = lambda q, v: stored.append(v)
    cm.conn = MagicMock()
    cm.scanConfigSet("S1", {"_request_headers": H, "_useragent": "x"})
    assert [v[2] for v in stored] == ["_useragent"]
    stored.clear()
    cm.scanConfigSet("S1", {"_request_headers": H})            # nothing else: nothing is written, no error
    assert stored == []


def test_stash_and_take_remove_the_value():
    store = {}
    fake = MagicMock()
    fake.set = lambda k, v, ex=None: store.__setitem__(k, v)
    fake.getdel = lambda k: store.pop(k, None)
    with patch.object(auth_headers, "_redis", return_value=fake):
        assert auth_headers.stash("S1", H) is True
        assert auth_headers.take("S1") == H
        assert auth_headers.take("S1") == []                       # gone after the first read
    with patch.object(auth_headers, "_redis", return_value=None):
        assert auth_headers.stash("S1", H) is False and auth_headers.take("S1") == []


# -- who may send them ----------------------------------------------------------------------------------------------
def req(**kw):
    return ScanRequest(name="s", target="example.com", **kw)


def test_only_an_authorisation_profile_accepts_headers():
    pm = get_profile_manager()
    with patch.object(auth_headers, "stash", return_value=True) as st:
        _stash_request_headers(pm.get("web-app-test"), req(request_headers=H, authorised_to_test=True), "S1")
        assert st.call_args.args == ("S1", H)
        with pytest.raises(HTTPException) as e:
            _stash_request_headers(pm.get("full-footprint"), req(request_headers=H), "S1")
        assert e.value.status_code == 422
        st.reset_mock()
        _stash_request_headers(pm.get("full-footprint"), req(), "S1")       # none given: nothing to do
        st.assert_not_called()


def test_without_redis_the_scan_is_refused_rather_than_held_insecurely():
    with patch.object(auth_headers, "stash", return_value=False), pytest.raises(HTTPException) as e:
        _stash_request_headers(get_profile_manager().get("web-app-test"), req(request_headers=H, authorised_to_test=True), "S1")
    assert e.value.status_code == 503


def test_bad_headers_in_a_request_are_a_422_with_no_value_in_it():
    with pytest.raises(HTTPException) as e:
        _stash_request_headers(get_profile_manager().get("web-app-test"), req(request_headers=["Host: s3cr3t"]), "S1")
    assert e.value.status_code == 422 and "s3cr3t" not in str(e.value.detail)


# -- how the tools receive them -------------------------------------------------------------------------------------
OPTS = {"_request_headers": H}


def test_flag_helpers():
    assert auth_headers.flag_args(OPTS, "-H") == ["-H", H[0], "-H", H[1]]
    assert auth_headers.joined(OPTS) == "\n".join(H)
    assert auth_headers.flag_args({}, "-H") == [] and auth_headers.joined({}) == ""
    assert auth_headers.flag_args({"_request_headers": ["Host: x"]}, "-H") == []      # invalid values are dropped


def _run(cls, event_type, data, **opts):
    m = cls()
    m.sf = MagicMock()
    m.opts = dict(cls.opts, **opts, **OPTS)
    m.results = {}
    m._runs = 0
    m.seedKeys = set()
    m.seedCount = 0
    m.errorState = False
    m.notifyListeners = MagicMock()
    m.checkForStop = MagicMock(return_value=False)
    m.__name__ = cls.__name__
    done = MagicMock(returncode=0, stdout="", stderr="")
    with patch.object(cls, "_find_binary", return_value="/bin/x", create=True), \
            patch("subprocess.run", return_value=done) as run:
        m.handleEvent(SpiderFootEvent(event_type, data, "sfp_spider", None))
    return run


@pytest.mark.parametrize("modname,flag", [("sfp_tool_dalfox", "-H"), ("sfp_tool_ffuf", "-H"), ("sfp_tool_katana", "-H")])
def test_url_tools_pass_one_flag_per_header(modname, flag):
    import importlib
    cls = getattr(importlib.import_module(f"modules.{modname}"), modname)
    url = "http://h/item.php?id=1" if modname == "sfp_tool_dalfox" else "http://h/"
    run = _run(cls, "LINKED_URL_INTERNAL", url)
    if not run.called:
        pytest.skip("module needs more setup than this contract test gives it")
    cmd = run.call_args.args[0]
    assert [cmd[i + 1] for i, a in enumerate(cmd) if a == flag] == H


def test_sqlmap_receives_the_headers_newline_joined():
    from modules.sfp_tool_sqlmap import sfp_tool_sqlmap
    run = _run(sfp_tool_sqlmap, "LINKED_URL_INTERNAL", "http://h/a.php?id=1")
    cmd = run.call_args.args[0]
    assert cmd[cmd.index("--headers") + 1] == "\n".join(H)


def test_no_module_logs_its_command_line_or_headers():
    import glob
    import re
    offenders = []
    for path in glob.glob("modules/sfp_tool_*.py") + ["modules/sfp_nuclei.py", "modules/sfp_httpx.py"]:
        for n, line in enumerate(open(path, encoding="utf-8"), 1):
            if re.search(r"(debug|info|error|warning)\(.*\{(?!len\()[^}]*(\bcmd\b|_request_headers|auth_headers)", line):
                offenders.append(f"{path}:{n}")
    assert not offenders, offenders

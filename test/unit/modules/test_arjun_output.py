"""sfp_tool_arjun reads both arjun output formats and does not default to the 15-minute stable mode."""
import json
from unittest.mock import MagicMock, patch

import pytest

from spiderfoot import SpiderFootEvent
from modules.sfp_tool_arjun import sfp_tool_arjun


def make():
    m = sfp_tool_arjun()
    m.sf = MagicMock()
    m.opts = dict(sfp_tool_arjun.opts)
    m.results = {}
    m._runs = 0
    m.errorState = False
    m.notifyListeners = MagicMock()
    m.checkForStop = MagicMock(return_value=False)
    m.__name__ = "sfp_tool_arjun"
    return m


def run_with_output(payload):
    m = make()

    def fake_run(cmd, **kw):
        with open(cmd[cmd.index("-oJ") + 1], "w") as f:
            json.dump(payload, f)
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch.object(sfp_tool_arjun, "_find_binary", return_value="/bin/arjun"), \
            patch("modules.sfp_tool_arjun.subprocess.run", side_effect=fake_run) as run:
        m.handleEvent(SpiderFootEvent("LINKED_URL_INTERNAL", "http://h/search.jsp", "sfp_spider", None))
    return m, run


@pytest.mark.parametrize("payload", [
    {"http://h/search.jsp": {"headers": {"A": "b"}, "method": "GET", "params": ["query"]}},   # arjun 2.x
    {"http://h/search.jsp": ["query"]},                                                         # older arjun
])
def test_both_output_formats_produce_a_form_url(payload):
    m, _ = run_with_output(payload)
    urls = [c.args[0].data for c in m.notifyListeners.call_args_list if c.args[0].eventType == "URL_FORM"]
    assert urls == ["http://h/search.jsp?query=FUZZ"]


def test_stable_mode_is_off_by_default():
    m, run = run_with_output({})
    assert "--stable" not in run.call_args.args[0]

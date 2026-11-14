"""ffuf reported Windows device names (con, aux, com1...) as pages: 166 of 234 hits in one scan."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import modules.sfp_tool_ffuf as mod
from modules.sfp_tool_ffuf import _is_windows_device_name, sfp_tool_ffuf
from spiderfoot import SpiderFootEvent
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase


class TestFfufDeviceNames(TestModuleBase):

    def test_device_names_are_recognised(self):
        for url in ("http://e.com/swagger/com2", "http://e.com/pr/lpt1", "https://e.com:443/AUX", "http://e.com/nul.txt",
                    "http://e.com/a/CON/", "http://e.com/prn.jsp?x=1"):
            self.assertTrue(_is_windows_device_name(url), url)
        for url in ("http://e.com/admin", "http://e.com/console", "http://e.com/com10", "http://e.com/auxiliary",
                    "http://e.com/con/page", "http://e.com/", "http://e.com/lpt"):
            self.assertFalse(_is_windows_device_name(url), url)

    def test_only_real_paths_are_reported(self):
        sf = SpiderFoot(self.default_options)
        m = sfp_tool_ffuf()
        m.setup(sf, dict())
        m.__name__ = "sfp_tool_ffuf"
        events = []
        m.notifyListeners = events.append
        hits = [{"url": f"http://target/{n}", "status": 200, "length": 0} for n in ("con", "aux", "com1", "lpt2", "nul")]
        hits += [{"url": "http://target/admin", "status": 302, "length": 0},
                 {"url": "http://target/bank", "status": 200, "length": 1427}]

        def fake_run(cmd, **kwargs):
            with open(cmd[cmd.index("-o") + 1], "w") as fh:
                json.dump({"results": hits}, fh)
            return MagicMock(returncode=0)

        with patch.object(mod.os.path, "isfile", return_value=True), patch.object(mod.subprocess, "run", side_effect=fake_run):
            m.handleEvent(SpiderFootEvent("LINKED_URL_INTERNAL", "http://target/", "sfp_spider", None))
        links = [e.data for e in events if e.eventType == "LINKED_URL_INTERNAL"]
        self.assertEqual(links, ["http://target/admin", "http://target/bank"])
        self.assertEqual(sum(1 for e in events if e.eventType == "HTTP_CODE"), 2)

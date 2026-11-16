"""sfp_tool_nikto: findings about paths a catch-all server answers for every request are dropped. The CSV rows have the
shape of a live Nikto run (2026-11-16); the host is an example address."""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock

from modules.sfp_tool_nikto import sfp_tool_nikto
from spiderfoot import SpiderFootEvent
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase

CATCH_ALL = {"code": "200", "content": "<html>" + "x" * 1500 + "</html>", "headers": {"content-type": "text/html"}}
REAL = {"code": "200", "content": "# real config\nkey=value\n" * 20, "headers": {"content-type": "text/plain"}}

ROWS = [
    '"203.0.113.10","203.0.113.10","443","","GET","/.htpasswd","/.htpasswd: Contains authorization information."',
    '"203.0.113.10","203.0.113.10","443","","GET","/.bash_history","/.bash_history: A user\'s home directory may be set to the web root, the shell history was retrieved."',
    '"203.0.113.10","203.0.113.10","443","","GET","/server-status.cfg","/server-status.cfg: Configuration file found (backup)."',
    '"203.0.113.10","203.0.113.10","443","","GET","/","/: Suggested security header missing: content-security-policy."',
]


class TestNiktoCatchAll(TestModuleBase):

    def _run(self, **opts):
        m = sfp_tool_nikto()
        m.__name__ = "sfp_tool_nikto"
        m.setup(SpiderFoot(self.default_options), opts)
        self.events = []
        m.notifyListeners = self.events.append
        m.checkForStop = lambda: False
        m.error = lambda *a, **k: None
        m._find_binary = lambda: "/usr/bin/nikto"

        def fake_fetch(url, **kw):
            return REAL if url.endswith("/server-status.cfg") else CATCH_ALL     # the server answers everything else alike
        m.fetch_url = fake_fetch

        def fake_run(cmd, **kw):
            path = cmd[cmd.index("-o") + 1]
            with open(path, "w") as fh:
                fh.write("\n".join(ROWS) + "\n")
            return MagicMock(stdout="", stderr="", returncode=0)
        import modules.sfp_tool_nikto as mod
        orig, mod.subprocess.run = mod.subprocess.run, fake_run
        try:
            m.handleEvent(SpiderFootEvent("INTERNET_NAME", "https://203.0.113.10:443/", "sfp_spider",
                                          SpiderFootEvent("ROOT", "root", "", None)))
        finally:
            mod.subprocess.run = orig
        return [e.data for e in self.events if e.eventType in ("VULNERABILITY_GENERAL", "INTERESTING_FILE", "VULNERABILITY_CVE_MEDIUM")]

    def test_catch_all_findings_are_dropped_and_the_real_ones_kept(self):
        found = self._run()
        text = " ".join(found)
        assert ".htpasswd" not in text and ".bash_history" not in text
        assert "server-status.cfg" in text                                  # a path the server really serves
        assert "content-security-policy" in text                            # a header advisory is not a path claim

    def test_with_the_filter_off_everything_is_reported_as_before(self):
        text = " ".join(self._run(catchall_filter=False))
        assert ".htpasswd" in text and ".bash_history" in text and "server-status.cfg" in text

    def test_the_option_is_documented(self):
        assert set(sfp_tool_nikto.opts) == set(sfp_tool_nikto.optdescs)

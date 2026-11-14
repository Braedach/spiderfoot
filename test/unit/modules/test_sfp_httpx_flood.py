"""httpx must probe each site once and report each host fact once (it produced 44% of a scan's events)."""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import modules.sfp_httpx as mod
from modules.sfp_httpx import sfp_httpx
from spiderfoot import SpiderFootEvent
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase


def _result(url, host="demo.example", port="443", tech=("Java", "Apache Tomcat"), server="Apache-Coyote/1.1"):
    return json.dumps({"url": url, "host": host, "port": port, "status_code": 200, "title": "Home",
                       "webserver": server, "tech": list(tech)})


class TestHttpxFlood(TestModuleBase):

    def _module(self):
        sf = SpiderFoot(self.default_options)
        m = sfp_httpx()
        m.__name__ = "sfp_httpx"
        m.setup(sf, {})
        m._find_httpx = lambda: "/bin/true"
        self.events = []
        m.notifyListeners = self.events.append
        self.runs = []

        def fake_run(cmd, **kwargs):
            infile = cmd[cmd.index("-l") + 1]
            outfile = cmd[cmd.index("-o") + 1]
            target = open(infile).read().strip()
            self.runs.append((target, "-ports" in cmd))
            url = target if target.startswith("http") else f"https://{target}"
            with open(outfile, "w") as fh:
                fh.write(_result(url) + "\n")
            return MagicMock(returncode=0, stderr="")

        self._patch = MagicMock(side_effect=fake_run)
        mod.subprocess.run, self._orig = self._patch, mod.subprocess.run
        self.addCleanup(lambda: setattr(mod.subprocess, "run", self._orig))
        return m

    def _ev(self, etype, data):
        return SpiderFootEvent(etype, data, "sfp_spider", None)

    def _count(self, etype):
        return sum(1 for e in self.events if e.eventType == etype)

    def test_origin(self):
        o = sfp_httpx._origin
        self.assertEqual(o("https://Demo.Example/a/b?x=1"), "https://demo.example")
        self.assertEqual(o("http://demo.example:80/a"), "http://demo.example")
        self.assertEqual(o("http://demo.example:8080/a"), "http://demo.example:8080")
        self.assertEqual(o("https://10.0.0.1:443/"), "https://10.0.0.1")
        self.assertIsNone(o("ftp://demo.example/a"))
        self.assertIsNone(o("not a url"))
        self.assertIsNone(o("http://demo.example:99999/"))

    def test_hundreds_of_links_on_one_site_mean_one_probe(self):
        m = self._module()
        for i in range(300):
            m.handleEvent(self._ev("LINKED_URL_INTERNAL", f"https://demo.example/page{i}.jsp?id={i}"))
        self.assertEqual(len(self.runs), 1)
        self.assertEqual(self.runs[0], ("https://demo.example", False))   # the origin, on its own port
        self.assertEqual(self._count("WEBSERVER_BANNER"), 1)
        self.assertEqual(self._count("WEBSERVER_TECHNOLOGY"), 2)
        self.assertEqual(self._count("TCP_PORT_OPEN"), 1)

    def test_each_scheme_host_and_port_is_its_own_site(self):
        m = self._module()
        for url in ("http://demo.example/a", "https://demo.example/a", "http://demo.example:8080/a",
                    "https://other.example/a", "https://demo.example/b"):
            m.handleEvent(self._ev("LINKED_URL_INTERNAL", url))
        self.assertEqual([r[0] for r in self.runs], ["http://demo.example", "https://demo.example",
                                                     "http://demo.example:8080", "https://other.example"])

    def test_a_site_found_by_a_host_probe_is_not_probed_again_from_a_link(self):
        m = self._module()
        m.handleEvent(self._ev("INTERNET_NAME", "demo.example"))        # reports https://demo.example
        m.handleEvent(self._ev("LINKED_URL_INTERNAL", "https://demo.example/bank/login.jsp"))
        self.assertEqual(self.runs, [("demo.example", True)])

    def test_the_same_fact_from_two_probes_is_reported_once(self):
        m = self._module()
        m.handleEvent(self._ev("INTERNET_NAME", "demo.example"))
        m.handleEvent(self._ev("TCP_PORT_OPEN", "demo.example:443"))
        self.assertEqual(len(self.runs), 2)
        self.assertEqual(self._count("WEBSERVER_BANNER"), 1)
        self.assertEqual(self._count("TCP_PORT_OPEN"), 1)

    def test_host_and_port_events_still_probe_as_before(self):
        m = self._module()
        m.handleEvent(self._ev("IP_ADDRESS", "198.51.100.7"))
        m.handleEvent(self._ev("TCP_PORT_OPEN", "198.51.100.7:3000"))
        self.assertEqual(self.runs, [("198.51.100.7", True), ("198.51.100.7:3000", False)])

    def test_non_http_links_are_ignored(self):
        m = self._module()
        m.handleEvent(self._ev("LINKED_URL_INTERNAL", "mailto:someone@demo.example"))
        self.assertEqual(self.runs, [])

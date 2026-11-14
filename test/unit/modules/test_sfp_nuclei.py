"""sfp_nuclei: it must find its templates, say so when it cannot run, and scan a host once (rc.36: it never ran)."""
from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock

import modules.sfp_nuclei as mod
from modules.sfp_nuclei import sfp_nuclei
from spiderfoot import SpiderFootEvent
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase

FTL = ("WARNING: sonic/ast only supports (go1.17~1.26 and amd64 CPU)\n"
       "[\x1b[1;31mFTL\x1b[0m] Could not run nuclei: no templates provided for scan\n")
# One finding in the shape nuclei v3.11.1 printed against a real host
MEDIUM = {"template-id": "weak-cipher-suites", "info": {"name": "Weak Cipher Suites", "severity": "medium",
          "tags": ["ssl", "tls"]}, "type": "ssl", "host": "demo.example", "matched-at": "demo.example:443"}
INFO = {"template-id": "apache-detect", "info": {"name": "Apache Detect", "severity": "info"}, "type": "http",
        "host": "demo.example", "matched-at": "https://demo.example"}


class TestNucleiModule(TestModuleBase):

    def _module(self, **opts):
        m = sfp_nuclei()
        m.__name__ = "sfp_nuclei"
        m.setup(SpiderFoot(self.default_options), {"auto_update_templates": False, **opts})
        self.events, self.errors, self.runs = [], [], []
        m.notifyListeners = self.events.append
        m.error = self.errors.append
        m.checkForStop = lambda: False
        if not hasattr(self, "_real_isdir"):          # patch once per test, however many modules it creates
            self._real_isdir = mod.os.path.isdir
            real = self._real_isdir
            mod.os.path.isdir = lambda p: True if p == sfp_nuclei.PINNED_TEMPLATES else real(p)
            self.addCleanup(lambda: setattr(mod.os.path, "isdir", real))
        return m

    def _stub_run(self, stdout="", stderr="", returncode=0, timeout=False):
        def fake_run(cmd, **kwargs):
            if "-version" in cmd:
                return MagicMock(returncode=0, stdout="v3.11.1", stderr="")
            self.runs.append(cmd)
            if timeout:
                raise subprocess.TimeoutExpired(cmd, 1, output=stdout.encode())
            return MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)
        self._orig_run = mod.subprocess.run
        mod.subprocess.run = fake_run
        self.addCleanup(lambda: setattr(mod.subprocess, "run", self._orig_run))

    def _ev(self, etype, data):
        return SpiderFootEvent(etype, data, "sfp_x", None)

    # ---- the command line
    def test_opts_and_descriptions_match(self):
        m = sfp_nuclei()
        self.assertEqual(set(m.opts), set(m.optdescs))

    def test_default_command_finds_the_pinned_templates_and_stays_quiet(self):
        """The rc.36 failure: no -ud, so nuclei looked in $HOME and printed 'no templates provided for scan'."""
        cmd = self._module()._build_cmd("targets.txt")
        self.assertEqual(cmd[cmd.index("-ud") + 1], "/tools/nuclei-templates")
        for flag in ("-duc", "-ni", "-jsonl", "-silent", "-nc"):
            self.assertIn(flag, cmd)
        self.assertNotIn("-as", cmd)                      # the template selection is added per pass
        self.assertEqual(cmd[cmd.index("-severity") + 1], "low,medium,high,critical")
        self.assertEqual(cmd[cmd.index("-etags") + 1], "dos,fuzz,intrusive")
        self.assertNotIn("-t", cmd)
        self.assertNotIn("-ut", cmd)

    def test_default_is_a_cheap_baseline_pass_then_the_automatic_pass(self):
        """nuclei -as cannot be combined with -tags in one run (it then finds nothing), so they are separate runs."""
        self.assertEqual(self._module()._selections(), [["-tags", "ssl"], ["-as"]])

    def test_chosen_tags_replace_both_passes(self):
        m = self._module(template_tags="cve,exposure")
        self.assertEqual(m._selections(), [["-tags", "cve,exposure"]])
        cmd = m._build_cmd("t.txt", m._selections()[0])
        self.assertEqual(cmd[cmd.index("-tags") + 1], "cve,exposure")
        self.assertNotIn("-as", cmd)

    def test_either_pass_can_be_turned_off(self):
        self.assertEqual(self._module(baseline_tags="")._selections(), [["-as"]])
        self.assertEqual(self._module(automatic_scan=False)._selections(), [["-tags", "ssl"]])
        self.assertEqual(self._module(baseline_tags="", automatic_scan=False)._selections(), [[]])   # all templates, deliberately

    def test_the_user_can_allow_callbacks_and_move_the_templates(self):
        cmd = self._module(use_interactsh=True, templates_dir="/srv/t")._build_cmd("t.txt")
        self.assertNotIn("-ni", cmd)
        self.assertEqual(cmd[cmd.index("-ud") + 1], "/srv/t")

    def test_custom_templates_run_alone(self):
        m = self._module(custom_templates_dir="/srv/mine")
        mod.os.path.isdir = lambda p: True
        self.assertEqual(m._selections(), [[]])
        self.assertEqual(m._build_cmd("t.txt", [])[m._build_cmd("t.txt", []).index("-t") + 1], "/srv/mine")

    def test_without_a_pinned_copy_nuclei_is_left_to_find_its_own(self):
        m = self._module()
        mod.os.path.isdir = lambda p: False
        self.assertNotIn("-ud", m._build_cmd("t.txt"))

    # ---- running it
    def test_a_fatal_error_is_reported_and_stops_the_module(self):
        m = self._module()
        self._stub_run(stderr=FTL, returncode=1)
        self.assertEqual(m._run_nuclei(["demo.example"]), [])
        self.assertEqual(self.errors, ["Nuclei could not run: [FTL] Could not run nuclei: no templates provided for scan"])
        self.assertTrue(m.errorState)

    def test_findings_before_a_timeout_are_kept(self):
        m = self._module()
        self._stub_run(stdout=json.dumps(MEDIUM) + "\n" + '{"truncated', timeout=True)
        findings = m._run_nuclei(["demo.example"])
        self.assertEqual([f["template-id"] for f in findings], ["weak-cipher-suites"])
        self.assertIn("timed out", self.errors[0])
        self.assertIn("keeping the 1 finding", self.errors[0])
        self.assertFalse(m.errorState)

    def test_nonzero_exit_without_a_fatal_line_is_not_an_error(self):
        m = self._module()
        self._stub_run(stderr="[WRN] some target unreachable", returncode=1)
        self.assertEqual(m._run_nuclei(["demo.example"]), [])
        self.assertEqual(self.errors, [])
        self.assertFalse(m.errorState)

    # ---- what a finding becomes
    def test_findings_become_events(self):
        m = self._module()
        self._stub_run(stdout=json.dumps(MEDIUM) + "\n" + json.dumps(INFO) + "\n")
        m.handleEvent(self._ev("INTERNET_NAME", "demo.example"))
        self.assertEqual(len(self.runs), 2)                                  # baseline pass, then automatic pass
        self.assertIn("-tags", self.runs[0])
        self.assertIn("-as", self.runs[1])
        types = [e.eventType for e in self.events]
        self.assertEqual(types.count("VULNERABILITY_CVE_MEDIUM"), 1)         # the same finding from both passes: once
        self.assertIn("VULNERABILITY_CVE_MEDIUM", types)
        self.assertIn("RAW_RIR_DATA", types)
        self.assertFalse([e for e in self.events if "Apache" in e.data and e.eventType.startswith("VULN")])  # info dropped

    # ---- how many runs
    def test_a_host_named_two_ways_is_scanned_once(self):
        m = self._module()
        self._stub_run()
        m.handleEvent(self._ev("INTERNET_NAME", "demo.example"))
        m.handleEvent(self._ev("DOMAIN_NAME", "Demo.Example"))
        self.assertEqual(len(self.runs), 2)

    def test_discovered_urls_do_not_each_start_a_run(self):
        """300 pages of one site used to mean 300 full template runs."""
        m = self._module()
        self._stub_run()
        m.handleEvent(self._ev("INTERNET_NAME", "demo.example"))
        for i in range(300):
            for scheme in ("http", "https"):
                m.handleEvent(self._ev("LINKED_URL_INTERNAL", f"{scheme}://demo.example/page{i}.jsp?id={i}"))
            m.handleEvent(self._ev("LINKED_URL_INTERNAL", f"http://demo.example:80/other{i}"))
        self.assertEqual(len(self.runs), 2)

    def test_a_web_server_on_another_port_is_its_own_run(self):
        m = self._module()
        self._stub_run()
        m.handleEvent(self._ev("INTERNET_NAME", "demo.example"))
        for i in range(20):
            m.handleEvent(self._ev("LINKED_URL_INTERNAL", f"http://demo.example:8080/p{i}"))
        self.assertEqual(len(self.runs), 4)  # host + the :8080 origin, two passes each

    def test_the_number_of_runs_is_capped(self):
        m = self._module(max_targets=3)
        self._stub_run()
        for i in range(10):
            m.handleEvent(self._ev("IP_ADDRESS", f"198.51.100.{i}"))
        self.assertEqual(len(self.runs), 6)  # three targets, two passes each

    def test_ips_and_urls_can_be_switched_off(self):
        m = self._module(scan_ips=False, scan_urls=False)
        self._stub_run()
        m.handleEvent(self._ev("IP_ADDRESS", "198.51.100.7"))
        m.handleEvent(self._ev("LINKED_URL_INTERNAL", "https://other.example/x"))
        self.assertEqual(self.runs, [])

    def test_origin_helper(self):
        o = sfp_nuclei._origin
        self.assertEqual(o("HTTPS://Demo.Example:443/a?b=1"), "https://demo.example")
        self.assertEqual(o("http://demo.example:8080/a"), "http://demo.example:8080")
        self.assertEqual(o("http://[::1]:80/"), "http://[::1]")
        for bad in ("ftp://x/", "not a url", "http://h:99999/", ""):
            self.assertIsNone(o(bad))

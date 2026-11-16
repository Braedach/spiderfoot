"""sfp_tool_maigret: fixtures have the structure of a real Maigret 0.6.6 "simple" JSON report (captured 2026-11-14)."""
from __future__ import annotations

import json
import os
import subprocess
from unittest.mock import MagicMock

import modules.sfp_tool_maigret as mod
from modules.sfp_tool_maigret import sfp_tool_maigret
from spiderfoot import SpiderFootEvent
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase


def _entry(site, url, tags, ids=None, similar=False, status="Claimed", username="exampleuser"):
    return {"cookies": None, "http_status": 200, "is_similar": similar, "keywords": [], "parsing_enabled": False,
            "rank": 775, "site": {"tags": tags, "url": url, "urlMain": url, "usernameClaimed": "x"},
            "status": {"username": username, "site_name": site, "url": url, "status": status, "ids": ids or {},
                       "tags": tags, "keywords": [], "keyword_match_status": "No Keywords"},
            "url_main": url, "url_probe": url, "url_user": url, "username": username}


REPORT = {
    "Example Pay": _entry("Example Pay", "https://pay.example/me/exampleuser", ["apps", "business", "finance", "fintech"]),
    "ExampleGist [Example]": _entry("ExampleGist [Example]", "https://gist.example/exampleuser", ["coding", "sharing", "us"],
                                    ids={"name": "Example User", "location": "Perth"}),
    "Similar Site": _entry("Similar Site", "https://similar.example/exampleuser", ["forum"], similar=True),
    "Free Name": _entry("Free Name", "https://free.example/exampleuser", ["forum"], status="Available"),
}


class TestMaigretModule(TestModuleBase):

    def _module(self, report=None, returncode=0, **opts):
        m = sfp_tool_maigret()
        m.__name__ = "sfp_tool_maigret"
        m.setup(SpiderFoot(self.default_options), opts)
        self.events, self.errors, self.calls = [], [], []
        m.notifyListeners = self.events.append
        m.error = self.errors.append
        m.checkForStop = lambda: False
        self.target_type = "HUMAN_NAME"
        m.getTarget = lambda: MagicMock(targetType=self.target_type)
        m._find_binary = lambda: "/tools/venv/bin/maigret"

        def fake_run(cmd, **kw):
            self.calls.append((cmd, kw))
            folder = cmd[cmd.index("--folderoutput") + 1]
            if report is not None:
                with open(os.path.join(folder, f"report_{cmd[1]}_simple.json"), "w") as fh:
                    json.dump(report, fh)
            return MagicMock(returncode=returncode, stdout="", stderr="")

        self._orig = mod.subprocess.run
        mod.subprocess.run = fake_run
        self.addCleanup(lambda: setattr(mod.subprocess, "run", self._orig))
        return m

    def _ev(self, data, etype="USERNAME"):
        return SpiderFootEvent(etype, data, "sfp_accounts", None)

    def _of(self, etype):
        return [e.data for e in self.events if e.eventType == etype]

    # ---- options and command
    def test_opts_and_descriptions_match(self):
        self.assertEqual(set(sfp_tool_maigret().opts), set(sfp_tool_maigret().optdescs))

    def test_the_command_is_safe_by_default(self):
        cmd = self._module()._build_cmd("maigret", "exampleuser", "/tmp/x")
        self.assertEqual(cmd[:2], ["maigret", "exampleuser"])
        for flag in ("--no-autoupdate", "--no-recursion", "--no-progressbar", "--no-color"):
            self.assertIn(flag, cmd)
        for forbidden in ("--ai", "--web", "--submit", "--self-check", "-a", "--all-sites", "--cookies-jar-file"):
            self.assertNotIn(forbidden, cmd)
        self.assertEqual(cmd[cmd.index("--json") + 1], "simple")
        self.assertEqual(cmd[cmd.index("--top-sites") + 1], "500")
        self.assertEqual(cmd[cmd.index("--exclude-tags") + 1], "porn,erotic,webcam")
        self.assertNotIn("--proxy", cmd)

    def test_a_configured_proxy_is_used_unless_switched_off(self):
        proxy = {"_socks1type": "5", "_socks2addr": "px.example", "_socks3port": "1080"}
        cmd = self._module(**proxy)._build_cmd("maigret", "exampleuser", "/tmp/x")
        self.assertEqual(cmd[cmd.index("--proxy") + 1], "socks5h://px.example:1080")
        self.assertNotIn("--proxy", self._module(use_proxy=False, **proxy)._build_cmd("maigret", "exampleuser", "/tmp/x"))

    # ---- what the report becomes
    def test_claimed_accounts_become_account_events(self):
        m = self._module(report=REPORT)
        m.handleEvent(self._ev("exampleuser"))
        accounts = self._of("ACCOUNT_EXTERNAL_OWNED")
        self.assertEqual(len(accounts), 2)                                   # not the similar one, not the unclaimed one
        self.assertIn("Example Pay (Category: apps, business, finance)\n<SFURL>https://pay.example/me/exampleuser</SFURL>", accounts)
        self.assertIn("ExampleGist [Example] (Category: coding, sharing)\n<SFURL>https://gist.example/exampleuser</SFURL>", accounts)
        self.assertFalse([a for a in accounts if "Similar" in a])
        self.assertEqual(self.errors, [])

    def test_details_a_profile_publishes_are_reported(self):
        m = self._module(report=REPORT)
        m.handleEvent(self._ev("exampleuser"))
        raw = [json.loads(r) for r in self._of("RAW_RIR_DATA")]
        self.assertEqual(len(raw), 1)
        self.assertEqual(raw[0]["details"], {"name": "Example User", "location": "Perth"})

    def test_similar_matches_can_be_kept(self):
        m = self._module(report=REPORT, skip_similar=False)
        m.handleEvent(self._ev("exampleuser"))
        self.assertEqual(len(self._of("ACCOUNT_EXTERNAL_OWNED")), 3)

    # ---- how it is run
    def test_it_runs_in_a_private_directory_with_no_input_and_a_time_limit(self):
        m = self._module(report=REPORT)
        m.handleEvent(self._ev("exampleuser"))
        cmd, kw = self.calls[0]
        self.assertEqual(kw["stdin"], subprocess.DEVNULL)
        self.assertEqual(kw["timeout"], 900)
        self.assertEqual(kw["env"]["HOME"], kw["cwd"])                      # its files stay in the temporary folder
        self.assertFalse(os.path.exists(kw["cwd"]))                         # and are gone afterwards

    # ---- which usernames
    def test_quotes_are_stripped_and_each_username_is_looked_up_once(self):
        m = self._module(report=REPORT)
        for name in ('"exampleuser"', "ExampleUser", "exampleuser"):
            m.handleEvent(self._ev(name))
        self.assertEqual(len(self.calls), 1)

    def test_values_that_are_not_plain_usernames_are_skipped(self):
        m = self._module(report=REPORT)
        for name in ("ab", "-oFile", "--ai", "two words", "a/b", "x" * 80, "bob@example.com", "semi;colon", '""'):
            m.handleEvent(self._ev(name))
        self.assertEqual(self.calls, [])

    def test_the_number_of_usernames_is_capped(self):
        m = self._module(report=REPORT, max_usernames=3)
        for i in range(8):
            m.handleEvent(self._ev(f"user{i}name"))
        self.assertEqual(len(self.calls), 3)

    # ---- failures
    def test_a_missing_binary_is_reported_once_and_stops_the_module(self):
        m = self._module(report=REPORT)
        m._find_binary = lambda: None
        m.handleEvent(self._ev("exampleuser"))
        m.handleEvent(self._ev("otheruser"))
        self.assertEqual(len(self.errors), 1)
        self.assertIn("binary was not found", self.errors[0])
        self.assertTrue(m.errorState)

    def test_no_report_is_an_error_not_silence(self):
        m = self._module(report=None, returncode=2)
        m.handleEvent(self._ev("exampleuser"))
        self.assertIn("produced no report", self.errors[0])
        self.assertIn("exit 2", self.errors[0])

    def test_a_timeout_is_reported(self):
        m = self._module(report=REPORT)

        def slow(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, 1)

        mod.subprocess.run = slow
        m.handleEvent(self._ev("exampleuser"))
        self.assertIn("timed out", self.errors[0])
        self.assertFalse(m.errorState)                                       # the next username may still work

    def test_a_damaged_report_is_an_error(self):
        m = self._module(report=REPORT)

        def corrupt(cmd, **kw):
            folder = cmd[cmd.index("--folderoutput") + 1]
            open(os.path.join(folder, "report_exampleuser_simple.json"), "w").write("{not json")
            return MagicMock(returncode=0, stdout="", stderr="")

        mod.subprocess.run = corrupt
        m.handleEvent(self._ev("exampleuser"))
        self.assertIn("Could not read Maigret's report", self.errors[0])

    # ---- whose details it will look up
    def test_it_does_nothing_in_a_scan_that_is_not_about_a_person(self):
        """In a domain scan the usernames and emails found are other people's (staff on a company website)."""
        m = self._module(report=REPORT)
        for target in ("INTERNET_NAME", "DOMAIN_NAME", "IP_ADDRESS", "NETBLOCK_OWNER", "BGP_AS_OWNER"):
            self.target_type = target
            m.handleEvent(self._ev("exampleuser"))
        self.assertEqual(self.calls, [])

    def test_every_person_target_type_is_allowed(self):
        for target in ("HUMAN_NAME", "EMAILADDR", "USERNAME", "PHONE_NUMBER"):
            m = self._module(report=REPORT)
            self.target_type = target
            m.handleEvent(self._ev("exampleuser"))
            self.assertEqual(len(self.calls), 1, target)

    def test_the_restriction_can_be_turned_off(self):
        m = self._module(report=REPORT, person_targets_only=False)
        self.target_type = "INTERNET_NAME"
        m.handleEvent(self._ev("exampleuser"))
        self.assertEqual(len(self.calls), 1)

    def test_an_unknown_target_is_treated_as_not_a_person(self):
        m = self._module(report=REPORT)
        m.getTarget = lambda: (_ for _ in ()).throw(RuntimeError("no scan"))
        m.handleEvent(self._ev("exampleuser"))
        self.assertEqual(self.calls, [])

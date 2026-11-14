"""sfp_tool_user_scanner: fixtures have the structure of a real user-scanner 1.5.2.3 JSON report (captured 2026-11-14)."""
from __future__ import annotations

import json
import os
import subprocess
from unittest.mock import MagicMock

import modules.sfp_tool_user_scanner as mod
from modules.sfp_tool_user_scanner import sfp_tool_user_scanner
from spiderfoot import SpiderFootEvent
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase

EMAIL = "someone@example.org"


def _row(status, site, category, url, extra=None, reason=""):
    return {"status": status, "reason": reason, "site_name": site, "category": category, "url": url,
            "extra": extra or {}, "media": {}, "email": EMAIL}


REPORT = [
    _row("Registered", "Tumblr", "Social", "https://tumblr.com"),
    _row("Registered", "Gravatar", "Social", "https://gravatar.com/exampleuser",
         extra={"username": "exampleuser", "display_name": "exampleuser", "profile_url": "https://gravatar.com/exampleuser",
                "profile_type": "Personal", "created": "7 years ago"}),
    _row("Registered", "Online Shop", "Shopping", "https://shop.example"),
    _row("Not Registered", "Some Forum", "Forums", "https://forum.example"),
    _row("Error", "Blocked Site", "Social", "https://blocked.example", reason="403"),
    _row("Skipped", "Loud Site", "Social", "https://loud.example", reason="loud module"),
]


class TestUserScannerModule(TestModuleBase):

    def _module(self, report=REPORT, returncode=0, **opts):
        m = sfp_tool_user_scanner()
        m.__name__ = "sfp_tool_user_scanner"
        m.setup(SpiderFoot(self.default_options), opts)
        self.events, self.errors, self.calls, self.seen_files = [], [], [], {}
        m.notifyListeners = self.events.append
        m.error = self.errors.append
        m.checkForStop = lambda: False
        self.target_type = "EMAILADDR"
        m.getTarget = lambda: MagicMock(targetType=self.target_type)
        m._find_binary = lambda: "/tools/venv/bin/user-scanner"

        def fake_run(cmd, **kw):
            self.calls.append((cmd, kw))
            # what the tool would read, while the temporary folder still exists
            cfg = kw["env"].get("USER_SCANNER_CONFIG")
            self.seen_files["settings"] = json.load(open(cfg)) if cfg and os.path.exists(cfg) else None
            if "-P" in cmd:
                self.seen_files["proxies"] = open(cmd[cmd.index("-P") + 1]).read()
            if report is not None:
                json.dump(report, open(cmd[cmd.index("-o") + 1], "w"))
            return MagicMock(returncode=returncode, stdout="", stderr="")

        self._orig = mod.subprocess.run
        mod.subprocess.run = fake_run
        self.addCleanup(lambda: setattr(mod.subprocess, "run", self._orig))
        return m

    def _ev(self, data=EMAIL):
        return SpiderFootEvent("EMAILADDR", data, "sfp_x", None)

    def _of(self, etype):
        return [e.data for e in self.events if e.eventType == etype]

    # ---- options and command
    def test_opts_and_descriptions_match(self):
        self.assertEqual(set(sfp_tool_user_scanner().opts), set(sfp_tool_user_scanner().optdescs))

    def test_by_default_it_will_not_trigger_notifications_or_follow_leads(self):
        m = self._module()
        cmd = m._build_cmd("user-scanner", EMAIL, "/tmp/o.json", "/tmp")
        self.assertEqual(cmd[:3], ["user-scanner", "-e", EMAIL])
        for forbidden in ("--allow-loud", "--cross-scan", "--hudson", "-U", "--all"):
            self.assertNotIn(forbidden, cmd)
        self.assertIn("--no-nsfw", cmd)
        self.assertEqual(cmd[cmd.index("-f") + 1], "json")

    def test_loud_checks_need_an_explicit_option(self):
        cmd = self._module(allow_loud=True)._build_cmd("user-scanner", EMAIL, "/tmp/o.json", "/tmp")
        self.assertIn("--allow-loud", cmd)

    def test_the_update_check_and_prompts_are_switched_off(self):
        """It asks PyPI for a newer version at start-up and offers to pip-install it."""
        m = self._module()
        m.handleEvent(self._ev())
        self.assertEqual(self.seen_files["settings"], {"auto_update_status": False, "auto_hudson_prompt": False,
                                                       "auto_loud_single_module_prompt": False})
        self.assertEqual(self.calls[0][1]["stdin"], subprocess.DEVNULL)

    def test_a_configured_proxy_is_passed_as_a_proxy_file(self):
        m = self._module(_socks1type="5", _socks2addr="px.example", _socks3port="1080")
        m.handleEvent(self._ev())
        self.assertEqual(self.seen_files["proxies"], "socks5h://px.example:1080\n")
        m2 = self._module(use_proxy=False, _socks1type="5", _socks2addr="px.example", _socks3port="1080")
        m2.handleEvent(self._ev())
        self.assertNotIn("-P", self.calls[-1][0])

    # ---- what the report becomes
    def test_only_registered_sites_are_reported(self):
        m = self._module()
        m.handleEvent(self._ev())
        accounts = self._of("ACCOUNT_EXTERNAL_OWNED")
        self.assertEqual(len(accounts), 3)
        self.assertIn("Tumblr (Category: social)\n<SFURL>https://tumblr.com</SFURL>", accounts)
        self.assertIn("Gravatar (Category: social)\n<SFURL>https://gravatar.com/exampleuser</SFURL>", accounts)
        self.assertIn("Online Shop (Category: shopping)\n<SFURL>https://shop.example</SFURL>", accounts)
        self.assertFalse([a for a in accounts if "Forum" in a or "Blocked" in a or "Loud" in a])
        self.assertEqual(self.errors, [])

    def test_a_username_a_site_attaches_to_the_address_is_reported_as_one(self):
        m = self._module()
        m.handleEvent(self._ev())
        self.assertEqual(self._of("USERNAME"), ["exampleuser"])

    def test_the_details_a_site_returns_are_kept(self):
        m = self._module()
        m.handleEvent(self._ev())
        raw = [json.loads(r) for r in self._of("RAW_RIR_DATA")]
        self.assertEqual(len(raw), 1)
        self.assertEqual(raw[0]["details"]["profile_type"], "Personal")

    # ---- which addresses
    def test_each_address_is_checked_once_and_junk_is_skipped(self):
        m = self._module()
        for value in (EMAIL, EMAIL.upper(), "-bad@example.org", "no-at-sign", "a b@example.org", "x@y"):
            m.handleEvent(self._ev(value))
        self.assertEqual(len(self.calls), 1)

    def test_the_number_of_addresses_is_capped(self):
        m = self._module(max_emails=2)
        for i in range(6):
            m.handleEvent(self._ev(f"user{i}@example.org"))
        self.assertEqual(len(self.calls), 2)

    # ---- failures
    def test_a_missing_binary_is_reported_once_and_stops_the_module(self):
        m = self._module()
        m._find_binary = lambda: None
        m.handleEvent(self._ev())
        m.handleEvent(self._ev("other@example.org"))
        self.assertEqual(len(self.errors), 1)
        self.assertTrue(m.errorState)

    def test_no_report_is_an_error(self):
        m = self._module(report=None, returncode=1)
        m.handleEvent(self._ev())
        self.assertIn("produced no report", self.errors[0])

    def test_a_timeout_is_reported(self):
        m = self._module()
        mod.subprocess.run = lambda cmd, **kw: (_ for _ in ()).throw(subprocess.TimeoutExpired(cmd, 1))
        m.handleEvent(self._ev())
        self.assertIn("timed out", self.errors[0])

    def test_the_dict_form_of_a_report_is_understood_too(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"results": REPORT}, fh)
        try:
            self.assertEqual(len(sfp_tool_user_scanner._parse_report(fh.name)), 3)
        finally:
            os.unlink(fh.name)

    # ---- whose details it will look up
    def test_it_does_nothing_in_a_scan_that_is_not_about_a_person(self):
        """In a domain scan the usernames and emails found are other people's (staff on a company website)."""
        m = self._module(report=REPORT)
        for target in ("INTERNET_NAME", "DOMAIN_NAME", "IP_ADDRESS", "NETBLOCK_OWNER", "BGP_AS_OWNER"):
            self.target_type = target
            m.handleEvent(self._ev(EMAIL))
        self.assertEqual(self.calls, [])

    def test_every_person_target_type_is_allowed(self):
        for target in ("HUMAN_NAME", "EMAILADDR", "USERNAME", "PHONE_NUMBER"):
            m = self._module(report=REPORT)
            self.target_type = target
            m.handleEvent(self._ev(EMAIL))
            self.assertEqual(len(self.calls), 1, target)

    def test_the_restriction_can_be_turned_off(self):
        m = self._module(report=REPORT, person_targets_only=False)
        self.target_type = "INTERNET_NAME"
        m.handleEvent(self._ev(EMAIL))
        self.assertEqual(len(self.calls), 1)

    def test_an_unknown_target_is_treated_as_not_a_person(self):
        m = self._module(report=REPORT)
        m.getTarget = lambda: (_ for _ in ()).throw(RuntimeError("no scan"))
        m.handleEvent(self._ev(EMAIL))
        self.assertEqual(self.calls, [])

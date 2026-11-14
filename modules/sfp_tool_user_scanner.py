from __future__ import annotations

"""SpiderFoot plug-in module: tool_user_scanner."""

# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_user_scanner
# Purpose:      Check which sites an email address is registered on, using user-scanner (email mode).
#               Tool: https://github.com/kaifcodec/user-scanner (MIT)
#
# Created:      14/11/2026
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import os
import re
import subprocess
import tempfile
from shutil import which

from spiderfoot import SpiderFootEvent
from spiderfoot.plugins.async_plugin import SpiderFootAsyncPlugin
from spiderfoot.sflib.proxy import general_proxy_url

# Never a leading hyphen (or dot): the address is given to the tool as a command-line value
_EMAIL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9][A-Za-z0-9.-]{0,189}\.[A-Za-z]{2,24}$")
_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")


class sfp_tool_user_scanner(SpiderFootAsyncPlugin):

    """Check which sites an email address is registered on, with user-scanner."""

    meta = {
        'name': "Tool - user-scanner (email registrations)",
        'summary': "Check which of about 200 sites an email address is registered on, using user-scanner. "
                   "Sites whose check could send the address a notification or reset email are skipped.",
        'flags': ["tool", "slow"],
        'useCases': ["Investigate"],
        'categories': ["Social Media"],
        'toolDetails': {
            'name': "user-scanner",
            'description': "Email and username OSINT: checks sites' own sign-up and sign-in endpoints to learn whether "
            "an address is registered.",
            'website': 'https://github.com/kaifcodec/user-scanner',
            'repository': 'https://github.com/kaifcodec/user-scanner',
        },
        'dataSource': {
            'website': "https://github.com/kaifcodec/user-scanner",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': ["https://github.com/kaifcodec/user-scanner"],
            'description': "user-scanner asks each site's own registration or login endpoint whether the address is known.",
        },
    }

    # Default options
    opts = {
        'userscannerpath': "",
        'timeout': 15,
        'concurrency': 10,
        'max_emails': 5,
        'skip_nsfw': True,
        'allow_loud': False,
        'run_timeout': 600,
        'use_proxy': True,
        'person_targets_only': True,
    }

    # Option descriptions
    optdescs = {
        'userscannerpath': "Path to the user-scanner binary. Blank searches PATH.",
        'timeout': "Seconds to wait for each site.",
        'concurrency': "How many sites to contact at once.",
        'max_emails': "Most email addresses to check in one scan.",
        'skip_nsfw': "Leave out adult sites.",
        'allow_loud': "ALSO check the sites whose test can send the address a password-reset or notification email or "
                      "text. Off by default: the address's owner would receive those messages.",
        'run_timeout': "Seconds to allow one address's check before giving up on it.",
        'person_targets_only': "Only act when the scan is about a person (a name, email address, username or phone number). Off = also look up every email addresses discovered during other scans, such as staff addresses found on a company's website, which sends those people's details to hundreds of sites.",
        'use_proxy': "Send the checks through the general outbound proxy (Settings > Network & Proxy) when one is set.",
    }

    # Target types that mean the user asked about a person
    PERSON_TARGETS = ("HUMAN_NAME", "EMAILADDR", "USERNAME", "PHONE_NUMBER")

    results = None
    errorState = False

    def setup(self, sfc, userOpts: dict = None) -> None:
        """Set up the module."""
        super().setup(sfc, userOpts or {})
        self.results = self.tempStorage()
        self.errorState = False
        self._checked = 0
        self.__dataSource__ = "Sites' own registration endpoints"

    def watchedEvents(self) -> list:
        """Return the list of events this module watches."""
        return ["EMAILADDR"]

    def producedEvents(self) -> list:
        """Return the list of events this module produces."""
        return ["ACCOUNT_EXTERNAL_OWNED", "USERNAME", "RAW_RIR_DATA"]

    def _person_scan(self) -> bool:
        """True when this module may act: the scan is about a person, or the user turned the restriction off."""
        if not self.opts.get('person_targets_only', True):
            return True
        try:
            return self.getTarget().targetType in self.PERSON_TARGETS
        except Exception:
            return False

    def _find_binary(self) -> str | None:
        custom = str(self.opts.get('userscannerpath') or '').strip()
        if custom and os.path.isfile(custom):
            return custom
        return which('user-scanner')

    @staticmethod
    def _write_settings(folder: str) -> str:
        """user-scanner's own settings, with its interactive prompts and its update check turned off.

        By default it asks PyPI for a newer version at start-up and offers to install it with pip, which a reviewed,
        hash-locked image must never do. USER_SCANNER_CONFIG points it at this file instead of its default.
        """
        path = os.path.join(folder, "settings.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"auto_update_status": False, "auto_hudson_prompt": False,
                       "auto_loud_single_module_prompt": False}, fh)
        return path

    def _build_cmd(self, binary: str, email: str, output: str, folder: str) -> list[str]:
        """The user-scanner command line (email mode, JSON report, no cross-scan pivoting)."""
        cmd = [
            binary, '-e', email, '-f', 'json', '-o', output,
            '-t', str(int(self.opts.get('timeout', 15))),
            '-C', str(int(self.opts.get('concurrency', 10))),
        ]
        if self.opts.get('skip_nsfw', True):
            cmd.append('--no-nsfw')
        if self.opts.get('allow_loud', False):
            cmd.append('--allow-loud')
        if self.opts.get('use_proxy', True):
            proxy = general_proxy_url(self.opts)
            if proxy:
                proxy_file = os.path.join(folder, "proxies.txt")
                with open(proxy_file, "w", encoding="utf-8") as fh:
                    fh.write(proxy + "\n")
                cmd.extend(['-P', proxy_file])
        return cmd

    @staticmethod
    def _parse_report(path: str) -> list[dict]:
        """The rows of a user-scanner JSON report whose status is Registered."""
        with open(path, encoding="utf-8") as fh:
            rows = json.load(fh)
        if isinstance(rows, dict):
            rows = rows.get("results") or rows.get("data") or []
        return [r for r in rows if isinstance(r, dict) and str(r.get("status", "")).lower() == "registered"
                and r.get("site_name")]

    def handleEvent(self, event: SpiderFootEvent) -> None:
        """Check the address and report the sites it is registered on."""
        if self.errorState:
            return

        if not self._person_scan():
            self.debug("Not acting: this scan is not about a person (option person_targets_only).")
            return

        email = str(event.data).strip()
        key = email.lower()
        if key in self.results:
            return
        self.results[key] = True

        if not _EMAIL.match(email):
            self.debug(f"Not checking '{email}': not a plain email address.")
            return
        if self._checked >= int(self.opts.get('max_emails', 5)):
            self.debug(f"Not checking '{email}': the limit of {self.opts.get('max_emails')} addresses is reached.")
            return
        if self.checkForStop():
            return

        binary = self._find_binary()
        if not binary:
            self.error("You enabled sfp_tool_user_scanner but the user-scanner binary was not found "
                       "(it is installed in the SpiderFoot active-scanner image).")
            self.errorState = True
            return

        self._checked += 1
        self.info(f"Checking which sites {email} is registered on with user-scanner...")
        with tempfile.TemporaryDirectory(prefix="sf_userscanner_") as workdir:
            output = os.path.join(workdir, "report.json")
            cmd = self._build_cmd(binary, email, output, workdir)
            env = {**os.environ, "HOME": workdir, "NO_COLOR": "1", "USER_SCANNER_CONFIG": self._write_settings(workdir)}
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, cwd=workdir, env=env,
                                      stdin=subprocess.DEVNULL, timeout=int(self.opts.get('run_timeout', 600)))
            except subprocess.TimeoutExpired:
                self.error(f"user-scanner timed out after {self.opts.get('run_timeout')}s checking {email}.")
                return
            except Exception as e:
                self.error(f"user-scanner could not be run: {e}")
                return

            if not os.path.isfile(output):
                tail = " ".join((proc.stderr or proc.stdout or "").split())[-200:]
                self.error(f"user-scanner produced no report for {email} (exit {proc.returncode}): {tail}")
                return
            try:
                registered = self._parse_report(output)
            except Exception as e:
                self.error(f"Could not read user-scanner's report for {email}: {type(e).__name__}: {e}")
                return

        self.info(f"{email} is registered on {len(registered)} site(s).")
        for row in registered:
            if self.checkForStop():
                return
            extra = row.get("extra") or {}
            category = str(row.get("category") or "unknown").replace("_", " ").lower()
            url = str(extra.get("profile_url") or row.get("url") or "")
            text = f"{row['site_name']} (Category: {category})" + (f"\n<SFURL>{url}</SFURL>" if url else "")
            self.notifyListeners(SpiderFootEvent("ACCOUNT_EXTERNAL_OWNED", text, self.__name__, event))

            # A site that confirms the address is registered and also says which username it belongs to is a
            # direct link between the two
            username = str(extra.get("username") or "").strip()
            if username and _USERNAME.match(username):
                self.notifyListeners(SpiderFootEvent("USERNAME", username, self.__name__, event))

            details = {k: v for k, v in extra.items() if v not in (None, "", [], {})}
            if details:
                raw = json.dumps({"tool": "user-scanner", "site": row["site_name"], "url": url, "details": details},
                                 indent=2, default=str)
                self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", raw, self.__name__, event))

# End of sfp_tool_user_scanner class

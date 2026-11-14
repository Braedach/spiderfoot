from __future__ import annotations

"""SpiderFoot plug-in module: tool_maigret."""

# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_maigret
# Purpose:      Look a username up on thousands of sites with Maigret and report the profiles it finds.
#               Tool: https://github.com/soxoj/maigret (MIT)
#
# Created:      14/11/2026
# Licence:      MIT
# -------------------------------------------------------------------------------

import glob
import json
import os
import re
import subprocess
import tempfile
from shutil import which

from spiderfoot import SpiderFootEvent
from spiderfoot.plugins.async_plugin import SpiderFootAsyncPlugin
from spiderfoot.sflib.proxy import general_proxy_url

# A username Maigret may be given: letters, digits, dot, underscore, hyphen; never a leading hyphen, so it cannot be
# read as an option.
_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
_COUNTRY_TAG = re.compile(r"^[a-z]{2}$")


class sfp_tool_maigret(SpiderFootAsyncPlugin):

    """Check a username on thousands of sites with Maigret and report the accounts it finds."""

    meta = {
        'name': "Tool - Maigret",
        'summary': "Look a username up on up to 5,900 sites with Maigret and report the profiles that exist, with the details those profiles publish.",
        'flags': ["tool", "slow"],
        'useCases': ["Investigate"],
        'categories': ["Social Media"],
        'toolDetails': {
            'name': "Maigret",
            'description': "Collects a dossier on a person by username from thousands of sites, with false-positive "
            "detection and extraction of the details a profile page publishes.",
            'website': 'https://github.com/soxoj/maigret',
            'repository': 'https://github.com/soxoj/maigret',
        },
        'dataSource': {
            'website': "https://github.com/soxoj/maigret",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': ["https://github.com/soxoj/maigret"],
            'description': "Maigret checks each site's own public profile URL for the username.",
        },
    }

    # Default options
    opts = {
        'maigretpath': "",
        'top_sites': 500,
        'timeout': 15,
        'max_connections': 25,
        'exclude_tags': "porn,erotic,webcam",
        'min_length': 4,
        'max_usernames': 10,
        'run_timeout': 900,
        'skip_similar': True,
        'use_proxy': True,
        'person_targets_only': True,
    }

    # Option descriptions
    optdescs = {
        'maigretpath': "Path to the maigret binary. Blank searches PATH.",
        'top_sites': "How many of the most popular sites to check (500 takes about a minute; the full list is about 5,900).",
        'timeout': "Seconds to wait for each site.",
        'max_connections': "How many sites to contact at once.",
        'exclude_tags': "Comma-separated site tags to leave out (adult sites by default).",
        'min_length': "Shortest username to look up. Short names match many unrelated people.",
        'max_usernames': "Most usernames to look up in one scan.",
        'run_timeout': "Seconds to allow one username's search before giving up on it.",
        'skip_similar': "Leave out matches Maigret itself marks as only similar to the username.",
        'person_targets_only': "Only act when the scan is about a person (a name, email address, username or phone number). Off = also look up every usernames discovered during other scans, such as staff addresses found on a company's website, which sends those people's details to hundreds of sites.",
        'use_proxy': "Send the searches through the general outbound proxy (Settings > Network & Proxy) when one is set.",
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
        self._searched = 0
        self.__dataSource__ = "Social media and other public profile pages"

    def watchedEvents(self) -> list:
        """Return the list of events this module watches."""
        return ["USERNAME"]

    def producedEvents(self) -> list:
        """Return the list of events this module produces."""
        return ["ACCOUNT_EXTERNAL_OWNED", "RAW_RIR_DATA"]

    def _person_scan(self) -> bool:
        """True when this module may act: the scan is about a person, or the user turned the restriction off."""
        if not self.opts.get('person_targets_only', True):
            return True
        try:
            return self.getTarget().targetType in self.PERSON_TARGETS
        except Exception:
            return False

    def _find_binary(self) -> str | None:
        custom = str(self.opts.get('maigretpath') or '').strip()
        if custom and os.path.isfile(custom):
            return custom
        return which('maigret')

    def _build_cmd(self, binary: str, username: str, folder: str) -> list[str]:
        """The Maigret command line.

        --no-autoupdate keeps it from downloading a newer site list from GitHub (the image's list is the reviewed
        one), --no-recursion keeps it from searching the usernames it finds on other people's profiles, and the AI
        report option is never used (it would send findings to a third-party service).
        """
        cmd = [
            binary, username,
            '--no-autoupdate', '--no-recursion', '--no-progressbar', '--no-color',
            '--timeout', str(int(self.opts.get('timeout', 15))),
            '--max-connections', str(int(self.opts.get('max_connections', 25))),
            '--retries', '0',
            '--top-sites', str(int(self.opts.get('top_sites', 500))),
            '--json', 'simple',
            '--folderoutput', folder,
        ]
        exclude = str(self.opts.get('exclude_tags') or '').strip()
        if exclude:
            cmd.extend(['--exclude-tags', exclude])
        if self.opts.get('use_proxy', True):
            proxy = general_proxy_url(self.opts)
            if proxy:
                cmd.extend(['--proxy', proxy])
        return cmd

    @staticmethod
    def _category(tags: list) -> str:
        """The site's topic tags, without country codes."""
        topics = [str(t) for t in tags if not _COUNTRY_TAG.match(str(t)) and str(t) != "global"]
        return ", ".join(topics[:3]) or "unknown"

    def _parse_report(self, path: str) -> list[dict]:
        """The accounts a Maigret JSON report ("simple" type) says exist."""
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        found = []
        for site, entry in (data or {}).items():
            if not isinstance(entry, dict):
                continue
            status = entry.get("status") or {}
            if str(status.get("status", "")).lower() != "claimed":
                continue
            if self.opts.get('skip_similar', True) and entry.get("is_similar"):
                continue
            url = status.get("url") or entry.get("url_user")
            if not url:
                continue
            found.append({"site": str(site), "url": str(url), "tags": status.get("tags") or [],
                          "ids": status.get("ids") or {}})
        return found

    def handleEvent(self, event: SpiderFootEvent) -> None:
        """Look the username up and report the profiles Maigret finds."""
        if self.errorState:
            return

        if not self._person_scan():
            self.debug("Not acting: this scan is not about a person (option person_targets_only).")
            return

        username = str(event.data).strip().strip('"').strip()
        key = username.lower()
        if key in self.results:
            return
        self.results[key] = True

        if len(username) < int(self.opts.get('min_length', 4)) or not _USERNAME.match(username):
            self.debug(f"Not looking up '{username}': too short or not a plain username.")
            return
        if self._searched >= int(self.opts.get('max_usernames', 10)):
            self.debug(f"Not looking up '{username}': the limit of {self.opts.get('max_usernames')} usernames is reached.")
            return
        if self.checkForStop():
            return

        binary = self._find_binary()
        if not binary:
            self.error("You enabled sfp_tool_maigret but the maigret binary was not found "
                       "(it is installed in the SpiderFoot active-scanner image).")
            self.errorState = True
            return

        self._searched += 1
        self.info(f"Looking up the username '{username}' with Maigret...")
        with tempfile.TemporaryDirectory(prefix="sf_maigret_") as workdir:
            cmd = self._build_cmd(binary, username, workdir)
            env = {**os.environ, "HOME": workdir, "NO_COLOR": "1"}
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, cwd=workdir, env=env,
                                      stdin=subprocess.DEVNULL, timeout=int(self.opts.get('run_timeout', 900)))
            except subprocess.TimeoutExpired:
                self.error(f"Maigret timed out after {self.opts.get('run_timeout')}s looking up '{username}'.")
                return
            except Exception as e:
                self.error(f"Maigret could not be run: {e}")
                return

            reports = glob.glob(os.path.join(workdir, "report_*_simple.json"))
            if not reports:
                tail = " ".join((proc.stderr or proc.stdout or "").split())[-200:]
                self.error(f"Maigret produced no report for '{username}' (exit {proc.returncode}): {tail}")
                return
            try:
                accounts = self._parse_report(reports[0])
            except Exception as e:
                self.error(f"Could not read Maigret's report for '{username}': {type(e).__name__}: {e}")
                return

        self.info(f"Maigret found {len(accounts)} account(s) for '{username}'.")
        for account in accounts:
            if self.checkForStop():
                return
            text = f"{account['site']} (Category: {self._category(account['tags'])})\n<SFURL>{account['url']}</SFURL>"
            self.notifyListeners(SpiderFootEvent("ACCOUNT_EXTERNAL_OWNED", text, self.__name__, event))
            if account["ids"]:
                raw = json.dumps({"tool": "maigret", "site": account["site"], "url": account["url"],
                                  "details": account["ids"]}, indent=2, default=str)
                self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", raw, self.__name__, event))

# End of sfp_tool_maigret class

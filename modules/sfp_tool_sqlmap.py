"""SpiderFoot module: sqlmap - SQL injection detection.

Runs sqlmap against a URL that has query parameters and reports the injection points it confirms.

DETECTION ONLY. The command line is built here from a fixed list, never from event data or free-form options:
  * risk is always 1 (risk 2 and 3 add heavy and potentially data-changing payloads) and level is capped at 3;
  * stacked queries are never used (that technique can run statements on the database);
  * nothing is extracted: no --dump, --dbs, --passwords, --os-*, --file-* or --sql-* option is ever passed.
It is only meant for the authorised web application test profile, where the scope guard keeps it on the target.

Requires: sqlmap (a pinned release is installed in the active-scanner image at /tools/sqlmap).

Licence note: sqlmap is GPLv2-or-later with extra terms that treat a program which runs sqlmap and parses its output as
a derived work. This module does exactly that, so this file is made available under GPL-2.0-or-later (SPDX below),
not under the MIT licence of the rest of SpiderFoot.
"""

# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

from spiderfoot import SpiderFootEvent
from spiderfoot.plugins.async_plugin import SpiderFootAsyncPlugin
from spiderfoot.url_targets import endpoint_key
from spiderfoot import auth_headers

DEFAULT_SQLMAP = "/tools/sqlmap/sqlmap.py"
# boolean-blind, error-based, UNION and time-based. Stacked queries ("S") are deliberately not offered.
ALLOWED_TECHNIQUES = "BEUT"
MAX_LEVEL = 3
MAX_EVIDENCE_CHARS = 600

_PARAM_RE = re.compile(r"^Parameter: (?P<param>.+?) \((?P<place>[^)]+)\)\s*$")
_TYPE_RE = re.compile(r"^\s+Type: (?P<v>.+)$")
_TITLE_RE = re.compile(r"^\s+Title: (?P<v>.+)$")
_DBMS_RE = re.compile(r"^back-end DBMS: (?P<v>.+)$", re.MULTILINE)


class sfp_tool_sqlmap(SpiderFootAsyncPlugin):
    """SQL injection detection via sqlmap (detection only)."""

    meta = {
        "name": "Tool - sqlmap",
        "summary": "Detect SQL injection in web parameters (detection only: nothing is extracted).",
        "flags": ["tool", "slow", "invasive"],
        "useCases": ["Investigate"],
        "categories": ["Crawling and Scanning"],
        "toolDetails": {
            "binaryName": "sqlmap.py",
            "installUrl": "https://github.com/sqlmapproject/sqlmap",
        },
        "dataSource": {
            "website": "https://sqlmap.org",
            "model": "FREE_NOAUTH_UNLIMITED",
            "references": ["https://github.com/sqlmapproject/sqlmap"],
            "description": "Automatic SQL injection detection tool.",
        },
    }

    _runs = 0  # runs started so far this scan (reset in setup); the cap counts these, not URLs seen

    opts = {
        "sqlmap_path": "",
        "timeout": 300,
        "max_targets": 10,
        "level": 1,
        "techniques": ALLOWED_TECHNIQUES,
        "request_timeout": 15,
    }

    optdescs = {
        "sqlmap_path": "Path to sqlmap.py. Leave blank to use the copy in the image (/tools/sqlmap/sqlmap.py).",
        "timeout": "Seconds one target may take before it is stopped.",
        "max_targets": "Maximum number of endpoints to test per scan.",
        "level": "Detection level, 1 to 3 (higher tests more places and sends more requests). Risk is fixed at 1.",
        "techniques": "Techniques to use, any of B (boolean), E (error), U (union), T (time). Stacked queries are never used.",
        "request_timeout": "Seconds to wait for each HTTP response.",
    }

    results = None

    def setup(self, sfc, userOpts=None):
        super().setup(sfc, userOpts or {})
        self.errorState = False
        self.results = self.tempStorage()
        self._runs = 0

    def watchedEvents(self):
        return ["URL_FORM", "LINKED_URL_INTERNAL"]

    def producedEvents(self):
        return ["VULNERABILITY_CVE_CRITICAL", "RAW_RIR_DATA"]

    # -- helpers ---------------------------------------------------------------------------------------------------

    def _find_binary(self):
        custom = self.opts.get("sqlmap_path", "")
        for candidate in (custom, DEFAULT_SQLMAP):
            if candidate and os.path.isfile(candidate):
                return candidate
        return None

    @staticmethod
    def _testable(url):
        """An http(s) URL with at least one named parameter."""
        try:
            parts = urlsplit(url)
        except ValueError:
            return False
        return parts.scheme in ("http", "https") and bool(parts.netloc) and "=" in parts.query

    def _techniques(self):
        asked = str(self.opts.get("techniques") or ALLOWED_TECHNIQUES).upper()
        kept = "".join(c for c in ALLOWED_TECHNIQUES if c in asked)
        return kept or ALLOWED_TECHNIQUES

    def _level(self):
        try:
            level = int(self.opts.get("level", 1))
        except (TypeError, ValueError):
            level = 1
        return max(1, min(level, MAX_LEVEL))

    def _command(self, binary, url, outdir):
        # A fixed argument list; `url` is only ever the value of -u. No shell is involved.
        cmd = [
            sys.executable, binary,
            "-u", url,
            "--batch",
            "--level", str(self._level()),
            "--risk", "1",                                   # never above 1, whatever the options say
            "--technique", self._techniques(),
            "--threads", "1",
            "--timeout", str(int(self.opts.get("request_timeout", 15))),
            "--retries", "1",
            "--disable-coloring",
            "--flush-session",
            "--output-dir", outdir,
        ]
        if auth_headers.from_opts(self.opts):
            cmd.extend(["--headers", auth_headers.joined(self.opts)])   # authenticated test; never logged
        return cmd

    @staticmethod
    def parse(output):
        """Return ([{param, place, techniques: [(type, title)]}], dbms or None) from sqlmap's text output.

        The result block sits between two ``---`` lines after "sqlmap identified the following injection point(s)".
        """
        findings = []
        current = None
        pending_type = None
        started = False      # saw the header line
        opened = False       # saw the opening ---
        for raw in output.splitlines():
            line = raw.rstrip()
            if not started:
                started = line.startswith("sqlmap identified the following injection point")
                continue
            if line.strip() == "---":
                if not opened:
                    opened = True
                    continue
                break        # the closing marker ends the block
            m = _PARAM_RE.match(line)
            if m:
                current = {"param": m.group("param"), "place": m.group("place"), "techniques": []}
                findings.append(current)
                pending_type = None
                continue
            if current is None:
                continue
            m = _TYPE_RE.match(line)
            if m:
                pending_type = m.group("v").strip()
                continue
            m = _TITLE_RE.match(line)
            if m and pending_type is not None:
                current["techniques"].append((pending_type, m.group("v").strip()))
                pending_type = None
        dbms = _DBMS_RE.search(output)
        return findings, (dbms.group("v").strip() if dbms else None)

    # -- event handling --------------------------------------------------------------------------------------------

    def handleEvent(self, event):
        url = event.data
        if self.errorState:
            return
        if not self._testable(url):
            return
        key = endpoint_key(url, with_param_names=True)
        if key is None or key in self.results:
            return
        self.results[key] = True
        if self._runs >= self.opts["max_targets"]:
            return
        self._runs += 1

        binary = self._find_binary()
        if not binary:
            self.error("sqlmap not found. It is installed at /tools/sqlmap in the active-scanner image.")
            self.errorState = True
            return

        with tempfile.TemporaryDirectory(prefix="sf-sqlmap-") as outdir:
            try:
                proc = subprocess.run(
                    self._command(binary, url, outdir), capture_output=True, text=True,
                    timeout=int(self.opts["timeout"]) + 30,
                )
            except subprocess.TimeoutExpired:
                self.error(f"sqlmap timed out for {url}")
                return
            except Exception as e:  # noqa: BLE001 - report and go on with the scan
                self.error(f"sqlmap error: {e}")
                return

        output = proc.stdout or ""
        findings, dbms = self.parse(output)
        if not findings:
            self.info(f"sqlmap found no SQL injection in {url}")
            return

        for f in findings:
            if self.checkForStop():
                return
            kinds = "; ".join(f"{t} ({title})" for t, title in f["techniques"]) or "injectable"
            text = f"SQL injection in {f['place']} parameter '{f['param']}' at {url}\nTechniques: {kinds}"
            if dbms:
                text += f"\nBack-end DBMS: {dbms}"
            self.notifyListeners(SpiderFootEvent("VULNERABILITY_CVE_CRITICAL", text, self.__name__, event))
            self.notifyListeners(SpiderFootEvent(
                "RAW_RIR_DATA", f"sqlmap: {text}"[:MAX_EVIDENCE_CHARS], self.__name__, event))
        self.info(f"sqlmap confirmed {len(findings)} injectable parameter(s) in {url}")

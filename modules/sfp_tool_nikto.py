"""SpiderFoot module: nikto - Web server vulnerability scanner.

Integrates Nikto for comprehensive web server scanning to detect
misconfigurations, outdated software, and known vulnerabilities.

Requires: nikto in PATH (apt install nikto).
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import time

from spiderfoot.plugins.async_plugin import SpiderFootAsyncPlugin
from spiderfoot import SpiderFootEvent
from spiderfoot.url_targets import host_key


class sfp_tool_nikto(SpiderFootAsyncPlugin):
    """Web server vulnerability scanning via Nikto."""

    meta = {
        "name": "Tool - Nikto",
        "summary": "Web server vulnerability scanner for misconfigurations and CVEs.",
        "flags": ["tool", "slow", "invasive"],
        "useCases": ["Investigate", "Footprint"],
        "categories": ["Crawling and Scanning"],
        "toolDetails": {
            "binaryName": "nikto",
            "installUrl": "https://github.com/sullo/nikto",
        },
        "dataSource": {
            "website": "https://github.com/sullo/nikto",
            "model": "FREE_NOAUTH_UNLIMITED",
            "references": ["https://github.com/sullo/nikto"],
            "description": "Web server vulnerability scanner.",
        },
    }

    _catchall = None   # per-scan baseline of how each server answers a path that cannot exist
    _runs = 0  # runs started so far this scan (reset in setup); the cap counts these, not URLs seen
    _spent = 0.0  # seconds of nikto time used so far this scan (reset in setup)
    _skipped = ()  # servers not tested because the limit or budget was spent (a list, set in setup)

    opts = {
        "nikto_path": "",
        "timeout": 300,
        "request_timeout": 10,
        "total_budget": 7200,
        "tuning": "",
        "max_targets": 0,
        "port": "",
        "ssl": False,
        "no_ssl": False,
        "plugins": "",
        "catchall_filter": True,
    }

    optdescs = {
        "nikto_path": "Path to nikto. Leave blank to use PATH.",
        "timeout": "Longest nikto may spend on one web server, in seconds (passed to nikto as -maxtime).",
        "request_timeout": "How long nikto waits for one answer from a server, in seconds. Keep this short: a server that never "
                           "answers should cost seconds, not the whole per-server allowance.",
        "total_budget": "Most nikto time to spend on one scan, in seconds (0 = no limit). Servers are tested in the order the scan "
                        "finds them; once the budget is used up the rest are skipped and the scan log lists them.",
        "tuning": "Nikto tuning options (e.g. '1234' for test types, blank=all).",
        "max_targets": "Most web servers to test in one scan (0 = every server the scan finds). Leave at 0: a count limit "
                       "silently drops whichever servers the scan happens to find last, so a repeat scan tests different ones.",
        "port": "Specific port to scan (blank=default 80/443).",
        "ssl": "Force SSL mode.",
        "no_ssl": "Disable SSL.",
        "plugins": "Specific Nikto plugins to run (comma-separated, blank=all).",
        "catchall_filter": "Drop a finding about a path when the server answers that path exactly as it answers a path "
                           "that cannot exist (a catch-all or single-page app). Without this, Nikto reports files such "
                           "as /.htpasswd as exposed on any server that answers every path with 200.",
    }

    results = None

    def setup(self, sfc, userOpts=None):
        super().setup(sfc, userOpts or {})
        self.errorState = False
        self.results = self.tempStorage()
        self._runs = 0
        self._spent = 0.0
        self._skipped = []
        self._catchall = None

    def watchedEvents(self):
        return ["DOMAIN_NAME", "IP_ADDRESS", "LINKED_URL_INTERNAL"]

    def producedEvents(self):
        return [
            "VULNERABILITY_GENERAL",
            "VULNERABILITY_CVE_HIGH",
            "VULNERABILITY_CVE_MEDIUM",
            "VULNERABILITY_CVE_LOW",
            "WEBSERVER_BANNER",
            "WEBSERVER_TECHNOLOGY",
            "INTERESTING_FILE",
            "RAW_RIR_DATA",
        ]

    def _find_binary(self):
        custom = self.opts.get("nikto_path", "")
        if custom and os.path.isfile(custom):
            return custom
        for p in os.environ.get("PATH", "").split(os.pathsep):
            for name in ("nikto", "nikto.pl"):
                candidate = os.path.join(p, name)
                if os.path.isfile(candidate):
                    return candidate
        return None

    def _is_catch_all_hit(self, target: str, uri: str) -> bool:
        """True when ``target``+``uri`` is answered like a path that cannot exist. Never raises."""
        try:
            if not uri.startswith("/") or not target.startswith("http"):
                return False
            if self._catchall is None:
                from spiderfoot.sflib.catchall import CatchAllBaseline
                self._catchall = CatchAllBaseline(
                    lambda u: self.fetch_url(u, timeout=15, useragent=self.opts.get("_useragent", "SpiderFoot"),
                                             sizeLimit=4096))
            return self._catchall.is_catch_all(target.rstrip("/") + uri)
        except Exception:
            return False

    def _skip(self, target):
        """Record a server that was not tested. Said once when it starts, and summed up when the scan ends."""
        self._skipped = [*self._skipped, target]
        if len(self._skipped) == 1:
            self.error(f"nikto: not testing {target} or any server found after it: the run limit (max_targets "
                       f"{self.opts['max_targets']}) or the time budget (total_budget {self.opts['total_budget']} s, "
                       f"{int(self._spent)} s used) is spent. The full list is in the log when the scan ends.")

    def finished(self):
        if self._skipped:
            self.error(f"nikto did not test {len(self._skipped)} web server(s): " + ", ".join(self._skipped[:50])
                       + (" ..." if len(self._skipped) > 50 else ""))
        super().finished()

    def handleEvent(self, event):
        data = event.data
        if self.errorState:
            return
        # nikto scans a whole web server, so run it once per server rather than once per page
        if data.startswith("http"):
            target = host_key(data)
            if target is None:
                return
            key = target
        else:
            target = data
            key = f"http://{data.lower()}"
        if key in self.results:
            return
        self.results[key] = True
        limit = int(self.opts["max_targets"] or 0)
        budget = float(self.opts["total_budget"] or 0)
        if (limit and self._runs >= limit) or (budget and self._spent >= budget):
            self._skip(target)
            return
        self._runs += 1

        binary = self._find_binary()
        if not binary:
            self.error("nikto not found. Install with: apt install nikto")
            self.errorState = True
            return

        output_path = tempfile.mktemp(suffix=".csv")

        cmd = [binary, "-h", target, "-o", output_path, "-Format", "csv", "-nointeractive"]

        if self.opts["port"]:
            cmd.extend(["-p", self.opts["port"]])
        if self.opts["ssl"]:
            cmd.append("-ssl")
        if self.opts["no_ssl"]:
            cmd.append("-nossl")
        if self.opts["tuning"]:
            cmd.extend(["-Tuning", self.opts["tuning"]])
        if self.opts["plugins"]:
            cmd.extend(["-Plugins", self.opts["plugins"]])
        cmd.extend(["-timeout", str(self.opts["request_timeout"]), "-maxtime", f"{int(self.opts['timeout'])}s"])

        cve_re = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)

        started = time.monotonic()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.opts["timeout"] + 60,
            )

            # Parse CSV output
            vuln_count = 0
            dropped = 0
            if os.path.exists(output_path):
                with open(output_path, "r") as f:
                    for line in f:
                        if self.checkForStop():
                            return
                        line = line.strip()
                        if not line or line.startswith('"Nikto') or line.startswith('"Host'):
                            continue

                        # CSV: "host","ip","port","ref","method","uri","description"
                        parts = line.replace('"', '').split(',', 6)
                        if len(parts) < 7:
                            continue

                        ref = parts[3].strip()
                        uri = parts[5].strip()
                        description = parts[6].strip()

                        if not description:
                            continue
                        vuln_count += 1

                        # Check for CVE references
                        cve_matches = cve_re.findall(description)

                        finding = f"{target}{uri}: {description}"

                        if self.opts["catchall_filter"] and self._is_catch_all_hit(target, uri):
                            dropped += 1
                            continue

                        if cve_matches:
                            evt = SpiderFootEvent(
                                "VULNERABILITY_CVE_MEDIUM", finding, self.__name__, event
                            )
                        elif any(x in description.lower() for x in ("vuln", "exploit", "injection", "xss", "rce")):
                            evt = SpiderFootEvent(
                                "VULNERABILITY_GENERAL", finding, self.__name__, event
                            )
                        elif any(x in description.lower() for x in ("interesting", "backup", "config", "admin")):
                            evt = SpiderFootEvent(
                                "INTERESTING_FILE", finding, self.__name__, event
                            )
                        else:
                            evt = SpiderFootEvent(
                                "VULNERABILITY_GENERAL", finding, self.__name__, event
                            )
                        self.notifyListeners(evt)

            # Also parse stdout for server info
            for line in (proc.stdout or "").splitlines():
                if "+ Server:" in line:
                    server = line.split("+ Server:", 1)[1].strip()
                    evt = SpiderFootEvent(
                        "WEBSERVER_BANNER", f"{target}: {server}", self.__name__, event
                    )
                    self.notifyListeners(evt)

            if dropped:
                self.info(f"nikto: dropped {dropped} finding(s) for {target} because the server answers those paths "
                          "exactly as it answers a path that cannot exist (a catch-all, not exposed files).")
            self.info(f"nikto found {vuln_count - dropped} findings for {target}")

        except subprocess.TimeoutExpired:
            self.error(f"nikto timed out for {target}")
        except Exception as e:
            self.error(f"nikto error: {e}")
        finally:
            self._spent += time.monotonic() - started
            try:
                os.unlink(output_path)
            except OSError:
                pass

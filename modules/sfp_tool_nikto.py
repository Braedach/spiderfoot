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
import threading
import time
from urllib.parse import urlsplit

from spiderfoot.plugins.async_plugin import SpiderFootAsyncPlugin
from spiderfoot import SpiderFootEvent


# A plain-http address on one of these ports is a TLS service (a scan finds "http://host:443" when a crawler or a banner
# gives the port but not the scheme). nikto speaking plain http to it waits out the whole per-server allowance.
TLS_PORTS = frozenset({443, 4443, 8443, 9443})
SOFT_BUDGET = 0.7   # past this share of total_budget every new run is shortened, so later servers still get tested
HARD_BUDGET = 1.5   # past this share nothing new starts and the servers left are listed
SHORT_RUN = 90      # seconds a run may take once the soft share is passed


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
    _reported = 0  # how many of _skipped finish() has already put in the log
    _done = 0  # runs finished this scan (for the progress line)
    _lock = threading.Lock()  # handleEvent runs in a thread pool: the counters and the seen-set need it (replaced in setup)

    opts = {
        "nikto_path": "",
        "timeout": 300,
        "request_timeout": 10,
        "total_budget": 0,
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
        "total_budget": "Nikto time to spend on one scan, in seconds (0 = no limit, the default: each server is already bounded by timeout). Past 70% of it every run is cut to 90 s so later "
                        "servers are still tested; past 150% nothing new starts and the scan log lists the servers left out.",
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
        self._reported = 0
        self._done = 0
        self._lock = threading.Lock()
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

    @staticmethod
    def _server(data):
        """(key, target) for the web server an event names, or None. One key per scheme, host and port.

        A plain-http address on a TLS port is the https server (see TLS_PORTS), and a default port is left out, so
        ``http://h:443``, ``https://h:443`` and ``https://h`` are one server, tested once.
        """
        if "://" not in data:
            return f"http://{data.lower()}", data      # a bare name or address (DOMAIN_NAME, IP_ADDRESS)
        try:
            parts = urlsplit(data.strip())
            port = parts.port
        except ValueError:
            return None
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return None
        scheme = "https" if parts.scheme == "http" and port in TLS_PORTS else parts.scheme
        host = parts.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        default = 443 if scheme == "https" else 80
        url = f"{scheme}://{host}" + (f":{port}" if port and port != default else "")
        return url, url

    def _allowance(self):
        """Seconds the next run may take, or None when nothing more may start (call with the lock held)."""
        limit = int(self.opts["max_targets"] or 0)
        if limit and self._runs >= limit:
            return None
        full = float(self.opts["timeout"])
        budget = float(self.opts["total_budget"] or 0)
        if not budget:
            return full
        if self._spent >= budget * HARD_BUDGET:
            return None
        if self._spent >= budget * SOFT_BUDGET:
            return min(full, SHORT_RUN)
        return full

    def _skip(self, target):
        """Record a server that was not tested, and say so now (the first as an error, the rest as notes)."""
        self._skipped = [*self._skipped, target]
        if len(self._skipped) == 1:
            self.error(f"nikto: not testing {target} or any server found after it: the run limit (max_targets "
                       f"{self.opts['max_targets']}) or the time budget (total_budget {self.opts['total_budget']} s, "
                       f"{int(self._spent)} s used) is spent. The full list is in the log when the scan ends.")
        else:
            self.info(f"nikto: not testing {target} (limit or time budget spent)")

    def progress_text(self):
        """One line for the scan's progress panel."""
        seen = len(self.results or {})
        return f"{self._done} of {seen} servers tested so far" if seen else ""

    def finish(self):
        """Called when the scan wraps up (possibly more than once): list the servers that were left untested."""
        with self._lock:
            new = list(self._skipped)[self._reported:]
            self._reported = len(self._skipped)
        if new:
            self.error(f"nikto did not test {len(new)} web server(s): " + ", ".join(new[:50])
                       + (" ..." if len(new) > 50 else ""))
        super().finish()

    def handleEvent(self, event):
        data = event.data
        if self.errorState:
            return
        # nikto scans a whole web server, so run it once per server rather than once per page
        server = self._server(data)
        if server is None:
            return
        key, target = server
        with self._lock:
            if key in self.results:
                return
            self.results[key] = True
            maxtime = self._allowance()
            if maxtime is None:
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
        cmd.extend(["-timeout", str(self.opts["request_timeout"]), "-maxtime", f"{int(maxtime)}s"])

        cve_re = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)

        started = time.monotonic()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=maxtime + 60,
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
            with self._lock:
                self._spent += time.monotonic() - started
                self._done += 1
            try:
                os.unlink(output_path)
            except OSError:
                pass

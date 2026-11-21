"""SpiderFoot module: naabu - Fast port scanner.

Integrates ProjectDiscovery's Naabu for high-speed SYN/CONNECT port
scanning to discover open TCP ports on targets.

Requires: naabu in PATH (go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest).
Note: SYN scanning requires NET_RAW capability (setcap cap_net_raw+ep).
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
import time

from spiderfoot.plugins.async_plugin import SpiderFootAsyncPlugin
from spiderfoot import SpiderFootEvent


class sfp_tool_naabu(SpiderFootAsyncPlugin):
    """Fast port scanning via Naabu."""

    meta = {
        "name": "Tool - Naabu",
        "summary": "High-speed port scanner for discovering open TCP ports.",
        "flags": ["tool", "invasive"],
        "useCases": ["Investigate", "Footprint"],
        "categories": ["Crawling and Scanning"],
        "toolDetails": {
            "binaryName": "naabu",
            "installUrl": "https://github.com/projectdiscovery/naabu",
        },
        "dataSource": {
            "website": "https://github.com/projectdiscovery/naabu",
            "model": "FREE_NOAUTH_UNLIMITED",
            "references": ["https://github.com/projectdiscovery/naabu"],
            "description": "High-speed port scanner by ProjectDiscovery.",
        },
    }

    opts = {
        "naabu_path": "",
        "timeout": 300,
        "total_budget": 3600,
        "max_targets": 0,
        "ports": "top-100",
        "rate": 1000,
        "retries": 3,
        "scan_type": "s",
        "exclude_ports": "",
        "warm_up_time": 2,
    }

    optdescs = {
        "naabu_path": "Path to naabu. Leave blank to use PATH.",
        "timeout": "Longest naabu may spend on one host, in seconds.",
        "total_budget": "Most naabu time to spend on one scan, in seconds (0 = no limit). Hosts are scanned in the order the scan "
                        "finds them; once the budget is used up the rest are skipped and the scan log lists them.",
        "max_targets": "Most hosts to scan in one scan (0 = every host the scan finds). Leave at 0: a count limit silently drops "
                       "whichever hosts the scan finds last, so a repeat scan checks different ones.",
        "ports": "Ports to scan: 'top-100', 'top-1000', 'full', or custom like '80,443,8080' or '1-1000'.",
        "rate": "Packets per second rate limit.",
        "retries": "Number of retries for port verification.",
        "scan_type": "Scan type: 's' for SYN scan, 'c' for CONNECT scan.",
        "exclude_ports": "Ports to exclude (comma-separated).",
        "warm_up_time": "Warm-up time in seconds before scanning.",
    }

    results = None
    _runs = 0
    _spent = 0.0  # seconds of naabu time used so far this scan (reset in setup)
    _skipped = ()  # hosts not scanned because the limit or budget was spent (a list, set in setup)
    _reported = 0  # how many of _skipped finish() has already put in the log
    _lock = threading.Lock()  # handleEvent runs in a thread pool: counters and the seen-set need it (replaced in setup)

    def setup(self, sfc, userOpts=None):
        super().setup(sfc, userOpts or {})
        self.errorState = False
        self.results = self.tempStorage()
        self._runs = 0
        self._spent = 0.0
        self._skipped = []
        self._reported = 0
        self._lock = threading.Lock()

    def watchedEvents(self):
        return ["IP_ADDRESS", "INTERNET_NAME", "DOMAIN_NAME"]

    def producedEvents(self):
        return ["TCP_PORT_OPEN"]

    def _find_binary(self):
        custom = self.opts.get("naabu_path", "")
        if custom and os.path.isfile(custom):
            return custom
        for p in os.environ.get("PATH", "").split(os.pathsep):
            candidate = os.path.join(p, "naabu")
            if os.path.isfile(candidate):
                return candidate
        for fallback in ("/usr/local/bin/naabu", "/usr/bin/naabu"):
            if os.path.isfile(fallback):
                return fallback
        return None

    def _skip(self, target):
        """Record a host that was not scanned, and say so now (the first as an error, the rest as notes)."""
        self._skipped = [*self._skipped, target]
        if len(self._skipped) == 1:
            self.error(f"naabu: not scanning {target} or any host found after it: the run limit (max_targets "
                       f"{self.opts['max_targets']}) or the time budget (total_budget {self.opts['total_budget']} s, "
                       f"{int(self._spent)} s used) is spent. The full list is in the log when the scan ends.")
        else:
            self.info(f"naabu: not scanning {target} (limit or time budget spent)")

    def finish(self):
        """Called by the scanner when the scan wraps up (possibly more than once; the hook is finish, not finished)."""
        with self._lock:
            new = list(self._skipped)[self._reported:]
            self._reported = len(self._skipped)
        if new:
            self.error(f"naabu did not scan {len(new)} host(s): " + ", ".join(new[:50])
                       + (" ..." if len(new) > 50 else ""))
        super().finish()

    def handleEvent(self, event):
        data = event.data
        if self.errorState:
            return
        with self._lock:
            if data in self.results:
                return
            self.results[data] = True

            limit = int(self.opts["max_targets"] or 0)
            budget = float(self.opts["total_budget"] or 0)
            if (limit and self._runs >= limit) or (budget and self._spent >= budget):
                self._skip(data)
                return
            self._runs += 1

        binary = self._find_binary()
        if not binary:
            self.error("naabu not found. Install: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
            self.errorState = True
            return

        output_path = tempfile.mktemp(suffix=".json")

        cmd = [
            binary,
            "-host", data,
            "-json",
            "-o", output_path,
            "-rate", str(self.opts["rate"]),
            "-retries", str(self.opts["retries"]),
            "-warm-up-time", str(self.opts["warm_up_time"]),
            "-silent",
            # naabu's own bundled resolvers can't see internal-only names (a Docker/Podman
            # compose service, an internal corporate zone). -system-resolver falls back to
            # the container's /etc/resolv.conf when they fail, with no effect on a target
            # the bundled resolvers already handle. Found by a live scan against a compose
            # hostname reporting "no valid ipv4 or ipv6 targets were found".
            "-system-resolver",
        ]

        # Port specification
        ports = self.opts["ports"]
        if ports == "top-100":
            cmd.extend(["-top-ports", "100"])
        elif ports == "top-1000":
            cmd.extend(["-top-ports", "1000"])
        elif ports == "full":
            cmd.extend(["-p", "-"])
        else:
            cmd.extend(["-p", ports])

        # Scan type
        if self.opts["scan_type"] == "c":
            cmd.append("-scan-type")
            cmd.append("c")

        if self.opts["exclude_ports"]:
            cmd.extend(["-exclude-ports", self.opts["exclude_ports"]])

        started = time.monotonic()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.opts["timeout"],
            )

            port_count = 0
            if os.path.exists(output_path):
                with open(output_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            result = json.loads(line)
                        except json.JSONDecodeError:
                            # Plain text format: host:port
                            if ":" in line:
                                parts = line.rsplit(":", 1)
                                if len(parts) == 2 and parts[1].isdigit():
                                    port_str = f"{parts[0]}:{parts[1]}"
                                    evt = SpiderFootEvent(
                                        "TCP_PORT_OPEN", port_str, self.__name__, event
                                    )
                                    self.notifyListeners(evt)
                                    port_count += 1
                            continue

                        host = result.get("host", result.get("ip", data))
                        port = result.get("port", "")

                        if port:
                            port_str = f"{host}:{port}"
                            evt = SpiderFootEvent(
                                "TCP_PORT_OPEN", port_str, self.__name__, event
                            )
                            self.notifyListeners(evt)
                            port_count += 1

            self.info(f"naabu found {port_count} open ports on {data}")

        except subprocess.TimeoutExpired:
            self.error(f"naabu timed out for {data}")
        except Exception as e:
            self.error(f"naabu error: {e}")
        finally:
            with self._lock:
                self._spent += time.monotonic() - started
            try:
                os.unlink(output_path)
            except OSError:
                pass

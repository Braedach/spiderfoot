"""SpiderFoot module: httpx - HTTP probing and technology detection.

Integrates ProjectDiscovery's httpx for fast HTTP probing, technology
fingerprinting, and web server analysis of discovered hosts.

Requires: httpx binary in PATH or configured via httpx_path option.
Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import urllib.parse
from typing import Any

from spiderfoot.plugins.async_plugin import SpiderFootAsyncPlugin
from spiderfoot import SpiderFootEvent


class sfp_httpx(SpiderFootAsyncPlugin):
    """HTTP probing and technology detection via httpx."""

    meta = {
        "name": "Tool - httpx",
        "summary": "HTTP probing and technology detection using ProjectDiscovery httpx.",
        "flags": ["tool", "slow"],
        "useCases": ["Investigate", "Footprint", "Passive"],
        "categories": ["Content Analysis"],
        "toolDetails": {
            "binaryName": "httpx",
            "installUrl": "https://github.com/projectdiscovery/httpx",
        },
        "dataSource": {
            "website": "https://github.com/projectdiscovery/httpx",
            "model": "FREE_NOAUTH_UNLIMITED",
            "references": ["https://github.com/projectdiscovery/httpx"],
            "description": "Fast HTTP probing and technology detection tool by ProjectDiscovery.",
        },
    }

    opts = {
        "httpx_path": "",
        "threads": 25,
        "timeout": 10,
        "follow_redirects": True,
        "tech_detect": True,
        "status_code": True,
        "content_length": True,
        "title": True,
        "web_server": True,
        "cdn_check": True,
        "tls_grab": True,
        "method": "GET",
        "ports": "80,443,8080,8443",
        "rate_limit": 150,
        "max_hosts": 500,
    }

    optdescs = {
        "httpx_path": "Path to httpx binary. Leave blank to use PATH.",
        "threads": "Number of concurrent threads.",
        "timeout": "Timeout in seconds per request.",
        "follow_redirects": "Follow HTTP redirects.",
        "tech_detect": "Enable technology detection (Wappalyzer signatures).",
        "status_code": "Extract HTTP status codes.",
        "content_length": "Extract content length.",
        "title": "Extract page titles.",
        "web_server": "Extract web server headers.",
        "cdn_check": "Check if host is behind a CDN.",
        "tls_grab": "Grab TLS certificate information.",
        "method": "HTTP method to use.",
        "ports": "Ports to probe (comma-separated).",
        "rate_limit": "Maximum requests per second.",
        "max_hosts": "Maximum number of hosts to probe.",
    }

    results = None
    emitted = None

    def setup(self, sfc, userOpts=None):
        super().setup(sfc, userOpts or {})
        self.errorState = False
        self.results = self.tempStorage()
        # (event type, data) already reported in this scan. A web server's banner, technology and
        # open port are facts about the host, not about each page: report each once.
        self.emitted = self.tempStorage()

    @staticmethod
    def _origin(url: str) -> str | None:
        """``scheme://host[:port]`` of a URL, or None when it is not an http(s) URL."""
        try:
            parts = urllib.parse.urlsplit(url)
        except ValueError:
            return None
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return None
        host = parts.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        default = 443 if parts.scheme == "https" else 80
        try:
            port = parts.port or default
        except ValueError:
            return None
        return f"{parts.scheme}://{host}" if port == default else f"{parts.scheme}://{host}:{port}"

    def _emit(self, event_type: str, data: str, parent_event: Any) -> None:
        """Report an event once per scan, however many probes return the same fact."""
        key = f"{event_type}\x00{data}"
        if key in self.emitted:
            return
        self.emitted[key] = True
        self.notifyListeners(SpiderFootEvent(event_type, data, self.__name__, parent_event))

    def watchedEvents(self):
        return [
            "INTERNET_NAME",
            "DOMAIN_NAME",
            "IP_ADDRESS",
            "LINKED_URL_INTERNAL",
            # A port a scanner (naabu, masscan...) actually found open. Probed on that
            # exact port regardless of the fixed "ports" option below - otherwise a web
            # app on anything other than 80/443/8080/8443 (found live: OWASP Juice Shop
            # on 3000) is invisible to every tool downstream of httpx.
            "TCP_PORT_OPEN",
        ]

    def producedEvents(self):
        return [
            "WEBSERVER_BANNER",
            "WEBSERVER_HTTPHEADERS",
            "WEBSERVER_TECHNOLOGY",
            "HTTP_CODE",
            "RAW_RIR_DATA",
            "URL_WEB",
            "TCP_PORT_OPEN",
            "LINKED_URL_INTERNAL",
            "SSL_CERTIFICATE_RAW",
            "CDN_DETECTED",
        ]

    def _find_httpx(self) -> str | None:
        """Find the httpx binary."""
        custom = self.opts.get("httpx_path", "")
        if custom and os.path.isfile(custom):
            return custom

        # Try PATH
        for p in os.environ.get("PATH", "").split(os.pathsep):
            candidate = os.path.join(p, "httpx")
            if os.path.isfile(candidate):
                return candidate
            candidate_exe = candidate + ".exe"
            if os.path.isfile(candidate_exe):
                return candidate_exe

        return None

    def _build_cmd(
        self, httpx_path: str, input_file: str, output_file: str, explicit_port: bool = False
    ) -> list[str]:
        """Build httpx command line.

        Args:
            explicit_port: the input line is already "host:port" (a TCP_PORT_OPEN
                event). -ports is omitted in that case: passing it makes httpx use
                that fixed list INSTEAD of the port already named in the input line
                (confirmed live - with -ports set, an explicit host:port in -l is not
                probed at all).
        """
        cmd = [
            httpx_path,
            "-l", input_file,
            "-o", output_file,
            "-json",
            "-silent",
            "-threads", str(self.opts["threads"]),
            "-timeout", str(self.opts["timeout"]),
            "-rate-limit", str(self.opts["rate_limit"]),
            "-method", self.opts["method"],
        ]

        if self.opts["ports"] and not explicit_port:
            cmd.extend(["-ports", self.opts["ports"]])
        if self.opts["follow_redirects"]:
            cmd.append("-follow-redirects")
        if self.opts["tech_detect"]:
            cmd.append("-tech-detect")
        if self.opts["status_code"]:
            cmd.append("-status-code")
        if self.opts["content_length"]:
            cmd.append("-content-length")
        if self.opts["title"]:
            cmd.append("-title")
        if self.opts["web_server"]:
            cmd.append("-web-server")
        if self.opts["cdn_check"]:
            cmd.append("-cdn")
        if self.opts["tls_grab"]:
            cmd.append("-tls-grab")

        return cmd

    def _parse_result(self, line: str, parent_event: Any) -> None:
        """Parse a single httpx JSON result line."""
        try:
            result = json.loads(line)
        except json.JSONDecodeError:
            return

        url = result.get("url", "")
        host = result.get("host", "")
        status_code = result.get("status_code")
        title = result.get("title", "")
        web_server = result.get("webserver", "")
        technologies = result.get("tech", [])
        cdn = result.get("cdn", False)
        cdn_name = result.get("cdn_name", "")
        port = result.get("port", "")
        tls = result.get("tls", {})

        # The origin httpx reached is now known; a later link to the same site need not be probed.
        origin = self._origin(url) if url else None
        if origin:
            self.results[origin] = True

        if url:
            self._emit("URL_WEB", url, parent_event)

        if status_code:
            data = f"{url} [{status_code}]"
            if title:
                data += f" [{title}]"
            self._emit("HTTP_CODE", data, parent_event)

        if web_server:
            self._emit("WEBSERVER_BANNER", f"{host}: {web_server}", parent_event)

        for tech in technologies or []:
            self._emit("WEBSERVER_TECHNOLOGY", f"{host}: {tech}", parent_event)

        if port:
            self._emit("TCP_PORT_OPEN", f"{host}:{port}", parent_event)

        if cdn and cdn_name:
            self._emit("CDN_DETECTED", f"{host}: {cdn_name}", parent_event)

        if tls and tls.get("subject_dn"):
            self._emit("SSL_CERTIFICATE_RAW", json.dumps(tls, indent=2), parent_event)

        # Full record of this probe
        self._emit("RAW_RIR_DATA", json.dumps(result, indent=2), parent_event)

    def handleEvent(self, event):
        data = event.data

        if self.errorState:
            return

        # httpx answers "is there a web server here, and what is it": a question about a site, not
        # about each page. A discovered link is therefore reduced to its origin (scheme, host, port)
        # and each origin is probed once. Probing every link separately re-ran httpx hundreds of
        # times per site and reported the same banner, technology and open port each time
        # (2,449 of 5,560 events in one scan of a small site). Pages are the spider's job.
        if event.eventType == "LINKED_URL_INTERNAL":
            data = self._origin(data)
            if not data:
                return

        if data in self.results:
            self.debug(f"Skipping already-scanned target: {data}")
            return
        self.results[data] = True

        # Rate limit total targets
        if len(self.results) > self.opts["max_hosts"]:
            self.info("Max hosts reached, skipping")
            return

        httpx_path = self._find_httpx()
        if not httpx_path:
            self.error("httpx binary not found. Install from https://github.com/projectdiscovery/httpx")
            self.errorState = True
            return

        target = data  # a host name, an IP address, host:port, or an origin URL
        is_url = target.startswith(("http://", "https://"))

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as infile:
            infile.write(target + "\n")
            input_path = infile.name

        output_path = input_path + ".json"

        try:
            cmd = self._build_cmd(
                httpx_path, input_path, output_path,
                # An origin URL names its own port too: probe it, not the fixed port list.
                explicit_port=(event.eventType == "TCP_PORT_OPEN" or is_url),
            )
            self.debug(f"Running: {' '.join(cmd)}")

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if proc.returncode != 0 and proc.stderr:
                self.debug(f"httpx stderr: {proc.stderr[:500]}")

            # Parse output
            if os.path.exists(output_path):
                with open(output_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            self._parse_result(line, event)

        except subprocess.TimeoutExpired:
            self.error("httpx timed out")
        except Exception as e:
            self.error(f"httpx error: {e}")
        finally:
            for p in (input_path, output_path):
                try:
                    os.unlink(p)
                except OSError:
                    pass

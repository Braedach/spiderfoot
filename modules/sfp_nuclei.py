from __future__ import annotations

"""SpiderFoot plug-in module: Nuclei vulnerability scanner integration.

Runs ProjectDiscovery's Nuclei scanner against discovered web endpoints
and IP addresses, parsing template-based findings into SpiderFoot events.

Nuclei must be installed on the system or available in the Docker image. In the SpiderFoot image the templates are a
pinned copy in /tools/nuclei-templates, which the module passes to nuclei (nuclei looks in its home directory by
default, found nothing there and exited with "no templates provided" on every run, which the module reported as
"0 findings"). A host is scanned once, not once per discovered URL.

Event flow:
  IN:  INTERNET_NAME, DOMAIN_NAME, IP_ADDRESS, LINKED_URL_INTERNAL
  OUT: VULNERABILITY_GENERAL, VULNERABILITY_CVE_CRITICAL,
       VULNERABILITY_CVE_HIGH, VULNERABILITY_CVE_MEDIUM,
       VULNERABILITY_CVE_LOW, RAW_RIR_DATA, WEBSERVER_TECHNOLOGY
"""

import json
import os
import re
import subprocess
import tempfile
import urllib.parse
from pathlib import Path

from spiderfoot import SpiderFootEvent
from spiderfoot.plugins.async_plugin import SpiderFootAsyncPlugin


class sfp_nuclei(SpiderFootAsyncPlugin):
    """Nuclei — fast, template-based vulnerability scanner by ProjectDiscovery."""

    meta = {
        'name': "Nuclei Scanner",
        'summary': "Run ProjectDiscovery Nuclei templates against discovered targets to find vulnerabilities, misconfigurations, and exposed services.",
        'flags': ["slow", "invasive"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Crawling and Scanning"],
        'toolDetails': {
            'name': "Nuclei",
            'description': "Fast and customisable vulnerability scanner based on simple YAML-based templates.",
            'website': 'https://nuclei.projectdiscovery.io/',
            'repository': 'https://github.com/projectdiscovery/nuclei',
        },
        'dataSource': {
            'website': "https://nuclei.projectdiscovery.io/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://docs.projectdiscovery.io/tools/nuclei/overview",
                "https://github.com/projectdiscovery/nuclei-templates",
            ],
            'favIcon': "https://nuclei.projectdiscovery.io/favicon.ico",
            'logo': "https://nuclei.projectdiscovery.io/static/nuclei-logo.png",
            'description': "Nuclei is a fast scanner for modern web applications, "
            "infrastructure, cloud platforms, and networks using a large library "
            "of community-maintained YAML templates.",
        },
    }

    opts = {
        'nuclei_path': 'nuclei',
        'severity_filter': 'low,medium,high,critical',
        'template_tags': '',
        'baseline_tags': 'ssl',
        'template_exclude_tags': 'dos,fuzz,intrusive',
        'templates_dir': '',
        'custom_templates_dir': '',
        'automatic_scan': True,
        'use_interactsh': False,
        'rate_limit': 50,
        'bulk_size': 25,
        'concurrency': 10,
        'timeout': 10,
        'max_scan_duration': 600,
        'max_targets': 20,
        'auto_update_templates': False,
        'scan_urls': True,
        'scan_ips': True,
        'include_info_findings': False,
    }

    optdescs = {
        'nuclei_path': "Path to the nuclei binary (default: 'nuclei' assumes it's in PATH).",
        'severity_filter': "Comma-separated severity levels to include (info,low,medium,high,critical). Informational templates are mostly technology detection, which httpx already does.",
        'template_tags': "Run ONLY templates with these tags (comma-separated). Empty = the baseline pass plus the automatic pass.",
        'baseline_tags': "Tags of a cheap first pass run on every target (default 'ssl': expired certificates, weak ciphers, deprecated TLS, a few seconds). Empty = no baseline pass.",
        'template_exclude_tags': "Exclude templates with these tags (comma-separated).",
        'templates_dir': "Directory holding the nuclei templates. Empty uses the copy pinned in the image (/tools/nuclei-templates) when it exists.",
        'custom_templates_dir': "Path to a custom templates directory to run INSTEAD of the standard templates.",
        'automatic_scan': "A second pass that picks templates from the technologies nuclei detects on each target (fast and relevant). If both passes are off, every template that matches the severity settings runs (about 7,600, several minutes per host).",
        'use_interactsh': "Allow templates that need an out-of-band callback server. Off by default: it contacts third-party servers.",
        'rate_limit': "Max requests per second sent by Nuclei.",
        'bulk_size': "Max hosts to scan per Nuclei invocation.",
        'concurrency': "Number of templates to run concurrently.",
        'timeout': "HTTP timeout per request in seconds.",
        'max_scan_duration': "Max total time in seconds for a single Nuclei invocation. Findings found before the limit are kept.",
        'max_targets': "Maximum number of separate nuclei runs (hosts, addresses and web origins) per scan.",
        'auto_update_templates': "Download newer templates when the scan starts. Off by default: the image carries a pinned, reviewed copy.",
        'scan_urls': "Scan the web origins (scheme, host, port) of discovered URLs that are not already covered. Each origin once, not each URL.",
        'scan_ips': "Scan discovered IP addresses.",
        'include_info_findings': "Include informational-severity findings (can be noisy).",
    }

    results = None
    errorState = False
    _nuclei_checked = False
    _nuclei_available = False

    def setup(self, sfc, userOpts=None):
        """Set up the module."""
        super().setup(sfc, userOpts or {})
        self.errorState = False
        self.results = self.tempStorage()
        self._nuclei_checked = False
        self._nuclei_available = False
        self._runs = 0
        self._cap_reported = False

    def watchedEvents(self):
        """Events consumed by this module."""
        events = ["INTERNET_NAME", "DOMAIN_NAME"]
        if self.opts.get('scan_ips', True):
            events.append("IP_ADDRESS")
        if self.opts.get('scan_urls', True):
            events.append("LINKED_URL_INTERNAL")
        return events

    def producedEvents(self):
        """Events produced by this module."""
        return [
            "VULNERABILITY_GENERAL",
            "VULNERABILITY_CVE_CRITICAL",
            "VULNERABILITY_CVE_HIGH",
            "VULNERABILITY_CVE_MEDIUM",
            "VULNERABILITY_CVE_LOW",
            "RAW_RIR_DATA",
            "WEBSERVER_TECHNOLOGY",
        ]

    def _check_nuclei(self) -> bool:
        """Verify that nuclei is installed and accessible."""
        if self._nuclei_checked:
            return self._nuclei_available

        self._nuclei_checked = True
        nuclei_path = self.opts.get('nuclei_path', 'nuclei')
        try:
            result = subprocess.run(
                [nuclei_path, '-version'],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0:
                version = result.stdout.strip() or result.stderr.strip()
                self.info(f"Nuclei available: {version}")
                self._nuclei_available = True

                # Auto-update templates
                if self.opts.get('auto_update_templates', True):
                    self._update_templates(nuclei_path)
            else:
                self.error(f"Nuclei returned error: {result.stderr}")
                self._nuclei_available = False
        except FileNotFoundError:
            self.error(f"Nuclei binary not found at '{nuclei_path}'. "
                       "Install from https://github.com/projectdiscovery/nuclei")
            self._nuclei_available = False
        except subprocess.TimeoutExpired:
            self.error("Nuclei version check timed out")
            self._nuclei_available = False

        return self._nuclei_available

    def _update_templates(self, nuclei_path: str) -> None:
        """Update Nuclei templates."""
        self.info("Updating Nuclei templates...")
        try:
            subprocess.run(
                [nuclei_path, '-ut'],
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.info("Nuclei templates updated")
        except Exception as e:
            self.debug(f"Template update failed (non-fatal): {e}")

    PINNED_TEMPLATES = "/tools/nuclei-templates"
    _ANSI = re.compile(r"\x1b\[[0-9;]*m")

    def _templates_dir(self) -> str:
        """The templates directory to hand to nuclei ('' when none is known: nuclei then looks in its home)."""
        configured = str(self.opts.get('templates_dir') or '').strip()
        if configured:
            return configured
        return self.PINNED_TEMPLATES if os.path.isdir(self.PINNED_TEMPLATES) else ''

    def _build_cmd(self, targets_file: str, selection: list[str] | None = None) -> list[str]:
        """The nuclei command line for a file of targets and one template selection (see _selections)."""
        cmd = [
            self.opts.get('nuclei_path', 'nuclei'),
            '-l', targets_file,
            '-jsonl',                   # JSON Lines output
            '-silent',                  # Suppress banner
            '-nc',                      # No color
            '-duc',                     # No update check: the templates are pinned, and a scan must not fetch code
            '-rl', str(self.opts.get('rate_limit', 50)),
            '-bs', str(self.opts.get('bulk_size', 25)),
            '-c', str(self.opts.get('concurrency', 10)),
            '-timeout', str(self.opts.get('timeout', 10)),
        ]

        # Where the templates are (-t alone does not tell the automatic mode, which also reads them)
        templates_dir = self._templates_dir()
        if templates_dir:
            cmd.extend(['-ud', templates_dir])

        # Out-of-band templates call a third-party server; off unless asked for
        if not self.opts.get('use_interactsh', False):
            cmd.append('-ni')

        severity = self.opts.get('severity_filter', 'low,medium,high,critical')
        if severity:
            cmd.extend(['-severity', severity])

        exclude_tags = self.opts.get('template_exclude_tags', 'dos,fuzz,intrusive')
        if exclude_tags:
            cmd.extend(['-etags', exclude_tags])

        custom_dir = self.opts.get('custom_templates_dir', '')
        if custom_dir and os.path.isdir(custom_dir):
            cmd.extend(['-t', custom_dir])

        return cmd + list(selection or [])

    def _selections(self) -> list[list[str]]:
        """The template selections to run on every target, one nuclei run each.

        nuclei's automatic mode (-as) cannot be combined with a tag list in one run (tried: it finds nothing), and a
        full run is about 7,600 templates. So: a cheap baseline pass on a few tags (ssl by default, 4 s on the test
        host, found an expired certificate and weak ciphers), then the automatic pass, which picks templates from
        the technologies found. A tag list set by the user replaces both.
        """
        custom_dir = self.opts.get('custom_templates_dir', '')
        if custom_dir and os.path.isdir(custom_dir):
            return [[]]                                   # -t is already in the command: run those templates
        tags = str(self.opts.get('template_tags', '') or '').strip()
        if tags:
            return [['-tags', tags]]
        passes = []
        baseline = str(self.opts.get('baseline_tags', '') or '').strip()
        if baseline:
            passes.append(['-tags', baseline])
        if self.opts.get('automatic_scan', True):
            passes.append(['-as'])
        return passes or [[]]

    def _parse_jsonl(self, text: str) -> list[dict]:
        """Findings from nuclei's JSON Lines output."""
        findings = []
        for line in (text or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                self.debug(f"Skipping non-JSON line: {line[:100]}")
        return findings

    def _fatal_message(self, stderr: str) -> str | None:
        """nuclei's own [FTL] line, if it stopped because it could not run at all."""
        for line in (stderr or "").splitlines():
            line = self._ANSI.sub("", line).strip()
            if "[FTL]" in line:
                return line[:300]
        return None

    def _run_nuclei(self, targets: list[str]) -> list[dict]:
        """Run Nuclei against a list of targets.

        Args:
            targets: List of hostnames, IPs, or URLs.

        Returns:
            List of parsed finding dicts from Nuclei JSON output.
        """
        # Write targets to temp file
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.txt', delete=False, prefix='sf_nuclei_'
        ) as tf:
            for t in targets:
                tf.write(t + '\n')
            targets_file = tf.name

        findings: list[dict] = []
        seen: set[tuple] = set()
        max_duration = self.opts.get('max_scan_duration', 600)

        try:
            for selection in self._selections():
                if self.errorState or self.checkForStop():
                    break
                cmd = self._build_cmd(targets_file, selection)
                label = " ".join(selection) or "all templates"
                self.info(f"Running Nuclei ({label}) against {len(targets)} target(s)...")
                try:
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max_duration)
                    found = self._parse_jsonl(proc.stdout)

                    if proc.returncode != 0 and not found:
                        fatal = self._fatal_message(proc.stderr)
                        if fatal:
                            # Every later run would fail the same way, and reporting "0 findings" hid it for a
                            # whole stack
                            self.error(f"Nuclei could not run: {fatal}")
                            self.errorState = True
                        else:
                            self.debug(f"Nuclei stderr: {(proc.stderr or '')[:500]}")
                except subprocess.TimeoutExpired as e:
                    partial = e.stdout.decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
                    found = self._parse_jsonl(partial)
                    self.error(f"Nuclei scan ({label}) timed out after {max_duration}s; keeping the {len(found)} "
                               "finding(s) found before the limit")

                for f in found:
                    key = (f.get("template-id", f.get("templateID")), f.get("matched-at", f.get("host")), f.get("matcher-name"))
                    if key not in seen:
                        seen.add(key)
                        findings.append(f)
        except Exception as e:
            self.error(f"Nuclei execution failed: {e}")
        finally:
            try:
                os.unlink(targets_file)
            except OSError:
                pass

        self.info(f"Nuclei returned {len(findings)} finding(s)")
        return findings

    @staticmethod
    def _origin(url: str) -> str | None:
        """scheme://host[:port] of an http(s) URL, the default port left out; None for anything else."""
        try:
            parts = urllib.parse.urlsplit(url)
            port = parts.port
        except ValueError:
            return None
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return None
        host = parts.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        default = 443 if parts.scheme == "https" else 80
        return f"{parts.scheme}://{host}" if port in (None, default) else f"{parts.scheme}://{host}:{port}"

    def _target_for(self, event_name: str, data: str) -> tuple[str | None, str]:
        """(what to give nuclei, the key that stands for "already scanned") for an event.

        A host name or address is scanned as it is and also covers its http and https origins; a discovered URL is
        reduced to its origin and skipped when that origin is already covered.
        """
        if event_name == "LINKED_URL_INTERNAL":
            origin = self._origin(data)
            return (origin, origin) if origin else (None, "")
        host = data.strip().lower()
        if not host:
            return None, ""
        # The host run reaches both schemes on the default ports: record them so URLs on them are not scanned again
        self.results[f"http://{host}"] = True
        self.results[f"https://{host}"] = True
        return host, f"host:{host}"

    def _severity_to_event_type(self, severity: str) -> str:
        """Map Nuclei severity to SpiderFoot event type."""
        severity = (severity or "").lower()
        mapping = {
            "critical": "VULNERABILITY_CVE_CRITICAL",
            "high": "VULNERABILITY_CVE_HIGH",
            "medium": "VULNERABILITY_CVE_MEDIUM",
            "low": "VULNERABILITY_CVE_LOW",
            "info": "VULNERABILITY_GENERAL",
        }
        return mapping.get(severity, "VULNERABILITY_GENERAL")

    def _format_finding(self, finding: dict) -> str:
        """Format a Nuclei finding into a human-readable string."""
        info = finding.get("info", {})
        template_id = finding.get("template-id", finding.get("templateID", "unknown"))
        name = info.get("name", template_id)
        severity = info.get("severity", "unknown")
        matched_at = finding.get("matched-at", finding.get("host", ""))
        matcher_name = finding.get("matcher-name", finding.get("matcher_name", ""))
        extracted = finding.get("extracted-results", [])
        description = info.get("description", "")

        parts = [
            f"[Nuclei] {name}",
            f"  Severity: {severity.upper()}",
            f"  Template: {template_id}",
            f"  Matched:  {matched_at}",
        ]
        if matcher_name:
            parts.append(f"  Matcher:  {matcher_name}")
        if description:
            parts.append(f"  Details:  {description[:500]}")

        # CVE references
        cve_ids = info.get("classification", {}).get("cve-id") or []
        if cve_ids:
            parts.append(f"  CVEs:     {', '.join(cve_ids)}")

        # CWE
        cwe_ids = info.get("classification", {}).get("cwe-id") or []
        if cwe_ids:
            parts.append(f"  CWEs:     {', '.join(cwe_ids)}")

        # CVSS
        cvss_score = info.get("classification", {}).get("cvss-score")
        if cvss_score:
            parts.append(f"  CVSS:     {cvss_score}")

        # Tags
        tags = info.get("tags") or []
        if tags:
            tag_list = tags if isinstance(tags, list) else [t.strip() for t in str(tags).split(",")]
            parts.append(f"  Tags:     {', '.join(tag_list[:10])}")

        if extracted:
            parts.append(f"  Extracted: {', '.join(str(e) for e in extracted[:5])}")

        return "\n".join(parts)

    def _extract_technologies(self, finding: dict) -> list[str]:
        """Extract technology names from info-level Nuclei findings."""
        info = finding.get("info", {})
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]

        techs = []
        # Technology detection templates often have specific tags
        template_id = finding.get("template-id", finding.get("templateID", ""))
        if "tech-detect" in template_id or "technologies" in template_id:
            matcher = finding.get("matcher-name", finding.get("matcher_name", ""))
            if matcher:
                techs.append(matcher)

        return techs

    def handleEvent(self, event):
        """Handle an incoming event by running Nuclei scans."""
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        # Check Nuclei availability
        if not self._check_nuclei():
            self.errorState = True
            return

        # One run per host or web origin. Running the full template set for every discovered URL turned a scan of a
        # small site into thousands of multi-minute runs; a host is probed on both schemes by a single run.
        target, key = self._target_for(eventName, eventData)
        if not target:
            return
        if key in self.results:
            self.debug(f"Skipping {eventData}, already covered by an earlier run.")
            return
        self.results[key] = True

        max_targets = int(self.opts.get('max_targets', 20) or 0)
        if max_targets and self._runs >= max_targets:
            if not self._cap_reported:
                self._cap_reported = True
                self.info(f"Reached the limit of {max_targets} nuclei runs for this scan; not scanning more targets.")
            return

        if eventName == "IP_ADDRESS" and not self.opts.get('scan_ips', True):
            return
        if eventName == "LINKED_URL_INTERNAL" and not self.opts.get('scan_urls', True):
            return

        if self.checkForStop():
            return

        self._runs += 1
        # Run Nuclei
        findings = self._run_nuclei([target])

        for finding in findings:
            if self.checkForStop():
                return

            info = finding.get("info", {})
            severity = info.get("severity", "info")

            # Skip info if not wanted
            if severity == "info" and not self.opts.get("include_info_findings", False):
                # Still extract technologies from info findings
                for tech in self._extract_technologies(finding):
                    tech_event = SpiderFootEvent(
                        "WEBSERVER_TECHNOLOGY", tech, self.__name__, event
                    )
                    self.notifyListeners(tech_event)
                continue

            # Emit raw data
            raw_event = SpiderFootEvent(
                "RAW_RIR_DATA", json.dumps(finding, indent=2), self.__name__, event
            )
            self.notifyListeners(raw_event)

            # Emit typed vulnerability event
            event_type = self._severity_to_event_type(severity)
            formatted = self._format_finding(finding)
            vuln_event = SpiderFootEvent(
                event_type, formatted, self.__name__, event
            )
            self.notifyListeners(vuln_event)

            # Extract technology detections
            for tech in self._extract_technologies(finding):
                tech_event = SpiderFootEvent(
                    "WEBSERVER_TECHNOLOGY", tech, self.__name__, event
                )
                self.notifyListeners(tech_event)

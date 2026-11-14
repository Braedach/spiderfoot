"""SpiderFoot module: katana - Next-gen web crawler.

Integrates ProjectDiscovery's katana for crawling web applications using
standard and headless browser modes with automatic form-filling.

Requires: katana binary in PATH or configured via katana_path option.
Install: go install -v github.com/projectdiscovery/katana/cmd/katana@latest
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from urllib.parse import urlparse

from spiderfoot.plugins.async_plugin import SpiderFootAsyncPlugin
from spiderfoot import SpiderFootEvent


class sfp_tool_katana(SpiderFootAsyncPlugin):
    """Next-gen web crawling via ProjectDiscovery katana."""

    meta = {
        "name": "Tool - katana",
        "summary": "Next-generation web crawler with headless browser support.",
        "flags": ["tool", "slow", "invasive"],
        "useCases": ["Investigate", "Footprint"],
        "categories": ["Crawling and Scanning"],
        "toolDetails": {
            "binaryName": "katana",
            "installUrl": "https://github.com/projectdiscovery/katana",
        },
        "dataSource": {
            "website": "https://github.com/projectdiscovery/katana",
            "model": "FREE_NOAUTH_UNLIMITED",
            "references": ["https://github.com/projectdiscovery/katana"],
            "description": "Next-generation web crawler with headless browser support by ProjectDiscovery.",
        },
    }

    opts = {
        "katana_path": "",
        "depth": 3,
        "js_crawl": True,
        "headless": False,
        "concurrent": 10,
        "parallelism": 10,
        "timeout": 10,
        "rate_limit": 150,
        "scope_filter": "",
        "extension_filter": "png,jpg,gif,svg,ico,woff,woff2,ttf,eot,css,mp4,mp3",
        "max_results": 5000,
        "run_timeout": 600,
        "max_seed_urls": 25,
    }

    optdescs = {
        "katana_path": "Path to katana binary. Leave blank to use PATH.",
        "depth": "Maximum crawl depth.",
        "js_crawl": "Enable JavaScript file endpoint extraction.",
        "headless": "Use headless browser for JavaScript-heavy sites.",
        "concurrent": "Number of concurrent requests.",
        "parallelism": "Number of parallel crawlers.",
        "timeout": "Request timeout in seconds.",
        "rate_limit": "Maximum requests per second.",
        "scope_filter": "Regex to limit crawl scope (blank=target domain only).",
        "extension_filter": "File extensions to exclude (comma-separated).",
        "max_results": "Maximum endpoints to return.",
        "run_timeout": "Total run timeout in seconds.",
        "max_seed_urls": "Maximum number of discovered URLs (beyond the target itself) to start a crawl from, one per host and top-level path. Each crawl already follows links to the configured depth, so crawling from every discovered URL repeats the same pages.",
    }

    results = None

    def setup(self, sfc, userOpts=None):
        super().setup(sfc, userOpts or {})
        self.errorState = False
        self.results = self.tempStorage()
        self.seedKeys = set()
        self.seedCount = 0

    def _is_static_asset(self, url: str) -> bool:
        """True for a URL that points at an image, stylesheet, font or media file: nothing to crawl."""
        ext = os.path.splitext(urlparse(url).path)[1].lstrip(".").lower()
        skip = {e.strip().lower() for e in str(self.opts.get("extension_filter", "")).split(",") if e.strip()}
        return bool(ext) and ext in skip

    @staticmethod
    def _seed_key(url: str) -> str:
        """One crawl per host and top-level path: deeper URLs are reached by the crawl itself."""
        parsed = urlparse(url)
        first = parsed.path.strip("/").split("/")[0] if parsed.path.strip("/") else ""
        return f"{parsed.netloc.lower()}/{first}"

    def _should_crawl_from(self, event) -> bool:
        """Decide whether this event starts a new katana crawl."""
        if event.eventType != "LINKED_URL_INTERNAL":
            return True  # the target domain itself
        if event.module == self.__name__:
            return False  # our own output; the crawl that found it already followed it
        if self._is_static_asset(event.data):
            return False
        key = self._seed_key(event.data)
        if key in self.seedKeys or self.seedCount >= int(self.opts.get("max_seed_urls", 25)):
            return False
        self.seedKeys.add(key)
        self.seedCount += 1
        return True

    def watchedEvents(self):
        return ["DOMAIN_NAME", "LINKED_URL_INTERNAL"]

    def producedEvents(self):
        return [
            "LINKED_URL_INTERNAL",
            "LINKED_URL_EXTERNAL",
            "URL_JAVASCRIPT",
            "URL_FORM",
            "RAW_RIR_DATA",
        ]

    def _find_binary(self):
        custom = self.opts.get("katana_path", "")
        if custom and os.path.isfile(custom):
            return custom
        for p in os.environ.get("PATH", "").split(os.pathsep):
            for name in ("katana", "katana.exe"):
                candidate = os.path.join(p, name)
                if os.path.isfile(candidate):
                    return candidate
        return None

    def handleEvent(self, event):
        data = event.data
        if self.errorState:
            return
        if data in self.results:
            return
        self.results[data] = True

        if not self._should_crawl_from(event):
            self.debug(f"katana: not starting a crawl from {data}")
            return

        binary = self._find_binary()
        if not binary:
            self.error("katana binary not found.")
            self.errorState = True
            return

        target = data if data.startswith("http") else f"https://{data}"
        output_path = tempfile.mktemp(suffix=".jsonl")

        cmd = [
            binary,
            "-u", target,
            "-d", str(self.opts["depth"]),
            "-c", str(self.opts["concurrent"]),
            "-p", str(self.opts["parallelism"]),
            "-timeout", str(self.opts["timeout"]),
            "-rl", str(self.opts["rate_limit"]),
            "-jsonl",
            "-o", output_path,
            "-silent",
        ]

        if self.opts["js_crawl"]:
            cmd.append("-jc")
        if self.opts["headless"]:
            cmd.append("-headless")
        if self.opts["extension_filter"]:
            cmd.extend(["-ef", self.opts["extension_filter"]])
        if self.opts["scope_filter"]:
            cmd.extend(["-fs", self.opts["scope_filter"]])

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.opts["run_timeout"],
            )
            if proc.returncode != 0 and proc.stderr:
                self.debug(f"katana stderr: {proc.stderr[:500]}")

            domain = data.lower() if not data.startswith("http") else ""
            count = 0

            if os.path.exists(output_path):
                with open(output_path, "r") as f:
                    for line in f:
                        if count >= self.opts["max_results"]:
                            break
                        line = line.strip()
                        if not line:
                            continue

                        try:
                            result = json.loads(line)
                            url = result.get("request", {}).get("endpoint", "")
                        except json.JSONDecodeError:
                            url = line if line.startswith("http") else ""

                        if not url or url in self.results:
                            continue
                        self.results[url] = True
                        count += 1

                        url_lower = url.lower()
                        if url_lower.endswith(".js") or "/js/" in url_lower:
                            evt_type = "URL_JAVASCRIPT"
                        elif "?" in url:
                            evt_type = "URL_FORM"
                        elif domain and domain in url_lower:
                            evt_type = "LINKED_URL_INTERNAL"
                        else:
                            evt_type = "LINKED_URL_EXTERNAL"

                        evt = SpiderFootEvent(
                            evt_type, url, self.__name__, event
                        )
                        self.notifyListeners(evt)

            self.info(f"katana found {count} endpoints from {target}")

        except subprocess.TimeoutExpired:
            self.error(f"katana timed out for {target}")
        except Exception as e:
            self.error(f"katana error: {e}")
        finally:
            try:
                os.unlink(output_path)
            except OSError:
                pass

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
from spiderfoot import auth_headers


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
        "max_host_seeds": 60,
        "spa_headless": True,
        "spa_max_runs": 10,
        "spa_timeout": 240,
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
        "max_host_seeds": "Maximum number of hosts whose front page is crawled in addition to the max_seed_urls path crawls. A new host always gets its own crawl, so an application host is not crowded out by the many pages of a blog.",
        "spa_headless": "After a normal crawl of a host front page that returns scripts but almost no pages (a single-page app), run one headless-browser pass that captures the API calls the app makes.",
        "spa_max_runs": "Maximum headless single-page-app passes per scan.",
        "spa_timeout": "Seconds one headless pass may take.",
        "max_seed_urls": "Maximum number of discovered URLs (beyond the target itself) to start a crawl from, one per host and top-level path. Each crawl already follows links to the configured depth, so crawling from every discovered URL repeats the same pages.",
    }

    results = None

    def setup(self, sfc, userOpts=None):
        super().setup(sfc, userOpts or {})
        self.errorState = False
        self.results = self.tempStorage()
        self.seedKeys = set()
        self.seedCount = 0
        self.hostSeeds = set()
        self.spaRuns = 0

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
        if key in self.seedKeys:
            return False
        host = urlparse(event.data).netloc.lower()
        if self.seedCount >= int(self.opts.get("max_seed_urls", 25)):
            # the path cap is spent, but a host not crawled yet still gets one crawl (separate, larger limit)
            if host in self.hostSeeds or len(self.hostSeeds) >= int(self.opts.get("max_host_seeds", 60)):
                return False
            self.hostSeeds.add(host)
            self.seedKeys.add(key)
            return True
        self.hostSeeds.add(host)
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
        domain = data.lower() if not data.startswith("http") else ""

        count, urls = self._crawl(binary, target, event, domain, headless=bool(self.opts["headless"]))
        self.info(f"katana found {count} endpoints from {target}")

        # A single-page app (Angular, React, Vue...) builds its API calls at run time, so a normal crawl only sees the
        # JavaScript bundles. One headless pass with XHR capture finds the API paths the browser actually calls.
        if (not self.opts["headless"] and self.opts.get("spa_headless", True)
                and self.spaRuns < int(self.opts.get("spa_max_runs", 10)) and self._looks_like_spa(target, urls)):
            self.spaRuns += 1
            n2, _ = self._crawl(binary, target, event, domain, headless=True, spa=True)
            self.info(f"katana headless pass found {n2} further endpoints from {target} (looks like a single-page app)")

    @staticmethod
    def _looks_like_spa(target: str, urls) -> bool:
        """A start page on its own host whose crawl returned scripts but almost no pages: the content is rendered by JS."""
        parsed = urlparse(target)
        if parsed.path.strip("/"):
            return False  # only the host's front page is judged
        scripts = 0
        pages = 0
        for u in urls:
            up = urlparse(u)
            if up.netloc.lower() != parsed.netloc.lower():
                continue
            path = up.path.lower()
            if path.endswith(".js") or path.endswith(".mjs"):
                scripts += 1
            elif path.rstrip("/") and os.path.splitext(path)[1] in ("", ".html", ".htm"):
                pages += 1
        return scripts >= 3 and pages <= 2

    def _crawl(self, binary, target, event, domain, headless=False, spa=False):
        """Run katana once and emit what it finds. Returns (new endpoint count, every URL it printed)."""
        output_path = tempfile.mktemp(suffix=".jsonl")
        cmd = [
            binary,
            "-u", target,
            "-d", str(2 if spa else self.opts["depth"]),
            "-c", str(self.opts["concurrent"]),
            "-p", str(self.opts["parallelism"]),
            "-timeout", str(15 if spa else self.opts["timeout"]),
            "-rl", str(self.opts["rate_limit"]),
            "-jsonl",
            "-o", output_path,
            "-silent",
        ]
        if self.opts["js_crawl"]:
            cmd.append("-jc")
        if headless:
            cmd.extend(["-headless", "-no-sandbox"])      # the scanner container runs as a non-sandboxed user
        if spa:
            cmd.append("-xhr")                            # also report the XHR/fetch calls the page makes
        if self.opts["extension_filter"]:
            cmd.extend(["-ef", self.opts["extension_filter"]])
        if self.opts["scope_filter"]:
            cmd.extend(["-fs", self.opts["scope_filter"]])

        cmd.extend(auth_headers.flag_args(self.opts, "-H"))  # authenticated test: the target only, never logged
        count = 0
        urls = []
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=int(self.opts.get("spa_timeout", 240)) if spa else self.opts["run_timeout"],
            )
            if proc.returncode != 0 and proc.stderr:
                self.debug(f"katana stderr: {proc.stderr[:500]}")

            if os.path.exists(output_path):
                with open(output_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            result = json.loads(line)
                            url = result.get("request", {}).get("endpoint", "")
                        except json.JSONDecodeError:
                            url = line if line.startswith("http") else ""
                        if not url:
                            continue
                        urls.append(url)
                        if count >= self.opts["max_results"] or url in self.results:
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

                        self.notifyListeners(SpiderFootEvent(evt_type, url, self.__name__, event))
        except subprocess.TimeoutExpired:
            self.error(f"katana timed out for {target}")
        except Exception as e:
            self.error(f"katana error: {e}")
        finally:
            try:
                os.unlink(output_path)
            except OSError:
                pass
        return count, urls

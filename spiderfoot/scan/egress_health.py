# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         spiderfoot.scan.egress_health
# Purpose:      Notice when a scan's connection to the outside world is broken or degraded, and say so.
# Created:      2026-11-16
# Licence:      MIT
# -------------------------------------------------------------------------------
"""Egress health: is the scan actually reaching the internet?

A scan whose network path is down does not fail loudly: every module's request simply gets no answer, the modules log
one error each, and the scan finishes with a short result that looks like "nothing was found". That is the worst kind of
failure for an intelligence tool, because an empty result reads as a clean one.

This module watches two things.

* **Canaries at scan start**: can the host resolve a name, and (when a proxy or Tor is configured) can it connect to the
  proxy. These touch no third party (a DNS lookup and a TCP connection to the configured proxy).
* **Symptoms during the scan**: the share of web requests that got no answer at all (no HTTP status of any kind, not
  even an error page) over a sliding window. Hidden-service (.onion) requests are tracked apart, because a dead onion
  service is normal. When the share is high, one warning is written to the scan log naming the likely cause (the
  network, the proxy, or a single host), and the scan-end summary repeats it.

Nothing here blocks anything: it only reports.
"""

from __future__ import annotations

import socket
import threading
import time
from collections import Counter, deque
from typing import Callable
from urllib.parse import urlsplit

OK, DEGRADED, FAILING = "ok", "degraded", "failing"

WINDOW_SECONDS = 300
MIN_REQUESTS = 20            # fewer requests than this in the window prove nothing
DEGRADED_SHARE = 0.60
FAILING_SHARE = 0.90
SINGLE_HOST_SHARE = 0.80     # one host holding this share of the failures means that host is the problem


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def answered(result: dict | None) -> bool:
    """Whether a fetch result got any answer from a server (an error page counts: the network worked)."""
    if not result:
        return False
    if result.get("status") == "scope-guard":          # we refused to send it; says nothing about the network
        return True
    code = result.get("code")
    return code not in (None, "", 0, "0")


class EgressHealth:
    """Sliding-window record of whether web requests got an answer."""

    def __init__(self, notify: Callable[[str], None] | None = None, clock: Callable[[], float] = time.monotonic,
                 window: float = WINDOW_SECONDS) -> None:
        self._notify = notify
        self._clock = clock
        self._window = window
        self._lock = threading.Lock()
        self._events: deque[tuple[float, bool, str]] = deque()
        self._onion: Counter[str] = Counter()
        self._state = OK
        self._worst = OK
        self.total = 0
        self.failures = 0
        self.canaries: list[tuple[str, bool, str]] = []

    # ----------------------------------------------------------------------------------------- recording

    def record(self, url: str, result: dict | None) -> None:
        """Note one request's outcome. Never raises."""
        try:
            host = _host(url)
            ok = answered(result)
            if host.endswith(".onion"):
                with self._lock:
                    self._onion["answered" if ok else "no answer"] += 1
                return
            now = self._clock()
            message = None
            with self._lock:
                self.total += 1
                self.failures += 0 if ok else 1
                self._events.append((now, ok, host))
                self._trim(now)
                state, _ = self._assess()
                if state != self._state:
                    message = self._describe_locked(state)
                    self._state = state
                    if self._rank(state) > self._rank(self._worst):
                        self._worst = state
            if message and self._notify:
                self._notify(message)
        except Exception:
            return

    # ----------------------------------------------------------------------------------------- assessment

    @staticmethod
    def _rank(state: str) -> int:
        return {OK: 0, DEGRADED: 1, FAILING: 2}[state]

    def _trim(self, now: float) -> None:
        while self._events and now - self._events[0][0] > self._window:
            self._events.popleft()

    def _assess(self) -> tuple[str, dict]:
        n = len(self._events)
        bad = [h for _, ok, h in self._events if not ok]
        info = {"requests": n, "no_answer": len(bad), "hosts": Counter(bad)}
        if n < MIN_REQUESTS:
            return OK, info
        share = len(bad) / n
        info["share"] = share
        if share >= FAILING_SHARE:
            return FAILING, info
        if share >= DEGRADED_SHARE:
            return DEGRADED, info
        return OK, info

    def _describe_locked(self, state: str) -> str:
        _, info = self._assess()
        if state == OK:
            return "Egress health: web requests are being answered again."
        hosts: Counter = info["hosts"]
        top, count = (hosts.most_common(1) or [("", 0)])[0]
        pct = round(100 * info.get("share", 0))
        base = (f"Egress health: {pct}% of the last {info['requests']} web requests got no answer at all "
                f"({'FAILING' if state == FAILING else 'degraded'}).")
        if top and info["no_answer"] and count / info["no_answer"] >= SINGLE_HOST_SHARE and len(hosts) > 0 \
                and len({h for _, ok, h in self._events}) > 1:
            return base + f" Most of them were to one host ({top}), so that service is probably down rather than the network."
        return (base + " Results from this scan may be incomplete, and an empty result is NOT a clean result. Check the "
                       "container's network, DNS, and the proxy or Tor setting.")

    def state(self) -> str:
        """Current state: ok, degraded or failing."""
        with self._lock:
            self._trim(self._clock())
            return self._assess()[0]

    # ----------------------------------------------------------------------------------------- reporting

    def summary(self) -> list[str]:
        """Lines for the scan-end log. Empty when everything was fine."""
        with self._lock:
            lines: list[str] = []
            failed_canaries = [c for c in self.canaries if not c[1]]
            for name, _, detail in failed_canaries:
                lines.append(f"start-of-scan check failed: {name}: {detail}")
            if self._rank(self._worst) > 0:
                lines.append(f"during the scan the connection was {self._worst} at one point")
            if self.total >= MIN_REQUESTS and self.failures / self.total >= DEGRADED_SHARE:
                lines.append(f"over the whole scan {self.failures} of {self.total} web requests got no answer at all")
            return lines


def run_canaries(config: dict, *, resolve: Callable[[str], object] | None = None,
                 connect: Callable[[str, int], None] | None = None) -> list[tuple[str, bool, str]]:
    """Checks at scan start: ``[(name, ok, detail), ...]``. Touches no third party.

    * DNS: the host can resolve a well-known name.
    * Proxy: when a proxy or Tor is configured, a TCP connection to it opens.
    """
    results: list[tuple[str, bool, str]] = []
    resolve = resolve or (lambda name: socket.getaddrinfo(name, 443))
    try:
        resolve("example.com")
        results.append(("DNS lookup", True, "ok"))
    except Exception as e:
        results.append(("DNS lookup", False, f"example.com did not resolve ({type(e).__name__})"))

    ptype = str(config.get("_socks1type") or "").strip()
    host = str(config.get("_socks2addr") or "").strip()
    try:
        port = int(config.get("_socks3port") or 0)
    except (TypeError, ValueError):
        port = 0
    if ptype and host and port:
        def _connect(h: str, p: int) -> None:
            with socket.create_connection((h, p), timeout=4):
                pass
        try:
            (connect or _connect)(host, port)
            results.append((f"{ptype} proxy", True, "ok"))
        except Exception as e:
            results.append((f"{ptype} proxy", False, f"cannot connect to the configured proxy ({type(e).__name__})"))
    return results

# -*- coding: utf-8 -*-
"""Scan liveness: a Redis heartbeat per running scan, and a reaper for dead ones.

Nothing used to notice when the process running a scan died (worker killed,
container restarted, OOM): the scan stayed RUNNING in the database forever.

* ``ScanHeartbeat`` - wraps a running scan and refreshes a short-TTL Redis key.
* ``reap_orphaned_scans`` - marks RUNNING / ABORT-REQUESTED scans whose
  heartbeat has vanished as ERROR-FAILED / ABORTED.

Everything here is best-effort and fails safe: with Redis unavailable the
heartbeat is a no-op and the reaper does nothing (it never reaps blind).
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

log = logging.getLogger("spiderfoot.scan.liveness")

ALIVE_KEY = "sf:scan:alive:{scan_id}"
LOCK_KEY = "sf:scan:reaper:lock"
HEARTBEAT_INTERVAL = float(os.environ.get("SF_SCAN_HEARTBEAT_INTERVAL", "15"))
HEARTBEAT_TTL = int(os.environ.get("SF_SCAN_HEARTBEAT_TTL", "90"))
# A scan must have had no heartbeat for this long (seconds) before being reaped.
REAP_GRACE = int(os.environ.get("SF_SCAN_REAP_GRACE", "180"))
# A STARTING scan may legitimately sit in the Celery queue; only reap it when
# it has been waiting an implausibly long time.
STARTING_MAX_AGE = int(os.environ.get("SF_SCAN_STARTING_MAX_AGE", str(6 * 3600)))
REAP_INTERVAL = int(os.environ.get("SF_SCAN_REAP_INTERVAL", "60"))


def _redis() -> Any | None:
    url = os.environ.get("SF_REDIS_URL", "")
    if not url:
        return None
    try:
        import redis

        client = redis.Redis.from_url(url, socket_connect_timeout=3, socket_timeout=3)
        client.ping()
        return client
    except Exception as exc:
        log.debug("liveness: redis unavailable: %s", exc)
        return None


class ScanHeartbeat:
    """Context manager keeping ``sf:scan:alive:<id>`` fresh while a scan runs."""

    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _beat(self, client: Any) -> None:
        try:
            client.set(ALIVE_KEY.format(scan_id=self.scan_id), str(int(time.time())), ex=HEARTBEAT_TTL)
        except Exception as exc:
            log.debug("liveness: heartbeat write failed: %s", exc)

    def _run(self) -> None:
        client = _redis()
        while not self._stop.is_set():
            if client is None:
                client = _redis()
            if client is not None:
                self._beat(client)
            self._stop.wait(HEARTBEAT_INTERVAL)

    def __enter__(self) -> "ScanHeartbeat":
        self._thread = threading.Thread(
            target=self._run, daemon=True, name=f"scan-heartbeat-{self.scan_id}"
        )
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        client = _redis()
        if client is not None:
            try:
                client.delete(ALIVE_KEY.format(scan_id=self.scan_id))
            except Exception:
                pass


def reap_orphaned_scans(dbh: Any, now: float | None = None) -> list[str]:
    """Mark scans with no live executor as failed. Returns the reaped scan ids."""
    client = _redis()
    if client is None:
        return []
    try:
        if not client.set(LOCK_KEY, "1", nx=True, ex=max(30, REAP_INTERVAL)):
            return []
    except Exception:
        return []

    now = now or time.time()
    reaped: list[str] = []
    for row in dbh.scanInstanceList():
        guid, status = row[0], row[6]
        created, started = float(row[3] or 0), float(row[4] or 0)
        if status not in ("RUNNING", "ABORT-REQUESTED", "STARTING"):
            continue
        age = now - max(created, started)
        if status == "STARTING":
            if age < STARTING_MAX_AGE:
                continue
        elif age < REAP_GRACE:
            continue
        try:
            if client.exists(ALIVE_KEY.format(scan_id=guid)):
                continue
        except Exception:
            return reaped  # cannot verify liveness: never reap blind
        new_status = "ABORTED" if status == "ABORT-REQUESTED" else "ERROR-FAILED"
        try:
            dbh.scanInstanceSet(guid, ended=str(int(now * 1000)), status=new_status)
            reaped.append(guid)
            log.warning(
                "Reaped orphaned scan %s: was %s with no live executor, marked %s",
                guid, status, new_status,
            )
        except Exception as exc:
            log.error("Failed to reap scan %s: %s", guid, exc)
    return reaped


def start_reaper_thread() -> threading.Thread:
    """Run the reaper periodically in a daemon thread (safe in every API worker)."""

    def _loop() -> None:
        time.sleep(REAP_GRACE)
        while True:
            try:
                from spiderfoot.db import SpiderFootDb

                dbh = SpiderFootDb({"__database": os.environ["SF_POSTGRES_DSN"], "__dbtype": "postgresql"})
                try:
                    reap_orphaned_scans(dbh)
                finally:
                    dbh.close()
            except Exception as exc:
                log.debug("scan reaper pass failed: %s", exc)
            time.sleep(REAP_INTERVAL)

    t = threading.Thread(target=_loop, daemon=True, name="scan-reaper")
    t.start()
    return t

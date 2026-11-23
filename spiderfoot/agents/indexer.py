"""Index finished scans into the vector store (Qdrant), in the background, one at a time, at low priority.

Only the agents service has a real Qdrant server and the embedding model. Before this, the report indexed a scan's events inside its
own request (16 minutes for 42,000 events, longer than the report's 600 second limit), the scan workers embedded every scan into an
in-memory store that was thrown away, and the API's search found nothing. Now:

* a poller asks for every recently finished scan that is not indexed yet, so a scan is searchable minutes after it ends and a scan
  that finished before this existed is picked up too;
* ``request()`` puts one scan at the front of the queue (the on-demand catch-up) and ``status()`` reports how far it has got;
* indexing runs on one thread at low priority, in small batches with a short pause, so a running scan is not starved;
* a marker for each completed scan is stored in Qdrant itself, so "indexed" is exact and survives a restart. Points have fixed ids,
  so indexing a scan twice (or resuming after a restart) replaces points rather than adding copies.
"""
from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from collections import deque
from typing import Any, Callable

logger = logging.getLogger("sf.agents.indexer")

STATE_COLLECTION = "index_state"
BATCH = 500


def _marker_id(scan_id: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_OID, f"scan-index:{scan_id}"))


class ScanIndexer:
    """A queue of scans to index and the one thread that works through it.

    ``load_events(scan_id)`` returns the scan's events, ``engine.index_events(batch)`` embeds and stores a batch, ``qdrant`` holds the
    completion markers (``ensure_collection``, ``upsert``, ``get``) and ``candidates()`` lists scan ids that ought to be indexed.
    All four are passed in so the logic can be tested without Qdrant, a database or the embedding model.
    """

    def __init__(self, load_events: Callable[[str], list], engine: Any, qdrant: Any, candidates: Callable[[], list[str]] | None = None,
                 batch: int = BATCH, pause_s: float | None = None) -> None:
        self._load_events, self._engine, self._qdrant = load_events, engine, qdrant
        self._candidates = candidates or (lambda: [])
        self._batch = max(1, batch)
        self._pause = float(os.environ.get("SF_INDEX_PAUSE_S", "0.05")) if pause_s is None else pause_s
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._queue: deque[str] = deque()
        self._states: dict[str, dict] = {}
        self._thread: threading.Thread | None = None

    # ── the markers ─────────────────────────────────────────────────────────────────────────────────────────────
    def is_indexed(self, scan_id: str) -> bool:
        """True when the scan was indexed completely (its marker is in Qdrant). False when unknown or Qdrant is unreachable."""
        try:
            return bool(self._qdrant.get(STATE_COLLECTION, [_marker_id(scan_id)]))
        except Exception as exc:
            logger.debug("index marker check failed for %s: %s", scan_id, exc)
            return False

    def _mark_indexed(self, scan_id: str, total: int) -> None:
        from spiderfoot.ai.qdrant_client import VectorPoint
        self._qdrant.ensure_collection(STATE_COLLECTION, vector_size=1)
        self._qdrant.upsert(STATE_COLLECTION, [VectorPoint(id=_marker_id(scan_id), vector=[0.0],
                                                           payload={"scan_id": scan_id, "events": total, "completed_at": time.time()})])

    # ── requests and status ─────────────────────────────────────────────────────────────────────────────────────
    def status(self, scan_id: str) -> dict:
        """``{"scan_id", "status": none|queued|indexing|done|error, "indexed", "total", ...}``; ``done`` once the marker exists."""
        with self._lock:
            state = self._states.get(scan_id)
            if state is not None and state["status"] in ("queued", "indexing", "error"):
                return self._view(state)
        if state is not None and state["status"] == "done":
            return self._view(state)
        if self.is_indexed(scan_id):
            return {"scan_id": scan_id, "status": "done", "indexed": None, "total": None}
        return {"scan_id": scan_id, "status": "none", "indexed": 0, "total": None}

    def request(self, scan_id: str, front: bool = False) -> dict:
        """Ask for a scan to be indexed. ``front`` moves it ahead of the queue (an on-demand request)."""
        if not scan_id:
            raise ValueError("scan_id is required")
        current = self.status(scan_id)
        if current["status"] in ("done", "indexing"):
            return current
        with self._lock:
            state = self._states.get(scan_id)
            if state is None or state["status"] == "error":                  # an earlier failure is retried
                state = {"scan_id": scan_id, "status": "queued", "indexed": 0, "total": None, "queued_at": time.time(), "error": None}
                self._states[scan_id] = state
            if scan_id in self._queue:
                if front:
                    self._queue.remove(scan_id)
                    self._queue.appendleft(scan_id)
            else:
                (self._queue.appendleft if front else self._queue.append)(scan_id)
            result = self._view(state)
        self.start()
        self._wake.set()
        return result

    def overview(self) -> dict:
        with self._lock:
            return {"queue": list(self._queue), "states": [self._view(s) for s in self._states.values()]}

    @staticmethod
    def _view(state: dict) -> dict:
        view = {k: state.get(k) for k in ("scan_id", "status", "indexed", "total", "error")}
        total = state.get("total")
        view["percent"] = round(100.0 * (state.get("indexed") or 0) / total, 1) if total else (100.0 if state["status"] == "done" else 0.0)
        return view

    # ── the worker ──────────────────────────────────────────────────────────────────────────────────────────────
    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="scan-indexer", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def enqueue_candidates(self) -> int:
        """Queue every scan the candidate list names that is not indexed yet; returns how many were queued."""
        queued = 0
        try:
            ids = self._candidates()
        except Exception as exc:
            logger.warning("Could not list the scans to index: %s", exc)
            return 0
        for scan_id in ids:
            if self._stop.is_set():
                break
            before = self.status(scan_id)["status"]
            if before == "none":
                self.request(scan_id)
                queued += 1
        return queued

    def _loop(self) -> None:
        try:                                    # low priority: this thread's own niceness (Linux), so scans keep the CPU
            os.setpriority(os.PRIO_PROCESS, threading.get_native_id(), 10)
        except (AttributeError, OSError):
            pass
        while not self._stop.is_set():
            with self._lock:
                scan_id = self._queue.popleft() if self._queue else None
            if scan_id is None:
                self._wake.wait(timeout=5)
                self._wake.clear()
                continue
            self._index(scan_id)

    def _index(self, scan_id: str) -> None:
        with self._lock:
            state = self._states.setdefault(scan_id, {"scan_id": scan_id, "indexed": 0, "total": None, "error": None})
            state.update(status="indexing", started=time.time(), indexed=0, error=None)
        try:
            events = self._load_events(scan_id)
            with self._lock:
                state["total"] = len(events)
            for i in range(0, len(events), self._batch):
                if self._stop.is_set():
                    with self._lock:
                        state["status"] = "queued"                       # picked up again after a restart
                    return
                self._engine.index_events(events[i:i + self._batch])
                with self._lock:
                    state["indexed"] = min(len(events), i + self._batch)
                if self._pause:
                    time.sleep(self._pause)
            self._mark_indexed(scan_id, len(events))
            with self._lock:
                state.update(status="done", indexed=len(events), ended=time.time())
            logger.info("Indexed %d events of scan %s into Qdrant", len(events), scan_id)
        except Exception as exc:
            logger.warning("Indexing scan %s failed: %s", scan_id, exc)
            with self._lock:
                state.update(status="error", error=str(exc)[:300])

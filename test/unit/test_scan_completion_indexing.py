"""A worker with no Qdrant server must not embed a whole scan into a store that is thrown away (6 minutes per scan)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from spiderfoot import service_integration as si


@pytest.fixture(autouse=True)
def enabled(monkeypatch):
    monkeypatch.setenv("SF_VECTOR_CORRELATION_ENABLED", "true")
    monkeypatch.setenv("SF_VECTOR_AUTO_INDEX", "true")


def test_with_the_in_memory_backend_nothing_is_embedded_or_read(monkeypatch):
    monkeypatch.delenv("SF_QDRANT_BACKEND", raising=False)               # the default is the in-memory store
    mgr = MagicMock()
    with patch("spiderfoot.correlation.vector_collection_manager.get_collection_manager", return_value=mgr), \
            patch("spiderfoot.db.SpiderFootDb") as db:
        si._index_scan_events_to_qdrant("S1")
    mgr.create_scan_collection.assert_not_called()
    db.assert_not_called()                                               # the events were not even read


def test_with_a_real_qdrant_server_the_scan_is_indexed_as_before(monkeypatch):
    monkeypatch.setenv("SF_QDRANT_BACKEND", "http")
    mgr = MagicMock()
    with patch("spiderfoot.correlation.vector_collection_manager.get_collection_manager", return_value=mgr), \
            patch("spiderfoot.db.SpiderFootDb") as db:
        db.build_config_from_env.return_value = {}
        db.return_value.scanResultEvent.return_value = []
        si._index_scan_events_to_qdrant("S1")
    mgr.create_scan_collection.assert_called_once_with("S1")


def test_auto_indexing_can_still_be_switched_off(monkeypatch):
    monkeypatch.setenv("SF_QDRANT_BACKEND", "http")
    monkeypatch.setenv("SF_VECTOR_AUTO_INDEX", "false")
    mgr = MagicMock()
    with patch("spiderfoot.correlation.vector_collection_manager.get_collection_manager", return_value=mgr):
        si._index_scan_events_to_qdrant("S1")
    mgr.create_scan_collection.assert_not_called()

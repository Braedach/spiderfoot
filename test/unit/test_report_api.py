"""
Tests for spiderfoot.api.routers.reports — Report API Endpoints.

Tests the Pydantic models, in-memory store, background generation,
and FastAPI endpoint handlers using TestClient.
"""
from __future__ import annotations

import json
import time
from unittest.mock import patch, MagicMock

import pytest

from spiderfoot.api.routers.reports import (
    ReportFormatEnum,
    ReportListItem,
    ReportResponse,
    ReportStatusResponse,
    ReportTypeEnum,
    clear_store,
    delete_stored_report,
    get_stored_report,
    list_stored_reports,
    store_report,
)

# Try to import FastAPI TestClient
try:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from spiderfoot.api.routers.reports import router

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clean_store():
    """Ensure store is clean before and after each test."""
    clear_store()
    yield
    clear_store()


def _sample_stored_report(report_id="RPT-001", scan_id="SCAN-001", status="completed"):
    return {
        "report_id": report_id,
        "scan_id": scan_id,
        "title": "Test Report",
        "status": status,
        "report_type": "full",
        "progress_pct": 100.0 if status == "completed" else 0.0,
        "message": "Done" if status == "completed" else "Pending",
        "executive_summary": "Critical issues found." if status == "completed" else None,
        "recommendations": "Fix everything." if status == "completed" else None,
        "sections": [
            {
                "title": "Threat Intel",
                "content": "APT activity.",
                "section_type": "threat_intel",
                "source_event_count": 5,
                "token_count": 100,
            }
        ] if status == "completed" else [],
        "metadata": {"statistics": {"after_filter": 10}} if status == "completed" else {},
        "generation_time_ms": 500.0 if status == "completed" else 0.0,
        "total_tokens_used": 200 if status == "completed" else 0,
        "created_at": time.time(),
    }


def _sample_events(count=10):
    return [
        {
            "type": "IP_ADDRESS",
            "data": f"10.0.0.{i}",
            "module": "sfp_test",
            "source_event": "example.com",
        }
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# Pydantic model tests
# ---------------------------------------------------------------------------

class TestPydanticModels:
    def test_report_type_enum(self):
        assert ReportTypeEnum.FULL == "full"
        assert ReportTypeEnum.EXECUTIVE == "executive"

    def test_report_format_enum(self):
        assert ReportFormatEnum.MARKDOWN == "markdown"
        assert ReportFormatEnum.HTML == "html"
        assert ReportFormatEnum.CSV == "csv"

    def test_status_response(self):
        resp = ReportStatusResponse(
            report_id="R-1", scan_id="S-1", status="pending"
        )
        assert resp.progress_pct == 0.0
        assert resp.message == ""

    def test_report_response(self):
        resp = ReportResponse(
            report_id="R-1", scan_id="S-1", title="Test",
            status="completed", report_type="full",
        )
        assert resp.sections == []
        assert resp.metadata == {}

    def test_list_item(self):
        item = ReportListItem(
            report_id="R-1", scan_id="S-1", title="Test",
            status="completed", report_type="full",
        )
        assert item.generation_time_ms == 0.0
        assert item.created_at == 0.0


# ---------------------------------------------------------------------------
# Store tests
# ---------------------------------------------------------------------------

class TestReportStore:
    def test_store_and_retrieve(self):
        store_report("RPT-1", {"report_id": "RPT-1", "status": "pending"})
        result = get_stored_report("RPT-1")
        assert result is not None
        assert result["status"] == "pending"

    def test_retrieve_nonexistent(self):
        assert get_stored_report("NOPE") is None

    def test_delete_report(self):
        store_report("RPT-1", {"report_id": "RPT-1"})
        assert delete_stored_report("RPT-1") is True
        assert get_stored_report("RPT-1") is None

    def test_delete_nonexistent(self):
        assert delete_stored_report("NOPE") is False

    def test_list_reports(self):
        store_report("R-1", {"report_id": "R-1"})
        store_report("R-2", {"report_id": "R-2"})
        reports = list_stored_reports()
        assert len(reports) == 2

    def test_clear_store(self):
        store_report("R-1", {"report_id": "R-1"})
        clear_store()
        assert list_stored_reports() == []


# ---------------------------------------------------------------------------
# Background generation tests
# ---------------------------------------------------------------------------

def _make_mock_report(executive_summary="No findings to report."):
    """Create a fake GeneratedReport-like object for tests."""
    from unittest.mock import MagicMock
    mock_report = MagicMock()
    mock_report.title = "Mock Report"
    mock_report.executive_summary = executive_summary
    mock_report.recommendations = "No recommendations."
    mock_report.sections = []
    mock_report.metadata = {}
    mock_report.generation_time_ms = 100.0
    mock_report.total_tokens_used = 50
    mock_report.report_type.value = "full"
    return mock_report


# ---------------------------------------------------------------------------
# FastAPI endpoint tests (using TestClient)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")
class TestAPIEndpoints:
    @pytest.fixture
    def client(self):
        from spiderfoot.api.dependencies import get_scan_service, get_api_key
        from unittest.mock import MagicMock
        app = FastAPI()
        app.include_router(router, prefix="/api")
        # Override DB-dependent services so tests don't need a real PostgreSQL
        mock_svc = MagicMock()
        mock_svc.get_scan.return_value = None
        mock_svc.get_events.return_value = []
        app.dependency_overrides[get_scan_service] = lambda: mock_svc
        app.dependency_overrides[get_api_key] = lambda: "test-key"
        return TestClient(app)

    @pytest.fixture(autouse=True)
    def mock_llm(self):
        """Prevent real LLM/network calls in all endpoint tests."""
        with patch(
            "spiderfoot.reporting.report_generator.ReportGenerator",
        ) as mock_cls:
            mock_cls.return_value.generate.side_effect = (
                lambda events, metadata: _make_mock_report(
                    "No findings to report." if not events else "Mock executive summary."
                )
            )
            mock_cls.return_value.generate_executive_only.return_value = (
                "Mock executive-only summary."
            )
            yield mock_cls

    def test_get_report_completed(self, client):
        report_id = "RPT-TEST-1"
        store_report(report_id, _sample_stored_report(report_id))

        resp = client.get(f"/api/reports/{report_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["report_id"] == report_id
        assert data["status"] == "completed"
        assert data["executive_summary"] == "Critical issues found."
        assert len(data["sections"]) == 1

    def test_get_report_not_found(self, client):
        resp = client.get("/api/reports/NOPE")
        assert resp.status_code == 404

    def test_get_report_status(self, client):
        report_id = "RPT-TEST-2"
        store_report(report_id, _sample_stored_report(report_id, status="generating"))

        resp = client.get(f"/api/reports/{report_id}/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "generating"

    def test_get_report_status_not_found(self, client):
        resp = client.get("/api/reports/NOPE/status")
        assert resp.status_code == 404

    def test_export_markdown(self, client):
        report_id = "RPT-EXP-1"
        store_report(report_id, _sample_stored_report(report_id))

        resp = client.get(f"/api/reports/{report_id}/export?format=markdown")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/markdown")
        assert "Test Report" in resp.text

    def test_export_html(self, client):
        report_id = "RPT-EXP-2"
        store_report(report_id, _sample_stored_report(report_id))

        resp = client.get(f"/api/reports/{report_id}/export?format=html")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/html")
        assert "<!DOCTYPE html>" in resp.text

    def test_export_json(self, client):
        report_id = "RPT-EXP-3"
        store_report(report_id, _sample_stored_report(report_id))

        resp = client.get(f"/api/reports/{report_id}/export?format=json")
        assert resp.status_code == 200
        data = json.loads(resp.text)
        assert data["schema_version"] == "1.0.0"

    def test_export_csv(self, client):
        report_id = "RPT-EXP-4"
        store_report(report_id, _sample_stored_report(report_id))

        resp = client.get(f"/api/reports/{report_id}/export?format=csv")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")
        assert "Section" in resp.text

    def test_export_plain_text(self, client):
        report_id = "RPT-EXP-5"
        store_report(report_id, _sample_stored_report(report_id))

        resp = client.get(f"/api/reports/{report_id}/export?format=plain_text")
        assert resp.status_code == 200
        assert "TEST REPORT" in resp.text

    def test_export_not_found(self, client):
        resp = client.get("/api/reports/NOPE/export?format=markdown")
        assert resp.status_code == 404

    def test_export_not_ready(self, client):
        report_id = "RPT-EXP-NR"
        store_report(report_id, _sample_stored_report(report_id, status="generating"))

        resp = client.get(f"/api/reports/{report_id}/export?format=markdown")
        assert resp.status_code == 409

    def test_list_reports_empty(self, client):
        resp = client.get("/api/reports")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_reports_with_data(self, client):
        store_report("R-1", _sample_stored_report("R-1"))
        store_report("R-2", _sample_stored_report("R-2"))

        resp = client.get("/api/reports")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2

    def test_list_reports_filter_by_scan(self, client):
        store_report("R-1", _sample_stored_report("R-1", scan_id="S-1"))
        store_report("R-2", _sample_stored_report("R-2", scan_id="S-2"))

        resp = client.get("/api/reports?scan_id=S-1")
        data = resp.json()
        assert len(data) == 1
        assert data[0]["scan_id"] == "S-1"

    def test_list_reports_pagination(self, client):
        for i in range(5):
            r = _sample_stored_report(f"R-{i}")
            r["created_at"] = time.time() + i
            store_report(f"R-{i}", r)

        resp = client.get("/api/reports?limit=2&offset=0")
        assert len(resp.json()) == 2

        resp = client.get("/api/reports?limit=2&offset=3")
        assert len(resp.json()) == 2

    def test_delete_report_endpoint(self, client):
        store_report("R-DEL", _sample_stored_report("R-DEL"))

        resp = client.delete("/api/reports/R-DEL")
        assert resp.status_code == 204
        assert get_stored_report("R-DEL") is None

    def test_delete_report_not_found(self, client):
        resp = client.delete("/api/reports/NOPE")
        assert resp.status_code == 404

    def test_export_content_disposition(self, client):
        report_id = "RPT-CD-1"
        store_report(report_id, _sample_stored_report(report_id))

        resp = client.get(f"/api/reports/{report_id}/export?format=html")
        cd = resp.headers.get("content-disposition", "")
        assert "attachment" in cd
        assert report_id[:8] in cd
        assert ".html" in cd

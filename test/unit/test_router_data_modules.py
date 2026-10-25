"""Tests for the module-management surface of spiderfoot.api.routers.data.

Covers runtime enable/disable, bulk-disable, status, config validation, and the
metadata endpoints (categories/types/risk-levels/options), with get_app_config
and SpiderFoot mocked.

Includes a regression test for a bug where POST /data/modules/bulk-disable
declared ``module_names: list = []`` — which FastAPI bound as a multipart
form field, so a JSON body never populated it and the endpoint always returned
400. It now accepts a JSON ``{"module_names": [...]}`` body.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("fastapi")
from fastapi import FastAPI
from fastapi.testclient import TestClient

import spiderfoot.api.routers.data as data
from spiderfoot.api.dependencies import get_api_key


_MODULES = {
    "sfp_dnsresolve": {"opts": {"timeout": 30, "verify": True},
                       "optdescs": {"timeout": "t", "verify": "v"},
                       "cats": ["Passive"], "flags": []},
    "sfp_whois": {"opts": {"key": ""}, "optdescs": {"key": "k"},
                  "cats": ["Footprint"], "flags": ["apikey"]},
}


@pytest.fixture
def client():
    data._disabled_modules.clear()
    fake_cfg = MagicMock()
    fake_cfg.get_config.return_value = {"__modules__": _MODULES}
    fake_sf = MagicMock()
    fake_sf.getModules.return_value = _MODULES
    fake_sf.getEventTypes.return_value = {"IP_ADDRESS": "x"}
    with patch.object(data, "get_app_config", lambda: fake_cfg), \
            patch.object(data, "SpiderFoot", lambda cfg: fake_sf):
        app = FastAPI()
        app.dependency_overrides[get_api_key] = lambda: "test-key"
        app.include_router(data.router)
        yield TestClient(app)
    data._disabled_modules.clear()


class TestEnableDisable:
    def test_disable_then_enable(self, client):
        r = client.post("/data/modules/sfp_whois/disable")
        assert r.status_code == 200 and r.json()["enabled"] is False
        # Idempotent: disabling again reports already-disabled.
        assert client.post("/data/modules/sfp_whois/disable").json()["message"] \
            == "already disabled"
        r = client.post("/data/modules/sfp_whois/enable")
        assert r.status_code == 200 and r.json()["enabled"] is True
        assert client.post("/data/modules/sfp_whois/enable").json()["message"] \
            == "already enabled"

    def test_disable_unknown_404(self, client):
        assert client.post("/data/modules/sfp_nope/disable").status_code == 404

    def test_status_reflects_disabled(self, client):
        client.post("/data/modules/sfp_whois/disable")
        body = client.get("/data/modules/status").json()
        assert body["total"] == 2
        assert body["disabled"] == 1
        statuses = {s["module"]: s["enabled"] for s in body["modules"]}
        assert statuses["sfp_whois"] is False
        assert statuses["sfp_dnsresolve"] is True


class TestBulkDisable:
    def test_json_body_accepted(self, client):
        """Regression: a JSON body must populate module_names (was always 400)."""
        r = client.post("/data/modules/bulk-disable",
                        json={"module_names": ["sfp_whois", "sfp_nope"]})
        assert r.status_code == 200
        results = {x["module"]: x["status"] for x in r.json()["results"]}
        assert results["sfp_whois"] == "disabled"
        assert results["sfp_nope"] == "not_found"
        assert r.json()["disabled_count"] == 1

    def test_empty_list_400(self, client):
        assert client.post("/data/modules/bulk-disable",
                           json={"module_names": []}).status_code == 400


class TestValidateConfig:
    def test_type_mismatch_is_error(self, client):
        r = client.post("/data/modules/sfp_dnsresolve/validate-config",
                        json={"timeout": "not-an-int"})
        assert r.status_code == 200
        body = r.json()
        assert body["valid"] is False
        assert any(e["field"] == "timeout" for e in body["errors"])

    def test_unknown_option_is_warning(self, client):
        r = client.post("/data/modules/sfp_dnsresolve/validate-config",
                        json={"bogus_opt": 1})
        body = r.json()
        assert body["valid"] is True  # warnings don't invalidate
        assert any(w["field"] == "bogus_opt" for w in body["warnings"])

    def test_apikey_module_warns_when_missing(self, client):
        r = client.post("/data/modules/sfp_whois/validate-config", json={})
        assert any(w["field"] == "api_key" for w in r.json()["warnings"])

    def test_unknown_module_404(self, client):
        assert client.post("/data/modules/sfp_nope/validate-config",
                           json={}).status_code == 404


class TestNotFoundStatusPreserved:
    """Regression: unknown-resource lookups returned 500 because a broad
    'except Exception' swallowed the intended 404 (HTTPException is an
    Exception). They must return 404."""

    def test_entity_type_unknown_404(self, client):
        assert client.get("/data/entity-types/DEFINITELY_NOT_A_TYPE").status_code == 404

    def test_module_details_unknown_404(self, client):
        assert client.get("/data/modules/sfp_does_not_exist").status_code == 404

    def test_module_options_unknown_404(self, client):
        assert client.get(
            "/data/modules/sfp_does_not_exist/options").status_code == 404


class TestMetadata:
    @pytest.mark.parametrize("path", [
        "/data/module-categories",
        "/data/module-types",
        "/data/risk-levels",
        "/data/global-options",
        "/data/modules/sfp_dnsresolve/options",
    ])
    def test_metadata_endpoints(self, client, path):
        assert client.get(path).status_code == 200


class TestModuleOptsFreshness:
    """Regression coverage for the per-API-worker config cache going stale:
    a save on one worker was invisible to GET /data/modules served by a
    different worker until that worker restarted (2026-10-25, reported as
    Data Source Credentials "flickering" between there/not there, and
    Shodan/Censys keys appearing not to save). GET /data/modules must
    overlay a fresh database read on top of whatever the in-memory config
    happens to hold.
    """

    def test_fresh_db_value_overrides_stale_in_memory_value(self, client):
        # In-memory config (as mocked by the `client` fixture) says
        # sfp_whois's "key" opt is blank — but a save on another worker
        # already wrote a real value to the database.
        with patch.object(data, "get_fresh_config_values",
                           lambda: {"sfp_whois:key": "a-real-api-key"}):
            r = client.get("/data/modules", params={"page_size": 10})
        assert r.status_code == 200
        whois = next(m for m in r.json()["items"] if m["name"] == "sfp_whois")
        assert whois["opts"]["key"] == "a-real-api-key"

    def test_missing_db_row_keeps_in_memory_value(self, client):
        # No fresh row for this option — untouched, not blanked out.
        with patch.object(data, "get_fresh_config_values", lambda: {}):
            r = client.get("/data/modules", params={"page_size": 10})
        assert r.status_code == 200
        whois = next(m for m in r.json()["items"] if m["name"] == "sfp_whois")
        assert whois["opts"]["key"] == ""

    def test_get_fresh_config_values_degrades_gracefully_on_db_error(self):
        # Isolated unit test of get_fresh_config_values() itself: on a DB
        # error it must return {} rather than raise, so a caller that
        # forgets its own try/except (like _refresh_module_opts) still
        # can't turn a DB hiccup into a 500 on every module listing.
        import spiderfoot.api.dependencies as deps

        fake_cfg = MagicMock()
        fake_cfg.get_config.return_value = {}

        def _boom(*a, **kw):
            raise RuntimeError("db unavailable")

        with patch.object(deps, "get_app_config", lambda: fake_cfg), \
                patch.object(deps, "SpiderFootDb", _boom):
            assert deps.get_fresh_config_values() == {}

    def test_fresh_bool_value_is_coerced_not_left_as_string(self, client):
        # sfp_dnsresolve's "verify" opt is a bool in memory (True); the DB
        # only ever stores strings. The overlay must coerce back to bool so
        # frontend/consumer code relying on the type doesn't regress.
        with patch.object(data, "get_fresh_config_values",
                           lambda: {"sfp_dnsresolve:verify": "false"}):
            r = client.get("/data/modules", params={"page_size": 10})
        assert r.status_code == 200
        dnsresolve = next(m for m in r.json()["items"] if m["name"] == "sfp_dnsresolve")
        assert dnsresolve["opts"]["verify"] is False

"""Connection test for the administrator's SearXNG server. Example hosts only; no network is used."""
from __future__ import annotations

import json
from unittest import mock

import pytest
import requests

pytest.importorskip("fastapi")
from fastapi import FastAPI
from fastapi.testclient import TestClient

from spiderfoot.api.dependencies import get_api_key, get_app_config
from spiderfoot.api.routers import websearch as ws

OK_BODY = json.dumps({"results": [{"engine": "duckduckgo", "url": "https://a.example"},
                                  {"engine": "google cse", "url": "https://b.example"},
                                  {"engine": "duckduckgo", "url": "https://c.example"}],
                      "unresponsive_engines": [["brave", "CAPTCHA"]]})


class Resp:
    def __init__(self, code=200, text=OK_BODY):
        self.status_code, self.text = code, text


class Session:
    def __init__(self, result):
        self.result, self.calls, self.max_redirects = result, [], None

    def get(self, url, **kw):
        self.calls.append((url, kw))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture(autouse=True)
def no_dns(monkeypatch):
    monkeypatch.setattr(ws, "_refused_target", lambda host: None)


def test_a_working_server_reports_what_it_found():
    s = Session(Resp())
    out = ws.run_test("https://search.example.org/", s)
    assert out["ok"] and out["results"] == 3 and out["engines"] == ["duckduckgo", "google cse"]
    assert "3 results from 2 engine(s)" in out["message"] and "brave" in out["message"]
    assert out["unresponsive"] == ["brave"]
    url, kw = s.calls[0]
    assert url == "https://search.example.org/search" and kw["params"] == {"q": "test", "format": "json"}
    assert kw["timeout"] == ws.TIMEOUT_SECONDS and s.max_redirects == ws.MAX_REDIRECTS


def test_a_path_on_the_address_is_kept_and_the_trailing_slash_dropped():
    s = Session(Resp())
    ws.run_test("http://10.0.0.5:8080/searx/", s)
    assert s.calls[0][0] == "http://10.0.0.5:8080/searx/search"


@pytest.mark.parametrize("bad", ["", "   ", "ftp://search.example.org", "javascript:alert(1)", "search.example.org", "http://"])
def test_an_unusable_address_is_refused_before_any_request(bad):
    s = Session(Resp())
    out = ws.run_test(bad, s)
    assert out["ok"] is False and not s.calls


def test_a_cloud_metadata_address_is_refused(monkeypatch):
    monkeypatch.setattr(ws, "_refused_target",
                        lambda host: "That address points at a cloud metadata service, which is not a search server.")
    s = Session(Resp())
    out = ws.run_test("http://metadata.example/", s)
    assert out["ok"] is False and "metadata" in out["message"] and not s.calls


def test_the_metadata_check_looks_at_what_the_name_resolves_to(monkeypatch):
    monkeypatch.undo()
    with mock.patch.object(ws.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("169.254.169.254", 0))]):
        assert "metadata" in ws._refused_target("anything.example")
    with mock.patch.object(ws.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("10.0.0.5", 0))]):
        assert ws._refused_target("internal.example") is None                     # private addresses are normal for SearXNG
    with mock.patch.object(ws.socket, "getaddrinfo", side_effect=OSError("no such name")):
        assert ws._refused_target("gone.example") is None                         # the request will say so itself


@pytest.mark.parametrize("code,fragment", [(403, "search.formats"), (429, "rate limiter"), (500, "HTTP 500"), (404, "HTTP 404")])
def test_failures_say_what_to_do(code, fragment):
    out = ws.run_test("https://search.example.org", Session(Resp(code, "x")))
    assert out["ok"] is False and fragment in out["message"]


@pytest.mark.parametrize("body,fragment", [("<html>hello</html>", "not with JSON"), ("[1, 2]", "not a SearXNG"),
                                          ('{"something": 1}', "not a SearXNG")])
def test_an_answer_that_is_not_a_search_result_is_explained(body, fragment):
    out = ws.run_test("https://search.example.org", Session(Resp(200, body)))
    assert out["ok"] is False and fragment in out["message"]


@pytest.mark.parametrize("error,fragment", [
    (requests.exceptions.SSLError(), "certificate"), (requests.exceptions.TooManyRedirects(), "redirected"),
    (requests.exceptions.Timeout(), "No answer within"), (requests.exceptions.ConnectionError(), "Could not connect"),
    (requests.exceptions.InvalidURL(), "request failed")])
def test_network_problems_are_translated(error, fragment):
    out = ws.run_test("https://search.example.org", Session(error))
    assert out["ok"] is False and fragment in out["message"]


def test_the_answer_never_contains_the_servers_response_body():
    secret = "SECRET-INTERNAL-PAGE-CONTENT"
    out = ws.run_test("https://search.example.org", Session(Resp(200, secret)))
    assert secret not in json.dumps(out)
    out = ws.run_test("https://search.example.org", Session(Resp(500, secret)))
    assert secret not in json.dumps(out)


# ------------------------------------------------------------------------------------------------ the endpoint


@pytest.fixture
def client(monkeypatch):
    app = FastAPI()
    app.dependency_overrides[get_api_key] = lambda: "test-key"
    app.dependency_overrides[get_app_config] = lambda: type("C", (), {"get_config": lambda self: {"_searxng_url": "https://saved.example"}})()
    app.include_router(ws.router)
    seen = []
    monkeypatch.setattr(ws, "run_test", lambda url, session=None: seen.append(url) or {"ok": True, "message": "Connected."})
    client = TestClient(app)
    client.seen = seen
    return client


def test_the_endpoint_tests_the_typed_address(client):
    assert client.post("/websearch/test", json={"url": "https://typed.example"}).json()["ok"] is True
    assert client.seen == ["https://typed.example"]


def test_without_an_address_it_tests_the_saved_one(client):
    client.post("/websearch/test", json={})
    assert client.seen == ["https://saved.example"]


def test_an_over_long_address_is_rejected(client):
    assert client.post("/websearch/test", json={"url": "https://" + "a" * 2100}).status_code == 422

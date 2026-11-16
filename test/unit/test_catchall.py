"""Catch-all detection (spiderfoot/sflib/catchall.py). Synthetic servers only."""
from __future__ import annotations

from spiderfoot.sflib.catchall import CatchAllBaseline, fingerprint, origin_of

PAGE = "<html>" + "app shell " * 150 + "</html>"          # the page a catch-all server returns for every path
HTML = {"content-type": "text/html; charset=utf-8"}


def server(answers, default):
    """fetch() for a synthetic server: exact-path answers, else the default (the catch-all or a 404)."""
    calls = []

    def fetch(url):
        calls.append(url)
        for suffix, answer in answers.items():
            if url.endswith(suffix):
                return answer
        return default
    fetch.calls = calls
    return fetch


CATCH_ALL = {"code": "200", "content": PAGE, "headers": HTML}


def test_origin_of():
    assert origin_of("https://www.example.org:8443/a/b?c=1") == "https://www.example.org:8443"
    assert origin_of("ftp://www.example.org/") is None and origin_of("not a url") is None


def test_the_htpasswd_case_from_the_live_scan():
    base = CatchAllBaseline(server({}, CATCH_ALL))
    assert base.is_catch_all("https://203.0.113.10/.htpasswd")
    assert base.is_catch_all("https://203.0.113.10/.bash_history")


def test_a_real_file_on_a_catch_all_server_is_kept():
    real = {"code": "200", "content": "admin:$apr1$abc$def\n" * 5, "headers": {"content-type": "text/plain"}}
    base = CatchAllBaseline(server({"/.htpasswd": real}, CATCH_ALL))
    assert not base.is_catch_all("https://203.0.113.10/.htpasswd")


def test_a_normal_server_answering_404_for_the_impossible_path_keeps_a_real_hit():
    notfound = {"code": "404", "content": "Not found", "headers": HTML}
    ok = {"code": "200", "content": "secret", "headers": {"content-type": "text/plain"}}
    base = CatchAllBaseline(server({"/backup.txt": ok}, notfound))
    assert not base.is_catch_all("http://203.0.113.10/backup.txt")


def test_a_path_that_answers_404_like_the_baseline_is_not_evidence_either():
    notfound = {"code": "404", "content": "Not found", "headers": HTML}
    assert CatchAllBaseline(server({}, notfound)).is_catch_all("http://203.0.113.10/never-existed.xls")


def test_a_dynamic_page_that_echoes_the_path_still_counts_as_the_catch_all():
    def fetch(url):
        return {"code": "200", "content": PAGE + url[-20:], "headers": HTML}      # a few bytes differ per path
    assert CatchAllBaseline(fetch).is_catch_all("https://203.0.113.10/.git/config")


def test_a_different_content_type_or_status_is_never_the_catch_all():
    base = CatchAllBaseline(server({"/a.zip": {"code": "200", "content": PAGE, "headers": {"content-type": "application/zip"}},
                                    "/b": {"code": "302", "content": "", "headers": {}}}, CATCH_ALL))
    assert not base.is_catch_all("https://203.0.113.10/a.zip")
    assert not base.is_catch_all("https://203.0.113.10/b")


def test_the_front_page_is_not_a_path_claim_and_nothing_is_fetched_for_it():
    fetch = server({}, CATCH_ALL)
    assert not CatchAllBaseline(fetch).is_catch_all("https://203.0.113.10/")
    assert fetch.calls == []


def test_when_the_baseline_cannot_be_fetched_nothing_is_discarded():
    assert not CatchAllBaseline(lambda url: None).is_catch_all("https://203.0.113.10/.htpasswd")

    def boom(url):
        raise OSError("down")
    assert not CatchAllBaseline(boom).is_catch_all("https://203.0.113.10/.htpasswd")


def test_the_baseline_is_fetched_once_per_server_and_extension():
    fetch = server({}, CATCH_ALL)
    base = CatchAllBaseline(fetch)
    for path in ("/.htpasswd", "/.bash_history", "/a.xls", "/b.xls"):
        base.is_catch_all("https://203.0.113.10" + path)
    random_paths = [c for c in fetch.calls if c.endswith(".xls") and "/a.xls" not in c and "/b.xls" not in c]
    assert len(random_paths) == 1                                # one baseline for ".xls", one more for no extension
    assert len([c for c in fetch.calls if c.rsplit("/", 1)[-1] not in (".htpasswd", ".bash_history", "a.xls", "b.xls")]) == 2


def test_a_different_server_gets_its_own_baseline():
    base = CatchAllBaseline(lambda url: CATCH_ALL if "203.0.113.10" in url else {"code": "404", "content": "no", "headers": HTML})
    assert base.is_catch_all("https://203.0.113.10/x.cfg")
    # a normal server: the impossible path gets a 404, and so does the reported path, so there is no file either
    assert base.is_catch_all("https://203.0.113.20/x.cfg")


def test_fingerprint_handles_missing_pieces():
    assert fingerprint(None) is None and fingerprint({"content": "x"}) is None
    assert fingerprint({"code": "200", "content": None, "headers": None}) == ("200", "", 0, fingerprint({"code": "200", "content": ""})[3])

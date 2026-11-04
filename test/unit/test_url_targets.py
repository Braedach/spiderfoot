"""Tests for spiderfoot.url_targets."""
import pytest

from spiderfoot.url_targets import directory_base, endpoint_key, host_key


@pytest.mark.parametrize("url,expected", [
    ("http://h/index.jsp?content=x", "http://h/"),
    ("http://h/a/b.html?x=1#frag", "http://h/a/"),
    ("http://h/a/b/", "http://h/a/b/"),
    ("HTTPS://Example.COM:8443/dir/file", "https://example.com:8443/dir/"),
    ("http://h", "http://h/"),
])
def test_directory_base(url, expected):
    assert directory_base(url) == expected


@pytest.mark.parametrize("bad", ["", "ftp://h/x", "not a url", "http://", "javascript:alert(1)"])
def test_unusable_urls_give_none(bad):
    assert directory_base(bad) is None and host_key(bad) is None and endpoint_key(bad) is None


def test_host_key_ignores_path_and_query_but_keeps_scheme_and_port():
    assert host_key("http://h/a?x=1") == host_key("http://H/b") == "http://h"
    assert host_key("https://h/a") != host_key("http://h/a")
    assert host_key("http://h:8080/a") != host_key("http://h/a")


def test_endpoint_key_ignores_parameter_values():
    assert endpoint_key("http://h/p.jsp?id=1") == endpoint_key("http://h/p.jsp?id=2") == "http://h/p.jsp"
    assert endpoint_key("http://h/p.jsp") != endpoint_key("http://h/q.jsp")


def test_endpoint_key_with_param_names_separates_different_parameter_sets():
    a = endpoint_key("http://h/p.jsp?id=1&n=2", with_param_names=True)
    assert a == endpoint_key("http://h/p.jsp?n=9&id=8", with_param_names=True) == "http://h/p.jsp?id&n"
    assert a != endpoint_key("http://h/p.jsp?id=1", with_param_names=True)


def test_a_thousand_query_variants_collapse_to_one_target():
    urls = [f"http://h/index.jsp?content=page{i}.htm" for i in range(1000)]
    assert len({directory_base(u) for u in urls}) == 1
    assert len({endpoint_key(u) for u in urls}) == 1

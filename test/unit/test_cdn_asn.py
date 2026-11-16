"""Shared-edge recognition by origin ASN (cdn_ranges.knownCdnProvider)."""
from spiderfoot import cdn_ranges as c
from spiderfoot.target import SpiderFootTarget


def test_an_address_on_a_listed_asn_is_a_shared_edge():
    cache: dict = {}
    assert c.knownCdnProvider("203.0.113.9", {}, lambda ip: 13335, cache) == "Cloudflare"
    assert c.knownCdnProvider("203.0.113.10", {}, lambda ip: 20940, {}) == "Akamai"


def test_an_ordinary_asn_is_not():
    assert c.knownCdnProvider("203.0.113.9", {}, lambda ip: 64500, {}) is None


def test_cloud_platforms_and_bulk_hosters_are_not_listed():
    for asn in (16509, 15169, 8075, 14061, 16276, 30633):      # AWS, Google, Microsoft, DigitalOcean, OVH, Leaseweb
        assert asn not in c.CDN_ASNS


def test_a_failed_lookup_never_marks_an_address_shared():
    def boom(ip):
        raise RuntimeError("dns down")
    assert c.knownCdnProvider("203.0.113.9", {}, boom, {}) is None
    assert c.knownCdnProvider("203.0.113.9", {}, lambda ip: None, {}) is None


def test_the_published_range_wins_and_the_lookup_is_cached():
    calls = []
    cache: dict = {}

    def lookup(ip):
        calls.append(ip)
        return 54113
    assert c.knownCdnProvider("151.101.3.7", None, lookup, cache) == "Fastly"      # by range, no lookup needed
    assert calls == []
    c.knownCdnProvider("203.0.113.9", {}, lookup, cache)
    c.knownCdnProvider("203.0.113.9", {}, lookup, cache)
    assert calls == ["203.0.113.9"]


def test_target_only_uses_the_asn_list_when_given_a_lookup():
    t = SpiderFootTarget("example.com", "INTERNET_NAME")
    assert t.isKnownCdnIP("203.0.113.9", {}) is None                                   # no lookup: ranges only
    assert t.isKnownCdnIP("203.0.113.9", {}, lambda ip: 13335) == "Cloudflare"


def test_the_targets_own_authorised_address_is_never_judged_shared():
    t = SpiderFootTarget("203.0.113.9", "IP_ADDRESS")
    assert t.isKnownCdnIP("203.0.113.9", {}, lambda ip: 13335) is None


def test_cymru_lookup_returns_none_on_garbage_input():
    assert c.cymruAsnLookup("not-an-address") is None


def test_every_listed_provider_has_a_positive_asn():
    assert all(isinstance(a, int) and a > 0 and name for a, name in c.CDN_ASNS.items())

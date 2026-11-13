"""Tests for spiderfoot.cdn_ranges - the deterministic, dispatch-time-
independent check for known CDN/anycast provider IP ranges.

See the module's own docstring for the live incident this closes: a
target's owned subdomain resolving directly to a shared Cloudflare/Fastly
anycast edge, with no affiliate hop for the reactive markIPShared()
mechanism to ever key off.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from spiderfoot import cdn_ranges


class TestIsKnownCdnIP(unittest.TestCase):

    def test_detects_cloudflare_range(self):
        self.assertEqual(cdn_ranges.isKnownCdnIP("104.21.71.238"), "Cloudflare")

    def test_detects_fastly_range(self):
        self.assertEqual(cdn_ranges.isKnownCdnIP("151.101.3.7"), "Fastly")

    def test_returns_none_for_non_cdn_ip(self):
        self.assertIsNone(cdn_ranges.isKnownCdnIP("203.0.113.5"))

    def test_returns_none_for_invalid_input(self):
        self.assertIsNone(cdn_ranges.isKnownCdnIP(""))
        self.assertIsNone(cdn_ranges.isKnownCdnIP(None))
        self.assertIsNone(cdn_ranges.isKnownCdnIP("not-an-ip"))

    def test_uses_supplied_ranges_over_fallback(self):
        custom = {"TestProvider": ["198.51.100.0/24"]}
        self.assertEqual(
            cdn_ranges.isKnownCdnIP("198.51.100.42", custom), "TestProvider")
        # Fallback-only address is not in the custom set.
        self.assertIsNone(cdn_ranges.isKnownCdnIP("151.101.3.7", custom))


class TestRefreshCdnRanges(unittest.TestCase):

    def test_falls_back_to_static_snapshot_on_fetch_failure(self):
        sf = MagicMock()
        sf.cacheGet.return_value = None
        sf.optValueToData.return_value = None

        ranges = cdn_ranges.refreshCdnRanges(sf, cacheHours=24)

        self.assertEqual(
            sorted(ranges["Cloudflare"]),
            sorted(cdn_ranges.FALLBACK_RANGES["Cloudflare"]))
        self.assertEqual(
            sorted(ranges["Fastly"]),
            sorted(cdn_ranges.FALLBACK_RANGES["Fastly"]))

    def test_uses_cached_data_without_refetching(self):
        sf = MagicMock()
        sf.cacheGet.return_value = "203.0.113.0/24\n198.51.100.0/24"

        ranges = cdn_ranges.refreshCdnRanges(sf, cacheHours=24)

        sf.optValueToData.assert_not_called()
        self.assertIn("203.0.113.0/24", ranges["Cloudflare"])

    def test_parses_fastly_json_document(self):
        sf = MagicMock()

        def fake_cache_get(label, _hours):
            return None

        def fake_fetch(url):
            if "fastly" in url:
                return '{"addresses": ["151.101.0.0/16"], "ipv6_addresses": ["2a04:4e42::/32"]}'
            return "173.245.48.0/20"

        sf.cacheGet.side_effect = fake_cache_get
        sf.optValueToData.side_effect = fake_fetch

        ranges = cdn_ranges.refreshCdnRanges(sf, cacheHours=24)

        self.assertIn("151.101.0.0/16", ranges["Fastly"])
        self.assertIn("2a04:4e42::/32", ranges["Fastly"])

    def test_malformed_fastly_json_falls_back_without_raising(self):
        sf = MagicMock()
        sf.cacheGet.return_value = None
        sf.optValueToData.return_value = "not valid json"

        ranges = cdn_ranges.refreshCdnRanges(sf, cacheHours=24)

        self.assertEqual(
            sorted(ranges["Fastly"]), sorted(cdn_ranges.FALLBACK_RANGES["Fastly"]))


if __name__ == "__main__":
    unittest.main()

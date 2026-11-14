"""Name, username and bitcoin targets arrive wrapped in quotes; the quotes must not reach the scan.

Seen live: a scan of "Leon Scott" carried the quote marks into the root event and into every username derived from
it, so sfp_accounts searched for "leonscott" (quotes included) and reported https://www.patreon.com/"leonscott" as an
account, and the modules that follow usernames looked up text no site has.
"""
import uuid

import pytest

from spiderfoot.scan.scanner import SpiderFootScanner, clean_target_value
from test.unit.utils.test_scanner_base import TestScannerBase


@pytest.mark.parametrize("value,target_type,expected", [
    ('"Leon Scott"', "HUMAN_NAME", "Leon Scott"),
    ('  "Leon Marcus Scott" ', "HUMAN_NAME", "Leon Marcus Scott"),
    ('"leonscott"', "USERNAME", "leonscott"),
    ('"1BoatSLRHtKNngkdXEeobR76b53LETtpyT"', "BITCOIN_ADDRESS", "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"),
    ("Leon Scott", "HUMAN_NAME", "Leon Scott"),                  # already clean
    ('"O\'Brien, Pat"', "HUMAN_NAME", "O'Brien, Pat"),           # inner punctuation is kept
])
def test_quotes_that_mark_the_type_are_removed(value, target_type, expected):
    assert clean_target_value(value, target_type) == expected


@pytest.mark.parametrize("value,target_type", [
    ("demo.testfire.net", "INTERNET_NAME"), ("scottysau@gmail.com", "EMAILADDR"), ("+61459053405", "PHONE_NUMBER"),
    ("101.185.137.187", "IP_ADDRESS"), ("AS64500", "BGP_AS_OWNER"),
])
def test_other_target_types_are_untouched(value, target_type):
    assert clean_target_value(value, target_type) == value


def test_a_value_that_is_only_quotes_is_not_emptied():
    assert clean_target_value('""', "HUMAN_NAME") == '""'


class TestScannerUsesTheCleanValue(TestScannerBase):

    def test_a_name_scan_carries_no_quote_marks(self):
        scan = SpiderFootScanner("t", str(uuid.uuid4()), '"Leon Scott"', "HUMAN_NAME", ["sfp_example"],
                                 self.default_options.copy(), start=False)
        assert scan._SpiderFootScanner__targetValue == "Leon Scott"
        assert scan._SpiderFootScanner__target.targetValue == "Leon Scott"

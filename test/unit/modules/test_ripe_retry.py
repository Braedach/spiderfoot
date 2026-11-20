"""One slow RIPEstat answer must not cost the scan its netblock, AS, company and abuse contacts."""
from unittest.mock import MagicMock, patch

from spiderfoot import SpiderFootEvent
from spiderfoot.sflib import SpiderFoot
from modules.sfp_ripe import sfp_ripe

NETINFO = '{"data": {"prefix": "101.160.0.0/11", "asns": ["1221"]}}'
WHOIS = '{"data": {"records": [], "irr_records": [], "authorities": ["apnic"]}}'


def make(**opts):
    m = sfp_ripe()
    m.setup(SpiderFoot({"_useragent": "t", "_fetchtimeout": 5, "__logging": False}), {"_useragent": "t", "_fetchtimeout": 5, **opts})
    m.__name__ = "sfp_ripe"
    return m


def answers(*contents):
    return [{"content": c, "code": "200" if c else None} for c in contents]


def test_a_timeout_is_retried_and_the_answer_is_kept():
    m = make(retrywait=0)
    with patch.object(m, "fetch_url", side_effect=answers(None, None, WHOIS)) as fetch, patch("modules.sfp_ripe.time.sleep"):
        res = m.fetchRir("https://stat.ripe.net/data/whois/data.json?resource=101.160.0.0/11")
    assert res["content"] == WHOIS and fetch.call_count == 3
    assert m.lastContent == WHOIS


def test_it_gives_up_after_the_configured_retries_and_does_not_cache_a_failure():
    m = make(retries=1, retrywait=0)
    url = "https://stat.ripe.net/data/whois/data.json?resource=x"
    with patch.object(m, "fetch_url", side_effect=answers(None, None)) as fetch, patch("modules.sfp_ripe.time.sleep"):
        assert m.fetchRir(url)["content"] is None
    assert fetch.call_count == 2 and url not in m.memCache


def test_the_timeout_is_never_below_the_minimum():
    m = make(retrywait=0)
    with patch.object(m, "fetch_url", side_effect=answers(WHOIS)) as fetch:
        m.fetchRir("https://stat.ripe.net/data/whois/data.json?resource=x")
    assert fetch.call_args.kwargs["timeout"] >= 20


def test_an_ip_whose_first_whois_times_out_still_yields_its_netblock():
    m = make(retrywait=0)
    seen = []
    m.notifyListeners = lambda e: seen.append((e.eventType, e.data))
    m.ownsNetblock = lambda p: True
    replies = {"network-info": [NETINFO], "whois": [None, WHOIS]}

    def fake(url, **kw):
        key = "network-info" if "network-info" in url else "whois"
        c = replies[key].pop(0) if len(replies[key]) > 1 else replies[key][0]
        return {"content": c, "code": "200" if c else None}
    with patch.object(m, "fetch_url", side_effect=fake), patch("modules.sfp_ripe.time.sleep"), \
            patch.object(m, "netblockAs", return_value="1221"):
        root = SpiderFootEvent("ROOT", "101.185.137.187", "", "")
        m.handleEvent(SpiderFootEvent("IP_ADDRESS", "101.185.137.187", "sfp_x", root))
    assert ("NETBLOCK_OWNER", "101.160.0.0/11") in seen


def test_defaults_and_descriptions_agree():
    assert set(sfp_ripe.opts) == set(sfp_ripe.optdescs)
    assert sfp_ripe.opts["retries"] >= 1 and sfp_ripe.opts["min_timeout"] >= 15

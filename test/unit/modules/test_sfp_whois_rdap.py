"""sfp_whois asks RDAP first for domains and falls back to port-43 WHOIS (over 200 throttled WHOIS answers in two scans)."""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import modules.sfp_whois as mod
from modules.sfp_whois import sfp_whois
from spiderfoot import SpiderFootEvent
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase

BOOTSTRAP = {"services": [[["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
                          [["au"], ["https://rdap.cctld.au/rdap/", "http://rdap.cctld.au/rdap/"]],
                          [["org"], ["https://rdap.publicinterestregistry.org/rdap/"]]]}
# The shape of a real answer (rdap.verisign.com for example.com), plus a registrant contact with a vCard
RDAP = {"objectClassName": "domain", "handle": "2336799_DOMAIN_COM-VRSN", "ldhName": "EXAMPLE.COM",
        "status": ["client delete prohibited", "client transfer prohibited"],
        "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                   {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
                   {"eventAction": "last changed", "eventDate": "2026-08-14T07:01:34Z"},
                   {"eventAction": "last update of RDAP database", "eventDate": "2026-11-14T00:00:00Z"}],
        "nameservers": [{"ldhName": "ELLIOTT.NS.CLOUDFLARE.COM"}, {"ldhName": "HERA.NS.CLOUDFLARE.COM"}],
        "secureDNS": {"delegationSigned": True},
        "entities": [
            {"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                               ["fn", {}, "text", "MarkMonitor Corporate Services Inc"]]],
             "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@registrar.example"],
                                                                         ["tel", {}, "text", "+1.2083895740"]]]}]},
            {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Domain Admin"],
                                                               ["org", {}, "text", "Example Pty Ltd"],
                                                               ["email", {}, "text", "admin@example.com"],
                                                               ["adr", {}, "text", ["", "", "1 Main St", "Perth", "WA", "6000", "AU"]]]]}]}


class TestWhoisRdap(TestModuleBase):

    def _module(self, rdap_code="200", rdap_body=None, bootstrap=BOOTSTRAP, whois_text=None, **opts):
        m = sfp_whois()
        m.__name__ = "sfp_whois"
        m.setup(SpiderFoot(self.default_options), opts)
        self.events, self.errors, self.requests = [], [], []
        m.notifyListeners = self.events.append
        m.error = self.errors.append

        def fake_fetch(url, **kw):
            self.requests.append(url)
            if url == sfp_whois.BOOTSTRAP_URL:
                return {"code": "200", "content": json.dumps(bootstrap) if bootstrap else None}
            return {"code": rdap_code, "content": json.dumps(rdap_body if rdap_body is not None else RDAP)
                    if rdap_code == "200" else None}

        m.fetch_url = fake_fetch
        self.whois_calls = []
        long_text = whois_text or ("Domain Name: EXAMPLE.COM\n" + "Registrar: Old Registrar\n" * 20)

        def fake_whois(domain):
            self.whois_calls.append(domain)
            result = MagicMock()
            result.text = long_text
            result.get = lambda k, d=None: {"registrar": "Old Registrar"}.get(k, d)
            return result

        self._orig = mod.whois.whois
        mod.whois.whois = fake_whois
        self.addCleanup(lambda: setattr(mod.whois, "whois", self._orig))
        return m

    def _ev(self, etype="DOMAIN_NAME", data="example.com"):
        return SpiderFootEvent(etype, data, "sfp_x", None)

    def _of(self, etype):
        return [e.data for e in self.events if e.eventType == etype]

    def test_opts_and_descriptions_match(self):
        m = sfp_whois()
        self.assertEqual(set(m.opts), set(m.optdescs))

    def test_a_domain_is_looked_up_over_rdap_and_whois_is_not_used(self):
        m = self._module()
        m.handleEvent(self._ev())
        self.assertEqual(self.whois_calls, [])
        self.assertEqual(self.requests[-1], "https://rdap.verisign.com/com/v1/domain/example.com")
        self.assertEqual(self._of("DOMAIN_REGISTRAR"), ["MarkMonitor Corporate Services Inc"])
        text = self._of("DOMAIN_WHOIS")[0]
        for expected in ("Domain Name: EXAMPLE.COM", "Creation Date: 1995-08-14T04:00:00Z",
                         "Registry Expiry Date: 2027-08-13T04:00:00Z", "Domain Status: client delete prohibited",
                         "Name Server: ELLIOTT.NS.CLOUDFLARE.COM", "DNSSEC: signed", "Registrar: MarkMonitor",
                         "Registrar Abuse Contact Email: abuse@registrar.example", "Registrant Email: admin@example.com",
                         "Registrant Organization: Example Pty Ltd", "Registrant Address: 1 Main St, Perth, WA, 6000, AU"):
            self.assertIn(expected, text)
        self.assertNotIn("last update of RDAP database", text.lower())

    def test_the_text_still_gives_the_email_and_phone_modules_something_to_read(self):
        text = self._module()._render_rdap(RDAP)[0]
        self.assertRegex(text, r"[\w.]+@[\w.]+")
        self.assertIn("+1.2083895740", text)

    def test_the_server_is_chosen_from_the_iana_bootstrap_by_tld(self):
        m = self._module()
        self.assertEqual(m._rdap_base("anything.com"), "https://rdap.verisign.com/com/v1/")
        self.assertEqual(m._rdap_base("google.com.au"), "https://rdap.cctld.au/rdap/")   # https preferred, slash added
        self.assertIsNone(m._rdap_base("example.zz"))

    def test_the_bootstrap_file_is_fetched_once(self):
        m = self._module()
        for d in ("a.com", "b.com", "c.org"):
            m._rdap_base(d)
        self.assertEqual(self.requests.count(sfp_whois.BOOTSTRAP_URL), 1)

    def test_a_tld_without_rdap_falls_back_to_whois(self):
        m = self._module()
        m.handleEvent(self._ev(data="example.zz"))
        self.assertEqual(self.whois_calls, ["example.zz"])
        self.assertEqual(self._of("DOMAIN_REGISTRAR"), ["Old Registrar"])

    def test_an_rdap_miss_falls_back_to_whois(self):
        m = self._module(rdap_code="404")
        m.handleEvent(self._ev())
        self.assertEqual(self.whois_calls, ["example.com"])
        self.assertEqual(len(self._of("DOMAIN_WHOIS")), 1)

    def test_an_unreachable_bootstrap_falls_back_to_whois(self):
        m = self._module(bootstrap=None)
        m.handleEvent(self._ev())
        self.assertEqual(self.whois_calls, ["example.com"])

    def test_too_many_requests_backs_off_that_server(self):
        m = self._module(rdap_code="429")
        m.handleEvent(self._ev(data="a.com"))
        m.handleEvent(self._ev(data="b.com"))
        rdap_requests = [u for u in self.requests if "/domain/" in u]
        self.assertEqual(rdap_requests, ["https://rdap.verisign.com/com/v1/domain/a.com"])   # b.com not asked
        self.assertEqual(self.whois_calls, ["a.com", "b.com"])

    def test_rdap_can_be_turned_off(self):
        m = self._module(use_rdap=False)
        m.handleEvent(self._ev())
        self.assertEqual(self.whois_calls, ["example.com"])
        self.assertFalse([u for u in self.requests if "/domain/" in u])

    def test_a_throttled_whois_answer_is_still_discarded(self):
        m = self._module(rdap_code="404", whois_text="Too many queries")
        m.handleEvent(self._ev())
        self.assertEqual(self.events, [])
        self.assertIn("smaller than 250 bytes", self.errors[0])

    def test_other_domain_event_types_use_rdap_too(self):
        m = self._module()
        m.handleEvent(self._ev("AFFILIATE_DOMAIN_NAME", "example.com"))
        self.assertEqual(len(self._of("AFFILIATE_DOMAIN_WHOIS")), 1)
        self.assertEqual(self.whois_calls, [])

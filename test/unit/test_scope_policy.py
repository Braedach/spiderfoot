from __future__ import annotations

"""Tests for the scope policy (docs/scope-guard-design.md): per search case, the dispatch gate, the egress check and
the consistency of the module classes. Synthetic data only: documentation addresses (RFC 5737) and example names."""

import uuid

import pytest

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootTarget
from spiderfoot.scan import scope_policy as sp
from spiderfoot.scan.scanner import SpiderFootScanner
from test.unit.utils.test_scanner_base import TestScannerBase

IP = "203.0.113.10"
NEIGHBOUR = "203.0.113.11"


def policy_for(value, ttype, mode="enforce", aliases=(), resolver=None, cdn=None, **kw):
    target = SpiderFootTarget(value, ttype)
    for alias_value, alias_type in aliases:
        target.setAlias(alias_value, alias_type)
    return sp.ScopePolicy(target, mode, resolver=resolver, cdn_lookup=cdn, **kw)


# ------------------------------------------------------------------------------------------------ host_of


@pytest.mark.parametrize("value,expected", [
    ("example.com", "example.com"),
    ("Sub.Example.COM", "sub.example.com"),
    ("203.0.113.10", "203.0.113.10"),
    ("203.0.113.10:443", "203.0.113.10"),
    ("203.0.113.10:53/tcp (domain)", "203.0.113.10"),
    ("https://www.example.com/a/b?c=1", "www.example.com"),
    ("http://203.0.113.10:8080/", "203.0.113.10"),
    ("2001:db8::1", "2001:db8::1"),
    ("[2001:db8::1]:443", "2001:db8::1"),
    ("203.0.113.0/24", "203.0.113.0"),
    ("Apache Tomcat language: en", "apache"),   # why only host-carrying event types are judged
    ("", None),
    (None, None),
    (123, None),
])
def test_host_of(value, expected):
    assert sp.host_of(value) == expected


def test_registrable():
    assert sp.registrable("a.b.example.com") == "example.com"
    assert sp.registrable("host.example.com.au") == "example.com.au"
    assert sp.registrable("203.0.113.10") == "203.0.113.10"


# ------------------------------------------------------------------------------------------------ IP target


class TestIpTarget:

    def test_the_address_itself_is_in_scope(self):
        assert policy_for(IP, "IP_ADDRESS").decide(IP).allowed

    def test_a_neighbour_is_not(self):
        d = policy_for(IP, "IP_ADDRESS").decide(NEIGHBOUR)
        assert not d.allowed and "not the target" in d.reason

    def test_a_cdn_range_never_overrides_the_literal_address(self):
        p = policy_for(IP, "IP_ADDRESS", cdn=lambda ip: "SomeCDN")
        assert p.decide(IP).allowed
        assert not p.decide(NEIGHBOUR).allowed

    def test_reverse_dns_name_is_in_scope_but_its_parent_domain_is_not(self):
        p = policy_for(IP, "IP_ADDRESS", aliases=[("host.isp.example", "INTERNET_NAME")])
        assert p.decide("host.isp.example").allowed
        assert p.decide("www.host.isp.example").allowed
        assert not p.decide("isp.example").allowed        # the ISP's whole domain is not authorised

    def test_a_co_hosted_name_is_not_in_scope_unless_it_resolves_to_the_address_now(self):
        stale = policy_for(IP, "IP_ADDRESS", resolver=lambda n: [NEIGHBOUR])
        assert not stale.decide("old-tenant.example").allowed
        live = policy_for(IP, "IP_ADDRESS", resolver=lambda n: [IP])
        assert live.decide("current.example").allowed

    def test_a_resolver_failure_means_not_in_scope(self):
        def boom(name):
            raise OSError("dns down")
        assert not policy_for(IP, "IP_ADDRESS", resolver=boom).decide("x.example").allowed

    def test_resolution_is_cached(self):
        calls = []
        p = policy_for(IP, "IP_ADDRESS", resolver=lambda n: calls.append(n) or [IP])
        p.decide("a.example")
        p.decide("a.example")
        assert calls == ["a.example"]

    def test_the_rc39_incident_shape(self):
        # 193 stale co-hosted names must not be contactable by active modules
        p = policy_for(IP, "IP_ADDRESS", resolver=lambda n: [NEIGHBOUR])
        names = [f"tenant{i}.example" for i in range(193)]
        assert not any(p.decide(n).allowed for n in names)


# ------------------------------------------------------------------------------------------------ netblock / ipv6


class TestNetblockTarget:

    def test_inside_the_block_only(self):
        p = policy_for("198.51.100.0/24", "NETBLOCK_OWNER")
        assert p.decide("198.51.100.77").allowed
        assert not p.decide("198.51.101.1").allowed

    def test_a_name_resolving_into_the_block(self):
        p = policy_for("198.51.100.0/24", "NETBLOCK_OWNER", resolver=lambda n: ["198.51.100.5"])
        assert p.decide("in.example").allowed
        q = policy_for("198.51.100.0/24", "NETBLOCK_OWNER", resolver=lambda n: ["192.0.2.1"])
        assert not q.decide("out.example").allowed

    def test_ipv6_address_target(self):
        p = policy_for("2001:db8::10", "IPV6_ADDRESS")
        assert p.decide("2001:db8::10").allowed
        assert not p.decide("2001:db8::11").allowed


# ------------------------------------------------------------------------------------------------ domain target


class TestDomainTarget:

    def aliases(self):
        return [("example.com", "INTERNET_NAME"), ("192.0.2.5", "IP_ADDRESS")]

    def test_the_name_and_its_subdomains(self):
        p = policy_for("example.com", "INTERNET_NAME", aliases=self.aliases())
        assert p.decide("example.com").allowed
        assert p.decide("deep.sub.example.com").allowed

    def test_affiliates_and_look_alikes_are_not(self):
        p = policy_for("example.com", "INTERNET_NAME", aliases=self.aliases())
        assert not p.decide("example.org").allowed
        assert not p.decide("notexample.com").allowed
        assert not p.decide("third-party.example.net").allowed

    def test_a_resolved_address_is_in_scope(self):
        assert policy_for("example.com", "INTERNET_NAME", aliases=self.aliases()).decide("192.0.2.5").allowed

    def test_an_unrelated_address_is_not(self):
        assert not policy_for("example.com", "INTERNET_NAME", aliases=self.aliases()).decide("192.0.2.99").allowed

    def test_a_shared_edge_address_is_not_contactable_by_address(self):
        p = policy_for("example.com", "INTERNET_NAME", aliases=self.aliases(), cdn=lambda ip: "SomeCDN")
        d = p.decide("192.0.2.5")
        assert not d.allowed and "SomeCDN" in d.reason
        assert p.decide("www.example.com").allowed            # ...but the name still is, as today

    def test_an_address_proven_shared_is_not(self):
        p = policy_for("example.com", "INTERNET_NAME", aliases=self.aliases())
        p.target.markIPShared("192.0.2.5")
        assert not p.decide("192.0.2.5").allowed


# ------------------------------------------------------------------------------------------------ ASN


class TestAsnTarget:

    def test_no_active_contact_without_authorisation(self):
        p = policy_for("AS64496", "BGP_AS_OWNER", aliases=[("192.0.2.5", "IP_ADDRESS")])
        d = p.decide("192.0.2.5")
        assert not d.allowed and "authorisation" in d.reason

    def test_authorised_registered_addresses_only(self):
        p = policy_for("AS64496", "BGP_AS_OWNER", aliases=[("192.0.2.5", "IP_ADDRESS")], asn_authorised=True)
        assert p.decide("192.0.2.5").allowed
        assert not p.decide("192.0.2.6").allowed
        assert not p.decide("example.com").allowed

    def test_the_hard_cap(self):
        aliases = [(f"192.0.2.{i}", "IP_ADDRESS") for i in range(1, 6)]
        p = policy_for("AS64496", "BGP_AS_OWNER", aliases=aliases, asn_authorised=True, asn_max_addresses=3)
        results = [p.decide(f"192.0.2.{i}").allowed for i in range(1, 6)]
        assert results == [True, True, True, False, False]
        assert p.decide("192.0.2.1").allowed                  # an address already contacted stays allowed


# ------------------------------------------------------------------------------------------------ person targets


@pytest.mark.parametrize("ttype,value", [
    ("HUMAN_NAME", "Pat Example"), ("PHONE_NUMBER", "+61400000000"), ("USERNAME", "someuser"),
    ("EMAILADDR", "pat@example.com"), ("BITCOIN_ADDRESS", "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"),
])
def test_person_scans_authorise_no_active_contact(ttype, value):
    p = policy_for(value, ttype)
    for host in (IP, "example.com", "https://www.example.com/x"):
        assert not p.decide(host).allowed


def test_only_host_carrying_event_types_are_judged():
    p = policy_for("Pat Example", "HUMAN_NAME")
    assert p.decide_event("WEBSERVER_BANNER", "Apache Tomcat language: en").allowed     # text, not a host
    assert p.decide_event("HUMAN_NAME", "Pat Example").allowed
    assert not p.decide_event("IP_ADDRESS", IP).allowed
    assert not p.decide_event("LINKED_URL_INTERNAL", "https://example.com/").allowed


# ------------------------------------------------------------------------------------------------ egress


class TestEgress:

    def test_an_active_module_is_held_to_scope(self):
        p = policy_for(IP, "IP_ADDRESS")
        assert p.egress("sfp_sslcert", f"https://{IP}/").allowed
        assert not p.egress("sfp_sslcert", "https://other.example/").allowed

    def test_a_vendor_module_is_never_blocked_for_a_vendor_address(self):
        p = policy_for(IP, "IP_ADDRESS")
        assert p.egress("sfp_shodan", "https://api.shodan.example/host/1").allowed

    def test_a_non_active_module_touching_a_discovered_third_party_is_flagged_for_the_log(self):
        p = policy_for(IP, "IP_ADDRESS")
        p.observe("https://tenant.example/")
        d = p.egress("sfp_some_module", "https://tenant.example/page")
        assert not d.allowed and "log only" in d.reason

    def test_its_own_declared_vendor_domain_is_exempt_even_if_discovered(self):
        p = policy_for(IP, "IP_ADDRESS")
        p.observe("https://www.vendor.example/")
        assert p.egress("sfp_vendor", "https://api.vendor.example/x", ["https://vendor.example"]).allowed

    def test_no_host_means_no_judgement(self):
        assert policy_for(IP, "IP_ADDRESS").egress("sfp_sslcert", None).allowed


# ------------------------------------------------------------------------------------------------ module classes


def _catalog():
    import os
    root = os.path.join(os.path.dirname(os.path.abspath(sp.__file__)), "..", "..", "modules")
    return SpiderFootHelpers.loadModulesAsDict(root, ["sfp_template.py"])


def test_every_invasive_module_is_classed_active():
    invasive = {n for n, i in _catalog().items() if "invasive" in (i.get("meta", {}).get("flags") or [])
                and "deprecated" not in (i.get("meta", {}).get("flags") or [])}
    assert invasive <= sp.ACTIVE_MODULES, f"invasive but not in ACTIVE_MODULES: {sorted(invasive - sp.ACTIVE_MODULES)}"


def test_every_listed_module_exists():
    cat = _catalog()
    missing = sorted((sp.ACTIVE_MODULES | sp.IDENTITY_MODULES) - set(cat))
    assert not missing, missing


def test_active_and_identity_do_not_overlap():
    assert not sp.ACTIVE_MODULES & sp.IDENTITY_MODULES


def test_identity_modules_act_only_on_person_scans_by_default():
    cat = _catalog()
    for name in ("sfp_tool_maigret", "sfp_tool_user_scanner"):
        mod = __import__(f"modules.{name}", fromlist=[name])
        assert getattr(mod, name).opts["person_targets_only"] is True


# ------------------------------------------------------------------------------------------------ scanner gate


class _FakeModule:
    def __init__(self, name, flags=None):
        self.__name__ = name
        self.meta = {"flags": flags or []}


class TestScannerGate(TestScannerBase):

    def _scanner(self, value, ttype, mode):
        scanner = SpiderFootScanner("scope policy test", str(uuid.uuid4()), value, ttype, ["sfp_example"],
                                    self.default_options.copy(), start=False)
        cfg = scanner._SpiderFootScanner__config
        cfg["_strict_scope"] = True
        scanner._SpiderFootScanner__scopePolicy.mode = mode
        return scanner

    def test_sslcert_was_never_gated_and_now_is_in_enforce_mode(self):
        scanner = self._scanner(IP, "IP_ADDRESS", "enforce")
        mod = _FakeModule("sfp_sslcert")                                   # flags: [] as in the real module
        out = SpiderFootEvent("INTERNET_NAME", "tenant.example", "sfp_x", None)
        own = SpiderFootEvent("IP_ADDRESS", IP, "sfp_x", None)
        assert not scanner.shouldDispatchToModule(mod, out)
        assert scanner.shouldDispatchToModule(mod, own)

    def test_log_mode_blocks_nothing_extra_but_records_it(self):
        scanner = self._scanner(IP, "IP_ADDRESS", "log")
        mod = _FakeModule("sfp_sslcert")
        out = SpiderFootEvent("INTERNET_NAME", "tenant.example", "sfp_x", None)
        assert scanner.shouldDispatchToModule(mod, out)
        lines = scanner._SpiderFootScanner__scopePolicy.summary()
        assert lines and "sfp_sslcert" in lines[0] and "would block" in lines[0]

    def test_off_mode_is_the_old_behaviour(self):
        scanner = self._scanner(IP, "IP_ADDRESS", "off")
        out = SpiderFootEvent("INTERNET_NAME", "tenant.example", "sfp_x", None)
        assert scanner.shouldDispatchToModule(_FakeModule("sfp_sslcert"), out)

    def test_passive_and_identity_modules_are_never_affected(self):
        for mode in ("off", "log", "enforce"):
            scanner = self._scanner("Pat Example", "HUMAN_NAME", mode)
            events = [SpiderFootEvent("USERNAME", "someuser", "sfp_x", None),
                      SpiderFootEvent("INTERNET_NAME", "tenant.example", "sfp_x", None),
                      SpiderFootEvent("IP_ADDRESS", NEIGHBOUR, "sfp_x", None),
                      SpiderFootEvent("EMAILADDR", "pat@example.com", "sfp_x", None)]
            for name in ("sfp_shodan", "sfp_hudsonrock", "sfp_accounts", "sfp_tool_maigret", "sfp_tool_user_scanner"):
                for ev in events:
                    assert scanner.shouldDispatchToModule(_FakeModule(name), ev), (mode, name, ev.eventType)

    def test_person_scan_gives_active_modules_nothing_in_enforce_mode(self):
        scanner = self._scanner("Pat Example", "HUMAN_NAME", "enforce")
        ev = SpiderFootEvent("INTERNET_NAME", "example.com", "sfp_x", None)
        assert not scanner.shouldDispatchToModule(_FakeModule("sfp_httpx"), ev)

    def test_an_invasive_module_keeps_its_original_gate_in_every_mode(self):
        for mode in ("off", "log", "enforce"):
            scanner = self._scanner("example.com", "INTERNET_NAME", mode)
            nmap = _FakeModule("sfp_nmap", flags=["invasive"])
            assert not scanner.shouldDispatchToModule(nmap, SpiderFootEvent("IP_ADDRESS", "198.51.100.9", "sfp_x", None))

    def test_the_policy_is_reachable_from_the_target(self):
        scanner = self._scanner(IP, "IP_ADDRESS", "log")
        assert scanner._SpiderFootScanner__target.scopePolicy is scanner._SpiderFootScanner__scopePolicy

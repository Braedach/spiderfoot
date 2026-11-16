"""The AI report's digest, for every search type (domain, IP, netblock, ASN, email, phone, person name). Synthetic scans
only: documentation addresses (RFC 5737) and example names."""
from __future__ import annotations

from itertools import count

from spiderfoot.agents.report_digest import (
    build_digest, make_scope_check, not_tested, render_appendix, render_digest, summarise_log,
)

_n = count(1)


def row(etype, data, module="sfp_test", src="ROOT", risk=0):
    """An event row as SpiderFootDb.scanResultEvent() returns it."""
    return (1.0, data, module, f"h{next(_n)}", etype, src, 100, 100, risk)


def child(parent, etype, data, module="sfp_test"):
    return row(etype, data, module, src=parent[3])


def digest(rows, target, ttype, log=(), modules=None):
    return build_digest(rows, target=target, target_type=ttype, log_entries=log, modules_run=modules)


def types_of(d):
    return {g["type"]: g for g in d["findings"]}


def shown(d, etype):
    return [i["data"] for i in types_of(d)[etype]["shown"]]


# ------------------------------------------------------------------------------------------------ domain


def domain_scan():
    www = row("INTERNET_NAME", "www.example.com", "sfp_dnsresolve")
    other = row("INTERNET_NAME", "tenant.other.net", "sfp_rapiddns")
    ip = child(www, "IP_ADDRESS", "192.0.2.5", "sfp_dnsresolve")
    return [
        row("ROOT", "example.com"), www, other, ip, row("IP_ADDRESS", "192.0.2.99", "sfp_rapiddns"),
        row("TCP_PORT_OPEN", "192.0.2.5:443", "sfp_nmap"), row("TCP_PORT_OPEN", "192.0.2.99:22", "sfp_nmap"),
        row("SSL_CERTIFICATE_EXPIRED", "www.example.com: expired 2026-06-21", "sfp_tool_tlsx"),
        row("INTERESTING_FILE", "https://www.example.com/admin/clients.xls", "sfp_tool_nikto"),
        row("INTERESTING_FILE", "https://www.example.com/pr/report.pdf", "sfp_intfiles"),
        row("INTERESTING_FILE", "https://www.example.com/pr/report.pdf", "sfp_tool_nikto"),
        row("EMAILADDR", "staff@example.com", "sfp_email"), row("AFFILIATE_EMAILADDR", "person@other.net", "sfp_email"),
        row("HUMAN_NAME", "Pat Example", "sfp_names"), row("CO_HOSTED_SITE", "neighbour.example", "sfp_hackertarget"),
        row("SIMILARDOMAIN", "examp1e-lookalike.net", "sfp_tldsearch"),
    ]


def test_domain_scan_keeps_what_is_the_targets_and_counts_the_rest():
    d = digest(domain_scan(), "example.com", "INTERNET_NAME")
    assert shown(d, "INTERNET_NAME") == ["www.example.com"]
    assert shown(d, "IP_ADDRESS") == ["192.0.2.5"]                          # resolved from an in-scope name
    assert shown(d, "TCP_PORT_OPEN") == ["192.0.2.5:443"]
    assert shown(d, "SSL_CERTIFICATE_EXPIRED") == ["www.example.com: expired 2026-06-21"]
    assert d["context_counts"]["TCP_PORT_OPEN"] == 1 and d["context_counts"]["INTERNET_NAME"] == 1
    assert d["context_counts"]["CO_HOSTED_SITE"] == 1 and d["context_counts"]["SIMILARDOMAIN"] == 1


def _sections(text):
    """(in-scope part, context part) of the rendered digest."""
    head, _, rest = text.partition("── RELATED CONTEXT")
    return head, rest


def test_domain_scan_provides_other_peoples_details_but_only_in_their_own_labelled_section():
    """Provide the data, label it, let the model judge: nothing is withheld from the model."""
    text = render_digest(digest(domain_scan(), "example.com", "INTERNET_NAME"))
    findings, rest = _sections(text)
    context, _, third = rest.partition("── THIRD-PARTY PERSONAL DATA")
    assert "person@other.net" in third and "Pat Example" in third             # provided, to the model
    for private in ("person@other.net", "Pat Example"):
        assert private not in findings and private not in context, private    # never mixed into findings or context
    assert "NOT the target's exposure" in third
    for other in ("tenant.other.net", "192.0.2.99", "neighbour.example", "examp1e-lookalike.net"):
        assert other not in findings, other                                  # other hosts never in the findings
        assert other in context or other in third, other                     # but present, as context
    assert "NOT the target" in context
    assert "staff@example.com" in findings                                   # the target's own staff address


def test_a_file_one_heuristic_scanner_reported_alone_is_marked_unverified_and_a_corroborated_one_is_not():
    d = digest(domain_scan(), "example.com", "INTERNET_NAME")
    files = {i["data"]: i for i in types_of(d)["INTERESTING_FILE"]["shown"]}
    assert files["https://www.example.com/admin/clients.xls"]["verified"] is False
    assert files["https://www.example.com/pr/report.pdf"]["verified"] is True
    assert "UNVERIFIED" in render_digest(d)


def test_counts_are_for_the_whole_scan_not_a_sample():
    rows = domain_scan() + [row("LINKED_URL_INTERNAL", f"https://www.example.com/p{i}", "sfp_spider") for i in range(5000)]
    d = digest(rows, "example.com", "INTERNET_NAME")
    assert dict(d["by_type"])["LINKED_URL_INTERNAL"] == 5000 and d["total_events"] == len(rows) - 1   # minus ROOT
    assert dict(d["by_module"])["sfp_spider"] == 5000


# ------------------------------------------------------------------------------------------------ IP address


def ip_scan():
    root = row("ROOT", "203.0.113.10")
    ptr = child(root, "INTERNET_NAME", "host.isp.example", "sfp_dnsresolve")
    neighbour = row("IP_ADDRESS", "203.0.113.55", "sfp_internetdb")
    rows = [root, ptr, neighbour,
            child(neighbour, "GEOINFO", "Melbourne, Victoria, AU", "sfp_ipapico"),
            child(root, "GEOINFO", "Perth, Western Australia, AU", "sfp_ipapico"),
            row("TCP_PORT_OPEN", "203.0.113.10:8080", "sfp_nmap"), row("TCP_PORT_OPEN", "203.0.113.55:445", "sfp_internetdb"),
            row("TCP_PORT_OPEN_BANNER", "203.0.113.10:8080 - Apache Tomcat", "sfp_nmap"),
            row("PROVIDER_HOSTING", "Example ISP", "sfp_hosting"), row("BGP_AS_MEMBER", "64496", "sfp_ripe"),
            row("NETBLOCK_OWNER", "203.0.113.0/24", "sfp_ripe"), row("COUNTRY_NAME", "Australia", "sfp_countryname"),
            child(neighbour, "VULNERABILITY_CVE_HIGH", "CVE-2026-0001", "sfp_internetdb"),
            child(root, "VULNERABILITY_CVE_LOW", "CVE-2026-0002", "sfp_internetdb")]
    rows += [row("CO_HOSTED_SITE", f"tenant{i}.example", "sfp_rapiddns") for i in range(193)]
    rows += [row("INTERNET_NAME", f"stale{i}.example", "sfp_rapiddns") for i in range(40)]
    return rows


def test_ip_scan_reports_the_address_and_its_network_and_reduces_193_neighbours_to_a_count():
    """The rc.39 incident shape: the report was 95% about other organisations."""
    d = digest(ip_scan(), "203.0.113.10", "IP_ADDRESS")
    assert shown(d, "TCP_PORT_OPEN") == ["203.0.113.10:8080"]
    assert shown(d, "INTERNET_NAME") == ["host.isp.example"]                 # the reverse-DNS name only
    assert shown(d, "PROVIDER_HOSTING") == ["Example ISP"] and shown(d, "BGP_AS_MEMBER") == ["64496"]
    assert shown(d, "NETBLOCK_OWNER") == ["203.0.113.0/24"]
    assert d["context_counts"]["CO_HOSTED_SITE"] == 193 and d["context_counts"]["INTERNET_NAME"] == 40
    assert d["context_counts"]["TCP_PORT_OPEN"] == 1
    findings, context = _sections(render_digest(d))
    assert "tenant0.example" not in findings and "stale0.example" not in findings and "203.0.113.55" not in findings
    assert "tenant0.example" in context and "tenant99.example" in context     # the first 100 co-hosted sites are listed
    assert "… 93 more (see Appendix A)" in context                            # the rest are counted, and all are in the appendix
    assert "stale39.example" in context                                      # all 40 related names fit


def test_a_finding_is_judged_by_the_host_it_was_found_on_not_by_what_its_text_says():
    """The rc.39 IP report listed CVEs and locations of neighbouring organisations as the target's findings."""
    d = digest(ip_scan(), "203.0.113.10", "IP_ADDRESS")
    assert "VULNERABILITY_CVE_HIGH" not in types_of(d)                      # found on a neighbour: context
    assert shown(d, "VULNERABILITY_CVE_LOW") == ["CVE-2026-0002"]           # found on the target: a finding
    assert shown(d, "GEOINFO") == ["Perth, Western Australia, AU"]
    findings, context = _sections(render_digest(d))
    assert "Melbourne" not in findings and "CVE-2026-0001" not in findings
    assert "CVE-2026-0001" in context and "Melbourne" in context            # still available to mention as context


# ------------------------------------------------------------------------------------------------ netblock and ASN


def test_netblock_scan_scope_is_the_block():
    rows = [row("ROOT", "198.51.100.0/24"), row("TCP_PORT_OPEN", "198.51.100.7:22", "sfp_nmap"),
            row("TCP_PORT_OPEN", "198.51.101.7:22", "sfp_nmap"), row("IP_ADDRESS", "198.51.100.7", "sfp_dnsresolve")]
    d = digest(rows, "198.51.100.0/24", "NETBLOCK_OWNER")
    assert shown(d, "TCP_PORT_OPEN") == ["198.51.100.7:22"] and d["context_counts"]["TCP_PORT_OPEN"] == 1


def test_asn_scan_reports_registry_facts_as_the_targets_own_and_treats_every_host_as_context():
    rows = [row("ROOT", "AS64496"), row("BGP_AS_OWNER", "64496", "sfp_ripe"),
            row("NETBLOCK_OWNER", "192.0.2.0/24", "sfp_ripe"), row("NETBLOCK_OWNER", "198.51.100.0/24", "sfp_ripe"),
            row("NETBLOCK_WHOIS", "netname: EXAMPLE-NET country: AU", "sfp_whois"),
            row("COMPANY_NAME", "Example Networks Pty Ltd", "sfp_company"),
            row("TCP_PORT_OPEN", "192.0.2.9:80", "sfp_internetdb")]
    d = digest(rows, "AS64496", "BGP_AS_OWNER")
    assert shown(d, "NETBLOCK_OWNER") == ["192.0.2.0/24", "198.51.100.0/24"]
    assert shown(d, "COMPANY_NAME") == ["Example Networks Pty Ltd"] and shown(d, "BGP_AS_OWNER") == ["64496"]
    assert "TCP_PORT_OPEN" not in types_of(d) and d["context_counts"]["TCP_PORT_OPEN"] == 1
    assert any("application layer was not tested" in line for line in d["not_tested"])


# ------------------------------------------------------------------------------------------------ people


def email_scan():
    return [row("ROOT", "pat@example.com"), row("EMAILADDR", "pat@example.com", "SpiderFoot UI"),
            row("USERNAME", "patexample", "sfp_gravatar"), row("USERNAME", "pat", "sfp_tool_user_scanner"),
            row("ACCOUNT_EXTERNAL_OWNED", "Gravatar (Category: social)", "sfp_gravatar"),
            row("ACCOUNT_EXTERNAL_OWNED", "GitHub (Category: coding)", "sfp_accounts"),
            row("ACCOUNT_EXTERNAL_OWNED", "GitHub (Category: coding)", "sfp_tool_maigret"),
            row("RAW_RIR_DATA", '{"tool": "maigret", "site": "GitHub", "details": {"name": "Pat Example"}}', "sfp_tool_maigret"),
            row("RAW_RIR_DATA", '{"huge": "nmap blob"}', "sfp_nmap")]


def test_email_scan_lists_the_targets_accounts_usernames_and_the_structured_records():
    d = digest(email_scan(), "pat@example.com", "EMAILADDR")
    assert {a["data"] for a in d["own_addresses"]} == {"pat@example.com", "patexample", "pat"}
    assert shown(d, "ACCOUNT_EXTERNAL_OWNED") == ["Gravatar (Category: social)", "GitHub (Category: coding)"]
    assert [r["module"] for r in d["records"]] == ["sfp_tool_maigret"]       # a port scanner's blob is not a record
    text = render_digest(d)
    assert "STRUCTURED RECORDS" in text and "Pat Example" in text


def test_a_username_match_is_marked_unconfirmed_for_every_person_search():
    for ttype, target in (("EMAILADDR", "pat@example.com"), ("HUMAN_NAME", "Pat Example"), ("PHONE_NUMBER", "+61400000000"),
                          ("USERNAME", "patexample")):
        assert any("unconfirmed" in line for line in not_tested(set(), ttype)), ttype
        assert "unconfirmed" in render_digest(digest([row("ROOT", target)], target, ttype)).lower()


def test_phone_scan_keeps_the_phone_record_and_telco_facts():
    rec = ('{"number": "+61412345678", "valid": true, "line_type": "Mobile", "carrier": "Example Telco", '
           '"note": "original allocation"}')
    rows = [row("ROOT", "+61412345678"), row("PHONE_NUMBER", "+61412345678", "SpiderFoot UI"),
            row("PROVIDER_TELCO", "Example Telco", "sfp_phone"), row("PHONE_NUMBER_TYPE", "Mobile", "sfp_phone"),
            row("COUNTRY_NAME", "Australia", "sfp_countryname"), row("RAW_RIR_DATA", rec, "sfp_phone")]
    d = digest(rows, "+61412345678", "PHONE_NUMBER")
    assert shown(d, "PROVIDER_TELCO") == ["Example Telco"] and shown(d, "PHONE_NUMBER_TYPE") == ["Mobile"]
    assert d["records"][0]["module"] == "sfp_phone" and "original allocation" in d["records"][0]["data"]
    assert {a["data"] for a in d["own_addresses"]} == {"+61412345678"}


def test_name_scan_lists_every_account_up_to_the_cap_and_reports_the_exact_total_beyond_it():
    rows = [row("ROOT", "Pat Example")] + [row("ACCOUNT_EXTERNAL_OWNED", f"Site{i} (Category: social)", "sfp_accounts")
                                           for i in range(250)]
    d = digest(rows, "Pat Example", "HUMAN_NAME")
    group = types_of(d)["ACCOUNT_EXTERNAL_OWNED"]
    assert group["total"] == 250 and len(group["shown"]) == 200
    assert "and 50 more of this type (see Appendix A)" in render_digest(d)
    assert "Site249 (Category: social)" in render_appendix(d)                  # the appendix has all 250
    small = digest(rows[:114], "Pat Example", "HUMAN_NAME")                    # 113 accounts: all listed, none cut
    assert len(types_of(small)["ACCOUNT_EXTERNAL_OWNED"]["shown"]) == 113


def test_a_person_scans_hosts_are_all_context():
    rows = [row("ROOT", "Pat Example"), row("INTERNET_NAME", "pat-example.example", "sfp_accounts"),
            row("TCP_PORT_OPEN", "192.0.2.1:80", "sfp_internetdb")]
    d = digest(rows, "Pat Example", "HUMAN_NAME")
    assert "TCP_PORT_OPEN" not in types_of(d) and d["context_counts"]["TCP_PORT_OPEN"] == 1


# ------------------------------------------------------------------------------------------------ limitations, not tested


def test_the_scan_logs_failures_are_summarised_with_repeats_grouped():
    log = [(1, "plugin", "ERROR", f"No response from crt.sh for certificate {i}") for i in range(40)]
    log += [(2, "plugin", "WARNING", "Gobuster execution timed out after 300s")] * 3
    log += [(3, "core", "STATUS", "Scan initiated"), (4, "plugin", "ERROR", "Full traceback: Traceback ...")]
    assert summarise_log(log) == [(40, "No response from crt.sh for certificate #"),
                                  (3, "Gobuster execution timed out after #s")]
    text = render_digest(digest(domain_scan(), "example.com", "INTERNET_NAME", log=log))
    assert "40 x No response from crt.sh" in text and "COVERAGE AND LIMITATIONS" in text


def test_a_clean_log_says_so():
    assert "no errors or warnings were logged" in render_digest(digest(domain_scan(), "example.com", "INTERNET_NAME"))


def test_application_testing_is_reported_as_not_done_unless_a_tool_for_it_ran():
    assert any("application layer was not tested" in x for x in not_tested({"sfp_nmap"}, "INTERNET_NAME"))
    assert any("application layer was not tested" in x for x in not_tested({"sfp_nmap"}, "IP_ADDRESS"))
    assert not any("application layer" in x for x in not_tested({"sfp_tool_dalfox"}, "INTERNET_NAME"))
    assert not any("application layer" in x for x in not_tested(set(), "PHONE_NUMBER"))     # not a web target


def test_no_breach_source_is_reported_for_people_and_domains_but_not_when_one_ran():
    assert any("breach or leak database" in x for x in not_tested(set(), "EMAILADDR"))
    assert not any("breach or leak database" in x for x in not_tested({"sfp_hudsonrock"}, "EMAILADDR"))
    assert not any("breach or leak database" in x for x in not_tested(set(), "IP_ADDRESS"))


def test_junk_rows_and_the_root_event_are_ignored():
    d = digest([None, (), row("ROOT", "example.com"), row("INTERNET_NAME", "www.example.com")], "example.com", "INTERNET_NAME")
    assert d["total_events"] == 1


def test_an_unknown_target_type_treats_every_host_as_context_and_does_not_crash():
    d = digest([row("TCP_PORT_OPEN", "192.0.2.1:80")], "x", "SOMETHING_NEW")
    assert d["context_counts"]["TCP_PORT_OPEN"] == 1


def test_scope_check_for_a_domain_includes_subdomains_but_not_look_alikes():
    check = make_scope_check("example.com", "INTERNET_NAME", [])
    assert check("example.com") and check("a.b.example.com")
    assert not check("notexample.com") and not check("example.com.evil.test") and not check("")


def test_every_event_is_in_exactly_one_bucket_and_the_buckets_add_up_to_the_scan():
    for rows, target, ttype in ((domain_scan(), "example.com", "INTERNET_NAME"), (ip_scan(), "203.0.113.10", "IP_ADDRESS"),
                                (email_scan(), "pat@example.com", "EMAILADDR")):
        d = digest(rows, target, ttype)
        assert sum(d["accounting"].values()) == d["total_events"], (ttype, d["accounting"])


def test_the_digest_says_how_the_events_were_accounted_for():
    text = render_digest(digest(domain_scan(), "example.com", "INTERNET_NAME"))
    assert "ACCOUNTING" in text and "third-party personal data (labelled): 2" in text


def test_a_small_budget_drops_nothing_silently_it_counts_what_did_not_fit():
    d = digest(ip_scan(), "203.0.113.10", "IP_ADDRESS")
    small = render_digest(d, max_chars=3000)
    assert "SIZE LIMIT" in small and "did not fit in this digest" in small
    assert "ACCOUNTING" in small and "WHAT THIS SCAN DID NOT TEST" in small      # the mandatory parts always survive
    big = render_digest(d, max_chars=400000)
    assert "SIZE LIMIT" not in big and "tenant0.example" in big


def test_the_appendix_lists_every_in_scope_item_and_every_related_host():
    d = digest(ip_scan(), "203.0.113.10", "IP_ADDRESS")
    appendix = render_appendix(d)
    assert "203.0.113.10:8080" in appendix and "host.isp.example" in appendix
    assert all(f"tenant{i}.example" in appendix for i in range(193))         # all 193 neighbours, not a sample
    assert "left out of this appendix" not in appendix


def test_an_appendix_that_has_to_be_cut_says_exactly_how_much_was_cut():
    d = digest(ip_scan(), "203.0.113.10", "IP_ADDRESS")
    cut = render_appendix(d, max_lines=50)
    assert "were left out of this appendix for length" in cut and "still in the scan results" in cut


def test_the_appendix_never_lists_third_party_personal_data_and_says_it_was_withheld():
    appendix = render_appendix(digest(domain_scan(), "example.com", "INTERNET_NAME"))
    assert "person@other.net" not in appendix and "Pat Example" not in appendix
    assert "Withheld on purpose" in appendix and "remain in the scan results" in appendix

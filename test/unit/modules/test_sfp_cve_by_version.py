"""sfp_cve_by_version: versions from banners or the owner's declared list, matched by the databases, reported with caveats."""
from unittest.mock import MagicMock

from spiderfoot import SpiderFootEvent
from modules.sfp_cve_by_version import (
    parse_software, parse_declared, version_matches, read_github_advisories, read_nvd_cve, read_osv, cvss_rating, sfp_cve_by_version,
)

NVD_ITEM = {"cve": {"id": "CVE-2026-114938", "cisaExploitAdd": "2026-11-01",
                    "descriptions": [{"lang": "en", "value": "Remote   code execution\nin the importer."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}}


def make(**opts):
    m = sfp_cve_by_version()
    m.sf = MagicMock()
    m.opts = dict(sfp_cve_by_version.opts, **opts)
    m.results = {}
    m._warned = set()
    m._lookups = 0
    m._declared = None
    m.errorState = False
    m.notifyListeners = MagicMock()
    m.__name__ = "sfp_cve_by_version"
    return m


def ev(etype, data):
    return SpiderFootEvent(etype, data, "sfp_test", None)


def sent(m):
    return [c.args[0] for c in m.notifyListeners.call_args_list]


def test_parse_software_reads_banners_and_skips_noise():
    assert parse_software("nginx/1.18.0 (Ubuntu)") == [("nginx", "1.18.0")]
    assert parse_software("Apache/2.4.49 OpenSSL/1.1.1k PHP/7.4.3") == [("apache", "2.4.49"), ("openssl", "1.1.1k"), ("php", "7.4.3")]
    assert parse_software("jQuery 3.4.1") == [("jquery", "3.4.1")]
    assert parse_software("TLSv1.3 HTTP/1.1 Mozilla/5.0") == []
    assert parse_software("no version here") == []


def test_parse_declared_ignores_comments_and_incomplete_lines():
    rows = parse_declared("# note\nGrimmory.Example.org | grimmory | 3.5.0 | | pkg:maven/org.grimmory/grimmory\nbroken | line\n")
    assert rows == [{"host": "grimmory.example.org", "product": "grimmory", "version": "3.5.0", "vendor": "", "purl": "pkg:maven/org.grimmory/grimmory"}]


def test_nvd_record_reduced_with_score_summary_and_kev():
    cve = read_nvd_cve(NVD_ITEM)
    assert cve["id"] == "CVE-2026-114938" and cve["score"] == 9.8 and cve["kev"] is True
    assert cve["summary"] == "Remote code execution in the importer."
    assert cvss_rating(9.8) == "CRITICAL" and cvss_rating(7.0) == "HIGH" and cvss_rating(4.0) == "MEDIUM" and cvss_rating(0.1) == "LOW"
    assert cvss_rating(None) is None


def test_osv_record_uses_cve_alias_and_lists_fixed_versions():
    cve = read_osv({"id": "GHSA-xxxx", "aliases": ["CVE-2026-114938"], "summary": "Importer RCE",
                    "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.5.1"}]}]}]})
    assert cve["id"] == "CVE-2026-114938" and cve["fixed"] == ["3.5.1"] and cve["source"] == "OSV"


def test_declared_version_is_looked_up_and_reported_with_fix_and_caveat():
    m = make(declared_software="grimmory.example.org | grimmory | 3.5.0 | grimmory | pkg:maven/org.grimmory/grimmory")
    m.nvd_cves = MagicMock(return_value=[read_nvd_cve(NVD_ITEM)])
    m.osv_cves = MagicMock(return_value=[read_osv({"id": "GHSA-1", "aliases": ["CVE-2026-114938"],
                                                     "affected": [{"ranges": [{"events": [{"fixed": "3.5.1"}]}]}]})])
    m.handleEvent(ev("INTERNET_NAME", "grimmory.example.org"))
    events = sent(m)
    cves = [e for e in events if e.eventType == "VULNERABILITY_CVE_CRITICAL"]
    assert len(cves) == 1                     # NVD and OSV agree on one CVE: reported once
    text = cves[0].data
    assert "CVE-2026-114938" in text and "known to be exploited" in text and "grimmory 3.5.0" in text
    assert "declared by the owner" in text and "backported" in text
    m.nvd_cves.assert_called_once_with("grimmory", "grimmory", "3.5.0")


def test_fixed_version_reports_nothing():
    m = make(declared_software="grimmory.example.org | grimmory | 3.5.1 | grimmory")
    m.nvd_cves = MagicMock(return_value=[])
    m.handleEvent(ev("INTERNET_NAME", "grimmory.example.org"))
    assert sent(m) == []


def test_declared_software_for_another_host_is_ignored():
    m = make(declared_software="other.example.org | grimmory | 3.5.0 | grimmory")
    m.nvd_cves = MagicMock(return_value=[read_nvd_cve(NVD_ITEM)])
    m.handleEvent(ev("INTERNET_NAME", "grimmory.example.org"))
    m.nvd_cves.assert_not_called()


def test_banner_version_looked_up_once_with_any_vendor():
    m = make()
    m.nvd_cves = MagicMock(return_value=[read_nvd_cve(NVD_ITEM)])
    m.handleEvent(ev("WEBSERVER_BANNER", "nginx/1.18.0"))
    m.handleEvent(ev("WEBSERVER_BANNER", "nginx/1.18.0"))
    m.nvd_cves.assert_called_once_with("*", "nginx", "1.18.0")
    assert len([e for e in sent(m) if e.eventType == "VULNERABILITY_CVE_CRITICAL"]) == 1


def test_banner_names_are_mapped_to_nvd_products():
    m = make()
    m.nvd_cves = MagicMock(return_value=[])
    m.handleEvent(ev("WEBSERVER_BANNER", "Apache/2.4.49 (Unix)"))
    m.nvd_cves.assert_called_once_with("apache", "http_server", "2.4.49")


def test_rate_limit_is_reported_once_not_silently_swallowed():
    m = make()
    m.error = MagicMock()
    m.sf.fetchUrl = MagicMock(return_value={"code": "403", "content": "rate limit"})
    assert m.github_cves("o/r", "r", "1.0") == [] and m.github_cves("o/r", "r", "1.0") == []
    m.error.assert_called_once()
    assert "rate limited" in m.error.call_args.args[0]


def test_lookup_budget_and_per_product_cap():
    m = make(max_lookups=1, max_per_product=2)
    many = [{"id": f"CVE-2026-{i}", "score": float(i), "summary": "", "kev": False, "source": "NVD"} for i in range(1, 6)]
    m.nvd_cves = MagicMock(return_value=many)
    m.handleEvent(ev("WEBSERVER_BANNER", "nginx/1.18.0"))
    m.handleEvent(ev("WEBSERVER_BANNER", "apache/2.4.1"))
    cve_events = [e for e in sent(m) if e.eventType.startswith("VULNERABILITY_CVE_")]
    assert [e.data.split()[0] for e in cve_events] == ["CVE-2026-5", "CVE-2026-4"]   # highest score first; second product skipped
    assert m.nvd_cves.call_count == 1


def test_unrecognised_event_data_does_nothing():
    m = make()
    m.nvd_cves = MagicMock()
    m.handleEvent(ev("WEBSERVER_TECHNOLOGY", "Angular"))
    m.nvd_cves.assert_not_called()


# advisories as GitHub publishes them for grimmory (trimmed)
GRIMMORY = [
    {"ghsa_id": "GHSA-mx77", "cve_id": None, "severity": "low", "summary": "ReDoS in epub parsing", "vulnerabilities": [
        {"package": {"ecosystem": "maven", "name": "org.grimmory:epub4j-core"}, "vulnerable_version_range": ">= 1.0.0", "patched_versions": "2.1.0"},
        {"package": {"ecosystem": "other", "name": "grimmory"}, "vulnerable_version_range": "<= 3.4.1", "patched_versions": "3.5.0"}]},
    {"ghsa_id": "GHSA-7f4w", "cve_id": None, "severity": "medium", "summary": "IDOR upload", "vulnerabilities": [
        {"package": {"ecosystem": "docker", "name": "ghcr.io/grimmory-tools/grimmory"}, "vulnerable_version_range": "<=3.4.1", "patched_versions": "3.5.0"}]},
    {"ghsa_id": "GHSA-frv6", "cve_id": "CVE-2026-42451", "severity": "medium", "summary": "Stored XSS", "vulnerabilities": [
        {"package": {"ecosystem": "docker", "name": "ghcr.io/grimmory-tools/grimmory"}, "vulnerable_version_range": "<=2.3.0", "patched_versions": "2.3.1"}]},
]


def test_version_ranges():
    assert version_matches("3.4.1", "<= 3.4.1") and not version_matches("3.5.0", "<= 3.4.1")
    assert version_matches("1.5", ">= 1.0.0, < 2.1.0") and not version_matches("2.1.0", ">= 1.0.0, < 2.1.0")
    assert version_matches("3.4", "= 3.4.0") and version_matches("3.5.0", "<=3.5.0")
    assert not version_matches("3.5.0", "garbled") and not version_matches("", "<= 1") and not version_matches("x", "<= 1")


def test_github_advisories_match_the_product_not_its_libraries():
    got = read_github_advisories(GRIMMORY, "grimmory", "3.4.1")
    assert [c["id"] for c in got] == ["GHSA-mx77", "GHSA-7f4w"]                 # the epub library range alone would match 3.4.1 too
    assert got[0]["fixed"] == ["3.5.0"] and got[0]["source"] == "GitHub advisories"
    assert read_github_advisories(GRIMMORY, "grimmory", "3.5.0") == []           # 3.5.0 is outside every published range
    assert [c["id"] for c in read_github_advisories(GRIMMORY, "grimmory", "2.0.0")] == ["GHSA-mx77", "GHSA-7f4w", "CVE-2026-42451"]


def test_declared_github_source_is_used_for_the_declared_version():
    m = make(declared_software="g.example.org | grimmory | 3.4.1 | | github:grimmory-tools/grimmory", use_nvd=False)
    m.github_cves = MagicMock(return_value=read_github_advisories(GRIMMORY, "grimmory", "3.4.1"))
    m.handleEvent(ev("INTERNET_NAME", "g.example.org"))
    m.github_cves.assert_called_once_with("grimmory-tools/grimmory", "grimmory", "3.4.1")
    assert len(sent(m)) == 3          # two advisories plus the summary record
    assert "Fixed in: 3.5.0" in sent(m)[0].data

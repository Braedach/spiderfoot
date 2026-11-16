"""Cross-scan subject links (spiderfoot.agents.subject_links)."""
from __future__ import annotations

from spiderfoot.agents import subject_links as sl


def row(etype, data):
    return (0, data, "sfp_x", "h" + etype + data, etype, "src", 100, 0, 0)


NAME = {"scan_id": "N", "target": "Pat Example", "target_type": "HUMAN_NAME",
        "rows": [row("EMAILADDR", "Pat@Example.org"), row("PHONE_NUMBER", "+61 400 000 001"),
                 row("USERNAME", "patex"), row("ACCOUNT_EXTERNAL_OWNED", "GitHub (Category: coding)\n<SFURL>https://github.com/patex</SFURL>")]}
EMAIL = {"scan_id": "E", "target": "pat@example.org", "target_type": "EMAILADDR",
         "rows": [row("USERNAME", "PATEX"), row("HUMAN_NAME", "Example Pat"), row("ACCOUNT_EXTERNAL_OWNED", "GitHub (Category: coding)\n<SFURL>https://www.github.com/patex/</SFURL>"),
                  row("USERNAME", "other")]}
PHONE = {"scan_id": "P", "target": "0400 000 001", "target_type": "PHONE_NUMBER", "rows": [row("EMAILADDR", "nobody@example.net")]}


def test_normalising_makes_different_writings_equal():
    assert sl.normalise("email address", "Pat@Example.ORG") == "pat@example.org"
    assert sl.normalise("phone number", "+61 400 000 001") == sl.normalise("phone number", "0400000001")
    assert sl.normalise("name", "Pat  Example") == sl.normalise("name", "example, PAT")
    assert sl.normalise("account", "x\n<SFURL>https://www.GitHub.com/patex/</SFURL>") == "github.com/patex"
    assert sl.normalise("phone number", "123") == ""        # too short to compare


def test_a_scans_target_found_in_another_scan_is_a_target_link():
    r = sl.link_scans([NAME, EMAIL, PHONE])
    pairs = {(t["kind"], t["target_of"], t["found_in"]) for t in r["target_links"]}
    assert ("email address", "E", "N") in pairs               # the email scan's target is in the name scan's data
    assert ("phone number", "P", "N") in pairs                # phone written differently, same number
    assert ("name", "N", "E") in pairs                        # the name (any word order) is in the email scan's data


def test_identifiers_found_by_two_scans_are_shared_but_one_scan_only_items_are_not():
    r = sl.link_scans([NAME, EMAIL, PHONE])
    shared = {(e["kind"], tuple(sorted(e["scans"]))) for e in r["shared"]}
    assert ("username", ("E", "N")) in shared
    assert ("account", ("E", "N")) in shared
    assert not any("other" == e["value"].lower() for e in r["shared"])
    assert not any("nobody" in e["value"] for e in r["shared"])


def test_target_links_are_not_repeated_in_the_shared_list():
    r = sl.link_scans([NAME, EMAIL])
    values = [e["value"].lower() for e in r["shared"]]
    assert "pat@example.org" not in values


def test_unrelated_scans_have_no_links():
    a = {"scan_id": "A", "target": "a@example.org", "target_type": "EMAILADDR", "rows": [row("USERNAME", "aaa")]}
    b = {"scan_id": "B", "target": "b@example.org", "target_type": "EMAILADDR", "rows": [row("USERNAME", "bbb")]}
    r = sl.link_scans([a, b])
    assert r["target_links"] == [] and r["shared"] == []
    assert "No identifier appears in more than one" in sl.render_links(r, "x", "A")


def test_a_domain_scan_links_by_shared_accounts_only():
    d = {"scan_id": "D", "target": "example.org", "target_type": "INTERNET_NAME", "rows": [row("EMAILADDR", "pat@example.org")]}
    r = sl.link_scans([d, EMAIL])
    assert r["target_links"] == [{"kind": "email address", "value": "pat@example.org", "target_of": "E", "found_in": "D"}]


def test_malformed_rows_are_ignored():
    r = sl.link_scans([{"scan_id": "A", "target": "x", "target_type": "HUMAN_NAME", "rows": [None, (1,), "junk"]},
                       {"scan_id": "B", "target": "y", "target_type": "HUMAN_NAME", "rows": []}])
    assert r["shared"] == []


def test_the_rendering_names_every_scan_and_every_link():
    text = sl.render_links(sl.link_scans([NAME, EMAIL, PHONE]), "pat", "N")
    for needle in ("label: pat", "scan N", "scan E", "scan P", "found in scan", "Found by more than one scan", "github.com/patex"):
        assert needle in text or needle.lower() in text.lower(), needle


def test_shared_list_is_capped_but_counted():
    many = [row("USERNAME", f"u{i}") for i in range(sl.MAX_LINKS + 20)]
    a = {"scan_id": "A", "target": "a", "target_type": "USERNAME", "rows": many}
    b = {"scan_id": "B", "target": "b", "target_type": "USERNAME", "rows": many}
    r = sl.link_scans([a, b])
    assert len(r["shared"]) == sl.MAX_LINKS and r["shared_total"] == sl.MAX_LINKS + 20


# --- the database side --------------------------------------------------------------------------------------------
class FakeDb:
    def __init__(self, configs, instances, events):
        self.configs, self.instances, self.events = configs, instances, events

    def scanConfigGet(self, sid):
        return self.configs.get(sid, {})

    def scanInstanceList(self):
        return self.instances

    def scanResultEvent(self, sid):
        return self.events.get(sid, [])


def test_scans_with_the_same_label_are_linked_and_others_are_not():
    from spiderfoot.agents.report_generator import _subject_links_text
    db = FakeDb(
        {"N": {"_subject_label": "Pat"}, "E": {"_subject_label": "pat"}, "X": {"_subject_label": "someone"}, "Y": {}},
        [("N", "n", "Pat Example"), ("E", "e", "pat@example.org"), ("X", "x", "x@example.org"), ("Y", "y", "y@example.org")],
        {"N": NAME["rows"], "E": EMAIL["rows"], "X": [row("EMAILADDR", "pat@example.org")], "Y": []},
    )
    text = _subject_links_text(db, ["N"], "Pat Example")
    assert "scan E" in text and "scan X" not in text and "scan Y" not in text


def test_no_label_means_no_section_and_a_failure_never_raises():
    from spiderfoot.agents.report_generator import _subject_links_text
    assert _subject_links_text(FakeDb({"N": {}}, [], {}), ["N"], "t") == ""
    class Boom(FakeDb):
        def scanConfigGet(self, sid):
            raise RuntimeError("db down")
    assert _subject_links_text(Boom({}, [], {}), ["N"], "t") == ""


def test_a_label_with_no_other_scan_gives_no_section():
    from spiderfoot.agents.report_generator import _subject_links_text
    db = FakeDb({"N": {"_subject_label": "pat"}}, [("N", "n", "Pat Example")], {"N": NAME["rows"]})
    assert _subject_links_text(db, ["N"], "Pat Example") == ""


def test_the_scan_request_stores_the_label():
    from spiderfoot.api.routers.scan import ScanRequest, _subject_context
    req = ScanRequest(name="s", target="Pat Example", subject_label="  pat   one ")
    assert _subject_context(req) == {"_subject_label": "pat one"}

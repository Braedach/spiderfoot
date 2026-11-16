"""Confidence for the accounts a person search finds. Synthetic data only (example names, hosts and numbers)."""
from __future__ import annotations

import json
from itertools import count

from spiderfoot.agents.hit_scoring import parse_account, score_accounts, summarise

_n = count(1)


def row(etype, data, module="sfp_test", src="ROOT"):
    return (1.0, data, module, f"h{next(_n)}", etype, src, 100, 100, 0)


def child(parent, etype, data, module="sfp_test"):
    return row(etype, data, module, src=parent[3])


def account(site, url, category="social", countries=(), weak=False):
    text = f"{site} (Category: {category})\n<SFURL>{url}</SFURL>"
    if countries:
        text += f"\n(site countries: {', '.join(countries)})"
    if weak:
        text += "\n(weak evidence: this check requests the site's search page, not a profile)"
    return text


def record(url, **details):
    return json.dumps({"tool": "maigret", "site": "x", "url": url, "details": details})


def label_of(scored, site):
    return next(a for a in scored if a["site"] == site)


# ------------------------------------------------------------------------------------------------ parsing


def test_an_account_event_is_parsed():
    a = parse_account(account("ExampleSocial", "https://social.example/pat", "social, forum", ("PL", "CZ"), weak=True))
    assert a == {"site": "ExampleSocial", "url": "https://social.example/pat", "category": "social, forum",
                 "countries": ["PL", "CZ"], "weak": True}
    assert parse_account("plain text")["site"] == "plain text"


# ------------------------------------------------------------------------------------------------ the labels


def test_a_site_that_confirmed_the_exact_email_address_is_confirmed():
    email = row("EMAILADDR", "pat@example.com", "SpiderFoot UI")
    rows = [email, child(email, "ACCOUNT_EXTERNAL_OWNED", account("ExampleShop", "https://shop.example/"), "sfp_tool_user_scanner")]
    a = label_of(score_accounts(rows, target="pat@example.com", target_type="EMAILADDR"), "ExampleShop")
    assert a["label"] == "Confirmed" and "exact email address is registered" in a["reasons"][0]


def test_a_profile_that_publishes_the_email_or_the_phone_number_is_confirmed():
    url = "https://social.example/pat"
    rows = [row("ACCOUNT_EXTERNAL_OWNED", account("ExampleSocial", url), "sfp_tool_maigret"),
            row("RAW_RIR_DATA", record(url, bio="contact pat@example.com"), "sfp_tool_maigret")]
    assert label_of(score_accounts(rows, target="pat@example.com", target_type="EMAILADDR"), "ExampleSocial")["label"] == "Confirmed"
    rows[1] = row("RAW_RIR_DATA", record(url, bio="call +61 8 9234 5678"), "sfp_tool_maigret")
    assert label_of(score_accounts(rows, target="+61892345678", target_type="PHONE_NUMBER"), "ExampleSocial")["label"] == "Confirmed"


def test_the_same_profile_name_alone_is_not_enough_because_names_are_common():
    url = "https://social.example/pat"
    rows = [row("ACCOUNT_EXTERNAL_OWNED", account("ExampleSocial", url), "sfp_tool_maigret"),
            row("RAW_RIR_DATA", record(url, fullname="Example Pat Marcus"), "sfp_tool_maigret")]
    a = label_of(score_accounts(rows, target="Pat Marcus Example", target_type="HUMAN_NAME"), "ExampleSocial")
    assert a["label"] == "Unconfirmed" and "the same name" in a["reasons"][0] and "names and handles are common" in a["reasons"][0]


def test_the_same_name_and_a_matching_place_together_are_likely():
    url = "https://social.example/pat"
    rows = [row("ACCOUNT_EXTERNAL_OWNED", account("ExampleSocial", url), "sfp_tool_maigret"),
            row("RAW_RIR_DATA", record(url, fullname="Pat Example", location="Perth, Australia"), "sfp_tool_maigret")]
    a = label_of(score_accounts(rows, target="Pat Example", target_type="HUMAN_NAME", context={"country": "Australia", "region": "Perth"}),
                 "ExampleSocial")
    assert a["label"] == "Likely" and len(a["reasons"]) == 2


def test_a_similar_but_different_name_is_not_a_match():
    """The real case: a profile named 'Leonmarcus Scott' for the target 'Leon Marcus Scott' (username ending .9)."""
    url = "https://social.example/leon.marcus.scott"
    rows = [row("ACCOUNT_EXTERNAL_OWNED", account("ExampleSocial", url), "sfp_tool_maigret"),
            row("RAW_RIR_DATA", record(url, fullname="Leonmarcus Scott", username="leonmarcus.scott.9"), "sfp_tool_maigret")]
    a = label_of(score_accounts(rows, target="Leon Marcus Scott", target_type="HUMAN_NAME"), "ExampleSocial")
    assert a["label"] == "Unlikely" and any("similar but not the same" in r for r in a["reasons"])


def test_a_username_match_alone_is_unconfirmed_and_says_why():
    rows = [row("ACCOUNT_EXTERNAL_OWNED", account("ExampleSocial", "https://social.example/pat"), "sfp_accounts")]
    a = score_accounts(rows, target="Pat Example", target_type="HUMAN_NAME")[0]
    assert a["label"] == "Unconfirmed" and "nothing else ties it" in a["reasons"][0]


def test_a_site_for_another_country_than_the_subjects_is_unlikely_unless_something_points_to_the_subject():
    rows = [row("ACCOUNT_EXTERNAL_OWNED", account("ExampleFilm", "https://film.example/pat", "movies", ("PL",)), "sfp_tool_maigret")]
    ctx = {"country": "Australia"}
    a = score_accounts(rows, target="Pat Example", target_type="HUMAN_NAME", context=ctx)[0]
    assert a["label"] == "Unlikely" and "another country (PL)" in a["reasons"][0]
    same = score_accounts([row("ACCOUNT_EXTERNAL_OWNED", account("ExampleFilm", "https://film.example/pat", "movies", ("AU",)),
                               "sfp_tool_maigret")], target="Pat Example", target_type="HUMAN_NAME", context=ctx)[0]
    assert same["label"] == "Unconfirmed"                                    # a country match alone proves nothing
    unknown = score_accounts(rows, target="Pat Example", target_type="HUMAN_NAME")[0]
    assert unknown["label"] == "Unconfirmed"                                 # no context given: no country judgement


def test_a_matching_place_alone_is_unconfirmed_and_says_so():
    url = "https://social.example/pat"
    rows = [row("ACCOUNT_EXTERNAL_OWNED", account("ExampleSocial", url, countries=("US",)), "sfp_tool_maigret"),
            row("RAW_RIR_DATA", record(url, location="Perth, Western Australia"), "sfp_tool_maigret")]
    a = score_accounts(rows, target="Pat Example", target_type="HUMAN_NAME", context={"country": "Australia", "region": "Perth"})[0]
    assert a["label"] == "Unconfirmed" and "location 'Perth, Western Australia' matches" in a["reasons"][0]


def test_a_weak_search_page_check_is_unlikely_and_still_listed():
    rows = [row("ACCOUNT_EXTERNAL_OWNED", account("ExampleDocs", "https://docs.example/search?query=pat", "hobby", weak=True), "sfp_accounts")]
    a = score_accounts(rows, target="Pat Example", target_type="HUMAN_NAME")[0]
    assert a["label"] == "Unlikely" and a["weak"] and "search page" in a["reasons"][0]


def test_the_email_local_part_alone_is_unconfirmed_and_with_a_matching_profile_name_is_likely():
    email = row("EMAILADDR", "pat.example@example.com", "SpiderFoot UI")
    user = child(email, "USERNAME", "pat.example", "sfp_email")
    url = "https://social.example/pat.example"
    alone = [email, user, child(user, "ACCOUNT_EXTERNAL_OWNED", account("ExampleSocial", url), "sfp_tool_maigret")]
    a = score_accounts(alone, target="pat.example@example.com", target_type="EMAILADDR")[0]
    assert a["label"] == "Unconfirmed" and "local part" in a["reasons"][0]
    with_name = alone + [row("RAW_RIR_DATA", record(url, fullname="Pat Example"), "sfp_tool_maigret")]
    assert score_accounts(with_name, target="pat.example@example.com", target_type="EMAILADDR")[0]["label"] == "Likely"


# ------------------------------------------------------------------------------------------------ nothing hidden


def test_every_account_is_returned_once_with_its_modules_and_the_best_label_first():
    url = "https://social.example/pat"
    email = row("EMAILADDR", "pat@example.com", "SpiderFoot UI")
    rows = [email,
            row("ACCOUNT_EXTERNAL_OWNED", account("ExampleSocial", url), "sfp_accounts"),
            row("ACCOUNT_EXTERNAL_OWNED", account("ExampleSocial", url), "sfp_tool_maigret"),
            child(email, "ACCOUNT_EXTERNAL_OWNED", account("ExampleShop", "https://shop.example/"), "sfp_tool_user_scanner"),
            row("ACCOUNT_EXTERNAL_OWNED", account("ExampleDocs", "https://docs.example/search?q=pat", weak=True), "sfp_accounts")]
    scored = score_accounts(rows, target="pat@example.com", target_type="EMAILADDR")
    assert [a["site"] for a in scored] == ["ExampleShop", "ExampleSocial", "ExampleDocs"]
    assert [a["label"] for a in scored] == ["Confirmed", "Unconfirmed", "Unlikely"]
    assert next(a for a in scored if a["site"] == "ExampleSocial")["modules"] == ["sfp_accounts", "sfp_tool_maigret"]


def test_the_summary_counts_every_label_including_zero():
    scored = score_accounts([row("ACCOUNT_EXTERNAL_OWNED", account("A", "https://a.example/x"), "sfp_accounts")],
                            target="Pat Example", target_type="HUMAN_NAME")
    assert summarise(scored) == {"Confirmed": 0, "Likely": 0, "Unconfirmed": 1, "Unlikely": 0}


def test_no_accounts_no_scores_and_odd_input_does_not_crash():
    assert score_accounts([], target="x", target_type="HUMAN_NAME") == []
    rows = [row("ACCOUNT_EXTERNAL_OWNED", "just text, no url", "sfp_accounts"),
            row("RAW_RIR_DATA", "not json", "sfp_tool_maigret"), row("RAW_RIR_DATA", '{"url": 5}', "sfp_tool_maigret")]
    assert len(score_accounts(rows, target="x", target_type="HUMAN_NAME")) == 1

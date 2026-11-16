# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         spiderfoot.agents.hit_scoring
# Purpose:      Say how much each account found in a person search is worth, and why. Nothing is hidden: every hit
#               keeps its place in the report, with a label and the reasons.
# Created:      2026-11-16
# Licence:      MIT
# -------------------------------------------------------------------------------
"""Confidence for the accounts a person search finds.

A search for a name tries usernames built from it on thousands of sites; a hit there says only that SOMEONE holds that
username. In a real scan for a common name, 252 accounts came back, none of which the owner recognised (one belonged to
a different "Leonmarcus Scott", another to a Polish film site). The report must not present such matches as the
target's accounts, and must not hide them either.

Labels (the first rule that applies wins):

* **Confirmed**: the site itself confirmed the exact email address (a registration check on that address), or the
  profile publishes the target's email address or phone number.
* **Likely**: at least TWO independent signals agree: the profile's name is the target's name (every word, any order), the
  profile names a place that matches where the target is known to be, the username is the email's local part. One signal
  alone is not enough: a name is common, and a real scan for one produced seven profiles with exactly that name, none of
  them the owner's.
* **Unlikely**: something points away from the target: the profile's name is a different one, or the site is tied to
  another country than the target's, and nothing points toward the target.
* **Unconfirmed**: a username match and nothing else.

Pure functions over event rows.
"""

from __future__ import annotations

import json
import re
from typing import Iterable

_DATA, _MODULE, _HASH, _TYPE, _SRC = 1, 2, 3, 4, 5

LABELS = ("Confirmed", "Likely", "Unconfirmed", "Unlikely")
# Modules that ask a site about the exact email address they were given
IDENTIFIER_CHECKS = frozenset({"sfp_tool_user_scanner", "sfp_gravatar", "sfp_myspace", "sfp_venmo", "sfp_keybase"})
RECORD_MODULES = frozenset({"sfp_tool_maigret", "sfp_tool_user_scanner"})

_COUNTRY_NAMES = {
    "AU": "australia", "US": "united states", "GB": "united kingdom", "UK": "united kingdom", "NZ": "new zealand",
    "CA": "canada", "IE": "ireland", "DE": "germany", "FR": "france", "PL": "poland", "CZ": "czech republic",
    "IN": "india", "SG": "singapore", "ZA": "south africa", "NL": "netherlands", "ES": "spain", "IT": "italy",
}


def _signal_kind(reason: str) -> str:
    """Which independent signal a positive reason belongs to (name, place or the email's local part)."""
    if reason.startswith("the profile's name"):
        return "name"
    if reason.startswith("the profile's location"):
        return "place"
    return "handle"


def _tokens(name: str) -> frozenset[str]:
    return frozenset(t for t in re.split(r"[^\w]+", (name or "").lower()) if t)


def _country_codes(value: str) -> set[str]:
    """Country codes a context country (a code or a name) stands for."""
    v = (value or "").strip()
    out = {v.upper()} if len(v) == 2 else set()
    low = v.lower()
    out |= {code for code, name in _COUNTRY_NAMES.items() if name == low}
    return out


def parse_account(text: str) -> dict:
    """Site, URL, category, site countries and weakness flag from an ACCOUNT_EXTERNAL_OWNED event's text."""
    lines = [ln for ln in str(text).splitlines() if ln.strip()]
    head = lines[0] if lines else ""
    m = re.match(r"^(.*?)\s*\(Category:\s*(.*?)\)\s*$", head)
    site, category = (m.group(1), m.group(2)) if m else (head, "")
    url = ""
    um = re.search(r"<SFURL>(.*?)</SFURL>", str(text))
    if um:
        url = um.group(1)
    countries: list[str] = []
    cm = re.search(r"\(site countries:\s*([A-Za-z, ]+)\)", str(text))
    if cm:
        countries = [c.strip().upper() for c in cm.group(1).split(",") if c.strip()]
    return {"site": site.strip(), "url": url, "category": category, "countries": countries,
            "weak": "weak evidence" in str(text)}


def _record_details(rows: Iterable[tuple]) -> dict[str, dict]:
    """Profile details published by a site, keyed by profile URL, from the Maigret and user-scanner records."""
    out: dict[str, dict] = {}
    for r in rows:
        if r[_TYPE] != "RAW_RIR_DATA" or r[_MODULE] not in RECORD_MODULES:
            continue
        try:
            rec = json.loads(str(r[_DATA]))
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get("url"):
            details = rec.get("details")
            out[str(rec["url"])] = details if isinstance(details, dict) else {}
    return out


def score_accounts(rows: list, *, target: str, target_type: str, context: dict | None = None) -> list[dict]:
    """Score every ACCOUNT_EXTERNAL_OWNED event of a scan.

    Args:
        rows: event rows (generated, data, module, hash, type, source_event_hash, ...).
        target: the scan target.
        target_type: its SpiderFoot type (EMAILADDR, HUMAN_NAME, PHONE_NUMBER, USERNAME, ...).
        context: optional what the owner knows about the subject: ``{"country": "Australia", "region": "Perth"}``.

    Returns:
        One dict per distinct account: ``site``, ``url``, ``label``, ``reasons``, ``modules``, ``weak``.
    """
    context = context or {}
    ctx_codes = _country_codes(context.get("country", ""))
    region = (context.get("region") or "").strip().lower()
    by_hash = {r[_HASH]: r for r in rows}
    details_by_url = _record_details(rows)

    target_email = target.strip().lower() if target_type == "EMAILADDR" else ""
    local_part = target_email.split("@", 1)[0] if target_email else ""
    target_phone_digits = re.sub(r"\D", "", target) if target_type == "PHONE_NUMBER" else ""
    target_name = _tokens(target.strip().strip('"')) if target_type == "HUMAN_NAME" else frozenset()

    scored: dict[str, dict] = {}
    for r in rows:
        if r[_TYPE] != "ACCOUNT_EXTERNAL_OWNED":
            continue
        acct = parse_account(r[_DATA])
        key = acct["url"] or f"{acct['site']}|{r[_DATA]}"
        item = scored.setdefault(key, {**acct, "modules": set(), "positives": [], "strong": [], "negatives": []})
        module = str(r[_MODULE])
        item["modules"].add(module)

        parent = by_hash.get(r[_SRC])
        parent_data = str(parent[_DATA]).strip().lower() if parent else ""
        if module in IDENTIFIER_CHECKS and target_email and parent_data == target_email:
            item["strong"].append("the site confirmed that this exact email address is registered there")
        if local_part and parent and parent[_TYPE] == "USERNAME" and parent_data == local_part:
            item["positives"].append("the username is the email address's local part")

    for key, item in scored.items():
        details = details_by_url.get(item["url"], {}) if item["url"] else {}
        blob = json.dumps(details, ensure_ascii=False).lower() if details else ""
        if target_email and target_email in blob:
            item["strong"].append("the profile publishes this email address")
        if target_phone_digits and len(target_phone_digits) >= 8 and target_phone_digits[-9:] in re.sub(r"\D", "", blob):
            item["strong"].append("the profile publishes this phone number")

        profile_name = str(details.get("fullname") or details.get("name") or "").strip()
        if profile_name and target_name:
            ptoks = _tokens(profile_name)
            if ptoks == target_name:
                item["positives"].append(f"the profile's name is '{profile_name}', the same name")
            elif ptoks:
                item["negatives"].append(f"the profile's name is '{profile_name}', similar but not the same")
        elif profile_name and target_email:
            local_tokens = _tokens(local_part.replace(".", " ").replace("_", " "))
            if local_tokens and _tokens(profile_name) == local_tokens:
                item["positives"].append(f"the profile's name '{profile_name}' matches the email address")

        place = str(details.get("location") or details.get("country") or details.get("city") or "").strip()
        if place and region and region in place.lower():
            item["positives"].append(f"the profile's location '{place}' matches where the subject is based")
        elif place and ctx_codes and not any(n in place.lower() for n in (_COUNTRY_NAMES.get(c, "~") for c in ctx_codes)):
            item["negatives"].append(f"the profile's location '{place}' is not where the subject is based")

        if item["countries"] and ctx_codes and not (set(item["countries"]) & ctx_codes):
            item["negatives"].append(f"the site is for another country ({', '.join(item['countries'])}) than the subject's "
                                     f"({', '.join(sorted(ctx_codes))})")
        if item["weak"]:
            item["negatives"].append("the check asked the site's search page, not a profile (weak evidence)")

    out: list[dict] = []
    for item in scored.values():
        strong, pos, neg = item["strong"], item["positives"], item["negatives"]
        if strong:
            label, reasons = "Confirmed", strong + pos
        elif len({_signal_kind(p) for p in pos}) >= 2:
            label, reasons = "Likely", pos + neg
        elif pos:
            label = "Unconfirmed"
            reasons = [p + " (one signal alone is not enough: names and handles are common)" for p in pos] + neg
        elif neg:
            label, reasons = "Unlikely", neg
        else:
            label, reasons = "Unconfirmed", ["a username match and nothing else ties it to the subject"]
        out.append({"site": item["site"], "url": item["url"], "category": item["category"], "label": label,
                    "reasons": reasons, "modules": sorted(item["modules"]), "weak": item["weak"],
                    "countries": item["countries"]})
    order = {name: i for i, name in enumerate(LABELS)}
    out.sort(key=lambda x: (order[x["label"]], x["site"].lower()))
    return out


def summarise(scored: list[dict]) -> dict[str, int]:
    """Count of accounts per label (every label present, zero included)."""
    counts = {label: 0 for label in LABELS}
    for item in scored:
        counts[item["label"]] += 1
    return counts

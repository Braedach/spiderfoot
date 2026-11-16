# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         spiderfoot.agents.subject_links
# Purpose:      Link the scans an owner ran about the SAME subject (a person searched by name, email address and
#               phone number are three scans), so the report can say what the scans confirm about each other.
# Created:      2026-11-16
# Licence:      MIT
# -------------------------------------------------------------------------------
"""Cross-scan links for scans that share a subject label.

The owner gives scans a *subject label* (any short text, for example ``leon``). The report for one of those scans then
also sees the others: an identifier found in two scans (an email address in both the name scan and the phone scan, the
same profile URL from two directions) is a stronger lead than the same item found once, and a scan's own target found
inside another scan's results (the phone number's scan finds the email address that is the target of another scan) ties
the two together.

Pure functions over event rows. Nothing is hidden: every link lists the scans it appears in.
"""

from __future__ import annotations

import re
from typing import Iterable

_DATA, _TYPE = 1, 4

KINDS = {
    "EMAILADDR": "email address", "EMAILADDR_GENERIC": "email address", "AFFILIATE_EMAILADDR": "email address",
    "PHONE_NUMBER": "phone number", "AFFILIATE_PHONE_NUMBER": "phone number",
    "USERNAME": "username", "HUMAN_NAME": "name",
    "ACCOUNT_EXTERNAL_OWNED": "account", "SOCIAL_MEDIA": "account",
}
TARGET_KIND = {"EMAILADDR": "email address", "PHONE_NUMBER": "phone number", "USERNAME": "username",
               "HUMAN_NAME": "name"}
MAX_RELATED = 8
MAX_LINKS = 200


def normalise(kind: str, value: str) -> str:
    """A comparison key: the same thing written differently gets the same key."""
    v = " ".join(str(value).split())
    if kind == "email address":
        return v.lower()
    if kind == "phone number":
        digits = re.sub(r"\D", "", v)
        return digits[-9:] if len(digits) >= 8 else ""
    if kind == "username":
        return v.lower()
    if kind == "name":
        return " ".join(sorted(t for t in re.split(r"[^\w]+", v.lower()) if t))
    if kind == "account":
        m = re.search(r"<SFURL>(.*?)</SFURL>", v)
        url = m.group(1) if m else v.splitlines()[0] if v else ""
        return re.sub(r"^https?://(www\.)?", "", url.strip().lower()).rstrip("/")
    return v.lower()


def identifiers(rows: Iterable[tuple], target: str, target_type: str) -> dict[tuple[str, str], str]:
    """Every linkable identifier of a scan (and its own target): ``(kind, key) -> value as written``."""
    out: dict[tuple[str, str], str] = {}
    tk = TARGET_KIND.get(target_type)
    if tk:
        key = normalise(tk, target.strip().strip('"'))
        if key:
            out[(tk, key)] = target
    for r in rows:
        if not isinstance(r, (list, tuple)) or len(r) < 6:
            continue
        kind = KINDS.get(str(r[_TYPE]))
        if not kind:
            continue
        key = normalise(kind, str(r[_DATA]))
        if key:
            out.setdefault((kind, key), " ".join(str(r[_DATA]).split())[:200])
    return out


def link_scans(scans: list[dict]) -> dict:
    """Links among scans. Each scan is ``{"scan_id", "target", "target_type", "rows"}``.

    Returns ``{"scans": [...], "target_links": [...], "shared": [...]}``:

    * ``target_links``: a scan's own target found in another scan's results.
    * ``shared``: identifiers found in two or more scans (target links excluded).
    """
    per = []
    for s in scans:
        ids = identifiers(s.get("rows") or [], s.get("target", ""), s.get("target_type", ""))
        per.append((s, ids, {k for k in ids if (k[0], k[1]) == (TARGET_KIND.get(s.get("target_type", "")), normalise(
            TARGET_KIND.get(s.get("target_type", ""), ""), str(s.get("target", "")).strip('"')))}))

    target_links: list[dict] = []
    shared_map: dict[tuple[str, str], dict] = {}
    for i, (a, ids_a, own_a) in enumerate(per):
        for j, (b, ids_b, own_b) in enumerate(per):
            if i == j:
                continue
            for k in own_a:                              # a's target appears in b's own results
                if k in ids_b and k not in own_b:
                    target_links.append({"kind": k[0], "value": ids_a[k], "target_of": a["scan_id"],
                                         "found_in": b["scan_id"]})
    for idx, (s, ids, own) in enumerate(per):
        for k, val in ids.items():
            entry = shared_map.setdefault(k, {"kind": k[0], "value": val, "scans": []})
            if s["scan_id"] not in entry["scans"]:
                entry["scans"].append(s["scan_id"])
    linked_targets = {(t["kind"], normalise(t["kind"], t["value"])) for t in target_links}
    shared = [e for k, e in shared_map.items() if len(e["scans"]) >= 2 and k not in linked_targets]
    shared.sort(key=lambda e: (-len(e["scans"]), e["kind"], e["value"].lower()))
    return {
        "scans": [{"scan_id": s["scan_id"], "target": s.get("target", ""), "target_type": s.get("target_type", ""),
                   "identifiers": len(ids)} for s, ids, _ in per],
        "target_links": target_links,
        "shared": shared[:MAX_LINKS],
        "shared_total": len(shared),
    }


def render_links(result: dict, label: str, current: str) -> str:
    """The cross-scan section for the report prompt."""
    scans = result["scans"]
    lines = ["══════════════════════════════════════════════════",
             f"SCANS OF THE SAME SUBJECT (label: {label}); this report is for scan {current}",
             "══════════════════════════════════════════════════",
             "The owner marked these scans as being about one subject. An item found by two scans, or one scan's own "
             "target found inside another's results, is stronger evidence than the same item found once. Items found "
             "in one scan only are not listed here.", ""]
    for s in scans:
        lines.append(f"  scan {s['scan_id']}: {s['target']} ({s['target_type']}), {s['identifiers']} linkable identifiers")
    lines.append("")
    if result["target_links"]:
        lines.append("── One scan's target found in another scan's results ──")
        for t in result["target_links"]:
            lines.append(f"  {t['kind']} {t['value']} (the target of scan {t['target_of']}) was found in scan {t['found_in']}")
        lines.append("")
    if result["shared"]:
        lines.append(f"── Found by more than one scan ({result.get('shared_total', len(result['shared']))}) ──")
        for e in result["shared"]:
            lines.append(f"  {e['kind']}: {e['value']}  [scans: {', '.join(e['scans'])}]")
    elif not result["target_links"]:
        lines.append("No identifier appears in more than one of these scans.")
    return "\n".join(lines)

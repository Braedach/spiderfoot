# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         spiderfoot.agents.report_digest
# Purpose:      A structured, scope-aware digest of a scan for the AI report, built from every event in the database
#               rather than from a sample.
# Created:      2026-11-16
# Licence:      MIT
# -------------------------------------------------------------------------------
"""Scan digest for the AI report.

The report used to be written from the first N events the vector store returned (insertion order, so a crawler's
thousands of page events came first). Reviewing two real reports (2026-11-16) found:

* its counts were counts of that sample, not of the scan;
* an IP address scan's report was 95% about other organisations that merely shared the address's network, and told the
  owner to patch, and penetration-test, third parties;
* an unverified "interesting file" (a link to a page that redirects to login) was rated Critical;
* third-party individuals' contact details harvested from WHOIS records were presented as exposure;
* the scan's own failures (a certificate source that never answered) were not mentioned, so a stale certificate history
  looked complete.

The digest fixes the inputs: exact counts, every finding-type event always included, hosts outside the target's scope
reduced to counts (never assessed), no third-party personal data, the scan log's failures summarised, and a plain list of
what the scan did not test.

Pure functions over event rows: no database, no network, no model.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter, OrderedDict
from typing import Callable, Iterable

from spiderfoot.agents.hit_scoring import score_accounts, summarise as summarise_scores

# Row layout of SpiderFootDb.scanResultEvent(): generated, data, module, hash, type, source_event_hash, confidence,
# visibility, risk
_DATA, _MODULE, _HASH, _TYPE, _SRC = 1, 2, 3, 4, 5

FINDING_PREFIXES = ("VULNERABILITY_", "MALICIOUS_", "BLACKLISTED_", "DEFACED_")
FINDING_TYPES = frozenset({
    "SSL_CERTIFICATE_EXPIRED", "SSL_CERTIFICATE_EXPIRING", "SSL_CERTIFICATE_MISMATCH", "INTERESTING_FILE",
    "CLOUD_STORAGE_BUCKET_OPEN", "CLOUD_STORAGE_BUCKET", "LEAKSITE_URL", "EMAILADDR_COMPROMISED",
    "PHONE_NUMBER_COMPROMISED", "PASSWORD_COMPROMISED", "DARKNET_MENTION_URL", "DARKNET_MENTION_CONTENT",
    "TCP_PORT_OPEN", "UDP_PORT_OPEN", "TCP_PORT_OPEN_BANNER", "UDP_PORT_OPEN_INFO", "WEBSERVER_BANNER",
    "WEBSERVER_TECHNOLOGY", "OPERATING_SYSTEM", "SOFTWARE_USED", "DEVICE_TYPE", "URL_PASSWORD", "URL_UPLOAD",
    "CDN_DETECTED", "PROVIDER_HOSTING", "PROVIDER_DNS", "PROVIDER_MAIL", "PROVIDER_TELCO", "GEOINFO", "COUNTRY_NAME",
    "BGP_AS_MEMBER", "BGP_AS_OWNER", "DOMAIN_REGISTRAR", "PHONE_NUMBER_TYPE", "SSL_CERTIFICATE_ISSUED",
    "ACCOUNT_EXTERNAL_OWNED", "WEBSERVER_STRANGEHEADER",
    # registry facts: what an ASN or an IP address scan is about
    "NETBLOCK_OWNER", "NETBLOCK_MEMBER", "NETBLOCKV6_OWNER", "NETBLOCKV6_MEMBER", "NETBLOCK_WHOIS", "DOMAIN_WHOIS",
    "COMPANY_NAME", "PHYSICAL_ADDRESS", "PHYSICAL_COORDINATES", "TOR_EXIT_NODE",
    # the target's own names and addresses (context when they belong to someone else)
    "INTERNET_NAME", "IP_ADDRESS", "IPV6_ADDRESS", "DOMAIN_NAME",
})
# Types whose data names a host the finding is about (so the finding can be out of scope)
HOST_BEARING = frozenset({
    "TCP_PORT_OPEN", "UDP_PORT_OPEN", "TCP_PORT_OPEN_BANNER", "UDP_PORT_OPEN_INFO", "WEBSERVER_BANNER",
    "INTERESTING_FILE", "URL_PASSWORD", "URL_UPLOAD", "CLOUD_STORAGE_BUCKET_OPEN", "CLOUD_STORAGE_BUCKET",
    "SSL_CERTIFICATE_EXPIRED", "SSL_CERTIFICATE_EXPIRING", "SSL_CERTIFICATE_MISMATCH", "WEBSERVER_STRANGEHEADER",
    "INTERNET_NAME", "IP_ADDRESS", "IPV6_ADDRESS", "DOMAIN_NAME",
})
# Other hosts by definition (found through shared hosting, similar names, affiliates): counted, never listed
CONTEXT_ONLY_TYPES = frozenset({
    "CO_HOSTED_SITE", "CO_HOSTED_SITE_DOMAIN", "SIMILARDOMAIN", "AFFILIATE_INTERNET_NAME", "AFFILIATE_IPADDR",
    "AFFILIATE_IPV6_ADDRESS", "AFFILIATE_DOMAIN_NAME", "AFFILIATE_DOMAIN_WHOIS", "CO_HOSTED_SITE_DOMAIN_WHOIS",
    "LINKED_URL_EXTERNAL", "INTERNET_NAME_UNRESOLVED",
})
# Structured records from modules that describe the target itself (a phone number's details, a person's accounts)
RECORD_MODULES = frozenset({"sfp_phone", "sfp_tool_maigret", "sfp_tool_user_scanner", "sfp_hudsonrock", "sfp_gravatar",
                            "sfp_venmo", "sfp_github", "sfp_keybase", "sfp_emailformat", "sfp_debounce"})
# Event types that name a host; walking up an event's source chain stops at the first one (the host the finding was found on)
HOSTLIKE = frozenset({
    "IP_ADDRESS", "IPV6_ADDRESS", "INTERNET_NAME", "DOMAIN_NAME", "AFFILIATE_INTERNET_NAME", "AFFILIATE_IPADDR",
    "AFFILIATE_IPV6_ADDRESS", "CO_HOSTED_SITE", "TCP_PORT_OPEN", "UDP_PORT_OPEN", "LINKED_URL_INTERNAL",
    "LINKED_URL_EXTERNAL", "URL_FORM", "URL_STATIC", "URL_JAVASCRIPT",
})
# A netblock's registry data (its WHOIS, its owner's address, company and contacts) is about whoever holds the block
NETBLOCK_TYPES = frozenset({"NETBLOCK_OWNER", "NETBLOCK_MEMBER", "NETBLOCKV6_OWNER", "NETBLOCKV6_MEMBER", "NETBLOCK_WHOIS"})
MAX_RECORDS = 80                # structured records shown (a name scan alone produces dozens of profile records)
MAX_RECORD_CHARS = 700
PERSONAL_TYPES = frozenset({
    "EMAILADDR", "EMAILADDR_GENERIC", "AFFILIATE_EMAILADDR", "PHONE_NUMBER", "AFFILIATE_PHONE_NUMBER", "HUMAN_NAME",
    "USERNAME",
})
PERSON_TARGETS = frozenset({"HUMAN_NAME", "PHONE_NUMBER", "USERNAME", "EMAILADDR", "BITCOIN_ADDRESS"})
# Findings that a single heuristic scanner can report on its own; not trusted for a High or Critical rating without a
# second source
HEURISTIC_MODULES = frozenset({"sfp_tool_nikto", "sfp_junkfiles", "sfp_intfiles", "sfp_tool_snallygaster"})

MAX_EXAMPLES_PER_TYPE = 200      # in-scope items listed per type (the appendix lists them all)
MAX_CONTEXT_EXAMPLES = 100      # related hosts listed per type, as context the report may mention but must not assess
MAX_THIRD_PARTY = 150           # third-party personal details listed per type, labelled, for the model to judge
MAX_HOSTS_ROLLUP = 40           # hosts named, with their counts, for a type that has more items than are listed
MAX_OTHER_EXAMPLES = 15         # examples shown for each remaining event type (exact counts are always given)
NO_EXAMPLE_TYPES = frozenset({"HASH"})          # a hash tells the reader nothing; the count is enough
SECTION_SHARE = {"account confidence": 0.20}   # largest share of the budget one open-ended section may take
DEFAULT_BUDGET_CHARS = 300000   # size of the digest text; what does not fit is counted, never silently dropped
MAX_DATA_CHARS = 280

# Modules that test a web application's behaviour (injection, scripting flaws, parameters). If none ran, the report says
# the application layer was not tested.
APPLICATION_TEST_MODULES = frozenset({"sfp_tool_dalfox", "sfp_tool_arjun", "sfp_tool_sqlmap"})
BREACH_MODULES = frozenset({"sfp_haveibeenpwned", "sfp_intelx", "sfp_leakcheck", "sfp_dehashed", "sfp_emailrep",
                            "sfp_hudsonrock", "sfp_apileak"})


def _host_of(value: str) -> str | None:
    """The host in a finding's data (a URL, ``host:port``, a bare host or address, or 'host: description')."""
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    m = re.match(r"^[a-z][a-z0-9+.-]*://\[?([^\]/:?#\s]+)", text)
    if m:
        return m.group(1)
    first = re.split(r"[\s/]", text, maxsplit=1)[0].rstrip(":")
    first = re.sub(r":\d+$", "", first) if first.count(":") == 1 else first
    try:
        ipaddress.ip_address(first)
        return first
    except ValueError:
        pass
    return first if re.match(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$", first) else None


class Scope:
    """Whether a host, or a netblock, belongs to the target."""

    def __init__(self, host_check: Callable[[str], bool], netblock_check: Callable[[str], bool]) -> None:
        self._host, self._netblock = host_check, netblock_check

    def __call__(self, host: str) -> bool:
        return self._host(host)

    def netblock(self, cidr: str) -> bool:
        try:
            return self._netblock(cidr)
        except Exception:
            return False


def _cidr(value: str):
    """The network in a netblock event's data (a CIDR, possibly with text around it), or None."""
    m = re.search(r"([0-9a-fA-F:.]+/\d{1,3})", str(value))
    if not m:
        return None
    try:
        return ipaddress.ip_network(m.group(1), strict=False)
    except ValueError:
        return None


def make_scope_check(target: str, target_type: str, rows: list) -> Scope:
    """What belongs to the target.

    * domain or hostname target: the name, its subdomains, and the addresses the scan resolved them to (an
      IP_ADDRESS event whose source event is in scope); a netblock is the target's if it holds one of those addresses;
    * IP address target: that address and the name its reverse DNS gave; a netblock is the target's if it holds the
      address;
    * netblock target: addresses inside the block;
    * ASN target: the ASN's own registry data (its netblocks); every host is context;
    * person targets: nothing host-like belongs to them.
    """
    target = (target or "").strip().strip('"').lower()
    by_hash = {r[_HASH]: r for r in rows}
    none = lambda x: False  # noqa: E731

    if target_type == "INTERNET_NAME":
        def name_in_scope(h: str) -> bool:
            return h == target or h.endswith("." + target)
        resolved: set[str] = set()
        for r in rows:
            if r[_TYPE] in ("IP_ADDRESS", "IPV6_ADDRESS"):
                parent = by_hash.get(r[_SRC])
                if parent and parent[_TYPE] in ("INTERNET_NAME", "DOMAIN_NAME") and name_in_scope(str(parent[_DATA]).lower()):
                    resolved.add(str(r[_DATA]).lower())

        def host_check(host: str) -> bool:
            host = (host or "").lower()
            return bool(host) and (name_in_scope(host) or host in resolved)

        def netblock_check(cidr: str) -> bool:
            net = _cidr(cidr)
            return bool(net) and any(_addr_in(a, net) for a in resolved)
        return Scope(host_check, netblock_check)

    if target_type in ("IP_ADDRESS", "IPV6_ADDRESS"):
        names: set[str] = set()
        for r in rows:
            if r[_TYPE] == "INTERNET_NAME" and r[_MODULE] == "sfp_dnsresolve":
                parent = by_hash.get(r[_SRC])
                if parent and str(parent[_DATA]).lower() == target:
                    names.add(str(r[_DATA]).lower())

        def netblock_check(cidr: str) -> bool:
            net = _cidr(cidr)
            return bool(net) and _addr_in(target, net)
        return Scope(lambda host: (host or "").lower() == target or (host or "").lower() in names, netblock_check)

    if target_type in ("NETBLOCK_OWNER", "NETBLOCKV6_OWNER"):
        try:
            block = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return Scope(none, none)

        def netblock_check(cidr: str) -> bool:
            net = _cidr(cidr)
            return bool(net) and net.version == block.version and net.overlaps(block)
        return Scope(lambda host: _addr_in(host, block), netblock_check)

    if target_type == "BGP_AS_OWNER":
        return Scope(none, lambda cidr: True)        # an ASN's netblocks are its own registry data

    return Scope(none, none)


def _addr_in(host: str, net) -> bool:
    try:
        return ipaddress.ip_address(host) in net
    except ValueError:
        return False


def _clip(text: str) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= MAX_DATA_CHARS else text[:MAX_DATA_CHARS] + "…"


def _is_finding_type(etype: str) -> bool:
    return etype in FINDING_TYPES or etype.startswith(FINDING_PREFIXES)


def summarise_log(entries: Iterable[tuple], limit: int = 12) -> list[tuple[int, str]]:
    """Failures from the scan log, most frequent first, with numbers masked so repeats group together.

    Args:
        entries: rows ``(generated, component, type, message, ...)`` as returned by ``scanLogs``.
    """
    counts: Counter[str] = Counter()
    for row in entries:
        if len(row) < 4 or str(row[2]).upper() not in ("ERROR", "WARNING"):
            continue
        message = re.sub(r"\d+", "#", " ".join(str(row[3]).split()))[:200]
        if message.startswith("Full traceback") or not message:
            continue
        counts[message] += 1
    return [(n, m) for m, n in counts.most_common(limit)]


def not_tested(modules_run: set[str], target_type: str) -> list[str]:
    """Plain statements of what this scan did not test, from the modules that ran."""
    out: list[str] = []
    if target_type not in PERSON_TARGETS and not modules_run & APPLICATION_TEST_MODULES:
        out.append("The application layer was not tested: no injection, cross-site scripting, authentication or "
                   "access-control tests were run. A reachable web application can have flaws this scan cannot see.")
    if target_type in PERSON_TARGETS | {"INTERNET_NAME"} and not modules_run & BREACH_MODULES:
        out.append("No breach or leak database was consulted (no key saved for such a service), so the absence of "
                   "leaked-credential findings means nothing.")
    if target_type in PERSON_TARGETS:
        out.append("Accounts found by matching a username or a name on a site are unconfirmed unless something ties them "
                   "to the target (the same email address or phone number, a matching profile detail). A username on a "
                   "site can belong to anyone; do not present such matches as the target's accounts.")
    out.append("Findings that a single heuristic scanner reported and nothing else confirmed are marked unverified.")
    return out


def build_digest(rows: list, *, target: str, target_type: str, log_entries: Iterable[tuple] = (),
                 modules_run: Iterable[str] | None = None, context: dict | None = None) -> dict:
    """Build the digest of one scan from all of its event rows.

    ``context`` is what the owner told the scan about the subject (``country``, ``region``); it is kept under another name
    here because a local counter of related-host events is also called ``context`` below.
    """
    subject_context = dict(context or {})
    all_rows = [r for r in rows if isinstance(r, (list, tuple)) and len(r) >= 9]
    rows = [r for r in all_rows if r[_TYPE] != "ROOT"]
    in_scope = make_scope_check(target, target_type, all_rows)     # the root event is a parent: keep it for lookups
    person_scan = target_type in PERSON_TARGETS
    modules_seen = set(modules_run or []) or {str(r[_MODULE]) for r in rows}

    by_type = Counter(str(r[_TYPE]) for r in rows)
    by_module = Counter(str(r[_MODULE]) for r in rows)

    findings: "OrderedDict[str, OrderedDict[str, dict]]" = OrderedDict()
    context: Counter[str] = Counter()
    context_examples: "OrderedDict[str, OrderedDict[str, None]]" = OrderedDict()
    context_full: "OrderedDict[str, OrderedDict[str, None]]" = OrderedDict()
    personal_omitted: Counter[str] = Counter()
    third_party: "OrderedDict[str, OrderedDict[str, set]]" = OrderedDict()
    other: "OrderedDict[str, OrderedDict[str, set]]" = OrderedDict()     # every remaining type: examples
    http_codes: Counter[str] = Counter()
    header_counts: Counter[str] = Counter()
    header_responses = 0
    own_addresses: "OrderedDict[str, dict]" = OrderedDict()

    records: list[dict] = []
    by_hash = {r[_HASH]: r for r in all_rows}
    disposition: Counter[str] = Counter()

    def subject_in_scope(r) -> bool:
        """Whether the host this event is about belongs to the target.

        A host-bearing event is judged by the host in its data. Any other finding (a vulnerability, a country, a hosting
        provider) is judged by the host it was found on: the first host-like event up its source chain. A fact that
        hangs straight off the target (the root event) is the target's own.
        """
        etype = str(r[_TYPE])
        if etype in NETBLOCK_TYPES:
            return in_scope.netblock(str(r[_DATA]))
        host = _host_of(str(r[_DATA])) if etype in HOST_BEARING else None
        if host:
            return in_scope(host)
        cur, steps = by_hash.get(r[_SRC]), 0
        while cur is not None and steps < 8:
            if cur[_TYPE] == "ROOT":
                return True
            if cur[_TYPE] in NETBLOCK_TYPES:
                return in_scope.netblock(str(cur[_DATA]))
            if cur[_TYPE] in HOSTLIKE:
                parent_host = _host_of(str(cur[_DATA]))
                if parent_host:
                    return in_scope(parent_host)
            cur, steps = by_hash.get(cur[_SRC]), steps + 1
        return True

    for r in rows:
        etype, data, module = str(r[_TYPE]), str(r[_DATA]), str(r[_MODULE])
        if etype == "RAW_RIR_DATA":
            if not subject_in_scope(r):                      # a record about another host or party is context
                context[etype] += 1
                disposition["related context"] += 1
            elif module in RECORD_MODULES and len(records) < MAX_RECORDS:
                records.append({"module": module, "data": " ".join(data.split())[:MAX_RECORD_CHARS]})
                disposition["record shown"] += 1
            else:
                disposition["record beyond the cap (counted; all are in the scan results)"] += 1
            continue
        if etype in CONTEXT_ONLY_TYPES:
            context[etype] += 1
            context_full.setdefault(etype, OrderedDict()).setdefault(_clip(data), None)
            context_examples.setdefault(etype, OrderedDict()).setdefault(_clip(data), None)
            disposition["related context"] += 1
            continue
        if etype in PERSONAL_TYPES:
            host = data.split("@", 1)[1].lower() if etype.startswith("EMAILADDR") and "@" in data else None
            if person_scan or (host and in_scope(host)):
                bucket = own_addresses.setdefault(f"{etype}|{data}", {"type": etype, "data": data, "modules": set()})
                bucket["modules"].add(module)
                disposition["the target's own contact data"] += 1
            else:
                personal_omitted[etype] += 1
                third_party.setdefault(etype, OrderedDict()).setdefault(_clip(data), set()).add(module)
                disposition["third-party personal data (labelled)"] += 1
            continue
        if not _is_finding_type(etype):
            # Not a "finding" type, but still data the model may want: keep exact counts (by_type), lossless
            # aggregates for the bulky ones, and examples of the rest.
            if etype == "HTTP_CODE":
                http_codes[data.strip()[:20]] += 1
            elif etype == "WEBSERVER_HTTPHEADERS":
                try:
                    headers = json.loads(data)
                    if isinstance(headers, dict):
                        header_responses += 1
                        header_counts.update(str(k).lower() for k in headers)
                except (ValueError, TypeError):
                    pass
            if etype not in NO_EXAMPLE_TYPES and etype not in ("HTTP_CODE",):
                per = other.setdefault(etype, OrderedDict())
                if len(per) < MAX_OTHER_EXAMPLES or _clip(data) in per:
                    per.setdefault(_clip(data), set()).add(module)
            if not subject_in_scope(r):
                context[etype] += 1
                disposition["related context"] += 1
            else:
                disposition["other event types (exact counts, examples shown)"] += 1
            continue
        if not subject_in_scope(r):
            context[etype] += 1
            context_full.setdefault(etype, OrderedDict()).setdefault(_clip(data), None)
            context_examples.setdefault(etype, OrderedDict()).setdefault(_clip(data), None)
            disposition["related context"] += 1
            continue
        disposition["in-scope finding"] += 1
        per = findings.setdefault(etype, OrderedDict())
        key = _clip(data)
        item = per.setdefault(key, {"data": key, "modules": set(), "count": 0})
        item["modules"].add(module)
        item["count"] += 1

    inventory = {etype: [{"data": it["data"], "modules": sorted(it["modules"]), "count": it["count"]}
                         for it in per.values()] for etype, per in findings.items()}
    finding_list = []
    for etype, per in findings.items():
        items = list(per.values())
        shown = []
        for it in _spread(items, MAX_EXAMPLES_PER_TYPE):
            shown.append({"data": it["data"], "modules": sorted(it["modules"]), "verified": not _unverified(it)})
        hosts = Counter(h for h in (_host_of(it["data"]) for it in items) if h)
        finding_list.append({"type": etype, "total": len(items), "shown": shown,
                             "by_host": hosts.most_common(MAX_HOSTS_ROLLUP) if len(hosts) > 1 else []})

    account_scores = (score_accounts(all_rows, target=target, target_type=target_type, context=subject_context)
                      if by_type.get("ACCOUNT_EXTERNAL_OWNED") else [])
    return {
        "context": subject_context,
        "account_scores": account_scores,
        "account_score_summary": summarise_scores(account_scores),
        "target": target, "target_type": target_type,
        "total_events": len(rows),
        "by_type": by_type.most_common(25),
        "by_module": by_module.most_common(15),
        "findings": finding_list,
        "context_counts": dict(context.most_common()),
        "context_examples": {t: list(v)[:MAX_CONTEXT_EXAMPLES] for t, v in context_examples.items()},
        "own_addresses": [{"type": v["type"], "data": v["data"], "modules": sorted(v["modules"])}
                          for v in list(own_addresses.values())[:40]],
        "records": records,
        "accounting": dict(disposition),
        "other_types": {t: [{"data": k, "modules": sorted(m)} for k, m in v.items()] for t, v in other.items()},
        "http_codes": http_codes.most_common(),
        "header_stats": {"responses": header_responses, "present": header_counts.most_common(60)},
        "third_party": {t: [{"data": k, "modules": sorted(m)} for k, m in v.items()] for t, v in third_party.items()},
        "inventory": inventory,
        "context_inventory": {t: list(v) for t, v in context_full.items()},
        "personal_omitted": dict(personal_omitted.most_common()),
        "limitations": summarise_log(log_entries),
        "not_tested": not_tested(modules_seen, target_type),
    }


def _unverified(item: dict) -> bool:
    """True when one heuristic scanner alone reported the item and nothing else confirmed it."""
    mods = sorted(item["modules"])
    return len(mods) == 1 and mods[0] in HEURISTIC_MODULES


def _spread(items: list[dict], cap: int) -> list[dict]:
    """The items to list for one type when there are more than ``cap``: confirmed findings before unconfirmed ones, and spread
    round-robin across hosts so every host is represented (the first ``cap`` in discovery order were all from the hosts the scan
    happened to reach first). Within a host, discovery order. At or under the cap nothing is reordered."""
    if len(items) <= cap:
        return items
    queues: OrderedDict = OrderedDict()
    for it in sorted(items, key=_unverified):          # stable: confirmed first, discovery order kept within each group
        queues.setdefault(_host_of(it["data"]) or "", []).append(it)
    picked: list[dict] = []
    while len(picked) < cap and queues:
        for host in list(queues):
            picked.append(queues[host].pop(0))
            if not queues[host]:
                del queues[host]
            if len(picked) >= cap:
                break
    return picked


def _take(lines: list[str], budget: int) -> tuple[list[str], int, int]:
    """Lines that fit in ``budget`` characters, the budget left, and how many lines did not fit."""
    out: list[str] = []
    used = 0
    for n, line in enumerate(lines):
        if used + len(line) + 1 > budget:
            return out, budget - used, len(lines) - n
        out.append(line)
        used += len(line) + 1
    return out, budget - used, 0


def render_digest(d: dict, max_chars: int | None = None) -> str:
    """The digest as text for the report prompt.

    Everything is provided and labelled; the model decides what matters. Within ``max_chars`` (default
    ``DEFAULT_BUDGET_CHARS``) the sections are filled in priority order and anything that does not fit is reported by
    exact count (all of it is in the appendix and the scan results).
    """
    budget = DEFAULT_BUDGET_CHARS if max_chars is None else max_chars
    head = ["══════════════════════════════════════════════════",
            "SCAN DIGEST (authoritative: built from every event of the scan)",
            "══════════════════════════════════════════════════", "",
            f"Target: {d['target']} ({d['target_type']})",
            "Subject context given by the owner: " + (", ".join(f"{k}={v}" for k, v in d.get("context", {}).items() if v)
                                                      or "none (no country or place was given, so no account was judged by where it is)"),
            f"Total events in the scan: {d['total_events']}", "",
            "Event counts by type (exact, whole scan): " + ", ".join(f"{t} {n}" for t, n in d["by_type"]), "",
            "Events by module (exact): " + ", ".join(f"{m} {n}" for m, n in d["by_module"]), ""]

    acc = d.get("accounting") or {}
    tail: list[str] = []
    if acc:
        tail += ["", "── ACCOUNTING (every event of the scan is in exactly one of these; nothing is dropped, and all of it "
                     "remains in the scan results) ──",
                 "  " + "; ".join(f"{k}: {v}" for k, v in sorted(acc.items(), key=lambda kv: -kv[1]))
                 + f"  (total {sum(acc.values())})"]
    tail += ["", "── COVERAGE AND LIMITATIONS (what went wrong during the scan; include these in the report) ──"]
    tail += [f"  - {n} x {m}" for n, m in d["limitations"]] or ["  (no errors or warnings were logged)"]
    tail += ["", "── WHAT THIS SCAN DID NOT TEST (state these plainly in the report) ──"]
    tail += [f"  - {line}" for line in d["not_tested"]]

    findings: list[str] = ["── IN-SCOPE FINDINGS (about the target itself) ──"]
    if not d["findings"]:
        findings.append("(none)")
    for group in d["findings"]:
        findings.append(f"\n[{group['type']}] {group['total']} distinct")
        for it in group["shown"]:
            flag = "" if it["verified"] else "  [UNVERIFIED: one heuristic scanner only]"
            findings.append(f"  - {it['data']}  (source: {', '.join(it['modules'])}){flag}")
        if group["total"] > len(group["shown"]):
            if group.get("by_host"):
                findings.append("  per host (all items of this type, not only those listed): "
                                + ", ".join(f"{h} {n}" for h, n in group["by_host"]))
            findings.append(f"  … and {group['total'] - len(group['shown'])} more of this type (see Appendix A)")

    own: list[str] = []
    if d["own_addresses"]:
        own = ["", "── THE TARGET'S OWN CONTACT DATA / ACCOUNTS ──"]
        own += [f"  - [{a['type']}] {a['data']} (source: {', '.join(a['modules'])})" for a in d["own_addresses"]]

    records: list[str] = []
    if d.get("records"):
        records = ["", "── STRUCTURED RECORDS ABOUT THE TARGET (as returned by the modules) ──"]
        records += [f"  - ({r['module']}) {r['data']}" for r in d["records"]]

    ctx: list[str] = ["", "── RELATED CONTEXT: other hosts that merely share the target's network or hosting ──"]
    if d["context_counts"]:
        ctx.append("These are NOT the target. You may describe them as related infrastructure, but do not assess or rate "
                   "them, and do not recommend patching or testing them. Counts: "
                   + ", ".join(f"{t} {n}" for t, n in d["context_counts"].items()))
        for etype, examples in d.get("context_examples", {}).items():
            more = d["context_counts"].get(etype, 0) - len(examples)
            ctx.append(f"  [{etype}] " + "; ".join(examples) + (f"; … {more} more (see Appendix A)" if more > 0 else ""))
    else:
        ctx.append("(none)")

    accounts: list[str] = []
    if d.get("account_scores"):
        summ = d["account_score_summary"]
        accounts = ["", "── ACCOUNT CONFIDENCE (every account found, scored from the evidence in the scan; none is hidden) ──",
                    "Labels: Confirmed = the site confirmed the exact email, or the profile publishes the target's email or "
                    "phone; Likely = the profile's name or place matches the target; Unconfirmed = a username match and "
                    "nothing else; Unlikely = something points away from the target. A username match alone proves "
                    "nothing: present only Confirmed and Likely accounts as the target's, and list the rest as unconfirmed "
                    "matches. Totals: " + ", ".join(f"{k} {v}" for k, v in summ.items())]
        for a in d["account_scores"]:
            accounts.append(f"  [{a['label']}] {a['site']} {a['url']} (found by {', '.join(a['modules'])}) because: "
                            + "; ".join(a["reasons"]))

    others: list[str] = []
    if d.get("http_codes"):
        others += ["", "── HTTP RESPONSES (exact, whole scan) ──",
                   "  status codes: " + ", ".join(f"{c} x{n}" for c, n in d["http_codes"])]
    hs = d.get("header_stats") or {}
    if hs.get("responses"):
        others += ["  response headers seen across " + str(hs["responses"]) + " responses (header: how many responses carried it): "
                   + ", ".join(f"{h} {n}" for h, n in hs["present"])]
    if d.get("other_types"):
        others += ["", "── OTHER EVENT TYPES (exact counts are in the type counts above; examples shown) ──"]
        for etype, items in sorted(d["other_types"].items(), key=lambda kv: -dict(d["by_type"]).get(kv[0], 0)):
            n = next((c for t, c in d["by_type"] if t == etype), None)
            total = f"{n} events" if n is not None else "events"
            others.append(f"  [{etype}] {total}: " + "; ".join(i["data"] for i in items))

    third: list[str] = []
    if d.get("third_party"):
        third = ["", "── THIRD-PARTY PERSONAL DATA found in public records about OTHER parties ──",
                 "Provided so you can judge whether any of it matters. It is NOT the target's exposure: do not present "
                 "it as a finding against the target and do not recommend action against these individuals. Counts: "
                 + ", ".join(f"{t} {n}" for t, n in d["personal_omitted"].items())]
        for etype, items in d["third_party"].items():
            shown_items = items[:MAX_THIRD_PARTY]
            third.append(f"  [{etype}] " + "; ".join(f"{i['data']} ({', '.join(i['modules'])})" for i in shown_items)
                         + (f"; … {len(items) - len(shown_items)} more (in the scan results)" if len(items) > len(shown_items) else ""))

    # mandatory parts first, then the variable sections in priority order within what is left
    used = sum(len(x) + 1 for x in head + tail)
    room = max(0, budget - used)
    body: list[str] = []
    omitted_notes: list[str] = []
    for name, block in (("in-scope findings", findings), ("the target's own data", own), ("account confidence", accounts),
                        ("structured records", records),
                        ("related context", ctx), ("other event types", others),
                        ("third-party personal data", third)):
        # one section may not crowd the others out: the account list was 1.4 million characters on a 42,000-event scan and
        # took everything left, so related context, other types and third-party data never reached the model
        allowed = min(room, int(budget * SECTION_SHARE[name])) if name in SECTION_SHARE else room
        taken, left_over, left = _take(block, allowed)
        room -= allowed - left_over
        body += taken
        if left:
            omitted_notes.append(f"{left} lines of {name} did not fit in this digest (all are in Appendix A and the scan results)")
    if omitted_notes:
        body += ["", "── SIZE LIMIT ──"] + [f"  - {n}" for n in omitted_notes]
    return "\n".join(head + body + tail)


def render_appendix(d: dict, max_lines: int = 3000) -> str:
    """A complete, deterministic inventory to append to the report (no model involved, nothing summarised).

    Lists every in-scope finding and every related host. Third-party personal data is not listed (it stays in the scan
    results and the export). If the inventory is longer than ``max_lines`` the cut is stated, with the exact number of
    items left out, never silent.
    """
    lines: list[str] = []
    for etype, items in sorted(d.get("inventory", {}).items()):
        lines.append(f"### {etype} ({len(items)})")
        for it in items:
            times = f" x{it['count']}" if it["count"] > 1 else ""
            lines.append(f"- {it['data']}{times} [{', '.join(it['modules'])}]")
    if d.get("account_scores"):
        lines.append(f"### Accounts by confidence ({len(d['account_scores'])})")
        for a in d["account_scores"]:
            lines.append(f"- [{a['label']}] {a['site']} {a['url']} [{', '.join(a['modules'])}]: " + "; ".join(a["reasons"]))
    in_scope_lines = len(lines)
    ctx: list[str] = []
    for etype, items in sorted(d.get("context_inventory", {}).items()):
        ctx.append(f"### {etype} ({len(items)})")
        ctx.extend(f"- {x}" for x in items)

    total = in_scope_lines + len(ctx)
    out = ["## Appendix A: Complete inventory (generated from the scan data, not written by the model)", ""]
    out.append("### A.1 About the target")
    out.extend(lines[:max_lines] or ["(nothing)"])
    budget = max(0, max_lines - len(lines))
    out += ["", "### A.2 Related infrastructure (other hosts that share the target's network or hosting; NOT the target)"]
    out.extend(ctx[:budget] or ["(none)" if not ctx else "(see note below)"])
    shown = min(len(lines), max_lines) + min(len(ctx), budget)
    if total > shown:
        out += ["", f"**Note:** {total - shown} of {total} inventory lines were left out of this appendix for length. They "
                    "are all still in the scan results and the export."]
    if d.get("personal_omitted"):
        out += ["", "**Withheld on purpose:** personal details of people who are not the target ("
                + ", ".join(f"{t} {n}" for t, n in d["personal_omitted"].items())
                + "). They are not lost: they remain in the scan results and the export."]
    return "\n".join(out)

from __future__ import annotations

"""SpiderFoot plug-in module: whois."""

# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_whois
# Purpose:      SpiderFoot plug-in for searching Whois servers for domain names
#               and netblocks identified.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/04/2015
# Copyright:   (c) Steve Micallef 2012
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import time

import ipwhois
import netaddr
import whois

from spiderfoot import SpiderFootEvent
from spiderfoot.plugins.async_plugin import SpiderFootAsyncPlugin


class sfp_whois(SpiderFootAsyncPlugin):

    """Perform a WHOIS look-up on domain names and owned netblocks."""

    meta = {
        'name': "Whois",
        'summary': "Perform a WHOIS look-up on domain names (RDAP first, port-43 WHOIS as a fallback) and owned netblocks.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Public Registries"],
        "dataSource": {
            "website": "https://www.iana.org/whois",
            "model": "FREE_NOAUTH_LIMITED",
            "references": ["https://tools.ietf.org/html/rfc3912", "https://tools.ietf.org/html/rfc9083",
                           "https://data.iana.org/rdap/dns.json"],
            "description": "Domain and IP WHOIS registration data lookup.",
        },
    }

    # Default options
    opts = {
        'use_rdap': True,
        'rdap_timeout': 15,
    }

    # Option descriptions
    optdescs = {
        'use_rdap': "Look domains up over RDAP (the structured, rate-limit-aware successor to WHOIS) and use port-43 WHOIS only when RDAP has no answer.",
        'rdap_timeout': "Seconds to wait for an RDAP server.",
    }

    BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
    # Seconds to leave an RDAP server alone after it answers "too many requests"
    RDAP_BACKOFF = 60

    results = None

    def setup(self, sfc: SpiderFoot, userOpts: dict = None) -> None:
        """Set up the module."""
        super().setup(sfc, userOpts or {})
        self.results = self.tempStorage()
        self._bootstrap = None            # IANA's TLD -> RDAP server table, fetched once per scan
        self._backoff = {}                # RDAP server -> time before which it is not asked again
    # What events is this module interested in for input
    def watchedEvents(self) -> list:
        """Return the list of events this module watches."""
        return ["DOMAIN_NAME", "DOMAIN_NAME_PARENT", "NETBLOCK_OWNER", "NETBLOCKV6_OWNER",
                "CO_HOSTED_SITE_DOMAIN", "AFFILIATE_DOMAIN_NAME", "SIMILARDOMAIN"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self) -> list:
        """Return the list of events this module produces."""
        return ["DOMAIN_WHOIS", "NETBLOCK_WHOIS", "DOMAIN_REGISTRAR",
                "CO_HOSTED_SITE_DOMAIN_WHOIS", "AFFILIATE_DOMAIN_WHOIS",
                "SIMILARDOMAIN_WHOIS"]

    # ------------------------------------------------------------------
    # RDAP
    # ------------------------------------------------------------------

    def _load_bootstrap(self) -> dict:
        """TLD -> RDAP base URL, from IANA's bootstrap file (fetched once; {} if it cannot be)."""
        if self._bootstrap is not None:
            return self._bootstrap
        table = {}
        res = self.fetch_url(self.BOOTSTRAP_URL, timeout=self.opts.get('rdap_timeout', 15),
                             useragent="SpiderFoot")
        try:
            for tlds, urls in json.loads(res["content"])["services"]:
                base = next((u for u in urls if u.startswith("https://")), urls[0] if urls else None)
                if base:
                    for tld in tlds:
                        table[tld.lower()] = base if base.endswith("/") else base + "/"
        except Exception as e:
            self.debug(f"Could not read the IANA RDAP bootstrap file: {type(e).__name__}")
        self._bootstrap = table
        return table

    def _rdap_base(self, domain: str) -> str | None:
        tld = domain.rstrip(".").rsplit(".", 1)[-1].lower()
        return self._load_bootstrap().get(tld)

    def _rdap_domain(self, domain: str) -> dict | None:
        """The RDAP record of a domain, or None when RDAP has no usable answer (the caller falls back to WHOIS)."""
        base = self._rdap_base(domain)
        if not base:
            return None
        if time.monotonic() < self._backoff.get(base, 0):
            return None
        res = self.fetch_url(f"{base}domain/{domain}", timeout=self.opts.get('rdap_timeout', 15),
                             useragent="SpiderFoot", headers={"Accept": "application/rdap+json"})
        code = str((res or {}).get("code") or "")
        if code == "429":
            self._backoff[base] = time.monotonic() + self.RDAP_BACKOFF
            self.debug(f"{base} asked us to slow down; using WHOIS for {self.RDAP_BACKOFF}s")
            return None
        if code != "200" or not (res or {}).get("content"):
            return None
        try:
            record = json.loads(res["content"])
        except ValueError:
            return None
        return record if isinstance(record, dict) and record.get("objectClassName") == "domain" else None

    @staticmethod
    def _vcard(entity: dict) -> dict:
        """The contact fields of an RDAP entity's vCard, as {field: first value}."""
        out = {}
        for item in ((entity.get("vcardArray") or [None, []])[1] or []):
            if len(item) >= 4 and item[0] in ("fn", "org", "email", "tel", "adr", "kind"):
                value = item[3]
                if isinstance(value, list):                                   # a structured address
                    value = ", ".join(str(v) for v in value if v)
                if value and item[0] not in out:
                    out[item[0]] = str(value).strip()
        return out

    def _render_rdap(self, record: dict) -> tuple[str, str | None]:
        """(text in the classic WHOIS 'Label: value' form, registrar name) for an RDAP domain record.

        The text keeps the labels WHOIS output has so the modules that read DOMAIN_WHOIS (email, phone,
        company, names) work on it as before.
        """
        lines = [f"Domain Name: {str(record.get('ldhName') or '').upper()}"]
        if record.get("handle"):
            lines.append(f"Registry Domain ID: {record['handle']}")
        for event in record.get("events") or []:
            label = {"registration": "Creation Date", "expiration": "Registry Expiry Date",
                     "last changed": "Updated Date", "transfer": "Transfer Date"}.get(event.get("eventAction"))
            if label and event.get("eventDate"):
                lines.append(f"{label}: {event['eventDate']}")
        for status in record.get("status") or []:
            lines.append(f"Domain Status: {status}")
        registrar = None
        role_labels = {"registrar": "Registrar", "registrant": "Registrant", "administrative": "Admin",
                       "technical": "Tech", "billing": "Billing", "abuse": "Registrar Abuse Contact"}

        def walk(entities):
            nonlocal registrar
            for entity in entities or []:
                fields = self._vcard(entity)
                for role in entity.get("roles") or []:
                    label = role_labels.get(role)
                    if not label:
                        continue
                    if role == "registrar" and fields.get("fn") and registrar is None:
                        registrar = fields["fn"]
                    names = {"fn": "Name", "org": "Organization", "email": "Email", "tel": "Phone", "adr": "Address"}
                    if role == "registrar":
                        lines.append(f"Registrar: {fields.get('fn', '')}".rstrip())
                    for key, text in names.items():
                        if fields.get(key) and not (role == "registrar" and key == "fn"):
                            lines.append(f"{label} {text}: {fields[key]}")
                walk(entity.get("entities"))

        walk(record.get("entities"))
        for ns in record.get("nameservers") or []:
            if ns.get("ldhName"):
                lines.append(f"Name Server: {ns['ldhName']}")
        secure = record.get("secureDNS") or {}
        if "delegationSigned" in secure:
            lines.append(f"DNSSEC: {'signed' if secure['delegationSigned'] else 'unsigned'}")
        return "\n".join(lines), registrar

    # Handle events sent to this module
    def handleEvent(self, event: SpiderFootEvent) -> None:
        """Handle an event received by this module."""
        if self.errorState:
            return
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventName.startswith("DOMAIN_NAME"):
            typ = "DOMAIN_WHOIS"
        elif eventName.startswith("NETBLOCK"):
            typ = "NETBLOCK_WHOIS"
        elif eventName.startswith("AFFILIATE_DOMAIN_NAME"):
            typ = "AFFILIATE_DOMAIN_WHOIS"
        elif eventName.startswith("CO_HOSTED_SITE_DOMAIN"):
            typ = "CO_HOSTED_SITE_DOMAIN_WHOIS"
        elif eventName == "SIMILARDOMAIN":
            typ = "SIMILARDOMAIN_WHOIS"
        else:
            self.error(f"Invalid event type: {eventName}")
            return

        data = None
        registrar = None

        if eventName in ["NETBLOCK_OWNER", "NETBLOCKV6_OWNER"]:
            try:
                netblock = netaddr.IPNetwork(eventData)
            except Exception as e:
                self.error(f"Invalid netblock {eventData}: {e}")
                return

            ip = netblock[0]
            self.debug(f"Sending RDAP query for IP address: {ip}")

            try:
                # NOTE: ipwhois does not support proxy configuration
                r = ipwhois.IPWhois(ip)
                data = str(r.lookup_rdap(depth=1))
            except Exception as e:
                self.error(f"Unable to perform WHOIS query on {ip}: {e}")
        else:
            registrar = None
            # RDAP first: structured, and it says "slow down" instead of returning a short error page. Over 200 port-43
            # answers in two scans were short throttling replies that had to be discarded.
            if self.opts.get('use_rdap', True):
                self.debug(f"Sending RDAP query for domain: {eventData}")
                record = self._rdap_domain(eventData)
                if record:
                    data, registrar = self._render_rdap(record)
            if not data:
                self.debug(f"Sending WHOIS query for domain: {eventData}")
                try:
                    whoisdata = whois.whois(eventData)
                    data = str(whoisdata.text)
                    registrar = whoisdata.get('registrar')
                except Exception as e:
                    self.error(
                        f"Unable to perform WHOIS query on {eventData}: {e}")
                else:
                    # This is likely to be an error about being throttled rather than real data
                    if data and len(str(data)) < 250:
                        self.error(
                            f"WHOIS data ({len(data)} bytes) is smaller than 250 bytes. Throttling from WHOIS server is probably happening. Ignoring response.")
                        return

        if not data:
            self.error(f"No WHOIS record for {eventData}")
            return

        # This is likely to be an error about being throttled rather than real data
        if eventName.startswith("NETBLOCK") and len(str(data)) < 250:
            self.error(
                f"WHOIS data ({len(data)} bytes) is smaller than 250 bytes. Throttling from WHOIS server is probably happening. Ignoring response.")
            return

        rawevt = SpiderFootEvent(typ, data, self.__name__, event)
        self.notifyListeners(rawevt)

        if eventName.startswith("DOMAIN_NAME") and registrar:
            evt = SpiderFootEvent(
                "DOMAIN_REGISTRAR", registrar, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_whois class

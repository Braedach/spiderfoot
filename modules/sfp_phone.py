from __future__ import annotations

"""SpiderFoot plug-in module: phone."""

# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_phone
# Purpose:      SpiderFoot plug-in for scanning retrieved content by other
#               modules (such as sfp_spider) to identify phone numbers, and
#               lookup carrier information in Google's libphonenumber DB.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     19/06/2016
# Copyright:   (c) Steve Micallef 2016
# Licence:     MIT
# -------------------------------------------------------------------------------

import json

import phonenumbers
from phonenumbers import PhoneNumberFormat, PhoneNumberType, carrier, geocoder, timezone

from spiderfoot import SpiderFootEvent
from spiderfoot.plugins.async_plugin import SpiderFootAsyncPlugin


class sfp_phone(SpiderFootAsyncPlugin):

    """Identify phone numbers in scraped webpages."""

    meta = {
        'name': "Phone Number Extractor",
        'summary': "Identify phone numbers in scraped webpages, and describe each one from Google's libphonenumber data: whether it is valid, the line type (mobile, landline, VoIP and so on), the region, time zones, the carrier it was originally allocated to, and its standard formats.",
        'flags': [],
        'useCases': ["Passive", "Footprint", "Investigate"],
        'categories': ["Content Analysis"],
        "dataSource": {
            "website": None,
            "model": "FREE_NOAUTH_UNLIMITED",
            "references": [],
            "description": "Local data processing and extraction (no external API).",
        },
    }

    opts = {}

    results = None
    optdescs = {}

    def setup(self, sfc: SpiderFoot, userOpts: dict = None) -> None:
        """Set up the module."""
        super().setup(sfc, userOpts or {})
        self.results = self.tempStorage()
    def watchedEvents(self) -> list:
        """Return the list of events this module watches."""
        return ['TARGET_WEB_CONTENT', 'DOMAIN_WHOIS', 'NETBLOCK_WHOIS', 'PHONE_NUMBER']

    def producedEvents(self) -> list:
        """Return the list of events this module produces."""
        return ['PHONE_NUMBER', 'PROVIDER_TELCO', 'PHONE_NUMBER_TYPE', 'GEOINFO', 'RAW_RIR_DATA']

    def handleEvent(self, event: SpiderFootEvent) -> None:
        """Handle an event received by this module."""
        if self.errorState:
            return
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        sourceData = self.sf.hashstring(eventData)

        if sourceData in self.results:
            return

        self.results[sourceData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventName in ['TARGET_WEB_CONTENT', 'DOMAIN_WHOIS', 'NETBLOCK_WHOIS']:
            # Make potential phone numbers more friendly to parse
            content = eventData.replace('.', '-')

            for match in phonenumbers.PhoneNumberMatcher(content, region=None):
                n = phonenumbers.format_number(
                    match.number, phonenumbers.PhoneNumberFormat.E164)
                evt = SpiderFootEvent("PHONE_NUMBER", n, self.__name__, event)
                if event.moduleDataSource:
                    evt.moduleDataSource = event.moduleDataSource
                else:
                    evt.moduleDataSource = "Unknown"
                self.notifyListeners(evt)

        if eventName == 'PHONE_NUMBER':
            try:
                number = phonenumbers.parse(eventData)
            except Exception as e:
                self.debug(f"Error parsing phone number: {e}")
                return

            facts = self.describe(number)
            source = event.moduleDataSource or "Unknown"

            def emit(etype: str, data: str) -> None:
                evt = SpiderFootEvent(etype, data, self.__name__, event)
                evt.moduleDataSource = source
                self.notifyListeners(evt)

            if facts["carrier"]:
                emit("PROVIDER_TELCO", facts["carrier"])
            if facts["valid"] and facts["line_type"] != "Unknown":
                emit("PHONE_NUMBER_TYPE", facts["line_type"])
            # The map places a GEOINFO event by its two-letter country code, so always say which country the number
            # belongs to, even when libphonenumber has no finer location (mobile numbers carry only the country).
            region = facts.get("region_code")
            if facts["location"] or (facts["valid"] and region):
                emit("GEOINFO", ", ".join(p for p in (facts["location"], region) if p))
            emit("RAW_RIR_DATA", json.dumps(facts, indent=2))

    _LINE_TYPES = {
        PhoneNumberType.FIXED_LINE: "Fixed line",
        PhoneNumberType.MOBILE: "Mobile",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed line or mobile",
        PhoneNumberType.TOLL_FREE: "Toll free",
        PhoneNumberType.PREMIUM_RATE: "Premium rate",
        PhoneNumberType.SHARED_COST: "Shared cost",
        PhoneNumberType.VOIP: "VoIP",
        PhoneNumberType.PERSONAL_NUMBER: "Personal number",
        PhoneNumberType.PAGER: "Pager",
        PhoneNumberType.UAN: "Universal access number",
        PhoneNumberType.VOICEMAIL: "Voicemail",
        PhoneNumberType.UNKNOWN: "Unknown",
    }

    NOTE = ("The carrier is the one the number range was originally allocated to. A number that has been ported to "
            "another carrier still shows the original; only a live lookup service can tell the current one.")

    def describe(self, number) -> dict:
        """Everything libphonenumber knows about a parsed number (offline, no key).

        Each lookup is independent, so one failing never hides the others.
        """
        def safe(fn, default):
            try:
                return fn()
            except Exception as e:
                self.debug(f"Phone lookup failed: {e}")
                return default

        facts = {
            "number": safe(lambda: phonenumbers.format_number(number, PhoneNumberFormat.E164), str(number)),
            "international": safe(lambda: phonenumbers.format_number(number, PhoneNumberFormat.INTERNATIONAL), ""),
            "national": safe(lambda: phonenumbers.format_number(number, PhoneNumberFormat.NATIONAL), ""),
            "country_calling_code": number.country_code,
            "region_code": safe(lambda: phonenumbers.region_code_for_number(number), None),
            "valid": safe(lambda: phonenumbers.is_valid_number(number), False),
            "possible": safe(lambda: phonenumbers.is_possible_number(number), False),
            "line_type": self._LINE_TYPES.get(safe(lambda: phonenumbers.number_type(number),
                                                   PhoneNumberType.UNKNOWN), "Unknown"),
            "location": safe(lambda: geocoder.description_for_number(number, "en"), "") or "",
            "carrier": safe(lambda: carrier.name_for_number(number, "en"), "") or "",
            "time_zones": [z for z in safe(lambda: timezone.time_zones_for_number(number), ()) if z != "Etc/Unknown"],
            "note": self.NOTE,
        }
        return facts

    def registerEventEmitter(self, emitter: str) -> None:
        """Register event emitter"""
        self.eventEmitter = emitter

# End of sfp_phone class

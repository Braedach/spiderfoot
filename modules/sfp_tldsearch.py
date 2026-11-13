from __future__ import annotations

"""SpiderFoot plug-in module: tldsearch."""

# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tldsearch
# Purpose:      SpiderFoot plug-in for identifying the existence of this target
#               on other TLDs.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     31/08/2013
# Copyright:   (c) Steve Micallef 2013
# Licence:     MIT
# -------------------------------------------------------------------------------

import random
import threading
import time

import dns.resolver

from spiderfoot import SpiderFootEvent
from spiderfoot.plugins.async_plugin import SpiderFootAsyncPlugin


class sfp_tldsearch(SpiderFootAsyncPlugin):

    """Search all Internet TLDs for domains with the same name as the target (this can be very slow.)"""

    meta = {
        'name': "TLD Searcher",
        'summary': "Search all Internet TLDs for domains with the same name as the target (this can be very slow.)",
        'flags': ["slow"],
        'useCases': ["Footprint"],
        'categories': ["DNS"]
    }

    # Default options
    opts = {
        # Only report domains that have content (try to fetch the page)
        'activeonly': False,
        'skipwildcards': True,
        # Renamed from '_maxthreads' 2026-11-13: that name collided with
        # the scan-wide global _maxthreads config key. SpiderFootScanner
        # merges every global config key into each module's own opts dict
        # AFTER copying the module's own defaults (see waitForThreads()'s
        # module-load loop), so the global value always won - this
        # module's intended batch size of 50 was silently being replaced
        # by the global dispatch-pool size (3, then 12) on every scan,
        # ~4-6x more sequential batches than intended for a full ~9,000-
        # entry TLD sweep. Found live investigating a 28+ minute scan
        # stall (rc.25 scope re-test) that turned out to be this, not
        # pool contention. 6 other modules had the same collision -
        # see sfp_accounts/sfp_s3bucket/sfp_dnsbrute/sfp_googleobjectstorage/
        # sfp_digitaloceanspace/sfp_azureblobstorage.
        'batch_size': 50
    }

    # Option descriptions
    optdescs = {
        'activeonly': "Only report domains that have content (try to fetch the page)?",
        "skipwildcards": "Skip TLDs and sub-TLDs that have wildcard DNS.",
        "batch_size": "Maximum concurrent lookups per batch for this module's own enumeration (independent of the scan-wide _maxthreads)."
    }

    # Internal results tracking
    results = None

    # Track TLD search results between threads
    tldResults = dict()
    lock = None

    def setup(self, sfc: SpiderFoot, userOpts: dict = None) -> None:
        """Set up the module."""
        super().setup(sfc, userOpts or {})
        self.results = self.tempStorage()
        self.__dataSource__ = "DNS"
        self.lock = threading.Lock()
    # What events is this module interested in for input
    def watchedEvents(self) -> list:
        """Return the list of events this module watches."""
        return ["INTERNET_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self) -> list:
        """Return the list of events this module produces."""
        return ["SIMILARDOMAIN"]

    def tryTld(self, target: str, tld: str) -> None:
        """TryTld."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1
        resolver.lifetime = 1
        resolver.search = list()
        if self.opts.get('_dnsserver', "") != "":
            resolver.nameservers = [self.opts['_dnsserver']]

        if self.opts['skipwildcards'] and self.sf.checkDnsWildcard(tld):
            return

        try:
            if not self.resolve_host(target) and not self.resolve_host6(target):
                with self.lock:
                    self.tldResults[target] = False
            else:
                with self.lock:
                    self.tldResults[target] = True
        except Exception as e:
            with self.lock:
                self.tldResults[target] = False

    def tryTldWrapper(self, tldList: list, sourceEvent: SpiderFootEvent) -> None:
        """TryTldWrapper."""
        self.tldResults = dict()
        running = True
        t = []

        # Spawn threads for scanning
        self.info(f"Spawning threads to check TLDs: {tldList}")
        for i, pair in enumerate(tldList):
            (domain, tld) = pair
            tn = 'thread_sfp_tldsearch_' + \
                str(random.SystemRandom().randint(0, 999999999))
            t.append(threading.Thread(
                name=tn, target=self.tryTld, args=(domain, tld,)))
            # daemon=True: an abandoned-on-timeout thread (see the deadline
            # below) must never block process shutdown.
            t[i].daemon = True
            t[i].start()

        # Block until all threads are finished, bounded by an overall
        # deadline - a single hung TLD lookup must never be able to block
        # this forever, which stalls the WHOLE SCAN forever since
        # handleEvent() won't return until this does, and this module
        # calls tryTldWrapper() once per batch across the entire ~9,000-
        # entry TLD list. Confirmed live 2026-11-13: this pattern, shared
        # by 6 other modules, silently stalled a scan overnight with no
        # error, no crash, no symptom beyond the scan never finishing.
        deadline = time.monotonic() + 30
        while running:
            found = False
            for rt in threading.enumerate():
                if rt.name.startswith("thread_sfp_tldsearch_"):
                    found = True

            if not found:
                running = False
            elif time.monotonic() > deadline:
                self.error(
                    "Timed out waiting for TLD lookups - abandoning this"
                    " batch (a DNS lookup may be unresponsive).")
                running = False

            time.sleep(0.1)

        for res in self.tldResults:
            if self.getTarget().matches(res, includeParents=True, includeChildren=True):
                continue
            if self.tldResults[res] and res not in self.results:
                self._emitEvent(sourceEvent, res)

    # Store the result internally and notify listening modules
    def _emitEvent(self, source: str, result: str) -> None:
        """SendEvent."""
        self.info("Found a TLD with the target's name: " + result)
        self.results[result] = True

        # Inform listening modules
        if self.opts['activeonly']:
            if self.checkForStop():
                return

            pageContent = self.fetch_url('http://' + result,
                                           timeout=self.opts['_fetchtimeout'],
                                           useragent=self.opts['_useragent'],
                                           noLog=True,
                                           verify=False)
            if pageContent is not None and pageContent.get('content') is not None:
                evt = SpiderFootEvent(
                    "SIMILARDOMAIN", result, self.__name__, source)
                self.notifyListeners(evt)
        else:
            evt = SpiderFootEvent("SIMILARDOMAIN", result,
                                  self.__name__, source)
            self.notifyListeners(evt)

    # Search for similar sounding domains
    def handleEvent(self, event: SpiderFootEvent) -> None:
        """Handle an event received by this module."""
        if self.errorState:
            return
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        keyword = self.sf.domainKeyword(eventData, self.opts['_internettlds'])

        if not keyword:
            self.error(f"Failed to extract keyword from {eventData}")
            return

        self.debug(f"Keyword extracted from {eventData}: {keyword}")

        if keyword in self.results:
            return

        self.results[keyword] = True

        # Look through all TLDs for the existence of this target keyword
        targetList = list()
        for tld in self.opts['_internettlds']:
            if not isinstance(tld, str):
                tld = str(tld.strip(), errors='ignore')
            else:
                tld = tld.strip()

            if tld.startswith("//") or len(tld) == 0:
                continue

            if tld.startswith("!") or tld.startswith("*") or tld.startswith(".."):
                continue

            if tld.endswith(".arpa"):
                continue

            tryDomain = keyword + "." + tld

            if self.checkForStop():
                return

            if len(targetList) <= self.opts['batch_size']:
                targetList.append([tryDomain, tld])
            else:
                self.tryTldWrapper(targetList, event)
                targetList = list()

        # Scan whatever may be left over.
        if len(targetList) > 0:
            self.tryTldWrapper(targetList, event)

# End of sfp_tldsearch class

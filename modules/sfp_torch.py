from __future__ import annotations

"""SpiderFoot plug-in module: torch."""

# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_torch
# Purpose:      Searches the Tor search engine 'TORCH' for content related
#               to the domain in question.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     20/06/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     MIT
# -------------------------------------------------------------------------------

import re
from urllib.parse import urlencode

from spiderfoot import SpiderFootEvent
from spiderfoot.plugins.async_plugin import SpiderFootAsyncPlugin


class sfp_torch(SpiderFootAsyncPlugin):

    """Search Tor """

    meta = {
        'name': "TORCH",
        'summary': "Search Tor 'TORCH' search engine for mentions of the target domain.",
        'flags': ["tor"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://torchsearch.wordpress.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Torch or TorSearch is the best search engine "
                "for the hidden part of the internet. They're also the "
                "oldest and longest running search engine on Tor.\n"
                "Torch claims to have over one billion dark net pages indexed. "
                "They also don't censor search results or track what you "
                "search for.",
        }
    }

    opts = {
        'torch_url': "http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion",
        'fetchlinks': True,
        'pages': 20,
        'fullnames': True
    }

    optdescs = {
        'torch_url': "Address of the TORCH search engine's onion service. TORCH has moved before; set the current address here if this stops working.",
        'fetchlinks': "Fetch the darknet pages (via TOR, if enabled) to verify they mention your target.",
        'pages': "Number of results pages to iterate through (10 results per page).",
        'fullnames': "Search for human names?"
    }

    HITS_PER_PAGE = 10
    _ONION_BASE = re.compile(r"^https?://[a-z2-7]{16,56}\.onion/?$", re.IGNORECASE)
    # Each result is a bold link at the start of a table cell: <td><b><a href="URL">Title</a></b>
    _RESULT_LINK = re.compile(r'<td><b><a href="(https?://[^"]+)"', re.IGNORECASE)

    results = None

    def setup(self, sfc: SpiderFoot, userOpts: dict = None) -> None:
        """Set up the module."""
        super().setup(sfc, userOpts or {})
        self.results = self.tempStorage()
    def watchedEvents(self) -> list:
        """Return the list of events this module watches."""
        return [
            "DOMAIN_NAME",
            "HUMAN_NAME",
            "EMAILADDR"
        ]

    def producedEvents(self) -> list:
        """Return the list of events this module produces."""
        return [
            "DARKNET_MENTION_URL",
            "DARKNET_MENTION_CONTENT"
        ]

    @staticmethod
    def _query(event_type: str, data: str) -> str:
        """The TORCH (Omega) query for an event.

        Names and domains are searched as an exact phrase, so a name does not match every page that merely contains
        its words. TORCH cannot match a term containing "@" (checked live 2026-11-16: even generic addresses
        returned nothing), so an email address is searched as its local part AND its domain; the page is then fetched
        and checked for the exact address (the fetchlinks option).
        """
        data = data.replace('"', "").strip()
        if event_type == "EMAILADDR" and "@" in data:
            local, _, domain = data.partition("@")
            return f"{local} {domain}"
        return f'"{data}"'

    def handleEvent(self, event: SpiderFootEvent) -> None:
        """Handle an event received by this module."""
        if self.errorState:
            return
        eventName = event.eventType
        eventData = event.data

        if not self.opts['fullnames'] and eventName == 'HUMAN_NAME':
            return

        if eventData in self.results:
            self.debug(f"Already did a search for {eventData}, skipping.")
            return

        self.results[eventData] = True

        base = str(self.opts.get('torch_url') or "").strip()
        if not self._ONION_BASE.match(base):
            self.error(f"The TORCH address '{base}' is not an onion address; set torch_url to the current TORCH onion address.")
            self.errorState = True
            return
        base = base.rstrip("/")

        phrase = self._query(eventName, eventData)

        pagecount = 0
        while pagecount < self.opts['pages']:
            # Check if we've been asked to stop
            if self.checkForStop():
                return

            params = {"P": phrase, "DEFAULTOP": "and", "HITSPERPAGE": self.HITS_PER_PAGE,
                      "TOPDOC": pagecount * self.HITS_PER_PAGE}
            pagecount += 1

            qry = urlencode(params)
            data = self.fetch_url(
                f"{base}/cgi-bin/omega/omega?{qry}",
                useragent=self.opts['_useragent'],
                timeout=60)

            if data is None or not data.get('content'):
                self.info("Couldn't get results from TORCH (it may be down, or its address in the torch_url option is out of date).")
                return

            if "No documents match your query" in data['content']:
                if pagecount == 1:
                    self.info(f"No results found on TORCH for {eventData}")
                return

            links = self._RESULT_LINK.findall(data['content'])

            linkcount = 0
            for link in links:
                if link in self.results:
                    continue

                self.results[link] = True
                self.debug(f"Found a darknet mention: {link}")
                if self.sf.urlFQDN(link).endswith(".onion"):
                    if self.checkForStop():
                        return
                    if self.opts['fetchlinks']:
                        res = self.fetch_url(link, timeout=self.opts['_fetchtimeout'],
                                               useragent=self.opts['_useragent'])

                        if res['content'] is None:
                            self.debug(f"Ignoring {link} as no data returned")
                            continue

                        if eventData not in res['content']:
                            self.debug(
                                f"Ignoring {link} as no mention of {eventData}")
                            continue
                        evt = SpiderFootEvent(
                            "DARKNET_MENTION_URL", link, self.__name__, event)
                        self.notifyListeners(evt)
                        linkcount += 1

                        try:
                            startIndex = res['content'].index(eventData) - 120
                            endIndex = startIndex + len(eventData) + 240
                        except Exception as e:
                            self.debug("String not found in content.")
                            continue

                        darkcontent = res['content'][startIndex:endIndex]
                        evt = SpiderFootEvent("DARKNET_MENTION_CONTENT", f"...{darkcontent}...",
                                              self.__name__, evt)
                        self.notifyListeners(evt)

                    else:
                        evt = SpiderFootEvent(
                            "DARKNET_MENTION_URL", link, self.__name__, event)
                        self.notifyListeners(evt)
                        linkcount += 1

            if linkcount == 0:
                # No more pages
                return


# End of sfp_torch class

from __future__ import annotations

"""SpiderFoot plug-in module: intfiles."""

# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_intfiles
# Purpose:      From Spidered pages found, identifies files of potential interest.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     MIT
# -------------------------------------------------------------------------------

import re

from spiderfoot import SpiderFootEvent
from spiderfoot.plugins.async_plugin import SpiderFootAsyncPlugin


class sfp_intfiles(SpiderFootAsyncPlugin):
    """Identifies potential files of interest, e.g. office documents, zip files."""

    __name__ = "sfp_intfiles"

    meta = {
        'name': "Interesting File Finder",
        'summary': "Identifies files of interest linked from the target's website, e.g. office documents and zip files, and checks that the server really serves each one before reporting it.",
        'flags': [],
        'useCases': ["Footprint", "Passive"],
        'categories': ["Crawling and Scanning"]
    }

    # Default options
    opts = {
        'fileexts': ["doc", "docx", "ppt", "pptx", "pdf", 'xls', 'xlsx', 'zip'],
        'verify': True,
        'verifytimeout': 15,
    }

    # Option descriptions
    optdescs = {
        'fileexts': "File extensions of files you consider interesting.",
        'verify': "Request each file (only its first few kilobytes) and report it only if the server really serves "
                  "it: HTTP 200, not an empty answer and not a web page. A link to a file that redirects to a login "
                  "page, or answers 404, is not an exposed file. Turn off to report every link with such an extension "
                  "without checking.",
        'verifytimeout': "Seconds to wait for each file when verifying.",
    }

    results = None

    def setup(self, sfc: SpiderFoot, userOpts: dict = None) -> None:
        """Set up the module."""
        super().setup(sfc, userOpts or {})
        self.results = self.tempStorage()
        self.__dataSource__ = "Target Website"
    # What events is this module interested in for input
    def watchedEvents(self) -> list:
        """Return the list of events this module watches."""
        return ["LINKED_URL_INTERNAL"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self) -> list:
        """Return the list of events this module produces."""
        return ["INTERESTING_FILE"]

    # Handle events sent to this module
    def handleEvent(self, event: SpiderFootEvent) -> None:
        """Handle an event received by this module."""
        if self.errorState:
            return
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            return

        self.results[eventData] = True

        if not self._interesting(eventData):
            return

        if self.opts.get('verify', True):
            why = self._not_served(eventData)
            if why:
                self.debug(f"Not reporting {eventData}: {why}")
                return

        evt = SpiderFootEvent("INTERESTING_FILE", eventData, self.__name__, event)
        self.notifyListeners(evt)

    def _interesting(self, url: str) -> bool:
        """True when the URL names a file with one of the configured extensions (in its path, or as a query value)."""
        exts = [e.strip().lower().lstrip(".") for e in self.opts['fileexts'] if e and e.strip()]
        if not exts:
            return False
        pattern = r"\.(?:" + "|".join(re.escape(e) for e in exts) + r")(?:$|[?&#])"
        return re.search(pattern, url.lower()) is not None

    def _not_served(self, url: str) -> str | None:
        """None when the server really serves the file; otherwise the reason it is not reported."""
        try:
            res = self.fetch_url(url, timeout=int(self.opts.get('verifytimeout', 15)),
                                 useragent=self.opts.get('_useragent', 'SpiderFoot'), sizeLimit=2048)
        except Exception as e:
            return f"could not be checked ({type(e).__name__})"
        if not res:
            return "no answer"
        if str(res.get('code')) != "200":
            return f"HTTP {res.get('code')} (a redirect or an error, not the file)"
        if not res.get('content'):
            return "an empty answer"
        ctype = ""
        for k, v in (res.get('headers') or {}).items():
            if str(k).lower() == "content-type":
                ctype = str(v).lower()
        if ctype.startswith("text/html") or ctype.startswith("application/xhtml"):
            return "the server answered with a web page, not the file"
        return None

# End of sfp_intfiles class

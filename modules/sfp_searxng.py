from __future__ import annotations

"""SpiderFoot plug-in module: searxng."""

# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_searxng
# Purpose:      Search the web for a person's name, email address, phone number or username through the
#               administrator's OWN SearXNG server, and report the pages that come back.
#               SearXNG: https://docs.searxng.org/ (AGPL; run by the owner, not bundled)
#
# Created:      16/11/2026
# Licence:      MIT
# -------------------------------------------------------------------------------

import re
import time
from urllib.parse import urlencode, urlsplit

from spiderfoot import SpiderFootEvent
from spiderfoot.plugins.async_plugin import SpiderFootAsyncPlugin

try:                                        # phone formats (international, national): optional
    import phonenumbers
except ImportError:                         # pragma: no cover
    phonenumbers = None

_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{3,63}$")


class sfp_searxng(SpiderFootAsyncPlugin):

    """Search the web for a person, email address, phone number or username through your own SearXNG server."""

    meta = {
        'name': "Web Search (SearXNG)",
        'summary': "Search the web, in quotes, for a person's name, email address, phone number or username through "
                   "your own SearXNG server (Settings > Web Search), and report the pages that come back, each marked "
                   "with whether the searched term really appears in it.",
        'flags': ["slow"],
        'useCases': ["Investigate"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://docs.searxng.org/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': ["https://docs.searxng.org/dev/search_api.html"],
            'description': "A metasearch engine you run yourself. SpiderFoot sends each search to your server, which "
                           "queries the search engines behind it.",
        },
    }

    # Module options. The server address, switch and limits are global settings (Settings > Web Search).
    opts = {
        'person_targets_only': True,
    }

    optdescs = {
        'person_targets_only': "Only act when the scan is about a person (a name, email address, username or phone number). "
                               "Off = also search for every email address and name found during other scans, such as staff "
                               "listed on a company's website, which sends those people's details to the search engines.",
    }

    # Target types that mean the user asked about a person
    PERSON_TARGETS = ("HUMAN_NAME", "EMAILADDR", "USERNAME", "PHONE_NUMBER")

    results = None
    errorState = False

    def setup(self, sfc, userOpts: dict = None) -> None:
        """Set up the module."""
        super().setup(sfc, userOpts or {})
        self.results = self.tempStorage()
        self.errorState = False
        self._sent = 0
        self._limit_noted = False
        self.__dataSource__ = "Web search through SearXNG"
        self._base = self._configured_base()
        if self._base is None:
            self.info("Web Search (SearXNG) is not configured (Settings > Web Search: turn it on and enter the address of "
                      "your SearXNG server), so it is skipped.")
            self.errorState = True

    # ----------------------------------------------------------------------------------------- settings

    def _configured_base(self) -> str | None:
        """The SearXNG address without a trailing slash, or None when the feature is off or the address unusable."""
        enabled = self.opts.get('_searxng_enabled', False)
        if isinstance(enabled, str):
            enabled = enabled.strip().lower() in ("1", "true", "yes", "on")
        url = str(self.opts.get('_searxng_url') or "").strip()
        if not enabled or not url:
            return None
        try:
            parts = urlsplit(url)
        except ValueError:
            return None
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return None
        return f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"

    def _number(self, key: str, default: float) -> float:
        try:
            return float(self.opts.get(key, default))
        except (TypeError, ValueError):
            return default

    def watchedEvents(self) -> list:
        """Return the list of events this module watches."""
        return ["HUMAN_NAME", "EMAILADDR", "PHONE_NUMBER", "USERNAME"]

    def producedEvents(self) -> list:
        """Return the list of events this module produces."""
        return ["SEARCH_ENGINE_WEB_CONTENT"]

    def _person_scan(self) -> bool:
        """True when this module may act: the scan is about a person, or the user turned the restriction off."""
        if not self.opts.get('person_targets_only', True):
            return True
        try:
            return self.getTarget().targetType in self.PERSON_TARGETS
        except Exception:
            return False

    # ----------------------------------------------------------------------------------------- queries

    @staticmethod
    def _phone_forms(number: str) -> list[str]:
        """The ways a phone number is written on web pages: international, national and bare digits."""
        forms = [number.strip()]
        if phonenumbers is not None:
            try:
                parsed = phonenumbers.parse(number)
                forms += [phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                          phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
                          phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)]
            except Exception:
                pass
        seen: list[str] = []
        for f in forms:
            if f and f not in seen:
                seen.append(f)
        return seen[:4]

    def _queries(self, event_type: str, data: str) -> list[str]:
        """The searches for an event: each term quoted, so only pages with the exact term match."""
        data = data.replace('"', "").strip()
        if not data:
            return []
        if event_type == "PHONE_NUMBER":
            return [f'"{form}"' for form in self._phone_forms(data)]
        if event_type == "USERNAME" and not _USERNAME.match(data):
            return []
        return [f'"{data}"']

    @staticmethod
    def _digits(text: str) -> str:
        return re.sub(r"\D", "", text)

    def _term_in(self, term: str, event_type: str, *texts: str) -> bool:
        """Whether the searched term appears in a result (phone numbers are compared digit by digit)."""
        haystack = " ".join(t for t in texts if t).lower()
        if event_type == "PHONE_NUMBER":
            digits = self._digits(term)
            national = digits[len(digits) - 9:] if len(digits) > 9 else digits
            return bool(national) and national in self._digits(haystack)
        return term.lower() in haystack

    # ----------------------------------------------------------------------------------------- handling

    def handleEvent(self, event: SpiderFootEvent) -> None:
        """Search for the event's term and report what comes back."""
        if self.errorState:
            return
        if not self._person_scan():
            self.debug("Not searching: this scan is not about a person (option person_targets_only).")
            return

        term = str(event.data).strip().strip('"').strip()
        key = f"{event.eventType}|{term.lower()}"
        if not term or key in self.results:
            return
        self.results[key] = True

        max_queries = int(self._number('_searxng_max_queries', 6))
        delay = max(0.0, self._number('_searxng_delay', 2.0))
        timeout = max(1, int(self._number('_searxng_timeout', 20)))
        keep = max(1, int(self._number('_searxng_results', 10)))

        for query in self._queries(event.eventType, term):
            if self.checkForStop() or self.errorState:
                return
            if self._sent >= max_queries:
                if not self._limit_noted:
                    self._limit_noted = True
                    self.info(f"Web Search: the limit of {max_queries} searches for this scan is reached "
                              "(Settings > Web Search); further terms are not searched.")
                return
            if self._sent > 0 and delay:
                time.sleep(delay)
            self._sent += 1
            self._search(event, term, query, timeout, keep)

    def _search(self, event: SpiderFootEvent, term: str, query: str, timeout: int, keep: int) -> None:
        """Send one search and report its results."""
        url = f"{self._base}/search?{urlencode({'q': query, 'format': 'json', 'safesearch': 0})}"
        res = self.fetch_url(url, timeout=timeout, useragent=self.opts.get('_useragent', 'SpiderFoot'))
        code = str((res or {}).get('code') or "")
        host = urlsplit(self._base).netloc

        if not res or not code:
            self.error(f"No answer from the SearXNG server at {host}.")
            return
        if code == "403":
            self.error(f"The SearXNG server at {host} refused the search. Its JSON format is probably disabled: add 'json' "
                       "under search.formats in its settings.yml.")
            self.errorState = True
            return
        if code == "429":
            self.error(f"The SearXNG server at {host} is rate-limiting requests; Web Search stops for this scan. Its rate "
                       "limiter is configured on the server.")
            self.errorState = True
            return
        if code != "200":
            self.error(f"The SearXNG server at {host} answered HTTP {code}.")
            return
        try:
            import json
            data = json.loads(res.get('content') or "")
        except ValueError:
            self.error(f"The SearXNG server at {host} did not answer JSON (is the json format enabled?).")
            return

        unresponsive = data.get('unresponsive_engines') or []
        if unresponsive:
            self.info("SearXNG could not reach some engines for this search: "
                      + ", ".join(f"{e[0]} ({e[1]})" for e in unresponsive if isinstance(e, (list, tuple)) and len(e) > 1))

        found = 0
        for item in (data.get('results') or [])[:keep]:
            if not isinstance(item, dict) or not item.get('url'):
                continue
            title = " ".join(str(item.get('title') or "").split())
            snippet = " ".join(str(item.get('content') or "").split())
            link = str(item['url'])
            dedupe = f"{link}|{query}"
            if dedupe in self.results:
                continue
            self.results[dedupe] = True
            engines = item.get('engines') or ([item['engine']] if item.get('engine') else [])
            present = self._term_in(term, event.eventType, title, snippet, link)
            body = (f"{title}\n<SFURL>{link}</SFURL>\n{snippet}\n"
                    f"[search: {query}; engines: {', '.join(map(str, engines)) or 'unknown'}; "
                    f"the searched term {'appears' if present else 'does NOT appear'} in this result's title, link or snippet]")
            self.notifyListeners(SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", body, self.__name__, event))
            found += 1
        self.info(f"Web Search: {found} result(s) for {query}")

# End of sfp_searxng class

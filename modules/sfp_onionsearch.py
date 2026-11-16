from __future__ import annotations

"""SpiderFoot plug-in module: onionsearch."""

# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_onionsearch
# Purpose:      Search several dark-web search engines (onion services, through Tor) for the scan target and
#               report the hidden-service pages that mention it. One module, many engines: an engine that is down
#               or changes its page only costs that engine, not the module.
#
# Created:      16/11/2026
# Licence:      MIT
# -------------------------------------------------------------------------------

import re
import time
from urllib.parse import quote_plus, urlsplit

from spiderfoot import SpiderFootEvent
from spiderfoot.plugins.async_plugin import SpiderFootAsyncPlugin

# Engines that answered a live search through Tor on 2026-11-16 and returned result links in their page. Each line is
# "name = address", with {q} where the search term goes. Engines come and go; edit the list in the module options.
DEFAULT_ENGINES = "\n".join([
    "tor66 = http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/search?q={q}",
    "amnesia = http://amnesia7u5odx5xbwtpnqk3edybgud5bmiagu75bnqx2crntw5kry7ad.onion/search?query={q}",
    "onionland = http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={q}",
    "oniway = http://oniwayzz74cv2puhsgx4dpjwieww4wdphsydqvf5q7eyz4myjvyw26ad.onion/search.php?s={q}",
    "searchgf = http://searchgf7gdtauh7bhnbyed4ivxqmuoat3nm6zfrg3ymkq6mtnpye3ad.onion/search?q={q}",
    "tordex = http://2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad.onion/search?query={q}",
])

_ONION_HOST = re.compile(r"^[a-z2-7]{16,56}\.onion$", re.IGNORECASE)
_ANCHOR = re.compile(r"""<a\b[^>]*?href=["'](https?://[a-z2-7]{16,56}\.onion[^"'\s<>]*)["'][^>]*>""", re.IGNORECASE)
_SPONSORED = re.compile(r"""\brel=["'][^"']*\b(sponsor|sponsored|advert)""", re.IGNORECASE)
_TAG = re.compile(r"<[^>]+>")


class sfp_onionsearch(SpiderFootAsyncPlugin):

    """Search several dark-web search engines for the scan target."""

    meta = {
        'name': "Dark Web Search Engines",
        'summary': "Search several Tor search engines (Tor66, Amnesia, OnionLand, Oniway, Search.gf, Tordex) for the "
                   "scan target, and report the hidden-service pages whose result text mentions it. Opens no hidden-service "
                   "page unless 'verify' is turned on. Needs Settings > Tor on.",
        'flags': ["tor", "slow"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://github.com/apurvsinghgautam/robin",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Public Tor search engines, queried through your own Tor proxy. The engine list is an "
                           "option, because these services change address often.",
        },
    }

    opts = {
        'engines': DEFAULT_ENGINES,
        'target_only': True,
        'verify': False,
        'max_verify': 20,
        'delay': 3,
        'max_per_engine': 25,
    }

    optdescs = {
        'engines': "The search engines, one per line as 'name = address', with {q} where the search term goes. Onion "
                   "addresses only. Engines move often; remove ones that stop answering and add current ones.",
        'target_only': "Search only for the scan's own target (its name, email address, phone number or domain). Off = "
                       "also search for every name, address and number found during the scan, which sends other "
                       "people's details to those search engines.",
        'verify': "Fetch result pages (through Tor) to check that they really contain the searched term. OFF by default: "
                  "these engines also show paid adverts for hidden services of every kind, and fetching an arbitrary "
                  "hidden-service page can bring unlawful content into the scan. Off = only results whose text in the "
                  "engine's own page contains the term are reported, and no hidden-service page is opened.",
        'max_verify': "The most result pages fetched per scan target when 'verify' is on.",
        'delay': "Seconds to wait between searches.",
        'max_per_engine': "The most result links taken from each engine.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts: dict = None) -> None:
        """Set up the module."""
        super().setup(sfc, userOpts or {})
        self.results = self.tempStorage()
        self.errorState = False
        self._engines = self.parse_engines(str(self.opts.get('engines') or ""))
        if not self._engines:
            self.error("No usable search engine is configured (option 'engines'); this module is stopped.")
            self.errorState = True

    # ----------------------------------------------------------------------------------------- configuration

    @staticmethod
    def parse_engines(text: str) -> list[tuple[str, str]]:
        """Valid 'name = address' lines: an onion address with a {q} placeholder. Anything else is ignored."""
        engines: list[tuple[str, str]] = []
        for line in text.splitlines():
            name, sep, url = line.partition("=")
            name, url = name.strip(), url.strip()
            if not sep or not name or "{q}" not in url:
                continue
            try:
                parts = urlsplit(url.replace("{q}", "x"))
            except ValueError:
                continue
            if parts.scheme in ("http", "https") and parts.hostname and _ONION_HOST.match(parts.hostname):
                engines.append((name, url))
        return engines

    def watchedEvents(self) -> list:
        """Return the list of events this module watches."""
        return ["DOMAIN_NAME", "HUMAN_NAME", "EMAILADDR", "PHONE_NUMBER"]

    def producedEvents(self) -> list:
        """Return the list of events this module produces."""
        return ["DARKNET_MENTION_URL", "DARKNET_MENTION_CONTENT"]

    # ----------------------------------------------------------------------------------------- helpers

    @staticmethod
    def _phone_forms(number: str) -> list[str]:
        forms = [number.strip()]
        try:
            import phonenumbers
            parsed = phonenumbers.parse(number)
            forms += [phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                      phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)]
        except Exception:
            pass
        out: list[str] = []
        for f in forms:
            if f and f not in out:
                out.append(f)
        return out[:3]

    def _terms(self, event_type: str, data: str) -> list[str]:
        """The searches to make: names and domains as a phrase, an email address as written, a number in its forms."""
        data = data.replace('"', "").strip()
        if not data:
            return []
        if event_type == "PHONE_NUMBER":
            return self._phone_forms(data)
        if event_type == "HUMAN_NAME":
            return [f'"{data}"']
        return [data]

    @staticmethod
    def _contains(term: str, event_type: str, text: str) -> bool:
        """Whether text really holds the term (a number is compared digit by digit)."""
        term = term.strip('"')
        if event_type == "PHONE_NUMBER":
            digits = re.sub(r"\D", "", term)
            national = digits[-9:] if len(digits) > 9 else digits
            return bool(national) and national in re.sub(r"\D", "", text)
        return term.lower() in text.lower()

    def _is_target(self, event: SpiderFootEvent) -> bool:
        if not self.opts.get('target_only', True):
            return True
        try:
            target = self.getTarget().targetValue
        except Exception:
            return False
        norm = lambda v: re.sub(r"[\s\"']", "", str(v)).lower()   # noqa: E731
        return norm(event.data) == norm(target)

    def extract_links(self, page: str, engine_url: str) -> list[tuple[str, str]]:
        """Result links in an engine's page, each with the page text that follows it (the engine's snippet).

        Links to the engine's own address and links marked as sponsored (paid adverts) are skipped. Several engines show the same page under many links, so each
        address appears once.
        """
        own = (urlsplit(engine_url.replace("{q}", "x")).hostname or "").lower()
        seen: set[str] = set()
        out: list[tuple[str, str]] = []
        for m in _ANCHOR.finditer(page or ""):
            if _SPONSORED.search(m.group(0)):           # paid adverts: never results, never followed
                continue
            link = m.group(1)
            host = (urlsplit(link).hostname or "").lower()
            if host == own or link in seen:
                continue
            seen.add(link)
            snippet = " ".join(_TAG.sub(" ", page[m.end():m.end() + 700]).split())
            out.append((link, snippet))
        return out

    # ----------------------------------------------------------------------------------------- handling

    def handleEvent(self, event: SpiderFootEvent) -> None:
        """Search every engine for the event's term and report the pages that mention it."""
        if self.errorState or not self._is_target(event):
            return
        key = f"{event.eventType}|{str(event.data).lower()}"
        if key in self.results:
            return
        self.results[key] = True

        delay = max(0.0, float(self.opts.get('delay', 3)))
        verify_budget = int(self.opts.get('max_verify', 20))
        per_engine = max(1, int(self.opts.get('max_per_engine', 25)))
        reported: set[str] = set()
        searched = 0

        for term in self._terms(event.eventType, str(event.data)):
            for name, template in self._engines:
                if self.checkForStop():
                    return
                if searched and delay:
                    time.sleep(delay)
                searched += 1
                url = template.replace("{q}", quote_plus(term))
                res = self.fetch_url(url, timeout=60, useragent=self.opts.get('_useragent', 'Mozilla/5.0'))
                content = (res or {}).get('content')
                if not content:
                    self.info(f"{name}: no answer (it may be down or its address is out of date).")
                    continue
                links = self.extract_links(content, template)[:per_engine]
                if not links:
                    self.debug(f"{name}: no result links for {term}")
                    continue
                for link, snippet in links:
                    if link in reported:
                        continue
                    if self.checkForStop():
                        return
                    evidence = ""
                    if self._contains(term, event.eventType, snippet):
                        evidence = snippet[:240]
                    elif self.opts.get('verify', False):
                        if verify_budget <= 0:
                            continue
                        verify_budget -= 1
                        page = self.fetch_url(link, timeout=int(self.opts.get('_fetchtimeout', 30)),
                                              useragent=self.opts.get('_useragent', 'Mozilla/5.0'))
                        body = (page or {}).get('content') or ""
                        text = _TAG.sub(" ", body)
                        if not body or not self._contains(term, event.eventType, text):
                            continue
                        evidence = self._excerpt(text, term, event.eventType)
                    else:
                        continue                    # the engine's text does not mention the term, and no page is opened
                    reported.add(link)
                    url_evt = SpiderFootEvent("DARKNET_MENTION_URL", link, self.__name__, event)
                    self.notifyListeners(url_evt)
                    if evidence:
                        self.notifyListeners(SpiderFootEvent("DARKNET_MENTION_CONTENT",
                                                             f"...{evidence}... [found through {name}]",
                                                             self.__name__, url_evt))
        self.info(f"Dark web search: {len(reported)} page(s) mention {event.data}")

    @staticmethod
    def _excerpt(text: str, term: str, event_type: str) -> str:
        flat = " ".join(text.split())
        needle = term.strip('"').lower()
        i = flat.lower().find(needle)
        if i < 0:
            return ""
        return flat[max(0, i - 120): i + len(needle) + 120]

# End of sfp_onionsearch class

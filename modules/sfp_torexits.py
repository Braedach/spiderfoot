from __future__ import annotations

"""SpiderFoot plug-in module: torexits."""

# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_torexits
# Purpose:     Checks if an IP address or netblock appears on the TOR Metrics
#              exit node list.
#
# Author:       steve@binarypool.com
#
# Created:     14/12/2013
# Copyright:   (c) Steve Micallef, 2013
# Licence:     MIT
# -------------------------------------------------------------------------------

import json

from netaddr import IPAddress, IPNetwork

from spiderfoot import SpiderFootEvent
from spiderfoot.plugins.async_plugin import SpiderFootAsyncPlugin


class sfp_torexits(SpiderFootAsyncPlugin):

    """Check if an IP adddress or netblock appears on the Tor Metrics exit node list."""

    meta = {
        'name': "TOR Exit Nodes",
        'summary': "Check if an IP adddress or netblock appears on the Tor Metrics exit node list.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Secondary Networks"],
        'dataSource': {
            'website': "https://metrics.torproject.org/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://metrics.torproject.org/rs.html#search/flag:exit",
            ],
            'favIcon': "https://metrics.torproject.org/images/favicon.ico",
            'logo': "https://metrics.torproject.org/images/tor-metrics-white@2x.png",
            'description': "The relay search tool displays data about single relays and bridges in the Tor network."
        },
    }

    opts = {
        'checkaffiliates': True,
        'cacheperiod': 1,
        'checknetblocks': True,
    }

    optdescs = {
        'checkaffiliates': "Apply checks to affiliates?",
        'cacheperiod': "Hours to cache list data before re-fetching.",
        'checknetblocks': "Report if any malicious IPs are found within owned netblocks?",
    }

    results = None
    errorState = False
    _exit_set = None

    def setup(self, sfc: SpiderFoot, userOpts: dict = None) -> None:
        """Set up the module."""
        super().setup(sfc, userOpts or {})
        self.results = self.tempStorage()
        self.errorState = False
        self._exit_set = None
        self.__dataSource__ = "torproject.org"
    def watchedEvents(self) -> list:
        """Return the list of events this module watches."""
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "AFFILIATE_IPADDR",
            "AFFILIATE_IPV6_ADDRESS",
            "NETBLOCK_OWNER",
            "NETBLOCKV6_OWNER",
        ]

    def producedEvents(self) -> list:
        """Return the list of events this module produces."""
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "TOR_EXIT_NODE",
        ]

    def exitNodeSet(self) -> frozenset | None:
        """Return the exit node addresses as a set, built once per scan.

        The relay list is several megabytes of JSON. Parsing it for every
        address checked made a scan of an IP inside a /11 effectively endless.
        """
        if self._exit_set is None:
            exit_addresses = self.retrieveExitNodes()
            if not exit_addresses:
                return None
            self._exit_set = frozenset(exit_addresses)
        return self._exit_set

    def queryExitNodes(self, ip: str) -> bool:
        """Query ExitNodes."""
        exit_addresses = self.exitNodeSet()

        if not exit_addresses:
            self.errorState = True
            return False

        if ip in exit_addresses:
            self.debug(f"IP address {ip} found in TOR exit node list.")
            return True

        return False

    def exitNodesInNetblock(self, netblock: str) -> list | None:
        """Return the exit nodes inside a netblock without enumerating it.

        Walks the exit node list (a few thousand entries) rather than every
        address in the block, so a /8 costs the same as a /30.
        """
        exit_addresses = self.exitNodeSet()

        if not exit_addresses:
            self.errorState = True
            return None

        try:
            network = IPNetwork(netblock)
        except Exception as e:
            self.debug(f"Could not parse netblock {netblock}: {e}")
            return []

        found = []
        for addr in exit_addresses:
            try:
                if IPAddress(addr) in network:
                    found.append(addr)
            except Exception:
                continue
        return sorted(found)

    def retrieveExitNodes(self) -> list | None:
        """RetrieveExitNodes."""
        exit_addresses = self.cache_get(
            'torexitnodes', self.opts.get('cacheperiod', 1))

        if exit_addresses is not None:
            return self.parseExitNodes(exit_addresses)

        res = self.fetch_url(
            "https://onionoo.torproject.org/details?search=flag:exit",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(
                f"Unexpected HTTP response code {res['code']} from onionoo.torproject.org.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from onionoo.torproject.org.")
            self.errorState = True
            return None

        self.cache_put("torexitnodes", res['content'])

        return self.parseExitNodes(res['content'])

    def parseExitNodes(self, data: str) -> list | None:
        """Extract exit node IP addresses from TOR relay search results.

        Args:
            data (str): TOR relay search results

        Returns:
            list: list of TOR exit IP addresses
        """
        ips = list()

        if not data:
            return ips

        try:
            results = json.loads(data)
        except Exception as e:
            self.error(f"Error processing JSON response: {e}")
            return None

        relays = results.get('relays')

        if not relays:
            return ips

        for relay in relays:
            or_addresses = relay.get('or_addresses')

            if or_addresses:
                for ip in or_addresses:
                    # IPv6 addresses are wrapped in [] (For example: "[127.0.0.1]:443")
                    if ip.startswith("["):
                        ip = ip.split('[')[1].split(']')[0]
                        if self.sf.validIP6(ip):
                            ips.append(ip)
                    else:
                        ip = ip.split(':')[0]
                        if self.sf.validIP(ip):
                            ips.append(ip)

            # Exit addresses are only listed in the exit addreses array
            # if the address differs from the OR address.
            exit_addresses = relay.get('exit_addresses')

            if exit_addresses:
                for ip in exit_addresses:
                    if self.sf.validIP(ip) or self.sf.validIP6(ip):
                        ips.append(ip)

        return list(set(ips))

    def handleEvent(self, event: SpiderFootEvent) -> None:
        """Handle an event received by this module."""
        eventName = event.eventType
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if self.errorState:
            return

        self.results[eventData] = True

        if eventName in ['AFFILIATE_IPADDR', 'AFFILIATE_IPV6_ADDRESS']:
            if not self.opts.get('checkaffiliates', False):
                return

        if eventName in ['NETBLOCK_OWNER', 'NETBLOCKV6_OWNER']:
            if not self.opts.get('checknetblocks', False):
                return

        if eventName.startswith("NETBLOCK"):
            addrs = self.exitNodesInNetblock(eventData)
            if addrs is None:
                return
        else:
            addrs = [eventData] if self.queryExitNodes(eventData) else []
            if self.errorState:
                return

        for addr in addrs:
            if self.checkForStop():
                return

            self.results[addr] = True

            # For netblocks, we need to create the associated IP address event first.
            if eventName == 'NETBLOCK_OWNER':
                pevent = SpiderFootEvent(
                    "IP_ADDRESS", addr, self.__name__, event)
                self.notifyListeners(pevent)
            elif eventName == 'NETBLOCKV6_OWNER':
                pevent = SpiderFootEvent(
                    "IPV6_ADDRESS", addr, self.__name__, event)
                self.notifyListeners(pevent)
            else:
                pevent = event

            self.debug(f"IP address {addr} found in TOR exit node list.")
            evt = SpiderFootEvent("TOR_EXIT_NODE", addr, self.__name__, pevent)
            self.notifyListeners(evt)

# End of sfp_torexits class

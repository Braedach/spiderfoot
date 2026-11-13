"""Scan target abstraction.

Provides the :class:`SpiderFootTarget` class that encapsulates a scan's
root target (domain, IP address, hostname, etc.), validates its type, and
offers helpers for determining whether discovered hosts and IPs fall within
the target's scope.
"""

from __future__ import annotations

import sys
import typing

import netaddr

__all__ = ["SpiderFootTarget", "TargetAlias"]


class TargetAlias(typing.TypedDict):
        """Typed dictionary for a target alias entry."""

        type: str
        value: str


class SpiderFootTarget():
    """SpiderFoot target.

    Attributes:
        validTypes (typing.FrozenSet[str]): valid event types accepted as a target
        targetType (str): target type
        targetValue (str): target value
        targetAliases (list[TargetAlias]): target aliases
    """

    _validTypes: frozenset[str] = frozenset({
        "IP_ADDRESS", "IPV6_ADDRESS", "NETBLOCK_OWNER", "NETBLOCKV6_OWNER",
        "INTERNET_NAME", "EMAILADDR", "HUMAN_NAME", "BGP_AS_OWNER",
        "PHONE_NUMBER", "USERNAME", "BITCOIN_ADDRESS",
    })
    _targetType: str
    _targetValue: str
    _targetAliases: list[TargetAlias]

    def __init__(self, targetValue: str, typeName: str) -> None:
        """Initialize SpiderFoot target.

        Args:
            targetValue (str): target value
            typeName (str): target type
        """
        self.targetType = typeName
        self.targetValue = targetValue
        self.targetAliases = list()
        self._sharedIPs: set[str] = set()

    def __repr__(self) -> str:
        """Return a string representation of the target."""
        return f"SpiderFootTarget({self._targetValue!r}, {self._targetType!r})"

    @property
    def targetType(self) -> str:
        """Return the target type."""
        return self._targetType

    @targetType.setter
    def targetType(self, targetType: str) -> None:
        """Set and validate the target type."""
        if not isinstance(targetType, str):
            raise TypeError(
                f"targetType is {type(targetType)}; expected str()")

        if targetType not in self._validTypes:
            raise ValueError(
                f"targetType value is {targetType}; expected {self._validTypes}")

        self._targetType = targetType

    @property
    def targetValue(self) -> str:
        """Return the target value."""
        return self._targetValue

    @targetValue.setter
    def targetValue(self, targetValue: str) -> None:
        """Set and validate the target value."""
        if not isinstance(targetValue, str):
            raise TypeError(
                f"targetValue is {type(targetValue)}; expected str()")
        if not targetValue:
            raise ValueError("targetValue value is blank")

        self._targetValue = targetValue

    @property
    def targetAliases(self) -> list[TargetAlias]:
        """Return the list of target aliases."""
        return self._targetAliases

    @targetAliases.setter
    def targetAliases(self, value: list[TargetAlias]) -> None:
        """Set the list of target aliases."""
        self._targetAliases = value

    def setAlias(self, value: str, typeName: str) -> None:
        """Specify other hostnames, IPs, etc. that are aliases for this target.

        For instance, if the user searched for an ASN, a module
        might supply all the nested subnets as aliases.
        Or, if a user searched for an IP address, a module
        might supply the hostname as an alias.

        Args:
            value (str): Target alias value
            typeName (str): Target alias data type
        """
        if not isinstance(value, (str, bytes)):
            return

        if not value:
            return

        if not isinstance(typeName, (str, bytes)):
            return

        if not typeName:
            return

        alias: TargetAlias = {'type': typeName, 'value': value.lower()}

        if alias in self.targetAliases:
            return

        self.targetAliases.append(alias)

    def markIPShared(self, value: str) -> None:
        """Flag an IP/IPv6 address as known to be shared with a host that
        is NOT the target (e.g. a CDN edge IP that also serves other,
        unrelated customers).

        Call this with *positive evidence* only - a discovery module that
        has actually observed another, non-matching hostname resolving to
        this exact address (e.g. a reverse-IP lookup's own hostname list).
        Never call it from the mere absence of evidence (a missing or
        generic PTR record, for instance): most dedicated/single-tenant
        target IPs never get a custom PTR either, and treating that as
        "shared" would wrongly stop active scanning of the user's own,
        legitimately dedicated infrastructure - exactly the case the
        original scope guard (PR #37) was built to keep working.

        Once marked, matches() is unaffected (the address is still
        legitimately related to the target - discovery/passive modules
        should keep seeing it), but shouldDispatchToModule() in the
        scanner will refuse to let "invasive" modules act on it, since
        scanning a shared edge IP means probing someone else's traffic
        on it too, not just the target's.

        Found live 2026-11-13: a braedach.com domain scan treated a
        shared Fastly IP as fully in-scope purely because www.braedach.com
        resolves there, and active tools then scanned micahflee.com's
        traffic on that same shared edge.

        Never demotes the target's own directly-authorised scope, no
        matter what any discovery module reports - this mirrors exactly
        what matches() already treats as the target's own authority:

        * IP_ADDRESS / IPV6_ADDRESS target: the literal searched value
          itself is never eligible, even if a historical/passive-DNS
          service's hostname list for it looks like it has had other
          occupants (common on residential/dynamic IPs - see the
          rapiddns staleness note elsewhere in this project). The user
          explicitly authorised scanning that exact address; a stale or
          noisy third-party record about it is not grounds to silently
          stop.
        * NETBLOCK_OWNER / NETBLOCKV6_OWNER target: any address within
          the owned block - same authorisation logic as above, just at
          block granularity.
        * BGP_AS_OWNER target: matches() has no netblock-membership
          check for ASN targets at all (confirmed by reading it) - an
          ASN's entire scope is whatever gets registered as aliases, by
          construction, same reasoning as NETBLOCK_OWNER. Exempted here
          for consistency, but this path is UNTESTED: the user has no
          authorised ASN scope to validate it against (2026-11-13). Said
          so rather than silently assumed correct - see
          project_outstanding_work.md item 0.

        Args:
            value (str): the IP or IPv6 address to flag.
        """
        if not isinstance(value, str) or not value:
            return

        value = value.lower()

        if self.targetType in ("IP_ADDRESS", "IPV6_ADDRESS"):
            if value == self.targetValue.lower():
                return
        elif self.targetType in ("NETBLOCK_OWNER", "NETBLOCKV6_OWNER"):
            try:
                if netaddr.IPAddress(value) in netaddr.IPNetwork(self.targetValue):
                    return
            except netaddr.AddrFormatError:
                pass
        elif self.targetType == "BGP_AS_OWNER":
            return

        self._sharedIPs.add(value)

    def isSharedIP(self, value: str) -> bool:
        """Return True if this address has been flagged via markIPShared().

        Args:
            value (str): the IP or IPv6 address to check.

        Returns:
            bool: whether the address is known to be shared/multi-tenant.
        """
        if not isinstance(value, str):
            return False
        return value.lower() in self._sharedIPs

    def _getEquivalents(self, typeName: str) -> list[str]:
        """Get all aliases of the specfied target data type.

        Args:
            typeName (str): Target data type

        Returns:
            list[str]: target aliases
        """
        ret: list[str] = list()
        for item in self.targetAliases:
            if item['type'] == typeName:
                ret.append(item['value'].lower())
        return ret

    def getNames(self) -> list[str]:
        """Get all domains associated with the target.

        Returns:
            list[str]: domains associated with the target
        """
        e = self._getEquivalents("INTERNET_NAME")
        if self.targetType in ["INTERNET_NAME", "EMAILADDR"] and self.targetValue.lower() not in e:
            e.append(self.targetValue.lower())

        names: list[str] = list()
        for name in e:
            if isinstance(name, bytes):
                names.append(name.decode("utf-8"))
            else:
                names.append(name)

        return names

    def getAddresses(self) -> list[str]:
        """Get all IP subnet or IP address aliases associated with the target.

        Returns:
            list[str]: List of IP subnets and addresses
        """
        e = self._getEquivalents("IP_ADDRESS")
        if self.targetType == "IP_ADDRESS":
            e.append(self.targetValue)

        e.extend(self._getEquivalents("IPV6_ADDRESS"))
        if self.targetType == "IPV6_ADDRESS":
            e.append(self.targetValue)

        return e

    def matches(self, value: str, includeParents: bool = False, includeChildren: bool = True) -> bool:
        """Check whether the supplied value is "tightly" related to the
        original target.

        Tightly in this case means:

        If the value is an IP:
            * is it in the list of aliases or the target itself?
            * is it on the target's subnet?

        If the value is an internet name (subdomain, domain, hostname):
            * is it in the list of aliases or the target itself?
            * is it a parent of the aliases of the target (domain/subdomain)
            * is it a child of the aliases of the target (hostname)

        Args:
            value (str): can be an Internet Name (hostname, subnet, domain) or an IP address.
            includeParents (bool):  True means you consider a value that is
                a parent domain of the target to still be a tight relation.
            includeChildren (bool): False means you don't consider a value
                that is a child of the target to be a tight relation.

        Returns:
            bool: whether the value matches the target
        """
        if not isinstance(value, str) and not isinstance(value, bytes):
            return False

        if isinstance(value, bytes):
            value = value.decode("utf-8")

        if not value:
            return False

        # Target names/aliases are stored lowercased (DNS is case-insensitive);
        # lowercase the incoming value too so mixed-case hosts (e.g.
        # "Sub.Example.COM") are not wrongly treated as out-of-scope. Harmless
        # for IPs (IPv4 unaffected; IPv6 hex lowercasing is canonical).
        value = value.lower()

        # We can't really say anything about names, username, bitcoin addresses
        # or phone numbers, so everything matches
        if self.targetType in ["HUMAN_NAME", "PHONE_NUMBER", "USERNAME", "BITCOIN_ADDRESS"]:
            return True

        # NOTE(v6): Consider adding explicit scope matching for INTERNET_NAME
        # (suffix match), EMAILADDR (domain match), and BGP_AS_OWNER (AS lookup).
        # Currently these fall through to the IP/domain checks below.

        # For IP addreses, check if it is an alias of the target or within the target's subnet.
        if netaddr.valid_ipv4(value) or netaddr.valid_ipv6(value):
            if value in self.getAddresses():
                return True

            if self.targetType in ["IP_ADDRESS", "IPV6_ADDRESS", "NETBLOCK_OWNER", "NETBLOCKV6_OWNER"]:
                try:
                    if netaddr.IPAddress(value) in netaddr.IPNetwork(self.targetValue):
                        return True
                except netaddr.AddrFormatError:
                    return False

            return False

        # For everything else, check if the value is within or equal to target names
        for name in self.getNames():
            if value == name:
                return True
            if includeParents and name.endswith("." + value):
                return True
            if includeChildren and value.endswith("." + name):
                return True

        return False

# end of SpiderFootTarget class

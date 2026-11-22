"""Saved module settings that are really an old default, and so must not hold back a newer one.

The Settings screen saves every module option it shows, so a value that was only ever a default gets stored and then
beats the code default for good. That cost scans coverage three times: nikto and nuclei tested only the first 20 servers
(old default ``max_targets`` 20), naabu only the first 50, and arjun timed out on every URL (old defaults stable on,
180 s). Profile pins protect a scan started from a profile; this list protects every scan, including a custom module
list, for everyone who already has the old value saved.

When a release changes a module default that people may have saved, add the OLD value here. A saved value equal to a
retired default is then ignored and the code default applies. A person who chose exactly that value on purpose gets the
new default too; that is the price of a rule that needs no stored history, and the changelog should say so.

Values are compared as the database holds them (text; True is "1", False is "0").
"""
from __future__ import annotations

import logging

log = logging.getLogger("spiderfoot.config")

SUPERSEDED_DEFAULTS: dict[str, dict[str, frozenset[str]]] = {
    "sfp_tool_nikto": {"max_targets": frozenset({"20"}), "total_budget": frozenset({"7200"})},
    "sfp_tool_naabu": {"max_targets": frozenset({"50"})},
    "sfp_nuclei": {"max_targets": frozenset({"20"})},
    "sfp_tool_arjun": {"stable": frozenset({"1"}), "run_timeout": frozenset({"180"})},
}


def _as_text(value) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value).strip()


def is_superseded(module: str, opt: str, value) -> bool:
    """True when ``value`` is a default that ``module`` has since replaced."""
    return _as_text(value) in SUPERSEDED_DEFAULTS.get(module, {}).get(opt, frozenset())


def drop_superseded(stored: dict) -> dict:
    """``stored`` (as configGet returns it: ``"module:opt"`` keys) without the entries that are retired defaults."""
    kept = {}
    for key, value in stored.items():
        module, sep, opt = key.partition(":")
        if sep and is_superseded(module, opt, value):
            log.info("Ignoring saved %s=%s: it is an old default that has been replaced; the current default applies.", key, value)
            continue
        kept[key] = value
    return kept

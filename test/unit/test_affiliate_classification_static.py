from __future__ import annotations

"""Static regression test for the scope-escape class of bug found 2026-11-13.

A discovery module that does a reverse-IP/co-hosted-site lookup gets back
hostnames it doesn't control. The correct pattern, used correctly by most
such modules, is:

    if self.getTarget().matches(hostname):
        SpiderFootEvent("INTERNET_NAME", ...)
    else:
        SpiderFootEvent("AFFILIATE_INTERNET_NAME_UNRESOLVED", ...)   # or
        SpiderFootEvent("AFFILIATE_IPADDR", ...)                      # etc.

Six modules (sfp_internetdb, sfp_rapiddns, sfp_subdomainradar x2,
sfp_validin x3, sfp_bevigil) instead emitted the "ours" event type
(INTERNET_NAME / INTERNET_NAME_UNRESOLVED / IP_ADDRESS / IPV6_ADDRESS) in
the else branch too. sfp_dnsresolve trusts that event type as "ours" and
registers the resolved IP as a target alias, which then lets invasive
modules (nmap, httpx, sslyze, ...) actively scan it. Confirmed live: a
scan of braedach.com registered a shared Cloudflare/Fastly edge IP as
in-scope purely because an unrelated site shared it, and active tools
scanned that unrelated site's traffic.

A seventh, differently-shaped instance of the same underlying problem
was found in sfp_opennic: `if affiliate and not matches(): AFFILIATE_*
else: owned`, which - because `affiliate` only became True when the
*input* event was already AFFILIATE_-flagged - unconditionally trusted
every resolved address as owned whenever the input wasn't, regardless
of what the address itself resolved to. Fixed to the same canonical
shape as the other six (this test's detector doesn't understand De
Morgan's laws, so a `not matches()` guard on the affiliate branch
wouldn't be caught here even now - the module was restructured to the
canonical `if matches(): owned else: affiliate` form instead of relying
on the detector to see through the negation).

This test walks every module's AST looking for exactly that shape: an
`if` statement whose test calls `.matches(...)`, with an `else` branch
that directly emits one of the "owned" event types. It is deliberately
narrow (only the *direct* sibling else of the same if, not any matches()
call anywhere in the function) to avoid false positives on modules that
correctly gate the whole owned-type emission inside the `if` branch and
do something else entirely (continue, drop, emit CO_HOSTED_SITE, etc.)
in the else.
"""

import ast
import os
import unittest

MODULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "modules",
)

OWNED_EVENT_TYPES = {
    "INTERNET_NAME",
    "INTERNET_NAME_UNRESOLVED",
    "IP_ADDRESS",
    "IPV6_ADDRESS",
}


def _if_test_calls_matches(test_node: ast.expr) -> bool:
    for sub in ast.walk(test_node):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and sub.func.attr == "matches"
        ):
            return True
    return False


def _owned_event_types_in_branch(branch_stmts: list[ast.stmt]) -> list[str]:
    """Owned event-type string literals passed as SpiderFootEvent's first
    positional arg, found anywhere in this branch's statements."""
    found = []
    for stmt in branch_stmts:
        for sub in ast.walk(stmt):
            if (
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Name)
                and sub.func.id == "SpiderFootEvent"
                and sub.args
            ):
                first_arg = sub.args[0]
                if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                    if first_arg.value in OWNED_EVENT_TYPES:
                        found.append(first_arg.value)
    return found


def find_violations(module_source: str, filename: str) -> list[tuple[str, int, list[str]]]:
    """Return (filename, lineno, owned_event_types) for each matches()-gated
    if/else where the else branch emits an owned event type directly."""
    try:
        tree = ast.parse(module_source, filename=filename)
    except SyntaxError:
        return []

    violations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and _if_test_calls_matches(node.test) and node.orelse:
            bad = _owned_event_types_in_branch(node.orelse)
            if bad:
                violations.append((filename, node.lineno, bad))
    return violations


class TestAffiliateClassificationStatic(unittest.TestCase):
    """Every modules/*.py file must be free of the else-branch
    misclassification pattern that caused the 2026-11-13 scope escape."""

    def test_no_module_misclassifies_non_matching_hosts_as_owned(self):
        all_violations = []
        for fn in sorted(os.listdir(MODULES_DIR)):
            if not fn.endswith(".py"):
                continue
            path = os.path.join(MODULES_DIR, fn)
            with open(path, encoding="utf-8") as f:
                source = f.read()
            all_violations.extend(find_violations(source, fn))

        self.assertEqual(
            all_violations, [],
            "Found modules emitting an 'owned' event type (INTERNET_NAME, "
            "INTERNET_NAME_UNRESOLVED, IP_ADDRESS, IPV6_ADDRESS) in the "
            "else-branch of a getTarget().matches() check - that branch "
            "runs precisely when the host/address does NOT match the "
            "target, so it must emit the AFFILIATE_* variant instead. See "
            "this file's module docstring for the live incident this "
            f"exact pattern caused. Violations: {all_violations}",
        )

    def test_detector_flags_the_original_bug_pattern(self):
        """Sanity check the detector itself against a synthetic example of
        the exact bug, so a change to the detector that silently stops
        catching anything doesn't go unnoticed."""
        buggy_source = """
def handleEvent(self, event):
    for hostname in ['a', 'b']:
        if self.getTarget().matches(hostname):
            evt = SpiderFootEvent("INTERNET_NAME", hostname, self.__name__, event)
        else:
            evt = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", hostname, self.__name__, event)
"""
        violations = find_violations(buggy_source, "synthetic_buggy.py")
        self.assertEqual(len(violations), 1)
        self.assertIn("INTERNET_NAME_UNRESOLVED", violations[0][2])

    def test_detector_does_not_flag_the_correct_pattern(self):
        correct_source = """
def handleEvent(self, event):
    for hostname in ['a', 'b']:
        if self.getTarget().matches(hostname):
            evt = SpiderFootEvent("INTERNET_NAME", hostname, self.__name__, event)
        else:
            evt = SpiderFootEvent("AFFILIATE_INTERNET_NAME_UNRESOLVED", hostname, self.__name__, event)
"""
        violations = find_violations(correct_source, "synthetic_correct.py")
        self.assertEqual(violations, [])

    def test_detector_does_not_flag_unrelated_matches_elsewhere_in_function(self):
        """A matches() call somewhere else in the function, with an
        unrelated if/else nearby, must not be conflated with it (this
        caught two false positives - sfp_dnsresolve, sfp_alienvault -
        during development of this test)."""
        source = """
def handleEvent(self, event):
    if self.getTarget().matches(event.data):
        pass

    if event.eventType in ['IP_ADDRESS']:
        pass
    else:
        evt = SpiderFootEvent("IP_ADDRESS", event.data, self.__name__, event)
"""
        violations = find_violations(source, "synthetic_unrelated.py")
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()

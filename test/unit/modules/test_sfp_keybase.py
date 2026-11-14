from __future__ import annotations

"""Tests for sfp_keybase module."""

import pytest
import unittest

from modules.sfp_keybase import sfp_keybase
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleKeybase(TestModuleBase):

    def test_opts(self):
        module = sfp_keybase()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_keybase()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_keybase()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_keybase()
        self.assertIsInstance(module.producedEvents(), list)

    def setUp(self):
        """Set up before each test."""
        super().setUp()
        # Register event emitters if they exist
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def test_invalid_lookup_code_100_is_not_an_error(self):
        """Keybase answers code 100 for a name that is not a valid Keybase selector, which is the normal
        case for most names this module is asked about (300 error lines in one scan)."""
        import json
        sf = SpiderFoot(self.default_options)
        module = sfp_keybase()
        module.setup(sf, {'_useragent': 'x'})
        module.fetch_url = lambda *a, **k: {'code': '200', 'content': json.dumps({'status': {'code': 100}})}
        errors = []
        module.error = lambda m, *a, **k: errors.append(m)
        self.assertIsNone(module.query('usernames', 'not a valid name!'))
        self.assertEqual(errors, [])

    def test_other_unexpected_codes_are_still_errors(self):
        import json
        sf = SpiderFoot(self.default_options)
        module = sfp_keybase()
        module.setup(sf, {'_useragent': 'x'})
        module.fetch_url = lambda *a, **k: {'code': '200', 'content': json.dumps({'status': {'code': 205}})}
        errors = []
        module.error = lambda m, *a, **k: errors.append(m)
        self.assertIsNone(module.query('usernames', 'someone'))
        self.assertEqual(len(errors), 1)

    def tearDown(self):
        """Clean up after each test."""
        super().tearDown()

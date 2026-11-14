from __future__ import annotations

"""Tests for sfp_wikipediaedits module."""

import pytest
import unittest

from modules.sfp_wikipediaedits import sfp_wikipediaedits
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase
from test.unit.utils.test_helpers import safe_recursion


class TestModulewikipediaedits(TestModuleBase):

    def test_opts(self):
        module = sfp_wikipediaedits()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_wikipediaedits()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_wikipediaedits()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_wikipediaedits()
        self.assertIsInstance(module.producedEvents(), list)

    def setUp(self):
        """Set up before each test."""
        super().setUp()
        # Register event emitters if they exist
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def test_query_unescapes_links_without_error(self):
        """HTMLParser.unescape was removed in Python 3.9; every response raised AttributeError."""
        sf = SpiderFoot(self.default_options)
        module = sfp_wikipediaedits()
        module.setup(sf, {'_fetchtimeout': 5})
        module.fetch_url = lambda *a, **k: {
            'code': '200',
            'content': "<link>https://en.wikipedia.org/wiki/A&amp;B</link>\n<link>Special:Contributions/x</link>",
        }
        errors = []
        module.error = lambda m, *a, **k: errors.append(m)
        self.assertEqual(module.query('someone'), {'https://en.wikipedia.org/wiki/A&B'})
        self.assertEqual(errors, [])

    def tearDown(self):
        """Clean up after each test."""
        super().tearDown()

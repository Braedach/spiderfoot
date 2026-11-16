from __future__ import annotations

"""Tests for sfp_intfiles module."""

import pytest
import unittest

from modules.sfp_intfiles import sfp_intfiles
from spiderfoot.sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from test.unit.utils.test_module_base import TestModuleBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleIntfiles(TestModuleBase):


    def setUp(self):
        """Enhanced setUp with ThreadReaper module tracking."""
        super().setUp()
        # ThreadReaper infrastructure is automatically initialized
        
    def tearDown(self):
        """Enhanced tearDown with ThreadReaper cleanup."""
        # ThreadReaper infrastructure automatically cleans up
        super().tearDown()
    def test_opts(self):
        module = sfp_intfiles()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_intfiles()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_intfiles()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_intfiles()
        self.assertIsInstance(module.producedEvents(), list)

    @safe_recursion(max_depth=5)
    def test_handleEvent_event_data_internal_url_with_interesting_file_extension_should_return_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_intfiles()
        module.setup(sf, {'verify': False})   # extension matching only; verification has its own tests below

        target_value = 'van1shland.io'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            expected = 'INTERESTING_FILE'
            if str(event.eventType) != expected:
                raise Exception(f"{event.eventType} != {expected}")

            expected = 'https://van1shland.io/example.zip'
            if str(event.data) != expected:
                raise Exception(f"{event.data} != {expected}")

            raise Exception("OK")

        module.notifyListeners = new_notifyListeners.__get__(
            module, sfp_intfiles)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data,
                              event_module, source_event)

        event_type = 'LINKED_URL_INTERNAL'
        event_data = 'https://van1shland.io/example.zip'
        event_module = 'example module'
        source_event = evt

        evt = SpiderFootEvent(event_type, event_data,
                              event_module, source_event)

        with self.assertRaises(Exception) as cm:
            module.handleEvent(evt)

        self.assertEqual("OK", str(cm.exception))

    @safe_recursion(max_depth=5)
    def test_handleEvent_event_data_internal_url_without_interesting_file_extension_should_not_return_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_intfiles()
        module.setup(sf, dict())

        target_value = 'van1shland.io'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(
            module, sfp_intfiles)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data,
                              event_module, source_event)

        event_type = 'LINKED_URL_INTERNAL'
        event_data = 'https://van1shland.io/example'
        event_module = 'example module'
        source_event = evt

        evt = SpiderFootEvent(event_type, event_data,
                              event_module, source_event)
        result = module.handleEvent(evt)

        self.assertIsNone(result)

    def setUp(self):
        """Set up before each test."""
        super().setUp()
        # Register event emitters if they exist
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        """Clean up after each test."""
        super().tearDown()


# ---------------------------------------------------------------------------------------------------------------
# Behaviour tests (2026-11-16). The module used to report ANY discovered link containing a file extension. In a live
# scan "/admin/clients.xls" (a 302 to the login page) was reported as an exposed file, and an AI report rated it
# Critical. Hosts below are example names.

from spiderfoot import SpiderFootEvent as _Ev

_PDF = "https://www.example.org/docs/report.pdf"
_XLS = "https://www.example.org/admin/clients.xls"


class TestIntfilesVerification(TestModuleBase):

    def _module(self, answers=None, **opts):
        m = sfp_intfiles()
        m.__name__ = "sfp_intfiles"
        m.setup(SpiderFoot(self.default_options), opts)
        self.events, self.fetched = [], []
        m.notifyListeners = self.events.append
        m.checkForStop = lambda: False
        answers = answers or {}

        def fake_fetch(url, **kw):
            self.fetched.append((url, kw))
            return answers.get(url)
        m.fetch_url = fake_fetch
        return m

    def _send(self, m, url):
        m.handleEvent(_Ev("LINKED_URL_INTERNAL", url, "sfp_spider", _Ev("ROOT", "root", "", None)))

    def test_a_redirect_to_a_login_page_is_not_an_exposed_file(self):
        m = self._module({_XLS: {"code": "302", "content": "", "headers": {"location": "/login.jsp"}}})
        self._send(m, _XLS)
        assert not self.events

    def test_a_file_the_server_really_serves_is_reported(self):
        m = self._module({_PDF: {"code": "200", "content": "%PDF-1.7 ...", "headers": {"Content-Type": "application/pdf"}}})
        self._send(m, _PDF)
        assert [(e.eventType, e.data) for e in self.events] == [("INTERESTING_FILE", _PDF)]

    def test_a_404_a_web_page_and_an_empty_answer_are_not_files(self):
        for answer in ({"code": "404", "content": "Not found", "headers": {}},
                       {"code": "200", "content": "<html>login</html>", "headers": {"content-type": "text/html; charset=utf-8"}},
                       {"code": "200", "content": "", "headers": {"content-type": "application/pdf"}},
                       None):
            m = self._module({_PDF: answer})
            self._send(m, _PDF)
            assert not self.events, answer

    def test_a_failing_check_never_reports_the_file_and_never_crashes(self):
        m = self._module()
        m.fetch_url = lambda url, **kw: (_ for _ in ()).throw(OSError("boom"))
        self._send(m, _PDF)
        assert not self.events

    def test_only_the_first_kilobytes_are_requested(self):
        m = self._module({_PDF: {"code": "200", "content": "x", "headers": {"content-type": "application/pdf"}}})
        self._send(m, _PDF)
        assert self.fetched[0][1]["sizeLimit"] == 2048

    def test_with_verification_off_it_reports_links_without_requesting_anything(self):
        m = self._module(verify=False)
        self._send(m, _XLS)
        assert [e.data for e in self.events] == [_XLS] and not self.fetched

    def test_the_extension_must_end_the_path_or_be_a_query_value(self):
        m = self._module(verify=False)
        for url in ("https://www.example.org/a.pdfviewer", "https://www.example.org/page.html",
                    "https://www.example.org/cdn.xlsx.js"):
            self._send(m, url)
        assert not self.events
        for url in ("https://www.example.org/a.PDF", "https://www.example.org/dl?file=report.xls&x=1",
                    "https://www.example.org/b.zip#frag"):
            self._send(m, url)
        assert len(self.events) == 3

    def test_the_same_link_is_checked_once(self):
        m = self._module({_PDF: {"code": "200", "content": "x", "headers": {"content-type": "application/pdf"}}})
        self._send(m, _PDF)
        self._send(m, _PDF)
        assert len(self.fetched) == 1 and len(self.events) == 1

    def test_the_options_are_documented(self):
        assert set(sfp_intfiles.opts) == set(sfp_intfiles.optdescs)

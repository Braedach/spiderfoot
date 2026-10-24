from __future__ import annotations

"""Tests for sfp_tool_ffuf module."""

from unittest.mock import patch, MagicMock

from modules.sfp_tool_ffuf import sfp_tool_ffuf
from spiderfoot import SpiderFootEvent
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase


class TestModuleToolFfuf(TestModuleBase):

    def test_opts(self):
        module = sfp_tool_ffuf()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_tool_ffuf()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_tool_ffuf()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_tool_ffuf()
        self.assertIsInstance(module.producedEvents(), list)

    @patch('modules.sfp_tool_ffuf.os.path.isfile', return_value=True)
    @patch('modules.sfp_tool_ffuf.subprocess.run')
    def test_handleEvent_passes_auto_calibrate_by_default(self, mock_run, mock_isfile):
        """-ac must be on by default - without it, a single-page app's catch-all 200
        makes every wordlist entry match -mc (confirmed live: 4,740 false hits against
        OWASP Juice Shop without it, 9 real ones with it)."""
        sf = SpiderFoot(self.default_options)
        module = sfp_tool_ffuf()
        module.setup(sf, dict())
        module.__name__ = "sfp_tool_ffuf"
        mock_run.return_value = MagicMock(returncode=0)
        event = SpiderFootEvent("LINKED_URL_INTERNAL", "http://target/", "sfp_spider", None)
        with patch('modules.sfp_tool_ffuf.os.path.exists', return_value=False):
            module.handleEvent(event)
        cmd = mock_run.call_args[0][0]
        self.assertIn("-ac", cmd)

    @patch('modules.sfp_tool_ffuf.os.path.isfile', return_value=True)
    @patch('modules.sfp_tool_ffuf.subprocess.run')
    def test_handleEvent_auto_calibrate_can_be_disabled(self, mock_run, mock_isfile):
        sf = SpiderFoot(self.default_options)
        module = sfp_tool_ffuf()
        module.setup(sf, {"auto_calibrate": False})
        module.__name__ = "sfp_tool_ffuf"
        mock_run.return_value = MagicMock(returncode=0)
        event = SpiderFootEvent("LINKED_URL_INTERNAL", "http://target/", "sfp_spider", None)
        with patch('modules.sfp_tool_ffuf.os.path.exists', return_value=False):
            module.handleEvent(event)
        cmd = mock_run.call_args[0][0]
        self.assertNotIn("-ac", cmd)

    def setUp(self):
        """Set up before each test."""
        super().setUp()
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        """Clean up after each test."""
        super().tearDown()

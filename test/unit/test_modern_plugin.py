"""
Tests for the ModernPlugin base class.
"""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch, PropertyMock

from spiderfoot.plugins.modern_plugin import SpiderFootModernPlugin


class FakeModule(SpiderFootModernPlugin):
    """A concrete module for testing."""

    meta = {
        "name": "Test Module",
        "summary": "Test",
        "flags": [],
        "useCases": [],
        "categories": ["Test"],
    }

    opts = {"test_opt": "default"}
    optdescs = {"test_opt": "A test option"}

    def __init__(self):
        super().__init__()
        self.__name__ = "sfp_test"

    def watchedEvents(self):
        return ["IP_ADDRESS"]

    def producedEvents(self):
        return ["RAW_RIR_DATA"]

    def handleEvent(self, event):
        pass


class TestModernPluginInit(unittest.TestCase):
    """Test initialization and setup."""

    def test_inheritance(self):
        from spiderfoot.plugins.plugin import SpiderFootPlugin
        mod = FakeModule()
        self.assertIsInstance(mod, SpiderFootPlugin)
        self.assertIsInstance(mod, SpiderFootModernPlugin)

    def test_no_registry(self):
        mod = FakeModule()
        self.assertIsNone(mod._registry)
        self.assertIsNone(mod.http)
        self.assertIsNone(mod.dns)
        self.assertIsNone(mod.cache)
        self.assertIsNone(mod.data)
        self.assertIsNone(mod.event_bus)


class TestModernPluginSetup(unittest.TestCase):
    """Test setup with mocked SpiderFoot facade."""

    def test_setup_stores_sf(self):
        mod = FakeModule()
        mock_sf = MagicMock()
        mod.setup(mock_sf, {"test_opt": "custom"})
        self.assertEqual(mod.sf, mock_sf)
        self.assertEqual(mod.opts["test_opt"], "custom")


class TestModernPluginFetchUrl(unittest.TestCase):
    """Test fetch_url method."""

    def test_fallback_to_sf(self):
        mod = FakeModule()
        mod._enable_metrics = False
        mock_sf = MagicMock()
        mock_sf.fetchUrl.return_value = {"content": "ok", "code": 200}
        mod.sf = mock_sf

        result = mod.fetch_url("https://example.com")
        self.assertIsNotNone(result)
        mock_sf.fetchUrl.assert_called_once()

    def test_uses_http_service(self):
        mod = FakeModule()
        mod._enable_metrics = False
        mock_http = MagicMock()
        mock_http.fetch_url.return_value = {"content": "data", "code": 200}
        mod._http_service = mock_http

        result = mod.fetch_url("https://api.example.com")
        self.assertEqual(result["content"], "data")
        mock_http.fetch_url.assert_called_once()


class TestModernPluginDns(unittest.TestCase):
    """Test DNS methods."""

    def test_resolve_host_fallback(self):
        mod = FakeModule()
        mock_sf = MagicMock()
        mock_sf.resolveHost.return_value = ["1.2.3.4"]
        mod.sf = mock_sf

        result = mod.resolve_host("example.com")
        self.assertEqual(result, ["1.2.3.4"])

    def test_resolve_host_service(self):
        mod = FakeModule()
        mock_dns = MagicMock()
        mock_dns.resolve_host.return_value = ["5.6.7.8"]
        mod._dns_service = mock_dns

        result = mod.resolve_host("example.com")
        self.assertEqual(result, ["5.6.7.8"])


class TestModernPluginCache(unittest.TestCase):
    """Test cache methods."""

    def test_cache_get_put_fallback(self):
        mod = FakeModule()
        mock_sf = MagicMock()
        mock_sf.cacheGet.return_value = "cached_value"
        mod.sf = mock_sf

        val = mod.cache_get("key1")
        self.assertEqual(val, "cached_value")

        mod.cache_put("key2", "value2")
        mock_sf.cachePut.assert_called_with("key2", "value2")


class TestModernPluginAsDict(unittest.TestCase):
    """Test enhanced asdict."""

    def test_includes_modern_flag(self):
        mod = FakeModule()
        d = mod.asdict()
        self.assertTrue(d.get("modern_plugin"))
        self.assertIn("services", d)
        self.assertFalse(d["services"]["http"])


if __name__ == "__main__":
    unittest.main()


class TestEventFailureHandling(unittest.TestCase):
    """One failing event must not switch a module off, and every failure must reach the scan log."""

    def _module(self):
        m = FakeModule()
        m.errors = []
        m.error = m.errors.append                 # SpiderFootPlugin.error() adds the scanId the scan log needs
        m._enable_metrics = True
        return m

    def _event(self, etype="IP_ADDRESS"):
        ev = MagicMock()
        ev.eventType = etype
        return ev

    def test_a_single_failure_is_recorded_and_the_module_keeps_running(self):
        m = self._module()
        m._handle_event_exception(KeyError("hosts"), self._event("SSL_CERTIFICATE_RAW"))
        self.assertFalse(m.errorState)
        self.assertEqual(len(m.errors), 1)
        self.assertIn("sfp_test failed on a SSL_CERTIFICATE_RAW event: KeyError", m.errors[0])
        self.assertIn("hosts", m.errors[0])

    def test_repeated_failures_switch_the_module_off_with_a_message(self):
        m = self._module()
        for _ in range(SpiderFootModernPlugin.MAX_EVENT_FAILURES - 1):
            m._handle_event_exception(ValueError("x"), self._event())
        self.assertFalse(m.errorState)
        m._handle_event_exception(ValueError("x"), self._event())
        self.assertTrue(m.errorState)
        self.assertIn("switched off for the rest of this scan", m.errors[-1])

    def test_the_worker_loop_survives_a_failing_event(self):
        import queue
        m = self._module()
        handled = []

        def handle(event):
            if event.data == "bad":
                raise AttributeError("'NoneType' object has no attribute 'lower'")
            handled.append(event.data)

        m.handleEvent = handle
        m.incomingEventQueue = queue.Queue()
        stop = {"n": 0}

        def check_for_stop():
            stop["n"] += 1
            return stop["n"] > 4

        m.checkForStop = check_for_stop
        for data in ("good1", "bad", "good2"):
            ev = self._event()
            ev.data = data
            m.incomingEventQueue.put(ev)
        m.threadWorker()
        self.assertEqual(handled, ["good1", "good2"])         # the event after the failure was still handled
        self.assertFalse(m.errorState)
        self.assertEqual(len(m.errors), 1)

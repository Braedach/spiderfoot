"""katana must not re-crawl the same site once per discovered URL."""
from __future__ import annotations

from unittest.mock import MagicMock

from modules.sfp_tool_katana import sfp_tool_katana
from spiderfoot import SpiderFootEvent
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase


class TestModuleToolKatana(TestModuleBase):

    def _module(self, **opts):
        sf = SpiderFoot(self.default_options)
        m = sfp_tool_katana()
        m.__name__ = "sfp_tool_katana"  # set by the scanner in production
        m.setup(sf, {"katana_path": "/bin/true", **opts})
        return m

    def _ev(self, etype, data, module="sfp_spider"):
        return SpiderFootEvent(etype, data, module, None)

    def test_opts_and_descriptions_match(self):
        m = sfp_tool_katana()
        self.assertEqual(len(m.opts), len(m.optdescs))

    def test_the_target_domain_always_starts_a_crawl(self):
        m = self._module()
        self.assertTrue(m._should_crawl_from(self._ev("DOMAIN_NAME", "example.com")))

    def test_its_own_output_does_not_start_another_crawl(self):
        """katana emits LINKED_URL_INTERNAL and also listens for it, so it re-crawled its own finds."""
        m = self._module()
        self.assertFalse(m._should_crawl_from(self._ev("LINKED_URL_INTERNAL", "http://e.com/a/b", "sfp_tool_katana")))

    def test_static_assets_are_not_crawled(self):
        m = self._module()
        for url in ("http://e.com/images/home3.jpg", "http://e.com/style.css", "http://e.com/f.woff2", "http://e.com/logo.PNG"):
            self.assertFalse(m._should_crawl_from(self._ev("LINKED_URL_INTERNAL", url)), url)
        self.assertTrue(m._should_crawl_from(self._ev("LINKED_URL_INTERNAL", "http://e.com/bank/login.jsp")))

    def test_one_crawl_per_host_and_top_level_path(self):
        m = self._module()
        results = [m._should_crawl_from(self._ev("LINKED_URL_INTERNAL", u)) for u in (
            "http://e.com/bank/a", "http://e.com/bank/b/c", "http://e.com/bank/d.jsp",
            "http://e.com/admin/x", "http://other.e.com/bank/a")]
        self.assertEqual(results, [True, False, False, True, True])

    def test_seed_cap(self):
        m = self._module(max_seed_urls=3)
        started = sum(m._should_crawl_from(self._ev("LINKED_URL_INTERNAL", f"http://e.com/p{i}/x")) for i in range(50))
        self.assertEqual(started, 3)

    def test_handleEvent_runs_katana_only_for_seeds(self):
        """The flood: 300 discovered URLs used to mean 300 full crawls."""
        m = self._module()
        m._find_binary = lambda: "/bin/true"
        runs = []
        import modules.sfp_tool_katana as mod
        orig = mod.subprocess.run
        mod.subprocess.run = lambda *a, **k: runs.append(a[0][2]) or MagicMock(returncode=0, stderr="")
        try:
            m.notifyListeners = MagicMock()
            m.handleEvent(self._ev("DOMAIN_NAME", "example.com"))
            for i in range(300):
                m.handleEvent(self._ev("LINKED_URL_INTERNAL", f"http://example.com/dir{i % 20}/page{i}.jsp"))
                m.handleEvent(self._ev("LINKED_URL_INTERNAL", f"http://example.com/images/pic{i}.jpg"))
        finally:
            mod.subprocess.run = orig
        self.assertEqual(len(runs), 1 + 20)   # the domain, plus one per distinct top-level directory


class TestSinglePageApps(TestModuleBase):
    def _module(self, **opts):
        sf = MagicMock()
        sf.opts = {}
        m = sfp_tool_katana()
        m.__name__ = "sfp_tool_katana"
        m.setup(sf, {"katana_path": "/bin/true", **opts})
        m.notifyListeners = MagicMock()
        return m

    @staticmethod
    def _ev(t, d, module="sfp_spider"):
        return SpiderFootEvent(t, d, module, None)

    def test_a_new_host_is_crawled_even_after_the_path_cap_is_spent(self):
        m = self._module(max_seed_urls=3)
        for i in range(10):
            m._should_crawl_from(self._ev("LINKED_URL_INTERNAL", f"https://www.e.com/post{i}/"))
        self.assertTrue(m._should_crawl_from(self._ev("LINKED_URL_INTERNAL", "https://app.e.com/")))
        self.assertFalse(m._should_crawl_from(self._ev("LINKED_URL_INTERNAL", "https://app.e.com/other/")))   # one per host

    def test_host_seed_cap(self):
        m = self._module(max_seed_urls=0, max_host_seeds=2)
        started = sum(m._should_crawl_from(self._ev("LINKED_URL_INTERNAL", f"https://h{i}.e.com/")) for i in range(10))
        self.assertEqual(started, 2)

    def test_spa_detection(self):
        js = [f"https://a.e.com/chunk-{i}.js" for i in range(5)]
        self.assertTrue(sfp_tool_katana._looks_like_spa("https://a.e.com", ["https://a.e.com"] + js))
        pages = [f"https://a.e.com/p{i}" for i in range(6)]
        self.assertFalse(sfp_tool_katana._looks_like_spa("https://a.e.com", js + pages))        # a normal site
        self.assertFalse(sfp_tool_katana._looks_like_spa("https://a.e.com/blog", js))           # not a host front page
        self.assertFalse(sfp_tool_katana._looks_like_spa("https://a.e.com", js[:2]))

    def _run(self, m, normal_lines, spa_lines):
        import json as _json
        import modules.sfp_tool_katana as mod
        cmds = []

        def fake(cmd, **kw):
            cmds.append(cmd)
            lines = spa_lines if "-headless" in cmd else normal_lines
            with open(cmd[cmd.index("-o") + 1], "w") as f:
                for u in lines:
                    f.write(_json.dumps({"request": {"endpoint": u}}) + "\n")
            return MagicMock(returncode=0, stderr="")

        orig = mod.subprocess.run
        mod.subprocess.run = fake
        try:
            m._find_binary = lambda: "/bin/katana"
            m.handleEvent(self._ev("DOMAIN_NAME", "https://a.e.com"))
        finally:
            mod.subprocess.run = orig
        return cmds

    def test_a_spa_gets_one_headless_xhr_pass_and_its_api_paths_are_reported(self):
        m = self._module()
        js = [f"https://a.e.com/chunk-{i}.js" for i in range(5)]
        cmds = self._run(m, ["https://a.e.com"] + js, ["https://a.e.com/api/v1/setup/status"])
        self.assertEqual(len(cmds), 2)
        self.assertNotIn("-headless", cmds[0])
        self.assertTrue({"-headless", "-no-sandbox", "-xhr"} <= set(cmds[1]))
        found = [c.args[0].data for c in m.notifyListeners.call_args_list]
        self.assertIn("https://a.e.com/api/v1/setup/status", found)

    def test_a_normal_site_gets_no_headless_pass(self):
        m = self._module()
        cmds = self._run(m, ["https://a.e.com"] + [f"https://a.e.com/p{i}" for i in range(8)], [])
        self.assertEqual(len(cmds), 1)

    def test_the_headless_pass_can_be_switched_off_and_is_capped(self):
        js = [f"https://a.e.com/chunk-{i}.js" for i in range(5)]
        m = self._module(spa_headless=False)
        self.assertEqual(len(self._run(m, ["https://a.e.com"] + js, [])), 1)
        m = self._module(spa_max_runs=0)
        self.assertEqual(len(self._run(m, ["https://a.e.com"] + js, [])), 1)

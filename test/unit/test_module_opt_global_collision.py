"""Regression test for a real scan-slowdown bug found 2026-11-13: several
modules declared their own per-module "_maxthreads" option, which collided
with the scan-wide global "_maxthreads" config key.

SpiderFootScanner builds each module's runtime opts by starting from the
module's own saved defaults, then overwriting with every key from the
global scan config (see spiderfoot/scan/scanner.py's module-load loop,
`self.__modconfig[modName][opt] = deepcopy(self.__config[opt])` for every
`opt` in the global config). Any module option sharing a name with a
global config key is therefore always silently replaced by the global
value - these 7 modules' intended per-module batch sizes (20-100) were
being clamped down to the global dispatch-pool size (was 3, then 12)
on every single scan, with no error or warning. sfp_tldsearch in
particular (intended batch size 50, actually running at a fraction of
that) was a major, previously-unexplained contributor to multi-hour scan
stalls - found while investigating a live 28+ minute stall on the rc.25
scope re-test.

Fixed by renaming each affected module's option to "batch_size" (not a
global config key), restoring independent per-module tuning. This test
replicates the exact merge scanner.py performs, so it would have caught
the original collision and will catch any future one.
"""

from __future__ import annotations

import importlib
import unittest
from copy import deepcopy

from spiderfoot.core.config import ConfigManager

AFFECTED_MODULES = [
    ("sfp_accounts", "sfp_accounts", 20),
    ("sfp_s3bucket", "sfp_s3bucket", 20),
    ("sfp_tldsearch", "sfp_tldsearch", 50),
    ("sfp_dnsbrute", "sfp_dnsbrute", 100),
    ("sfp_googleobjectstorage", "sfp_googleobjectstorage", 20),
    ("sfp_digitaloceanspace", "sfp_digitaloceanspace", 20),
    ("sfp_azureblobstorage", "sfp_azureblobstorage", 20),
]


class TestModuleOptGlobalCollision(unittest.TestCase):

    def _merged_opts(self, module_opts: dict) -> dict:
        """Replicate SpiderFootScanner's exact per-module opts merge."""
        global_config = ConfigManager().initialize()
        merged = deepcopy(module_opts)
        for opt in list(global_config.keys()):
            merged[opt] = deepcopy(global_config[opt])
        return merged

    def test_no_module_option_is_named_the_same_as_a_global_config_key(self):
        # The actual regression check: whatever name each affected module
        # now uses for its own batch-size option must NOT be a key in the
        # global scan config, or it will be silently overwritten again.
        global_config = ConfigManager().initialize()
        for modname, importname, _ in AFFECTED_MODULES:
            mod = importlib.import_module(f"modules.{importname}")
            cls = getattr(mod, modname)
            for opt in cls.opts:
                self.assertNotIn(
                    opt, global_config,
                    f"{modname}'s opt '{opt}' collides with a global config"
                    " key and will be silently overwritten by it on every"
                    " scan - see this test file's docstring.")

    def test_batch_size_survives_the_global_config_merge(self):
        for modname, importname, expected_default in AFFECTED_MODULES:
            mod = importlib.import_module(f"modules.{importname}")
            cls = getattr(mod, modname)
            instance = cls()
            self.assertEqual(instance.opts["batch_size"], expected_default)

            merged = self._merged_opts(instance.opts)
            self.assertEqual(
                merged["batch_size"], expected_default,
                f"{modname}'s batch_size was clobbered by the global"
                " config merge - the exact bug this test guards against.")
            # The global _maxthreads key is still present in the merged
            # dict (every module gets it, used or not) - just under its
            # own name, not aliased to this module's batch size any more.
            self.assertIn("_maxthreads", merged)


if __name__ == "__main__":
    unittest.main()

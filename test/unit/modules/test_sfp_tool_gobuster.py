from __future__ import annotations

"""Tests for sfp_tool_gobuster module."""

# filepath: spiderfoot/test/unit/modules/test_sfp_tool_gobuster.py
from unittest.mock import patch, MagicMock
from spiderfoot.sflib import SpiderFoot
from spiderfoot import SpiderFootEvent
from modules.sfp_tool_gobuster import sfp_tool_gobuster
import unittest
from test.unit.utils.test_module_base import TestModuleBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleToolGobuster(TestModuleBase):
    """Test Tool Gobuster module."""

    def setUp(self):
        """Set up before each test."""
        super().setUp()
        # Create a mock for any logging calls
        self.log_mock = MagicMock()
        # Apply patches in setup to affect all tests
        patcher1 = patch('logging.getLogger', return_value=self.log_mock)
        self.addCleanup(patcher1.stop)
        self.mock_logger = patcher1.start()

        # Create module wrapper class dynamically
        module_attributes = {
            'descr': "Description for sfp_tool_gobuster",
            # Add module-specific options

        }

        self.module_class = self.create_module_wrapper(
            sfp_tool_gobuster,
            module_attributes=module_attributes
        )
        # Register event emitters if they exist
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)
        # Register mocks for cleanup during tearDown
        self.register_mock(self.mock_logger)
        # Register patchers for cleanup during tearDown
        if 'patcher1' in locals():
            self.register_patcher(patcher1)

    def test_opts(self):
        """Test the module options."""
        module = self.module_class()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        """
        Test setup(self, sfc, userOpts=dict())
        """
        sf = SpiderFoot(self.default_options)
        module = sfp_tool_gobuster()
        module.setup(sf, dict())
        self.assertIsNotNone(module.opts)
        self.assertTrue(hasattr(module, 'opts'))
        self.assertIsInstance(module.opts, dict)

    def test_watchedEvents_should_return_list(self):
        """Test the watchedEvents function returns a list."""
        module = self.module_class()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        """Test the producedEvents function returns a list."""
        module = self.module_class()
        self.assertIsInstance(module.producedEvents(), list)

    @patch('modules.sfp_tool_gobuster.subprocess.run')
    @patch('modules.sfp_tool_gobuster.os.path.isfile', return_value=True)
    @patch('modules.sfp_tool_gobuster.open', create=True)
    @patch('modules.sfp_tool_gobuster.tempfile.NamedTemporaryFile')
    def test_handleEvent_local_success(self, mock_tempfile, mock_open, mock_isfile, mock_subprocess_run):
        """Test handleEvent with successful local execution and event emission."""
        # Mock subprocess.run to simulate successful gobuster execution
        mock_subprocess_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        module = self.module_class()
        module.sf = MagicMock()
        module.sf.execute.return_value = 0
        module.sf.outputProgress.return_value = True
        module.opts["gobuster_path"] = "/usr/bin/gobuster"  # Use full path to skip 'which' logic
        module.opts["wordlist"] = "/tmp/wordlist.txt"
        module.opts["remote_enabled"] = False
        module.results = {}  # Ensure results is initialized
        # Simulate gobuster output file
        mock_file = MagicMock()
        mock_file.read.return_value = '{"results": [{"path": "/admin/", "status": 200}, {"path": "/index.html", "status": 200}]}'
        mock_open.return_value.__enter__.return_value = mock_file
        mock_tempfile.return_value.name = "/tmp/gobuster_out.json"
        event = SpiderFootEvent("URL", "http://target", "root", None)
        module.notifyListeners = MagicMock()
        module.__name__ = "sfp_tool_gobuster"
        # Patch os.unlink to avoid file deletion errors
        with patch('modules.sfp_tool_gobuster.os.unlink'):
            module.handleEvent(event)
        # Should emit two events: one directory, one file
        self.assertTrue(module.notifyListeners.called)
        self.assertEqual(module.notifyListeners.call_count, 2)

    @patch('modules.sfp_tool_gobuster.paramiko.SSHClient')
    @patch('modules.sfp_tool_gobuster.io.StringIO')
    @patch('modules.sfp_tool_gobuster.paramiko.RSAKey.from_private_key', return_value='pkey')
    def test_run_remote_tool_with_pasted_key(self, mock_rsa, mock_stringio, mock_sshclient):
        """Test remote execution with pasted SSH key data."""
        module = self.module_class()
        module.opts.update({
            "remote_enabled": True,
            "remote_host": "1.2.3.4",
            "remote_user": "user",
            "remote_ssh_key_data": "FAKEKEYDATA",
            "remote_tool_path": "/usr/bin/gobuster",
            "wordlist": "/tmp/wordlist.txt",
            "remote_password": ""
        })
        module.opts["remote_ssh_key"] = ""  # Clear keyfile
        mock_ssh = MagicMock()
        mock_sshclient.return_value = mock_ssh
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b'{"results": [{"path": "/admin/", "status": 200}]}'
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b''
        mock_ssh.exec_command.return_value = (None, mock_stdout, mock_stderr)
        result = module.run_remote_tool("http://target")
        self.assertIsInstance(result, dict)
        self.assertIn("results", result)
        mock_ssh.connect.assert_called_with('1.2.3.4', username='user', pkey='pkey', password="" or None, timeout=10)
        mock_rsa.assert_called()

    @patch('modules.sfp_tool_gobuster.paramiko.SSHClient')
    def test_run_remote_tool_with_keyfile(self, mock_sshclient):
        """Test remote execution with SSH key file path."""
        module = self.module_class()
        module.opts.update({
            "remote_enabled": True,
            "remote_host": "1.2.3.4",
            "remote_user": "user",
            "remote_ssh_key": "/tmp/keyfile",
            "remote_tool_path": "/usr/bin/gobuster",
            "wordlist": "/tmp/wordlist.txt",
            "remote_password": ""
        })
        module.opts["remote_ssh_key_data"] = ""  # Clear pasted key
        mock_ssh = MagicMock()
        mock_sshclient.return_value = mock_ssh
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b'{"results": [{"path": "/admin/", "status": 200}]}'
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b''
        mock_ssh.exec_command.return_value = (None, mock_stdout, mock_stderr)
        result = module.run_remote_tool("http://target")
        self.assertIsInstance(result, dict)
        self.assertIn("results", result)
        mock_ssh.connect.assert_called_with('1.2.3.4', username='user', key_filename='/tmp/keyfile', password="" or None, timeout=10)

    @patch('modules.sfp_tool_gobuster.paramiko.SSHClient')
    def test_run_remote_tool_with_password(self, mock_sshclient):
        """Test remote execution with password only."""
        module = self.module_class()
        module.opts.update({
            "remote_enabled": True,
            "remote_host": "1.2.3.4",
            "remote_user": "user",
            "remote_password": "pw",
            "remote_tool_path": "/usr/bin/gobuster",
            "wordlist": "/tmp/wordlist.txt",
            "remote_ssh_key": "",
            "remote_ssh_key_data": ""
        })
        mock_ssh = MagicMock()
        mock_sshclient.return_value = mock_ssh
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b'{"results": [{"path": "/admin/", "status": 200}]}'
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b''
        mock_ssh.exec_command.return_value = (None, mock_stdout, mock_stderr)
        result = module.run_remote_tool("http://target")
        self.assertIsInstance(result, dict)
        self.assertIn("results", result)
        mock_ssh.connect.assert_called_with('1.2.3.4', username='user', password='pw', timeout=10)

    @patch('modules.sfp_tool_gobuster.paramiko.SSHClient')
    def test_run_remote_tool_error(self, mock_sshclient):
        """Test remote execution error handling."""
        module = self.module_class()
        module.opts.update({
            "remote_enabled": True,
            "remote_host": "1.2.3.4",
            "remote_user": "user",
            "remote_tool_path": "/usr/bin/gobuster",
            "wordlist": "/tmp/wordlist.txt"
        })
        mock_ssh = MagicMock()
        mock_sshclient.return_value = mock_ssh
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b''
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b'error!'
        mock_ssh.exec_command.return_value = (None, mock_stdout, mock_stderr)
        module.error = MagicMock()
        result = module.run_remote_tool("http://target")
        self.assertIsNone(result)
        module.error.assert_called()

    def test_detect_soft_404_filters_a_single_page_app_catch_all(self):
        """A target that returns the same 200 page for any path (Angular/React/Vue
        client-side routing) must be recognised and filtered - otherwise every
        wordlist entry "hits". Confirmed live: 16+ hours against OWASP Juice Shop,
        resolved by a single random-path probe up front.
        """
        module = self.module_class()
        module.fetch_url = MagicMock(return_value={
            "code": "200", "content": "x" * 9984,
        })
        length = module._detect_soft_404("http://target")
        self.assertEqual(length, 9984)

    def test_detect_soft_404_leaves_a_real_404_alone(self):
        """A target that correctly 404s a nonexistent path needs no filtering -
        unchanged behaviour."""
        module = self.module_class()
        module.fetch_url = MagicMock(return_value={"code": "404", "content": "Not Found"})
        self.assertIsNone(module._detect_soft_404("http://target"))

    def test_detect_soft_404_can_be_disabled(self):
        """soft_404_detection=False skips the probe entirely (no fetch_url call)."""
        module = self.module_class()
        module.opts["soft_404_detection"] = False
        module.fetch_url = MagicMock()
        self.assertIsNone(module._detect_soft_404("http://target"))
        module.fetch_url.assert_not_called()

    def test_detect_soft_404_survives_a_failed_probe(self):
        """A network error on the probe itself must not block the real gobuster run -
        falls back to unfiltered (current) behaviour."""
        module = self.module_class()
        module.fetch_url = MagicMock(side_effect=OSError("connection refused"))
        self.assertIsNone(module._detect_soft_404("http://target"))

    def test_parse_output_captures_size_and_redirect_target(self):
        out = (
            "admin                (Status: 301) [Size: 0] [--> http://t/admin/]\n"
            "robots.txt           (Status: 200) [Size: 43]\n"
        )
        res = self.module_class._parse_output(out)["results"]
        self.assertEqual(res[0], {"path": "/admin/", "status": 301, "size": 0, "redirect": "http://t/admin/"})
        self.assertEqual(res[1]["size"], 43)

    def test_wildcard_flood_is_discarded(self):
        """A WAF/rate limit answering every request identically made every wordlist entry a hit
        (16,660 URL_FILE events on a live scan)."""
        flood = "".join(f"word{i}.php  (Status: 403) [Size: 110]\n" for i in range(200))
        real = "login               (Status: 200) [Size: 5120]\n"
        results = self.module_class._parse_output(flood + real)["results"]
        kept, dropped = self.module_class._drop_uniform_responses(results, 100)
        self.assertEqual(dropped, 200)
        self.assertEqual([r["path"] for r in kept], ["/login"])

    def test_wildcard_redirect_to_a_fixed_page_is_discarded(self):
        flood = "".join(f"w{i}  (Status: 302) [Size: 0] [--> https://t/home]\n" for i in range(150))
        kept, dropped = self.module_class._drop_uniform_responses(self.module_class._parse_output(flood)["results"], 100)
        self.assertEqual((kept, dropped), ([], 150))

    def test_real_directory_redirects_are_kept(self):
        """Each real directory redirects to its own trailing-slash URL, so none share a response."""
        dirs = "".join(f"d{i}  (Status: 301) [Size: 0] [--> http://t/d{i}/]\n" for i in range(300))
        results = self.module_class._parse_output(dirs)["results"]
        kept, dropped = self.module_class._drop_uniform_responses(results, 100)
        self.assertEqual((len(kept), dropped), (300, 0))

    def test_small_groups_and_disabled_threshold_keep_everything(self):
        few = "".join(f"w{i}  (Status: 403) [Size: 110]\n" for i in range(40))
        results = self.module_class._parse_output(few)["results"]
        self.assertEqual(self.module_class._drop_uniform_responses(results, 100)[1], 0)
        flood = self.module_class._parse_output("".join(f"w{i}  (Status: 403) [Size: 1]\n" for i in range(500)))["results"]
        self.assertEqual(self.module_class._drop_uniform_responses(flood, 0)[1], 0)

    def test_results_without_sizes_are_never_filtered(self):
        results = [{"path": f"/p{i}", "status": 200} for i in range(500)]
        self.assertEqual(self.module_class._drop_uniform_responses(results, 100), (results, 0))

    def tearDown(self):
        """Clean up after each test."""
        super().tearDown()


# ---------------------------------------------------------------------------------------------------------------
# Live scan of a test site (2026-11-16): gobuster failed against https targets with "tls: failed to verify
# certificate" (the certificate was expired, and by-IP requests never match a name), timed out 18 times, and brute-forced
# the same site once per origin (http and https, by name and by IP address).

from unittest import mock as _mock

from spiderfoot import SpiderFootEvent as _Ev
from spiderfoot.sflib import SpiderFoot as _SF
from modules.sfp_tool_gobuster import sfp_tool_gobuster as _Gobuster


class TestGobusterBehaviour(TestModuleBase):

    PAGE = {"code": "200", "content": "<html>Altoro   Mutual home</html>", "headers": {"content-type": "text/html"}}

    def _module(self, pages=None, **opts):
        m = _Gobuster()
        m.__name__ = "sfp_tool_gobuster"
        m.setup(_SF(self.default_options), {"gobuster_path": "/usr/bin/gobuster", "wordlist": "/tmp/w.txt",
                                            "soft_404_detection": False, **opts})
        self.commands = []
        m.execute_command = lambda cmd: self.commands.append(cmd) or None       # None: nothing to parse
        m.fetch_url = lambda url, **kw: (pages or {}).get(url, self.PAGE)
        m.notifyListeners = lambda e: None
        m.checkForStop = lambda: False
        return m

    def _run(self, m, url):
        with _mock.patch("modules.sfp_tool_gobuster.os.path.isfile", return_value=True):
            m.handleEvent(_Ev("LINKED_URL_INTERNAL", url, "sfp_spider", _Ev("ROOT", "root", "", None)))

    def test_tls_verification_is_skipped_by_default(self):
        m = self._module()
        self._run(m, "https://203.0.113.10/pr/")
        assert "-k" in self.commands[0]

    def test_it_can_be_turned_back_on(self):
        m = self._module(tls_skip_verify=False)
        self._run(m, "https://203.0.113.10/pr/")
        assert "-k" not in self.commands[0]

    def test_the_same_directory_under_another_origin_is_brute_forced_once(self):
        m = self._module()
        for origin in ("http://demo.example", "https://demo.example", "https://203.0.113.10", "http://203.0.113.10:8080"):
            self._run(m, origin + "/pr/")
        assert len(self.commands) == 1

    def test_a_different_page_at_the_same_path_is_still_brute_forced(self):
        other = {"code": "200", "content": "<html>a different site</html>", "headers": {}}
        m = self._module({"https://other.example/pr/": other})
        self._run(m, "https://demo.example/pr/")
        self._run(m, "https://other.example/pr/")
        assert len(self.commands) == 2

    def test_different_directories_are_each_brute_forced(self):
        m = self._module()
        self._run(m, "https://demo.example/pr/")
        self._run(m, "https://demo.example/images/")
        assert len(self.commands) == 2

    def test_the_equivalence_check_can_be_turned_off(self):
        m = self._module(skip_equivalent_directories=False)
        self._run(m, "http://demo.example/pr/")
        self._run(m, "https://demo.example/pr/")
        assert len(self.commands) == 2

    def test_a_failing_check_never_skips_a_directory(self):
        m = self._module()
        m.fetch_url = lambda url, **kw: (_ for _ in ()).throw(OSError("down"))
        self._run(m, "https://demo.example/pr/")
        assert len(self.commands) == 1

    def test_the_wall_clock_limit_is_configurable(self):
        m = self._module(max_runtime=77)
        with _mock.patch("modules.sfp_tool_gobuster.subprocess.run") as run, \
                _mock.patch("modules.sfp_tool_gobuster.tempfile.NamedTemporaryFile") as tmp:
            tmp.return_value.name = "/tmp/gb.out"
            run.return_value = _mock.MagicMock(returncode=0, stdout="", stderr="")
            _Gobuster.execute_command(m, ["gobuster", "dir"])
        assert run.call_args.kwargs["timeout"] == 77

    def test_the_options_are_documented(self):
        assert set(_Gobuster.opts) == set(_Gobuster.optdescs)

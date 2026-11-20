"""sfp_nmap runs read-only service checks only: no login guessing, exploits, fuzzing, DoS or intrusive scripts."""
import pytest

from modules.sfp_nmap import SAFE_SERVICE_SCRIPTS, safe_script_arg, sfp_nmap


@pytest.mark.parametrize("spec", [
    "brute", "dos", "exploit", "fuzzer", "intrusive", "vuln", "all", "BRUTE", "ssh-brute", "http-slowloris-check",
    "smb-vuln-ms17-010", "http-vuln-cve2017-5638", "ftp-brute", "mysql-brute", "http-dombased-xss-dos",
])
def test_dangerous_scripts_and_categories_are_refused(spec):
    assert safe_script_arg(spec) == ""


@pytest.mark.parametrize("spec", [
    "default and not brute", "(safe or vuln)", "/tmp/evil.nse", "../evil", "a b", "*", "http-*", "ssh-hostkey;id", "$(id)",
])
def test_expressions_paths_and_wildcards_are_dropped(spec):
    assert safe_script_arg(spec) == ""


def test_plain_names_and_safe_categories_pass_and_dangerous_ones_are_removed_from_a_mix():
    assert safe_script_arg("default, safe, ssh-hostkey, brute, vuln") == "default,safe,ssh-hostkey"


def test_service_checks_add_the_curated_list_once():
    arg = safe_script_arg("ssh-hostkey", service_checks=True).split(",")
    assert arg[0] == "ssh-hostkey" and arg.count("ssh-hostkey") == 1
    assert set(SAFE_SERVICE_SCRIPTS) <= set(arg)


def test_the_curated_list_is_itself_clean():
    for name in SAFE_SERVICE_SCRIPTS:
        assert safe_script_arg(name) == name, name


def test_the_option_exists_and_is_off_by_default():
    assert sfp_nmap.opts["service_checks"] is False
    assert "service_checks" in sfp_nmap.optdescs


@pytest.mark.parametrize("port_range,expected", [
    ("-F", ["-F"]),
    ("--top-ports 1000", ["--top-ports", "1000"]),
    ("1-1000", ["-p", "1-1000"]),
])
def test_port_range_becomes_valid_nmap_arguments(port_range, expected):
    mod = sfp_nmap.__new__(sfp_nmap)
    mod.opts = dict(sfp_nmap.opts, port_range=port_range)
    mod._is_root = False
    cmd = mod._build_nmap_cmd("192.0.2.1")
    assert all(" " not in a for a in cmd[:cmd.index("192.0.2.1")] if a != "--version-all"), cmd
    i = cmd.index(expected[0])
    assert cmd[i:i + len(expected)] == expected

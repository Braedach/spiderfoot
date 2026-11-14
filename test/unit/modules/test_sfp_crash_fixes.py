"""Regression tests for module crashes seen in the rc.36 scans (worker log: "Module X failed: ...")."""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock

from modules.sfp_cloudfront import sfp_cloudfront
from modules.sfp_sslcert import sfp_sslcert
from modules.sfp_subfinder import sfp_subfinder
from spiderfoot import SpiderFootEvent
from spiderfoot.sflib import SpiderFoot
from test.unit.utils.test_module_base import TestModuleBase


class TestCloudfrontHeaders(TestModuleBase):

    def _module(self, headers):
        m = sfp_cloudfront()
        m.__name__ = "sfp_cloudfront"
        m.setup(SpiderFoot(self.default_options), {})
        m.fetch_url = lambda *a, **k: {"headers": headers, "code": "200", "content": "x"}
        m.opts.setdefault("_fetchtimeout", 5)
        m.opts.setdefault("_useragent", "SpiderFoot")
        return m

    def test_headers_in_another_case_do_not_crash(self):
        """The live failure: 'NoneType' object has no attribute 'lower'."""
        m = self._module({"x-amz-cf-id": "abc", "Via": "1.1 abc.cloudfront.net (CloudFront)"})
        self.assertTrue(m.checkHeaders("example.org"))

    def test_a_header_with_no_value_does_not_crash(self):
        m = self._module({"X-Amz-Cf-Id": None, "server": "nginx"})
        self.assertFalse(m.checkHeaders("example.org"))

    def test_no_cloudfront_headers(self):
        self.assertFalse(self._module({"server": "nginx"}).checkHeaders("example.org"))


def _self_signed_pem(common_name, alt_names):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in alt_names]), critical=False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class TestSslcertMismatch(TestModuleBase):

    def test_parsecert_returns_the_hosts_the_certificate_is_valid_for(self):
        """parseCert flagged a mismatch but never returned the host list, so sfp_sslcert crashed on every mismatch."""
        sf = SpiderFoot(self.default_options)
        cert = sf.parseCert(_self_signed_pem("other.example", ["other.example", "alt.example"]), "demo.example", 30)
        self.assertTrue(cert["mismatch"])
        self.assertEqual(cert["hosts"], ["other.example", "other.example", "alt.example"])

    def test_a_matching_certificate_has_no_mismatch(self):
        sf = SpiderFoot(self.default_options)
        cert = sf.parseCert(_self_signed_pem("demo.example", ["demo.example"]), "demo.example", 30)
        self.assertFalse(cert["mismatch"])

    def test_the_module_reports_a_mismatch_with_the_real_hosts(self):
        """The live failure: 'can only join an iterable'."""
        import modules.sfp_sslcert as mod
        m = sfp_sslcert()
        m.__name__ = "sfp_sslcert"
        m.setup(SpiderFoot(self.default_options), {})
        events = []
        m.notifyListeners = events.append
        target = MagicMock()
        target.matches.return_value = False
        m.getTarget = lambda: target
        pem = _self_signed_pem("other.example", ["other.example", "alt.example"])
        sock = MagicMock()
        m.sf.safeSSLSocket = lambda *a, **k: sock
        m.opts.update({"tryhttp": False, "verify": False, "certexpiringdays": 30, "ssltimeout": 5, "_internettlds": ""})
        m.sf.isDomain = lambda *a, **k: False
        mod.SpiderFootHelpers.sslDerToPem, orig = staticmethod(lambda der: pem), mod.SpiderFootHelpers.sslDerToPem
        self.addCleanup(lambda: setattr(mod.SpiderFootHelpers, "sslDerToPem", orig))
        m.handleEvent(SpiderFootEvent("INTERNET_NAME", "demo.example", "sfp_dnsresolve", None))
        mismatch = [e.data for e in events if e.eventType == "SSL_CERTIFICATE_MISMATCH"]
        self.assertEqual(mismatch, ["other.example, other.example, alt.example"])

    def test_a_certificate_with_no_host_list_still_does_not_crash(self):
        import modules.sfp_sslcert as mod
        m = sfp_sslcert()
        m.__name__ = "sfp_sslcert"
        m.setup(SpiderFoot(self.default_options), {})
        events = []
        m.notifyListeners = events.append
        target = MagicMock()
        target.matches.return_value = False
        m.getTarget = lambda: target
        m.sf.safeSSLSocket = lambda *a, **k: MagicMock()
        m.sf.parseCert = lambda *a, **k: {"mismatch": True, "hosts": None, "text": "x", "issued": "a", "issuer": "b",
                                          "altnames": [], "expired": False, "expiring": False}
        m.opts.update({"tryhttp": False, "verify": False, "certexpiringdays": 30, "ssltimeout": 5, "_internettlds": ""})
        m.sf.isDomain = lambda *a, **k: False
        mod.SpiderFootHelpers.sslDerToPem, orig = staticmethod(lambda der: "pem"), mod.SpiderFootHelpers.sslDerToPem
        self.addCleanup(lambda: setattr(mod.SpiderFootHelpers, "sslDerToPem", orig))
        m.handleEvent(SpiderFootEvent("INTERNET_NAME", "demo.example", "sfp_dnsresolve", None))
        self.assertEqual([e.data for e in events if e.eventType == "SSL_CERTIFICATE_MISMATCH"],
                         ["the certificate lists no host names (served for demo.example)"])


class TestSubfinderRoot(TestModuleBase):

    def _module(self, target_type, target_value):
        m = sfp_subfinder()
        m.__name__ = "sfp_subfinder"
        m.setup(SpiderFoot(self.default_options), {})
        target = MagicMock(targetType=target_type, targetValue=target_value)
        m.getTarget = lambda: target
        m._find_subfinder = lambda: "/bin/true"
        self.ran = []

        def fake_run(cmd, **kw):
            self.ran.append(cmd[cmd.index("-d") + 1] if "-d" in cmd else None)
            return MagicMock(returncode=0, stderr="", stdout="")

        import modules.sfp_subfinder as mod
        mod.subprocess.run, self._orig = fake_run, mod.subprocess.run
        self.addCleanup(lambda: setattr(mod.subprocess, "run", self._orig))
        return m

    def test_a_host_name_target_is_enumerated_from_the_root_event(self):
        """The live failure: 'SpiderFoot' object has no attribute 'targetValue', on the first event of every scan."""
        m = self._module("INTERNET_NAME", "demo.testfire.net")
        m.handleEvent(SpiderFootEvent("ROOT", "demo.testfire.net", "", None))
        self.assertEqual(self.ran, ["demo.testfire.net"])

    def test_other_target_types_are_not_enumerated(self):
        for ttype, value in (("EMAILADDR", "a@b.c"), ("HUMAN_NAME", "Leon Scott"), ("IP_ADDRESS", "198.51.100.7"),
                             ("PHONE_NUMBER", "+61459053405")):
            m = self._module(ttype, value)
            m.handleEvent(SpiderFootEvent("ROOT", value, "", None))
            self.assertEqual(self.ran, [], ttype)

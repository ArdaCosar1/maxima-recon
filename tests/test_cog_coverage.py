#!/usr/bin/env python3
"""
Maxima Test Suite — Cog Coverage Tests
Düşük coverage'lı modüllerin run() metotlarını mock ile test eder.
Hedef: Genel coverage'ı %50+ seviyesine çıkarmak.
"""

import sys
import os
import json
import socket
import unittest
from unittest.mock import patch, MagicMock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

# Cache temizleme — her test izole çalışsın
from utils.base_module import BaseModule as _BM

_orig_setUp = unittest.TestCase.setUp


def _clear_cache_setUp(self):
    _BM._request_cache.clear()
    _BM._base_response_cache.clear()
    if _orig_setUp:
        try:
            _orig_setUp(self)
        except Exception:
            pass


unittest.TestCase.setUp = _clear_cache_setUp

# ── Ortak mock yanıtlar ──────────────────────────────────────
MOCK_200 = {
    "status": 200,
    "body": "<html><head><title>Test</title></head><body>test page</body></html>",
    "headers": {"Content-Type": "text/html", "Server": "Apache/2.4.49"},
    "url": "http://testhost.example.com",
}

MOCK_404 = {
    "status": 404,
    "body": "<html>Not Found</html>",
    "headers": {"Content-Type": "text/html"},
    "url": "http://testhost.example.com/notfound",
}

MOCK_EMPTY = {
    "status": 200,
    "body": "",
    "headers": {},
    "url": "http://testhost.example.com",
}

MOCK_ERR = {
    "status": 0,
    "body": "",
    "headers": {},
    "url": "http://testhost.example.com",
    "error": "Connection refused",
}


def _assert_valid_result(tc, result):
    """Ortak sonuç yapısı doğrulaması."""
    tc.assertIsInstance(result, dict)
    for key in ("module", "target", "timestamp", "findings", "summary"):
        tc.assertIn(key, result, f"Sonuçta '{key}' anahtarı eksik")
    tc.assertIsInstance(result["findings"], list)


# ═════════════════════════════════════════════════════════════
# Tier 1: Trivial mocking — yüksek ROI
# ═════════════════════════════════════════════════════════════

class TestFullReconScan(unittest.TestCase):
    """recon_01 coverage: FullReconScan"""

    def test_run_success_with_server(self):
        from cogs.recon_01_full_scan import FullReconScan
        mod = FullReconScan("http://testhost.example.com")
        mod.http_get = MagicMock(return_value=MOCK_200)
        mod.resolve_ip = MagicMock(return_value="93.184.216.34")
        result = mod.run()
        _assert_valid_result(self, result)
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Sunucu" in t for t in titles))
        self.assertEqual(result["summary"]["IP"], "93.184.216.34")

    def test_run_unreachable(self):
        from cogs.recon_01_full_scan import FullReconScan
        mod = FullReconScan("http://unreachable.example.com")
        mod.http_get = MagicMock(return_value=MOCK_ERR)
        mod.resolve_ip = MagicMock(return_value=None)
        result = mod.run()
        _assert_valid_result(self, result)
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Ulaşılamadı" in t for t in titles))

    def test_confidence_is_confirmed(self):
        from cogs.recon_01_full_scan import FullReconScan
        mod = FullReconScan("http://testhost.example.com")
        mod.http_get = MagicMock(return_value=MOCK_200)
        mod.resolve_ip = MagicMock(return_value="1.2.3.4")
        result = mod.run()
        for f in result["findings"]:
            self.assertEqual(f.get("confidence"), "confirmed")

    def test_powered_by_header(self):
        from cogs.recon_01_full_scan import FullReconScan
        resp = {**MOCK_200, "headers": {"X-Powered-By": "PHP/8.1"}}
        mod = FullReconScan("http://testhost.example.com")
        mod.http_get = MagicMock(return_value=resp)
        mod.resolve_ip = MagicMock(return_value="1.2.3.4")
        result = mod.run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Teknoloji" in t for t in titles))


class TestVulnerabilityScanner(unittest.TestCase):
    """recon_03 coverage: VulnerabilityScanner"""

    def test_run_missing_headers(self):
        from cogs.recon_03_vuln_scanner import VulnerabilityScanner
        mod = VulnerabilityScanner("https://testhost.example.com")
        mod.http_get = MagicMock(return_value={
            "status": 200, "body": "<html></html>",
            "headers": {"Content-Type": "text/html"},
            "url": "https://testhost.example.com",
        })
        result = mod.run()
        _assert_valid_result(self, result)
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("HSTS" in t for t in titles))
        self.assertTrue(any("CSP" in t for t in titles))
        self.assertTrue(any("Clickjacking" in t for t in titles))

    def test_run_wordpress_detected(self):
        from cogs.recon_03_vuln_scanner import VulnerabilityScanner
        mod = VulnerabilityScanner("http://testhost.example.com")
        mod.http_get = MagicMock(return_value={
            "status": 200,
            "body": '<link href="/wp-content/themes/default/style.css">',
            "headers": {"Content-Type": "text/html"},
            "url": "http://testhost.example.com",
        })
        result = mod.run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("WordPress" in t for t in titles))

    def test_run_drupal_detected(self):
        from cogs.recon_03_vuln_scanner import VulnerabilityScanner
        mod = VulnerabilityScanner("http://testhost.example.com")
        mod.http_get = MagicMock(return_value={
            "status": 200,
            "body": '<script>Drupal.settings = {};</script>',
            "headers": {"Content-Type": "text/html"},
            "url": "http://testhost.example.com",
        })
        result = mod.run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Drupal" in t for t in titles))

    def test_all_headers_present(self):
        """Tüm güvenlik header'ları varsa minimum bulgu."""
        from cogs.recon_03_vuln_scanner import VulnerabilityScanner
        mod = VulnerabilityScanner("https://testhost.example.com")
        mod.http_get = MagicMock(return_value={
            "status": 200,
            "body": "<html>safe</html>",
            "headers": {
                "Strict-Transport-Security": "max-age=31536000",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'self'",
                "X-XSS-Protection": "0",
            },
            "url": "https://testhost.example.com",
        })
        result = mod.run()
        _assert_valid_result(self, result)
        self.assertEqual(len(result["findings"]), 0)

    def test_confidence_is_confirmed(self):
        from cogs.recon_03_vuln_scanner import VulnerabilityScanner
        mod = VulnerabilityScanner("https://testhost.example.com")
        mod.http_get = MagicMock(return_value={
            "status": 200, "body": "", "headers": {},
            "url": "https://testhost.example.com",
        })
        result = mod.run()
        for f in result["findings"]:
            self.assertIn(f.get("confidence"), ("confirmed", "firm"))


class TestOpenRedirectScanner(unittest.TestCase):
    """recon_18 coverage: OpenRedirectScanner"""

    def test_run_no_redirect(self):
        from cogs.recon_18_open_redirect import OpenRedirectScanner
        import urllib.parse
        mod = OpenRedirectScanner("http://testhost.example.com")

        # Build the real URL the module would generate for first combo
        real_parallel = mod.parallel_get

        def mock_parallel(urls, **kw):
            # Return all URLs with safe responses (no redirect)
            return [(u, {"status": 200, "body": "ok", "headers": {},
                         "url": "http://testhost.example.com"})
                    for u in urls]

        mod.parallel_get = mock_parallel
        result = mod.run()
        _assert_valid_result(self, result)
        self.assertEqual(result["summary"]["Açık Yönlendirme"], 0)

    def test_run_redirect_found(self):
        from cogs.recon_18_open_redirect import OpenRedirectScanner
        import urllib.parse
        mod = OpenRedirectScanner("http://testhost.example.com")

        def mock_parallel(urls, **kw):
            results = []
            for u in urls:
                if "redirect=" in u:
                    results.append((u, {
                        "status": 302, "body": "",
                        "headers": {"location": "https://evil-redir-test.example.com/malicious"},
                        "url": u,
                    }))
                else:
                    results.append((u, {"status": 200, "body": "ok", "headers": {}, "url": u}))
            return results

        mod.parallel_get = mock_parallel
        result = mod.run()
        _assert_valid_result(self, result)
        self.assertGreaterEqual(result["summary"]["Açık Yönlendirme"], 1)


class TestDNSRecordAnalysis(unittest.TestCase):
    """recon_23 coverage: DNSRecordAnalysis"""

    @patch("subprocess.run")
    def test_run_with_dig(self, mock_run):
        from cogs.recon_23_dns_records import DNSRecordAnalysis
        mock_result = MagicMock()
        mock_result.stdout = "93.184.216.34"
        mock_run.return_value = mock_result

        mod = DNSRecordAnalysis("http://example.com")
        result = mod.run()
        _assert_valid_result(self, result)
        self.assertIn("DNS A", result["summary"])

    @patch("subprocess.run")
    def test_run_with_txt_spf(self, mock_run):
        """TXT kaydında SPF bulunursa finding eklenmeli."""
        from cogs.recon_23_dns_records import DNSRecordAnalysis

        def side_effect(args, **kw):
            m = MagicMock()
            if args[2] == "TXT":
                m.stdout = '"v=spf1 include:_spf.google.com ~all"'
            else:
                m.stdout = "93.184.216.34"
            return m

        mock_run.side_effect = side_effect
        mod = DNSRecordAnalysis("http://example.com")
        result = mod.run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("SPF" in t for t in titles))

    @patch("subprocess.run")
    def test_run_with_txt_sensitive(self, mock_run):
        """TXT kaydında hassas veri varsa high severity finding."""
        from cogs.recon_23_dns_records import DNSRecordAnalysis

        def side_effect(args, **kw):
            m = MagicMock()
            if args[2] == "TXT":
                m.stdout = 'secret=abc123token'
            else:
                m.stdout = "1.2.3.4"
            return m

        mock_run.side_effect = side_effect
        mod = DNSRecordAnalysis("http://example.com")
        result = mod.run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Hassas" in t for t in titles))

    @patch("subprocess.run", side_effect=FileNotFoundError)
    @patch("socket.gethostbyname", return_value="93.184.216.34")
    def test_run_dig_not_available(self, mock_dns, mock_run):
        """dig yoksa socket fallback çalışmalı."""
        from cogs.recon_23_dns_records import DNSRecordAnalysis
        mod = DNSRecordAnalysis("http://example.com")
        result = mod.run()
        _assert_valid_result(self, result)
        self.assertIn("A", result["summary"])

    def test_run_invalid_domain(self):
        from cogs.recon_23_dns_records import DNSRecordAnalysis
        mod = DNSRecordAnalysis("http://inv@lid!host.com")
        result = mod.run()
        _assert_valid_result(self, result)
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Geçersiz" in t for t in titles))


class TestRedirectChainAnalyzer(unittest.TestCase):
    """recon_28 coverage: RedirectChainAnalyzer"""

    @patch("urllib.request.build_opener")
    def test_run_no_redirect(self, mock_builder):
        from cogs.recon_28_redirect_chain import RedirectChainAnalyzer

        class FakeHeaders(dict):
            pass

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = FakeHeaders()

        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp
        mock_builder.return_value = mock_opener

        mod = RedirectChainAnalyzer("http://testhost.example.com")
        result = mod.run()
        _assert_valid_result(self, result)
        self.assertEqual(result["summary"]["Zincir Uzunluğu"], 1)

    @patch("urllib.request.build_opener")
    def test_run_long_chain(self, mock_builder):
        from cogs.recon_28_redirect_chain import RedirectChainAnalyzer

        call_count = [0]
        locations = [
            "http://step1.example.com",
            "http://step2.example.com",
            "https://step3.example.com",
            "https://final.example.com",
            "",  # son adım
        ]

        class FakeHeaders(dict):
            pass

        def mock_open(req, **kw):
            idx = min(call_count[0], len(locations) - 1)
            resp = MagicMock()
            resp.status = 301 if locations[idx] else 200
            h = FakeHeaders()
            h["Location"] = locations[idx]
            resp.headers = h
            call_count[0] += 1
            return resp

        mock_opener = MagicMock()
        mock_opener.open.side_effect = mock_open
        mock_builder.return_value = mock_opener

        mod = RedirectChainAnalyzer("http://testhost.example.com")
        result = mod.run()
        _assert_valid_result(self, result)
        self.assertGreaterEqual(result["summary"]["Zincir Uzunluğu"], 4)
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Uzun" in t for t in titles) or
                        any("HTTP->HTTPS" in t for t in titles))


# ═════════════════════════════════════════════════════════════
# Tier 2: Moderate mocking
# ═════════════════════════════════════════════════════════════

class TestSSRFScanner(unittest.TestCase):
    """recon_08 coverage: SSRFScanner run()"""

    def test_run_no_ssrf(self):
        from cogs.recon_08_ssrf import SSRFScanner
        mod = SSRFScanner("http://testhost.example.com")
        mod.http_get = MagicMock(return_value=MOCK_200)
        mod.parallel_get = MagicMock(return_value=[
            ("http://testhost.example.com?url=http://127.0.0.1/", {
                "status": 200, "body": "normal page",
                "headers": {}, "url": "http://testhost.example.com",
            })
        ])
        result = mod.run()
        _assert_valid_result(self, result)
        self.assertEqual(result["summary"]["SSRF Adayı"], 0)

    def test_run_ssrf_detected(self):
        from cogs.recon_08_ssrf import SSRFScanner
        mod = SSRFScanner("http://testhost.example.com")
        # Baseline (example.com baseline — no signatures)
        mod.http_get = MagicMock(return_value={
            "status": 200, "body": "baseline normal",
            "headers": {}, "url": "http://testhost.example.com",
        })
        # SSRF detected: ami-id in body
        mod.parallel_get = MagicMock(return_value=[
            ("http://testhost.example.com?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F", {
                "status": 200,
                "body": "ami-id: ami-12345\ninstance-id: i-abc",
                "headers": {},
                "url": "http://testhost.example.com?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F",
            })
        ])
        result = mod.run()
        _assert_valid_result(self, result)
        self.assertGreaterEqual(result["summary"]["SSRF Adayı"], 1)


class TestDirectoryEnumeration(unittest.TestCase):
    """recon_10 coverage: DirectoryEnumeration helpers + run()"""

    def test_sev_helper(self):
        from cogs.recon_10_dir_enum import DirectoryEnumeration
        self.assertEqual(DirectoryEnumeration._sev(("critical", "high", "medium"), 200), "critical")
        self.assertEqual(DirectoryEnumeration._sev(("critical", "high", "medium"), 403), "high")
        self.assertEqual(DirectoryEnumeration._sev(("critical", "high", "medium"), 401), "medium")

    def test_is_soft_404(self):
        from cogs.recon_10_dir_enum import DirectoryEnumeration
        mod = DirectoryEnumeration("http://testhost.example.com")
        # Short body = soft-404
        self.assertTrue(mod._is_soft_404("short", 5000))
        # Body very close to baseline = soft-404
        self.assertTrue(mod._is_soft_404("A" * 500, 500))
        # Body very different from baseline = not soft-404
        self.assertFalse(mod._is_soft_404("A" * 5000, 500))

    def test_run_with_mock(self):
        from cogs.recon_10_dir_enum import DirectoryEnumeration
        mod = DirectoryEnumeration("http://testhost.example.com")
        # baseline_404 response — short body
        baseline_resp = {"status": 404, "body": "Not Found", "headers": {}, "url": "http://testhost.example.com/Mx_rand_404_test_92f1"}

        call_count = [0]
        original_http_get = mod.http_get

        def mock_get(url, **kw):
            if "Mx_rand_404_test" in url:
                return baseline_resp
            return {"status": 404, "body": "Not Found", "headers": {}, "url": url}

        mod.http_get = mock_get
        mod.parallel_get = MagicMock(return_value=[
            ("http://testhost.example.com/.env", {
                "status": 200, "body": "DB_HOST=localhost\nDB_PASS=secret123\n" * 50,
                "headers": {}, "url": "http://testhost.example.com/.env",
            }),
            ("http://testhost.example.com/admin", {
                "status": 403, "body": "Forbidden",
                "headers": {}, "url": "http://testhost.example.com/admin",
            }),
            ("http://testhost.example.com/robots.txt", {
                "status": 200, "body": "User-agent: *\nDisallow: /admin",
                "headers": {}, "url": "http://testhost.example.com/robots.txt",
            }),
        ])
        result = mod.run()
        _assert_valid_result(self, result)
        self.assertGreaterEqual(result["summary"]["Erişilebilir"], 1)


class TestAPIFuzzer(unittest.TestCase):
    """recon_11 coverage: APIFuzzer"""

    def test_run_with_active_endpoints(self):
        from cogs.recon_11_api_fuzzer import APIFuzzer
        mod = APIFuzzer("http://testhost.example.com")

        # Step 1: endpoint discovery returns some active
        endpoint_results = [
            ("http://testhost.example.com/api", {
                "status": 200, "body": '{"version":"1.0"}',
                "headers": {}, "url": "http://testhost.example.com/api",
            }),
            ("http://testhost.example.com/api/debug", {
                "status": 200, "body": '{"stack":"trace info","error_message":"test"}',
                "headers": {}, "url": "http://testhost.example.com/api/debug",
            }),
            ("http://testhost.example.com/api/admin", {
                "status": 403, "body": "Forbidden",
                "headers": {}, "url": "http://testhost.example.com/api/admin",
            }),
        ]

        def mock_parallel_get(urls, **kw):
            results = []
            for url in urls:
                matched = False
                for eu, er in endpoint_results:
                    if url == eu:
                        results.append((url, er))
                        matched = True
                        break
                if not matched:
                    results.append((url, MOCK_404))
            return results

        mod.parallel_get = mock_parallel_get
        mod.parallel_post = MagicMock(return_value=[])
        mod.http_get = MagicMock(return_value=MOCK_404)
        mod.http_post = MagicMock(return_value=MOCK_404)

        result = mod.run()
        _assert_valid_result(self, result)
        self.assertGreaterEqual(result["summary"]["Bulunan Endpoint"], 1)

    def test_check_info_leak(self):
        from cogs.recon_11_api_fuzzer import APIFuzzer
        mod = APIFuzzer("http://testhost.example.com")
        # Has info leak keywords
        mod._check_info_leak('{"stack":"trace","password":"leaked"}', "/api/debug")
        self.assertTrue(any("Sızıntısı" in f["title"] for f in mod.results["findings"]))

    def test_check_info_leak_empty(self):
        from cogs.recon_11_api_fuzzer import APIFuzzer
        mod = APIFuzzer("http://testhost.example.com")
        mod._check_info_leak("", "/api/test")
        self.assertEqual(len(mod.results["findings"]), 0)


class TestSSLTLSAnalyzer(unittest.TestCase):
    """recon_13 coverage: SSLTLSAnalyzer"""

    @patch("socket.create_connection")
    def test_run_connection_error(self, mock_conn):
        from cogs.recon_13_ssl_tls import SSLTLSAnalyzer
        mock_conn.side_effect = OSError("Connection refused")
        mod = SSLTLSAnalyzer("https://testhost.example.com")
        result = mod.run()
        _assert_valid_result(self, result)
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Bağlantı Hatası" in t for t in titles))

    @patch("ssl.SSLContext")
    @patch("socket.create_connection")
    def test_run_success(self, mock_conn, mock_ctx_cls):
        from cogs.recon_13_ssl_tls import SSLTLSAnalyzer

        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            "subject": ((("commonName", "example.com"),),),
            "notAfter": "Dec 31 23:59:59 2099 GMT",
        }
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.__enter__ = lambda s: s
        mock_ssock.__exit__ = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)

        mock_conn.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock
        mock_ctx_cls.return_value = mock_ctx

        # Also patch ssl.create_default_context
        with patch("ssl.create_default_context", return_value=mock_ctx):
            mod = SSLTLSAnalyzer("https://testhost.example.com")
            result = mod.run()
            _assert_valid_result(self, result)
            self.assertIn("Protokol", result["summary"])


# ═════════════════════════════════════════════════════════════
# Confidence Scoring Tests
# ═════════════════════════════════════════════════════════════

class TestConfidenceScoring(unittest.TestCase):
    """Confidence scoring sistemi testleri."""

    def test_default_confidence_is_firm(self):
        m = _BM("http://example.com")
        m.add_finding("Test", "Detail", "info")
        self.assertEqual(m.results["findings"][0]["confidence"], "firm")

    def test_explicit_confirmed(self):
        m = _BM("http://example.com")
        m.add_finding("Test", "Detail", "high", confidence="confirmed")
        self.assertEqual(m.results["findings"][0]["confidence"], "confirmed")

    def test_explicit_tentative(self):
        m = _BM("http://example.com")
        m.add_finding("Test", "Detail", "medium", confidence="tentative")
        self.assertEqual(m.results["findings"][0]["confidence"], "tentative")

    def test_invalid_confidence_defaults_to_firm(self):
        m = _BM("http://example.com")
        m.add_finding("Test", "Detail", "low", confidence="maybe")
        self.assertEqual(m.results["findings"][0]["confidence"], "firm")

    def test_confidence_in_finding_dict(self):
        m = _BM("http://example.com")
        m.add_finding("Test", "Detail", "info")
        self.assertIn("confidence", m.results["findings"][0])

    def test_valid_confidences_set(self):
        self.assertEqual(_BM.VALID_CONFIDENCES, {"confirmed", "firm", "tentative"})


# ═════════════════════════════════════════════════════════════
# Report Generator Enhanced Tests
# ═════════════════════════════════════════════════════════════

class TestReportGeneratorEnhanced(unittest.TestCase):
    """Gelişmiş rapor üretici testleri."""

    def setUp(self):
        import tempfile
        from utils.report_generator import ReportGenerator
        self.tmpdir = tempfile.mkdtemp()
        self.gen = ReportGenerator(
            "http://test.example.com",
            {
                "VulnScanner": {
                    "findings": [
                        {"title": "HSTS Eksik", "detail": "HSTS yok", "severity": "medium",
                         "confidence": "confirmed", "remediation": "HSTS header ekleyin",
                         "evidence": "HTTP yanıtında Strict-Transport-Security yok"},
                        {"title": "CSP Eksik", "detail": "CSP yok", "severity": "high",
                         "confidence": "confirmed", "remediation": "CSP header ekleyin"},
                        {"title": "SQLi Olası", "detail": "Timing farkı", "severity": "high",
                         "confidence": "tentative"},
                    ],
                    "summary": {}
                },
                "PortScanner": {
                    "findings": [
                        {"title": "Port 22 Açık", "detail": "SSH", "severity": "low",
                         "confidence": "confirmed"},
                    ],
                    "summary": {}
                },
            },
            self.tmpdir
        )

    def test_confidence_counts(self):
        findings = self.gen._collect_findings()
        conf = self.gen._confidence_counts(findings)
        self.assertEqual(conf["confirmed"], 3)
        self.assertEqual(conf["tentative"], 1)
        self.assertEqual(conf["firm"], 0)

    def test_risk_score(self):
        findings = self.gen._collect_findings()
        counts = self.gen._severity_counts(findings)
        score = self.gen._risk_score(counts)
        self.assertIsInstance(score, float)
        self.assertGreater(score, 0)
        self.assertLessEqual(score, 10.0)

    def test_risk_score_zero(self):
        from utils.report_generator import ReportGenerator
        gen = ReportGenerator("http://x.com", {}, self.tmpdir)
        self.assertEqual(gen._risk_score({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}), 0.0)

    def test_executive_summary(self):
        findings = self.gen._collect_findings()
        counts = self.gen._severity_counts(findings)
        es = self.gen._executive_summary(findings, counts)
        self.assertIn("risk_score", es)
        self.assertIn("top_findings", es)
        self.assertIn("remediation_priorities", es)
        self.assertLessEqual(len(es["top_findings"]), 3)

    def test_generate_html_has_confidence(self):
        path = self.gen.generate_html()
        content = open(path, encoding="utf-8").read()
        # Confidence badge should appear (Turkish: Doğrulanmış or Güçlü or Olası)
        from utils.report_generator import CONF_TR
        has_conf = any(v in content for v in CONF_TR.values())
        self.assertTrue(has_conf, "Confidence badge HTML'de bulunamadı")

    def test_generate_html_has_evidence(self):
        path = self.gen.generate_html()
        content = open(path, encoding="utf-8").read()
        self.assertIn("Strict-Transport-Security", content)

    def test_generate_html_has_executive_summary(self):
        path = self.gen.generate_html()
        content = open(path, encoding="utf-8").read()
        self.assertIn("Yonetici Ozeti", content)

    def test_generate_html_has_risk_score(self):
        path = self.gen.generate_html()
        content = open(path, encoding="utf-8").read()
        self.assertIn("Risk Skoru", content)

    def test_generate_html_has_remediation_grouping(self):
        path = self.gen.generate_html()
        content = open(path, encoding="utf-8").read()
        self.assertIn("Iyilestirme Oncelikleri", content)

    def test_generate_json(self):
        path = self.gen.generate_json()
        self.assertTrue(os.path.exists(path))
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("metadata", data)
        self.assertIn("summary", data)
        self.assertIn("findings", data)
        self.assertIn("modules", data)
        self.assertEqual(data["summary"]["total_findings"], 4)
        self.assertIn("confidence_counts", data["summary"])

    def test_generate_json_findings_have_confidence(self):
        path = self.gen.generate_json()
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for finding in data["findings"]:
            self.assertIn("confidence", finding)

    def test_generate_all_returns_three(self):
        result = self.gen.generate_all()
        self.assertEqual(len(result), 3)
        html_path, pdf_path, json_path = result
        self.assertTrue(os.path.exists(html_path))
        self.assertTrue(os.path.exists(json_path))

    def test_empty_results(self):
        from utils.report_generator import ReportGenerator
        gen = ReportGenerator("http://x.com", {}, self.tmpdir)
        path = gen.generate_html()
        content = open(path, encoding="utf-8").read()
        self.assertIn("guvenlik acigi tespit edilmedi", content)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)


# ═════════════════════════════════════════════════════════════
# maxima.py function tests
# ═════════════════════════════════════════════════════════════

class TestMaximaFunctions(unittest.TestCase):
    """maxima.py fonksiyon testleri."""

    def _load_maxima(self):
        import importlib
        spec = importlib.util.spec_from_file_location(
            "maxima", os.path.join(PROJECT_ROOT, "maxima.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_menu_length(self):
        mod = self._load_maxima()
        self.assertEqual(len(mod.MENU), 41)

    def test_scan_profiles_keys(self):
        mod = self._load_maxima()
        for key in ("web", "osint", "vuln", "network", "full", "full-v2"):
            self.assertIn(key, mod.SCAN_PROFILES)

    def test_get_module_timeout_override(self):
        mod = self._load_maxima()
        # Module 9 has override 20
        self.assertEqual(mod._get_module_timeout(9, 8), 20)
        # No override
        self.assertEqual(mod._get_module_timeout(14, 8), 8)

    def test_compare_scans_empty(self):
        import tempfile
        mod = self._load_maxima()
        baseline = {"results": {}}
        current = {}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(baseline, f)
            f.flush()
            diff = mod.compare_scans(current, f.name)
        os.unlink(f.name)
        self.assertEqual(len(diff["new"]), 0)
        self.assertEqual(len(diff["fixed"]), 0)


# ═════════════════════════════════════════════════════════════
# Tier 3: Additional modules for 50%+ coverage
# ═════════════════════════════════════════════════════════════

class TestRedirectAwareHeaderAnalysis(unittest.TestCase):
    """recon_34 coverage"""

    def test_run_http_only(self):
        from cogs.recon_34_redirect_header import RedirectAwareHeaderAnalysis
        mod = RedirectAwareHeaderAnalysis("http://testhost.example.com")
        mod.http_get = MagicMock(return_value={
            "status": 200, "body": "",
            "headers": {"Server": "nginx/1.18", "X-Powered-By": "Express"},
            "url": "http://testhost.example.com",
        })
        result = mod.run()
        _assert_valid_result(self, result)
        # Should check both http and https versions
        self.assertEqual(result["summary"]["Kontrol Edilen URL"], 2)
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Sızıntısı" in t for t in titles))

    def test_run_https_no_hsts(self):
        from cogs.recon_34_redirect_header import RedirectAwareHeaderAnalysis
        mod = RedirectAwareHeaderAnalysis("https://testhost.example.com")
        mod.http_get = MagicMock(return_value={
            "status": 200, "body": "",
            "headers": {"Content-Type": "text/html"},
            "url": "https://testhost.example.com",
        })
        result = mod.run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("HSTS" in t for t in titles))

    def test_run_hsts_no_include_subdomains(self):
        from cogs.recon_34_redirect_header import RedirectAwareHeaderAnalysis
        mod = RedirectAwareHeaderAnalysis("https://testhost.example.com")
        mod.http_get = MagicMock(return_value={
            "status": 200, "body": "",
            "headers": {"Strict-Transport-Security": "max-age=31536000"},
            "url": "https://testhost.example.com",
        })
        result = mod.run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("includeSubDomains" in t for t in titles))

    def test_run_hsts_disabled(self):
        from cogs.recon_34_redirect_header import RedirectAwareHeaderAnalysis
        mod = RedirectAwareHeaderAnalysis("https://testhost.example.com")
        mod.http_get = MagicMock(return_value={
            "status": 200, "body": "",
            "headers": {"Strict-Transport-Security": "max-age=0"},
            "url": "https://testhost.example.com",
        })
        result = mod.run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Devre Dışı" in t for t in titles))


class TestJWTAnalyzer(unittest.TestCase):
    """recon_16 coverage"""

    def test_run_no_jwt(self):
        from cogs.recon_16_jwt_analyzer import JWTAnalyzer
        mod = JWTAnalyzer("http://testhost.example.com")
        mod.http_get = MagicMock(return_value={
            "status": 200, "body": "",
            "headers": {"set-cookie": "session=abc123"},
            "url": "http://testhost.example.com",
        })
        result = mod.run()
        _assert_valid_result(self, result)
        self.assertEqual(result["summary"]["Bulunan Token"], 0)

    def test_run_jwt_none_alg(self):
        from cogs.recon_16_jwt_analyzer import JWTAnalyzer
        import base64, json as _json
        header = base64.urlsafe_b64encode(_json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(_json.dumps({"sub": "1"}).encode()).rstrip(b"=").decode()
        token = f"{header}.{payload}."

        mod = JWTAnalyzer("http://testhost.example.com")
        mod.http_get = MagicMock(return_value={
            "status": 200, "body": "",
            "headers": {"set-cookie": f"token={token}"},
            "url": "http://testhost.example.com",
        })
        result = mod.run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("None" in t for t in titles))

    def test_run_jwt_hs256_no_exp(self):
        from cogs.recon_16_jwt_analyzer import JWTAnalyzer
        import base64, json as _json
        header = base64.urlsafe_b64encode(_json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(_json.dumps({"sub": "1"}).encode()).rstrip(b"=").decode()
        token = f"{header}.{payload}.fakesig"

        mod = JWTAnalyzer("http://testhost.example.com")
        mod.http_get = MagicMock(return_value={
            "status": 200, "body": "",
            "headers": {"set-cookie": f"auth={token}"},
            "url": "http://testhost.example.com",
        })
        result = mod.run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Simetrik" in t for t in titles))
        self.assertTrue(any("Süre" in t for t in titles))

    def test_decode_part_invalid(self):
        from cogs.recon_16_jwt_analyzer import JWTAnalyzer
        mod = JWTAnalyzer("http://testhost.example.com")
        self.assertEqual(mod._decode_part("not-valid-base64!!!"), {})


class TestSubdomainTakeoverCheck(unittest.TestCase):
    """recon_19 coverage"""

    @patch("socket.gethostbyname")
    def test_run_wildcard_dns(self, mock_dns):
        from cogs.recon_19_subdomain_takeover import SubdomainTakeoverCheck
        # Wildcard DNS: any subdomain resolves
        mock_dns.return_value = "1.2.3.4"
        mod = SubdomainTakeoverCheck("http://testhost.example.com")
        result = mod.run()
        _assert_valid_result(self, result)
        self.assertEqual(result["summary"].get("Wildcard DNS"), "Var")

    @patch("socket.gethostbyname")
    def test_run_no_wildcard_no_takeover(self, mock_dns):
        from cogs.recon_19_subdomain_takeover import SubdomainTakeoverCheck

        def dns_side_effect(host):
            if "maxima-wildcard" in host:
                raise socket.gaierror("NXDOMAIN")
            raise socket.gaierror("NXDOMAIN")

        mock_dns.side_effect = dns_side_effect
        mod = SubdomainTakeoverCheck("http://testhost.example.com")
        result = mod.run()
        _assert_valid_result(self, result)
        self.assertEqual(result["summary"]["Takeover Adayı"], 0)

    @patch("socket.gethostbyname")
    def test_run_takeover_detected(self, mock_dns):
        from cogs.recon_19_subdomain_takeover import SubdomainTakeoverCheck

        def dns_side_effect(host):
            if "maxima-wildcard" in host:
                raise socket.gaierror("NXDOMAIN")
            if "blog." in host:
                return "1.2.3.4"
            raise socket.gaierror("NXDOMAIN")

        mock_dns.side_effect = dns_side_effect
        mod = SubdomainTakeoverCheck("http://testhost.example.com")
        mod.http_get = MagicMock(return_value={
            "status": 200,
            "body": "There isn't a GitHub Pages site here.",
            "headers": {}, "url": "http://blog.testhost.example.com",
        })
        result = mod.run()
        _assert_valid_result(self, result)
        self.assertGreaterEqual(result["summary"]["Takeover Adayı"], 1)


class TestHTTP2Probe(unittest.TestCase):
    """recon_30 coverage"""

    @patch("socket.socket")
    @patch("socket.create_connection")
    def test_run_connection_error(self, mock_conn, mock_sock_cls):
        from cogs.recon_30_http2_probe import HTTP2Probe
        mock_conn.side_effect = OSError("Connection refused")
        # Mock socket for port scan part
        mock_s = MagicMock()
        mock_s.connect_ex.return_value = 1  # all ports closed
        mock_sock_cls.return_value = mock_s

        mod = HTTP2Probe("http://testhost.example.com")
        mod.timeout = 2
        result = mod.run()
        _assert_valid_result(self, result)
        self.assertIn("Test edilemedi", result["summary"]["HTTP/2"])

    @patch("socket.socket")
    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    def test_run_http2_supported(self, mock_conn, mock_ctx_fn, mock_sock_cls):
        from cogs.recon_30_http2_probe import HTTP2Probe

        mock_ssock = MagicMock()
        mock_ssock.selected_alpn_protocol.return_value = "h2"
        mock_ssock.__enter__ = lambda s: s
        mock_ssock.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock
        mock_ctx_fn.return_value = mock_ctx

        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        # Port scan mocks
        mock_s = MagicMock()
        mock_s.connect_ex.return_value = 1
        mock_sock_cls.return_value = mock_s

        mod = HTTP2Probe("https://testhost.example.com")
        mod.timeout = 2
        result = mod.run()
        _assert_valid_result(self, result)
        self.assertIn("Destekleniyor", result["summary"]["HTTP/2"])


class TestIPGeolocation(unittest.TestCase):
    """recon_22 coverage"""

    def test_run_no_ip(self):
        from cogs.recon_22_ip_geo import IPGeolocation
        mod = IPGeolocation("http://testhost.example.com")
        mod.resolve_ip = MagicMock(return_value=None)
        result = mod.run()
        _assert_valid_result(self, result)
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Çözümlenemedi" in t for t in titles))

    def test_run_private_ip(self):
        from cogs.recon_22_ip_geo import IPGeolocation
        mod = IPGeolocation("http://testhost.example.com")
        mod.resolve_ip = MagicMock(return_value="192.168.1.1")
        result = mod.run()
        _assert_valid_result(self, result)
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Özel" in t for t in titles))

    def test_run_public_ip_with_api(self):
        from cogs.recon_22_ip_geo import IPGeolocation
        mod = IPGeolocation("http://testhost.example.com")
        mod.resolve_ip = MagicMock(return_value="93.184.216.34")
        geo_json = json.dumps({
            "ip": "93.184.216.34", "country": "US", "city": "Los Angeles",
            "region": "California", "org": "AS15133 MCI Communications",
            "timezone": "America/Los_Angeles", "loc": "34.0522,-118.2437",
        })
        # Mock http_get for all API calls
        mod.http_get = MagicMock(return_value={
            "status": 200, "body": geo_json,
            "headers": {}, "url": "https://ipinfo.io/93.184.216.34/json",
        })
        mod.get_base_response = MagicMock(return_value={
            "status": 200, "body": "",
            "headers": {"Server": "nginx"},
            "url": "http://testhost.example.com",
        })
        result = mod.run()
        _assert_valid_result(self, result)
        self.assertEqual(result["summary"].get("Ülke"), "US")
        self.assertEqual(result["summary"].get("Şehir"), "Los Angeles")

    def test_run_loopback_ip(self):
        from cogs.recon_22_ip_geo import IPGeolocation
        mod = IPGeolocation("http://localhost")
        mod.resolve_ip = MagicMock(return_value="127.0.0.1")
        result = mod.run()
        _assert_valid_result(self, result)
        self.assertIn("Not", result["summary"])


class TestCVETemplateEngine(unittest.TestCase):
    """recon_33 coverage"""

    def test_run_no_match(self):
        from cogs.recon_33_cve_template import CVETemplateEngine
        mod = CVETemplateEngine("http://testhost.example.com")
        mod.http_get = MagicMock(return_value=MOCK_200)
        mod.http_post = MagicMock(return_value=MOCK_404)
        result = mod.run()
        _assert_valid_result(self, result)


if __name__ == "__main__":
    unittest.main()

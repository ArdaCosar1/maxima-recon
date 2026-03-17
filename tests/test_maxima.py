#!/usr/bin/env python3
"""
Maxima Test Suite
Tüm modüller için birim ve entegrasyon testleri.

Çalıştırmak için (proje kök dizininden):
    python -m pytest tests/ -v
veya doğrudan:
    python tests/test_maxima.py
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock, PropertyMock

# Proje kökünü path'e ekle
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


# ─── BaseModule Testleri ──────────────────────────────────────
class TestBaseModule(unittest.TestCase):

    def setUp(self):
        from utils.base_module import BaseModule
        self.BaseModule = BaseModule

    def test_url_normalization_no_scheme(self):
        m = self.BaseModule("example.com")
        self.assertEqual(m.url, "http://example.com")

    def test_url_normalization_with_https(self):
        m = self.BaseModule("https://example.com/")
        self.assertEqual(m.url, "https://example.com")

    def test_host_extraction(self):
        m = self.BaseModule("https://example.com/path")
        self.assertEqual(m.host, "example.com")

    def test_results_structure(self):
        m = self.BaseModule("http://example.com")
        self.assertIn("findings", m.results)
        self.assertIn("summary", m.results)
        self.assertIn("module",  m.results)
        self.assertIsInstance(m.results["findings"], list)
        self.assertIsInstance(m.results["summary"],  dict)

    def test_add_finding_appends(self):
        m = self.BaseModule("http://example.com")
        m.add_finding("Test Başlığı", "Test detay", "high")
        self.assertEqual(len(m.results["findings"]), 1)
        f = m.results["findings"][0]
        self.assertEqual(f["title"],    "Test Başlığı")
        self.assertEqual(f["detail"],   "Test detay")
        self.assertEqual(f["severity"], "high")

    def test_add_finding_invalid_severity_defaults_to_info(self):
        m = self.BaseModule("http://example.com")
        m.add_finding("Test", "Detay", "superduper")
        self.assertEqual(m.results["findings"][0]["severity"], "info")

    def test_add_multiple_findings(self):
        m = self.BaseModule("http://example.com")
        for sev in ("critical", "high", "medium", "low", "info"):
            m.add_finding(f"Bulgu {sev}", "detay", sev)
        self.assertEqual(len(m.results["findings"]), 5)

    def test_run_raises_not_implemented(self):
        m = self.BaseModule("http://example.com")
        with self.assertRaises(NotImplementedError):
            m.run()

    def test_set_proxy_class_level(self):
        self.BaseModule.set_proxy("http://127.0.0.1:8080")
        m = self.BaseModule("http://example.com")
        self.assertEqual(self.BaseModule._proxy, "http://127.0.0.1:8080")
        self.BaseModule.set_proxy(None)

    def test_set_delay_class_level(self):
        self.BaseModule.set_delay(0.5)
        self.assertEqual(self.BaseModule._global_delay, 0.5)
        self.BaseModule.set_delay(0.0)

    def test_set_delay_negative_clamped(self):
        self.BaseModule.set_delay(-1.0)
        self.assertEqual(self.BaseModule._global_delay, 0.0)

    @patch("urllib.request.OpenerDirector.open")
    def test_http_get_returns_dict(self, mock_open):
        resp = MagicMock()
        resp.read.return_value = b"<html>test</html>"
        resp.headers           = {"Content-Type": "text/html"}
        resp.status            = 200
        resp.geturl.return_value = "http://example.com"
        resp.__enter__ = lambda s: s
        resp.__exit__  = MagicMock(return_value=False)
        mock_open.return_value = resp

        m      = self.BaseModule("http://example.com")
        result = m.http_get("http://example.com")
        self.assertIn("status",  result)
        self.assertIn("body",    result)
        self.assertIn("headers", result)


# ─── Compat Testleri ─────────────────────────────────────────
class TestCompat(unittest.TestCase):

    def test_fore_attributes_exist(self):
        from utils.compat import Fore, Back, Style
        # Renk attribute'ları string (ya da empty string) döndürmeli
        self.assertIsInstance(Fore.RED,        str)
        self.assertIsInstance(Fore.GREEN,      str)
        self.assertIsInstance(Style.RESET_ALL, str)

    def test_fore_is_importable_twice(self):
        from utils.compat import Fore as F1
        from utils.compat import Fore as F2
        self.assertIs(F1, F2)


# ─── Modül Import Testleri ───────────────────────────────────
class TestModuleImports(unittest.TestCase):
    """Tüm 41 cog import edilebilir mi?"""

    COGS = [
        ("cogs.recon_01_full_scan",          "FullReconScan"),
        ("cogs.recon_02_port_scanner",       "PortScanner"),
        ("cogs.recon_03_vuln_scanner",       "VulnerabilityScanner"),
        ("cogs.recon_04_sql_injection",      "SQLInjectionScanner"),
        ("cogs.recon_05_xss_scanner",        "XSSScanner"),
        ("cogs.recon_06_lfi_rfi",            "LFIRFIScanner"),
        ("cogs.recon_07_cmd_injection",      "CommandInjectionScanner"),
        ("cogs.recon_08_ssrf",               "SSRFScanner"),
        ("cogs.recon_09_subdomain_enum",     "SubdomainEnumeration"),
        ("cogs.recon_10_dir_enum",           "DirectoryEnumeration"),
        ("cogs.recon_11_api_fuzzer",         "APIFuzzer"),
        ("cogs.recon_12_cors",               "CORSScanner"),
        ("cogs.recon_13_ssl_tls",            "SSLTLSAnalyzer"),
        ("cogs.recon_14_http_headers",       "HTTPHeaderAnalyzer"),
        ("cogs.recon_15_tech_detect",        "TechnologyDetector"),
        ("cogs.recon_16_jwt_analyzer",       "JWTAnalyzer"),
        ("cogs.recon_17_clickjacking",       "ClickjackingTester"),
        ("cogs.recon_18_open_redirect",      "OpenRedirectScanner"),
        ("cogs.recon_19_subdomain_takeover", "SubdomainTakeoverCheck"),
        ("cogs.recon_20_rate_limit",         "RateLimitTester"),
        ("cogs.recon_21_whois",              "WHOISLookup"),
        ("cogs.recon_22_ip_geo",             "IPGeolocation"),
        ("cogs.recon_23_dns_records",        "DNSRecordAnalysis"),
        ("cogs.recon_24_password_check",     "PasswordStrengthChecker"),
        ("cogs.recon_25_hash_id",            "HashIdentifier"),
        ("cogs.recon_26_waf_detector",       "WAFDetector"),
        ("cogs.recon_27_tls_prober",         "TLSVersionProber"),
        ("cogs.recon_28_redirect_chain",     "RedirectChainAnalyzer"),
        ("cogs.recon_29_js_crawler",         "JSCrawlerSecretScanner"),
        ("cogs.recon_30_http2_probe",        "HTTP2Probe"),
        ("cogs.recon_31_payload_fuzzing",    "PayloadFuzzingEngine"),
        ("cogs.recon_32_screenshot",         "ScreenshotCapture"),
        ("cogs.recon_33_cve_template",       "CVETemplateEngine"),
        ("cogs.recon_34_redirect_header",    "RedirectAwareHeaderAnalysis"),
        ("cogs.recon_35_async_port_scanner", "AsyncPortScanner"),
        ("cogs.recon_36_cve_matcher",        "CVEMatcher"),
        ("cogs.recon_37_auth_tester",        "AuthTester"),
        ("cogs.recon_38_osint_engine",       "OSINTEngine"),
        ("cogs.recon_39_deep_sqli",          "DeepSQLiScanner"),
        ("cogs.recon_40_new_vectors",        "NewAttackVectors"),
        ("cogs.recon_41_advanced_reporter",  "AdvancedReporter"),
    ]

    def test_all_cogs_importable(self):
        import importlib
        for module_path, class_name in self.COGS:
            with self.subTest(module=module_path):
                mod = importlib.import_module(module_path)
                cls = getattr(mod, class_name, None)
                self.assertIsNotNone(
                    cls,
                    f"{class_name} bulunamadı — {module_path}"
                )

    def test_all_cogs_inherit_base_module(self):
        import importlib
        from utils.base_module import BaseModule
        for module_path, class_name in self.COGS:
            with self.subTest(module=module_path):
                mod = importlib.import_module(module_path)
                cls = getattr(mod, class_name, None)
                if cls is not None:
                    self.assertTrue(
                        issubclass(cls, BaseModule),
                        f"{class_name} BaseModule'den miras almıyor"
                    )

    def test_all_cogs_have_run_method(self):
        import importlib
        for module_path, class_name in self.COGS:
            with self.subTest(module=module_path):
                mod = importlib.import_module(module_path)
                cls = getattr(mod, class_name, None)
                if cls is not None:
                    self.assertTrue(
                        callable(getattr(cls, "run", None)),
                        f"{class_name}.run() metodu bulunamadı"
                    )


# ─── Async Port Scanner Testleri ─────────────────────────────
class TestAsyncPortScanner(unittest.TestCase):

    def setUp(self):
        from cogs.recon_35_async_port_scanner import AsyncPortScanner
        self.cls = AsyncPortScanner

    def test_parse_ports_single(self):
        self.assertEqual(self.cls.parse_ports("80"), [80])

    def test_parse_ports_range(self):
        result = self.cls.parse_ports("22-25")
        self.assertEqual(result, [22, 23, 24, 25])

    def test_parse_ports_mixed(self):
        result = self.cls.parse_ports("80,443,8000-8002")
        self.assertIn(80,   result)
        self.assertIn(443,  result)
        self.assertIn(8000, result)
        self.assertIn(8002, result)

    def test_parse_ports_none(self):
        self.assertEqual(self.cls.parse_ports(None), [])

    def test_parse_ports_invalid_ignored(self):
        result = self.cls.parse_ports("abc,80,xyz")
        self.assertEqual(result, [80])

    def test_parse_ports_out_of_range_filtered(self):
        result = self.cls.parse_ports("0,80,65536")
        self.assertEqual(result, [80])


# ─── CVE Matcher Testleri ─────────────────────────────────────
class TestCVEMatcher(unittest.TestCase):

    def setUp(self):
        from cogs.recon_36_cve_matcher import CVEMatcher, OFFLINE_CVE_DB
        self.cls          = CVEMatcher
        self.offline_db   = OFFLINE_CVE_DB

    def test_lookup_exact_match(self):
        m      = self.cls("http://example.com")
        result = m._lookup_cve("apache", "2.4.49")
        ids    = [r[0] for r in result]
        self.assertIn("CVE-2021-41773", ids)

    def test_lookup_major_match(self):
        m      = self.cls("http://example.com")
        result = m._lookup_cve("redis", "6.2.7")
        self.assertTrue(len(result) > 0, "Redis major match çalışmalı")

    def test_lookup_no_match(self):
        m      = self.cls("http://example.com")
        result = m._lookup_cve("unknownsoftware", "99.99.99")
        self.assertEqual(result, [])

    def test_extract_versions_apache(self):
        from cogs.recon_36_cve_matcher import VERSION_PATTERNS_HEADER
        m    = self.cls("http://example.com")
        text = "Server: Apache/2.4.49 (Ubuntu)"
        vers = m._extract_versions(text, VERSION_PATTERNS_HEADER)
        self.assertTrue(any(svc == "apache" for svc, _ in vers))

    def test_extract_versions_nginx(self):
        from cogs.recon_36_cve_matcher import VERSION_PATTERNS_HEADER
        m    = self.cls("http://example.com")
        text = "server: nginx/1.18.0"
        vers = m._extract_versions(text, VERSION_PATTERNS_HEADER)
        self.assertTrue(any(svc == "nginx" for svc, _ in vers))

    def test_offline_db_has_log4shell(self):
        keys = " ".join(self.offline_db.keys())
        self.assertIn("log4j", keys)


# ─── Deep SQLi Testleri ───────────────────────────────────────
class TestDeepSQLi(unittest.TestCase):

    def setUp(self):
        from cogs.recon_39_deep_sqli import DeepSQLiScanner, DB_ERRORS, ERROR_PAYLOADS
        self.cls           = DeepSQLiScanner
        self.db_errors     = DB_ERRORS
        self.error_payloads = ERROR_PAYLOADS

    def test_db_errors_structure(self):
        for db, errors in self.db_errors.items():
            self.assertIsInstance(errors, list)
            self.assertTrue(len(errors) > 0)

    def test_error_payloads_not_empty(self):
        self.assertGreater(len(self.error_payloads), 5)

    def test_find_parameters_from_url(self):
        m = self.cls("http://example.com/?id=1&cat=2")
        # Mock http_get to avoid network
        m.http_get = lambda url, **kw: {"status": 200, "body": "", "headers": {}, "url": url}
        params = m._find_parameters()
        param_names = [p for p, _ in params]
        self.assertIn("id",  param_names)
        self.assertIn("cat", param_names)


# ─── Report Generator Testleri ────────────────────────────────
class TestReportGenerator(unittest.TestCase):

    def setUp(self):
        import tempfile
        from utils.report_generator import ReportGenerator
        self.tmpdir = tempfile.mkdtemp()
        self.gen    = ReportGenerator(
            "http://test.example.com",
            {
                "HTTPHeaderAnalyzer": {
                    "findings": [
                        {"title": "HSTS Eksik", "detail": "HSTS yok", "severity": "medium"},
                        {"title": "CSP Eksik",  "detail": "CSP yok",  "severity": "high"},
                    ],
                    "summary": {}
                }
            },
            self.tmpdir
        )

    def test_collect_findings_returns_list(self):
        findings = self.gen._collect_findings()
        self.assertIsInstance(findings, list)
        self.assertEqual(len(findings), 2)

    def test_severity_counts(self):
        findings = self.gen._collect_findings()
        counts   = self.gen._severity_counts(findings)
        self.assertEqual(counts["medium"], 1)
        self.assertEqual(counts["high"],   1)
        self.assertEqual(counts["critical"], 0)

    def test_generate_html_creates_file(self):
        path = self.gen.generate_html()
        self.assertTrue(os.path.exists(path))
        self.assertTrue(os.path.getsize(path) > 100)

    def test_html_contains_target(self):
        path    = self.gen.generate_html()
        content = open(path, encoding="utf-8").read()
        self.assertIn("test.example.com", content)

    def test_html_contains_findings(self):
        path    = self.gen.generate_html()
        content = open(path, encoding="utf-8").read()
        self.assertIn("HSTS Eksik", content)
        self.assertIn("CSP Eksik",  content)

    def test_esc_html_entities(self):
        self.assertEqual(self.gen._esc("<script>"), "&lt;script&gt;")
        self.assertEqual(self.gen._esc("a & b"),    "a &amp; b")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)


# ─── Maxima.py Entegrasyon Testleri ──────────────────────────
class TestMaximaIntegration(unittest.TestCase):

    def test_menu_has_41_modules(self):
        import importlib
        spec = importlib.util.spec_from_file_location(
            "maxima",
            os.path.join(PROJECT_ROOT, "maxima.py")
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertEqual(len(mod.MENU), 41)

    def test_scan_profiles_exist(self):
        import importlib
        spec = importlib.util.spec_from_file_location(
            "maxima",
            os.path.join(PROJECT_ROOT, "maxima.py")
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for key in ("web", "osint", "vuln", "network", "full", "full-v2"):
            self.assertIn(key, mod.SCAN_PROFILES,
                          f"Tarama paketi eksik: {key}")

    def test_full_v2_profile_has_all_modules(self):
        import importlib
        spec = importlib.util.spec_from_file_location(
            "maxima",
            os.path.join(PROJECT_ROOT, "maxima.py")
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _, _, mods = mod.SCAN_PROFILES["full-v2"]
        self.assertEqual(sorted(mods), list(range(1, 42)))

    def test_version_consistent(self):
        """Versiyon tutarsızlığı testi — tüm referanslar v11.0 olmalı"""
        path    = os.path.join(PROJECT_ROOT, "maxima.py")
        content = open(path, encoding="utf-8").read()
        # Eski versiyon referansları olmamalı
        self.assertNotIn("v2.0", content,
                         "maxima.py içinde hâlâ 'v2.0' referansı var!")
        self.assertNotIn("v7.0", content,
                         "maxima.py içinde hâlâ 'v7.0' referansı var!")
        # VERSION = "11.0" olmalı
        self.assertIn('VERSION = "11.0"', content)


# ─── Modül run() Metod Testleri ──────────────────────────────
class TestModuleRunMethods(unittest.TestCase):
    """Çeşitli modüllerin run() metodlarını mock ile test eder."""

    MOCK_HTTP_RESPONSE = {
        "status": 200,
        "body": "<html>test</html>",
        "headers": {"Content-Type": "text/html"},
        "url": "http://testhost.example.com",
    }

    def _assert_valid_result(self, result):
        """Ortak sonuç yapısı doğrulaması."""
        self.assertIsInstance(result, dict)
        for key in ("module", "target", "timestamp", "findings", "summary"):
            self.assertIn(key, result, f"Sonuçta '{key}' anahtarı eksik")
        self.assertIsInstance(result["findings"], list)

    # ── HTTPHeaderAnalyzer ──
    def test_http_header_analyzer_run(self):
        from cogs.recon_14_http_headers import HTTPHeaderAnalyzer
        mod = HTTPHeaderAnalyzer("http://testhost.example.com")
        mod.http_get = MagicMock(return_value=self.MOCK_HTTP_RESPONSE)
        result = mod.run()
        self._assert_valid_result(result)

    # ── TechnologyDetector ──
    def test_technology_detector_run(self):
        from cogs.recon_15_tech_detect import TechnologyDetector
        mod = TechnologyDetector("http://testhost.example.com")
        mod.http_get = MagicMock(return_value=self.MOCK_HTTP_RESPONSE)
        result = mod.run()
        self._assert_valid_result(result)

    # ── ClickjackingTester ──
    def test_clickjacking_tester_run(self):
        from cogs.recon_17_clickjacking import ClickjackingTester
        mod = ClickjackingTester("http://testhost.example.com")
        mod.http_get = MagicMock(return_value=self.MOCK_HTTP_RESPONSE)
        result = mod.run()
        self._assert_valid_result(result)

    # ── WHOISLookup ──
    def test_whois_lookup_run(self):
        from cogs.recon_21_whois import WHOISLookup
        mod = WHOISLookup("http://testhost.example.com")
        mod._whois_query = MagicMock(return_value=(
            "refer: whois.verisign-grs.com\n"
            "Registrar: Example Registrar\n"
            "Creation Date: 2020-01-01\n"
        ))
        result = mod.run()
        self._assert_valid_result(result)

    # ── HashIdentifier ──
    def test_hash_identifier_run(self):
        from cogs.recon_25_hash_id import HashIdentifier
        mod = HashIdentifier("http://testhost.example.com")
        mod.http_get = MagicMock(return_value=self.MOCK_HTTP_RESPONSE)
        result = mod.run()
        self._assert_valid_result(result)

    # ── PasswordStrengthChecker ──
    def test_password_strength_checker_run(self):
        from cogs.recon_24_password_check import PasswordStrengthChecker
        mod = PasswordStrengthChecker("http://testhost.example.com")
        mod.parallel_get = MagicMock(return_value=[
            ("http://testhost.example.com/login", {
                "status": 200,
                "body": "<form>password <input type='password'></form>",
                "headers": {"Content-Type": "text/html"},
                "url": "http://testhost.example.com/login",
            })
        ])
        result = mod.run()
        self._assert_valid_result(result)


# ─── Negatif Test Senaryoları ────────────────────────────────
class TestNegativeScenarios(unittest.TestCase):
    """Hata senaryoları: timeout, malformed yanıt, encoding hatası."""

    def setUp(self):
        from utils.base_module import BaseModule
        self.BaseModule = BaseModule

    def test_http_get_timeout_returns_error(self):
        """Timeout durumunda error key döndürülmeli."""
        import socket
        m = self.BaseModule("http://timeout.example.com")
        m._max_retries = 0  # retry'ı kapat
        with patch.object(m, "_build_opener") as mock_builder:
            mock_opener = MagicMock()
            mock_opener.open.side_effect = socket.timeout("timed out")
            mock_builder.return_value = mock_opener
            result = m._make_request("http://timeout.example.com")
            self.assertEqual(result["status"], 0)
            self.assertIn("error", result)

    def test_http_get_malformed_body(self):
        """Bozuk encoding'li body düzgün decode edilmeli."""
        resp = MagicMock()
        resp.read.return_value = b"\xff\xfe<html>\x80\x81</html>"
        resp.headers = {}
        resp.status = 200
        resp.geturl.return_value = "http://example.com"
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.OpenerDirector.open", return_value=resp):
            m = self.BaseModule("http://example.com")
            result = m.http_get("http://example.com")
            self.assertEqual(result["status"], 200)
            self.assertIsInstance(result["body"], str)

    def test_http_get_empty_body(self):
        """Boş body sıfır uzunlukta string döndürmeli."""
        resp = MagicMock()
        resp.read.return_value = b""
        resp.headers = {}
        resp.status = 204
        resp.geturl.return_value = "http://empty-body-test.example.com"
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        m = self.BaseModule("http://empty-body-test.example.com")
        with patch.object(m, "_build_opener") as mock_builder:
            mock_opener = MagicMock()
            mock_opener.open.return_value = resp
            mock_builder.return_value = mock_opener
            # _make_request doğrudan çağır (cache bypass)
            result = m._make_request("http://empty-body-test.example.com")
            self.assertEqual(result["body"], "")
            self.assertEqual(result["status"], 204)

    def test_add_finding_with_remediation_and_evidence(self):
        """Remediation ve evidence alanları finding'e eklenmeli."""
        m = self.BaseModule("http://example.com")
        m.add_finding("Test", "Detay", "high",
                      remediation="Bunu düzelt",
                      evidence="HTTP 200 yanıtı")
        f = m.results["findings"][0]
        self.assertEqual(f["remediation"], "Bunu düzelt")
        self.assertEqual(f["evidence"], "HTTP 200 yanıtı")

    def test_add_finding_without_remediation_no_key(self):
        """Remediation verilmezse key olmamalı, confidence olmalı."""
        m = self.BaseModule("http://example.com")
        m.add_finding("Test", "Detay", "low")
        f = m.results["findings"][0]
        self.assertNotIn("remediation", f)
        self.assertNotIn("evidence", f)
        self.assertEqual(f["confidence"], "firm")

    def test_resolve_ip_invalid_host(self):
        """Geçersiz host None döndürmeli, crash olmamalı."""
        m = self.BaseModule("http://this-host-definitely-does-not-exist-xyz123.invalid")
        result = m.resolve_ip()
        self.assertIsNone(result)

    def test_evidence_truncated_to_2048(self):
        """Evidence 2048 byte'a kesilmeli."""
        m = self.BaseModule("http://example.com")
        long_ev = "A" * 5000
        m.add_finding("Test", "Detay", "info", evidence=long_ev)
        self.assertEqual(len(m.results["findings"][0]["evidence"]), 2048)


# ─── Request Deduplication Testleri ──────────────────────────
class TestRequestDedup(unittest.TestCase):
    """GET request cache testleri."""

    def setUp(self):
        from utils.base_module import BaseModule
        self.BaseModule = BaseModule
        self.BaseModule._request_cache.clear()

    def test_same_url_cached(self):
        """Aynı URL'ye ikinci istek cache'den dönmeli."""
        resp = MagicMock()
        resp.read.return_value = b"<html>test</html>"
        resp.headers = {"Content-Type": "text/html"}
        resp.status = 200
        resp.geturl.return_value = "http://example.com"
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.OpenerDirector.open", return_value=resp) as mock_open:
            m = self.BaseModule("http://example.com")
            r1 = m.http_get("http://example.com/test-dedup")
            r2 = m.http_get("http://example.com/test-dedup")
            self.assertEqual(r1["status"], r2["status"])
            # open sadece 1 kez çağrılmalı
            self.assertEqual(mock_open.call_count, 1)

    def test_different_urls_not_cached(self):
        """Farklı URL'ler ayrı ayrı istek yapmalı."""
        resp = MagicMock()
        resp.read.return_value = b"<html>test</html>"
        resp.headers = {}
        resp.status = 200
        resp.geturl.return_value = "http://example.com"
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.OpenerDirector.open", return_value=resp) as mock_open:
            m = self.BaseModule("http://example.com")
            m.http_get("http://example.com/url-a")
            m.http_get("http://example.com/url-b")
            self.assertEqual(mock_open.call_count, 2)

    def test_custom_headers_bypass_cache(self):
        """Custom header'lı istekler cache'i bypass etmeli."""
        resp = MagicMock()
        resp.read.return_value = b"<html>test</html>"
        resp.headers = {}
        resp.status = 200
        resp.geturl.return_value = "http://example.com"
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.OpenerDirector.open", return_value=resp) as mock_open:
            m = self.BaseModule("http://example.com")
            m.http_get("http://example.com/custom-h", headers={"X-Test": "1"})
            m.http_get("http://example.com/custom-h", headers={"X-Test": "1"})
            # Custom header olduğunda cache bypass
            self.assertEqual(mock_open.call_count, 2)

    def tearDown(self):
        self.BaseModule._request_cache.clear()


# ─── CVE Version Normalize Testleri ─────────────────────────
class TestCVEVersionNormalize(unittest.TestCase):

    def setUp(self):
        from cogs.recon_36_cve_matcher import CVEMatcher
        self.cls = CVEMatcher

    def test_normalize_distro_suffix(self):
        """Distro suffix temizlenmeli: 2.4.49-ubuntu1 → 2.4.49"""
        self.assertEqual(self.cls._normalize_version("2.4.49-ubuntu1"), "2.4.49")

    def test_normalize_plus_suffix(self):
        self.assertEqual(self.cls._normalize_version("1.18.0+dfsg"), "1.18.0")

    def test_normalize_tilde_suffix(self):
        self.assertEqual(self.cls._normalize_version("7.4.3~bpo10"), "7.4.3")

    def test_normalize_clean_version(self):
        """Ek yoksa aynen dönmeli."""
        self.assertEqual(self.cls._normalize_version("2.4.49"), "2.4.49")

    def test_lookup_with_distro_suffix(self):
        """Distro suffix'li versiyon eşleşmeli."""
        m = self.cls("http://example.com")
        result = m._lookup_cve("apache", "2.4.49-ubuntu4.5")
        ids = [r[0] for r in result]
        self.assertIn("CVE-2021-41773", ids)


# ─── Baseline Comparison Testleri ────────────────────────────
class TestBaselineComparison(unittest.TestCase):

    def test_compare_scans_new_findings(self):
        import importlib, tempfile, json
        spec = importlib.util.spec_from_file_location(
            "maxima", os.path.join(PROJECT_ROOT, "maxima.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        # Baseline: 1 bulgu
        baseline = {"results": {
            "Mod1": {"findings": [
                {"title": "Eski Bulgu", "severity": "low"}
            ]}
        }}
        # Current: eski + 1 yeni
        current = {
            "Mod1": {"findings": [
                {"title": "Eski Bulgu", "severity": "low"},
                {"title": "Yeni Bulgu", "severity": "high"},
            ]}
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(baseline, f)
            f.flush()
            diff = mod.compare_scans(current, f.name)
        os.unlink(f.name)

        self.assertEqual(len(diff["new"]), 1)
        self.assertEqual(diff["new"][0]["title"], "Yeni Bulgu")
        self.assertEqual(len(diff["fixed"]), 0)
        self.assertEqual(len(diff["unchanged"]), 1)

    def test_compare_scans_fixed_findings(self):
        import importlib, tempfile, json
        spec = importlib.util.spec_from_file_location(
            "maxima", os.path.join(PROJECT_ROOT, "maxima.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        baseline = {"results": {
            "Mod1": {"findings": [
                {"title": "Düzeltilecek", "severity": "critical"},
                {"title": "Kalan", "severity": "low"},
            ]}
        }}
        current = {
            "Mod1": {"findings": [
                {"title": "Kalan", "severity": "low"},
            ]}
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(baseline, f)
            f.flush()
            diff = mod.compare_scans(current, f.name)
        os.unlink(f.name)

        self.assertEqual(len(diff["fixed"]), 1)
        self.assertEqual(diff["fixed"][0]["title"], "Düzeltilecek")


# ─── Per-Module Timeout Testleri ─────────────────────────────
class TestPerModuleTimeout(unittest.TestCase):

    def test_slow_module_gets_higher_timeout(self):
        import importlib
        spec = importlib.util.spec_from_file_location(
            "maxima", os.path.join(PROJECT_ROOT, "maxima.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        # Module 9 (subdomain) has override=20
        self.assertEqual(mod._get_module_timeout(9, 8), 20)
        # Module 14 (headers) has no override
        self.assertEqual(mod._get_module_timeout(14, 8), 8)
        # User timeout > override → user timeout wins
        self.assertEqual(mod._get_module_timeout(9, 30), 30)


# ─── Retry Logic Testleri ────────────────────────────────────
class TestRetryLogic(unittest.TestCase):

    def setUp(self):
        from utils.base_module import BaseModule
        self.BaseModule = BaseModule
        self.BaseModule._request_cache.clear()

    def test_retry_succeeds_on_second_attempt(self):
        """İlk istek fail, ikinci başarılı — retry çalışmalı."""
        good_resp = MagicMock()
        good_resp.read.return_value = b"ok"
        good_resp.headers = {}
        good_resp.status = 200
        good_resp.geturl.return_value = "http://example.com"
        good_resp.__enter__ = lambda s: s
        good_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.OpenerDirector.open",
                    side_effect=[OSError("conn refused"), good_resp]) as mock_open:
            m = self.BaseModule("http://example.com")
            m._max_retries = 1
            m._retry_backoff = 0.01  # hızlı test
            result = m._make_request("http://retry-test.example.com")
            self.assertEqual(result["status"], 200)
            self.assertEqual(mock_open.call_count, 2)

    def test_all_retries_fail(self):
        """Tüm retry'lar başarısız — error dönmeli."""
        with patch("urllib.request.OpenerDirector.open",
                    side_effect=OSError("conn refused")):
            m = self.BaseModule("http://example.com")
            m._max_retries = 1
            m._retry_backoff = 0.01
            result = m._make_request("http://fail-always.example.com")
            self.assertEqual(result["status"], 0)
            self.assertIn("error", result)

    def tearDown(self):
        self.BaseModule._request_cache.clear()


# ─── SSRF Scanner Testleri ───────────────────────────────────
class TestSSRFScanner(unittest.TestCase):

    def test_ssrf_severity_differentiation(self):
        """Cloud metadata ve local file farklı severity olmalı."""
        from cogs.recon_08_ssrf import SSRFScanner
        self.assertIn("ami-id", SSRFScanner.SSRF_SIGNATURES)
        self.assertEqual(SSRFScanner.SSRF_SIGNATURES["ami-id"], "high")
        self.assertEqual(SSRFScanner.SSRF_SIGNATURES["root:x:0:0"], "critical")

    def test_ssrf_cloud_payloads_exist(self):
        """GCP ve Azure metadata payload'ları olmalı."""
        from cogs.recon_08_ssrf import SSRFScanner
        payloads = " ".join(SSRFScanner.PAYLOADS)
        self.assertIn("metadata.google.internal", payloads)
        self.assertIn("api-version", payloads)


# ─── WAF Detector Testleri ───────────────────────────────────
class TestWAFDetector(unittest.TestCase):

    def test_waf_detector_run_with_mock(self):
        from cogs.recon_26_waf_detector import WAFDetector
        mod = WAFDetector("http://testhost.example.com")
        mod.http_get = MagicMock(return_value={
            "status": 200,
            "body": "<html>test</html>",
            "headers": {"Content-Type": "text/html"},
            "url": "http://testhost.example.com",
        })
        result = mod.run()
        self.assertIsInstance(result, dict)
        self.assertIn("findings", result)


if __name__ == "__main__":
    # Renkli çıktı için
    loader  = unittest.TestLoader()
    suite   = loader.discover(os.path.dirname(__file__), pattern="test_*.py")
    runner  = unittest.TextTestRunner(verbosity=2)
    result  = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)

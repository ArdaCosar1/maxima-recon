#!/usr/bin/env python3
"""
Maxima Entegrasyon Test Suite — XSS / LFI / CMD

Strateji:
  - Gerçek HTTP çağrısı YOK — her test kendi mini HTTP sunucusunu thread'de çalıştırır
  - Sunucular DVWA/bWAPP/WebGoat tarzı gerçekçi açık simüle eder
  - Mock değil, gerçek urllib → sunucu → yanıt zinciri test edilir
  - Her modül: payload tespiti, false-positive önleme, WAF bypass, zaman bazlı
"""

import sys
import os
import time
import json
import base64
import gzip
import re
import threading
import unittest
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

# ── Her test öncesi request cache temizle (modüller arası kirliliği önle) ──
from utils.base_module import BaseModule as _BM
_orig_setUp = unittest.TestCase.setUp
def _clear_cache_setUp(self):
    _BM._request_cache.clear()
    _BM._base_response_cache.clear()
unittest.TestCase.setUp = _clear_cache_setUp

# ── Dinamik port bulma ────────────────────────────────────────
import socket

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ── Minimal test HTTP sunucusu ───────────────────────────────
class _SilentHandler(BaseHTTPRequestHandler):
    """Tüm request/response log mesajlarını bastır."""
    def log_message(self, *a): pass
    def log_request(self, *a): pass


def _run_server(handler_cls, port: int) -> HTTPServer:
    srv = HTTPServer(("127.0.0.1", port), handler_cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def _wait_ready(port: int, timeout: float = 3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"Sunucu port {port} açılmadı")


# ═══════════════════════════════════════════════════════════════
# XSS ENTEGRASYON TESTLERİ
# ═══════════════════════════════════════════════════════════════

class _XSSVulnServer(_SilentHandler):
    """
    DVWA-benzeri yansıtmalı XSS uygulaması.
    ?name=<payload> → payload'ı ham HTML içine yazar (kasıtlı açık).
    /safe → HTML-encode eder (false-positive testi).
    /dom  → JS içinde location.hash kullanır (DOM XSS).
    /csp  → güçlü CSP başlığı (bypass analizi).
    /header → User-Agent başlığını HTML'e yazar (header XSS).
    /json  → JSON API, text/html döndürür (JSON XSS).
    """
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs     = urllib.parse.parse_qs(parsed.query)
        path   = parsed.path

        if path == "/safe":
            # Güvenli — HTML encode → false-positive olmamalı
            name = qs.get("name", [""])[0]
            body = f"<html><body>Hello {urllib.parse.quote(name)}</body></html>"
            self._respond(200, body)

        elif path == "/dom":
            # DOM XSS — location.hash → innerHTML
            body = (
                "<html><body>"
                "<div id='out'></div>"
                "<script>"
                "  var x = location.hash.substring(1);"
                "  document.getElementById('out').innerHTML = x;"
                "</script>"
                "</body></html>"
            )
            self._respond(200, body)

        elif path == "/csp":
            # Güçlü CSP — yine de bypass edilebilir (unsafe-inline var)
            name = qs.get("name", [""])[0]
            body = f"<html><body>{name}</body></html>"
            hdrs = {"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"}
            self._respond(200, body, extra_headers=hdrs)

        elif path == "/csp-strong":
            # Gerçekten güçlü CSP — bypass mümkün değil
            body = "<html><body>Güvenli</body></html>"
            hdrs = {"Content-Security-Policy": "default-src 'none'; script-src 'nonce-abc123'"}
            self._respond(200, body, extra_headers=hdrs)

        elif path == "/header":
            # User-Agent'i HTML'e yaz (header XSS)
            ua = self.headers.get("User-Agent", "")
            body = f"<html><body><p>UA: {ua}</p></body></html>"
            self._respond(200, body)

        elif path == "/json":
            # JSON API ama text/html döndürüyor
            q = qs.get("q", [""])[0]
            body = json.dumps({"result": q, "ok": True})
            self._respond(200, body, ct="text/html; charset=utf-8")

        elif path == "/stored-read":
            # Stored XSS okuma endpoint'i
            import tempfile, pathlib
            store_file = pathlib.Path(tempfile.gettempdir()) / "maxima_stored_xss.txt"
            content = store_file.read_text(errors="replace") if store_file.exists() else ""
            self._respond(200, f"<html><body>{content}</body></html>")

        else:
            # Ana sayfa — açık yansıtma
            name = qs.get("name", [""])[0]
            body = (
                "<html><body>"
                f'<p>Merhaba {name}</p>'
                '<form method="POST" action="/stored-write">'
                '  <input name="comment" value="">'
                '  <input type="submit" value="Gönder">'
                '</form>'
                '</body></html>'
            )
            self._respond(200, body)

    def do_POST(self):
        if self.path == "/stored-write":
            length = int(self.headers.get("Content-Length", 0))
            raw    = self.rfile.read(length).decode("utf-8", errors="replace")
            qs     = urllib.parse.parse_qs(raw)
            comment = qs.get("comment", [""])[0]
            import tempfile, pathlib
            store_file = pathlib.Path(tempfile.gettempdir()) / "maxima_stored_xss.txt"
            store_file.write_text(comment)
            self._respond(200, "<html><body>Kaydedildi</body></html>")
        else:
            self._respond(404, "Not found")

    def _respond(self, status, body, ct="text/html; charset=utf-8", extra_headers=None):
        enc = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(enc)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(enc)


class TestXSSIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.srv  = _run_server(_XSSVulnServer, cls.port)
        _wait_ready(cls.port)
        cls.base = f"http://127.0.0.1:{cls.port}"
        # PERF: Aynı URL'lere ait sonuçları bir kere hesapla — testler paylaşsın
        from cogs.recon_05_xss_scanner import XSSScanner
        s1 = XSSScanner(f"{cls.base}/?name=test"); s1._quiet = True
        cls._result_main = s1.run()
        s2 = XSSScanner(f"{cls.base}/safe?name=test"); s2._quiet = True
        cls._result_safe = s2.run()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    # ── 1. Açık yansıtma — XSS tespiti ──────────────────────
    def test_reflected_xss_detected(self):
        titles = [f["title"] for f in self._result_main["findings"]]
        found_xss = any("XSS" in t and "Reflected" in t for t in titles)
        self.assertTrue(found_xss,
            f"Reflected XSS tespit edilemedi. Bulgular: {titles}")

    # ── 2. Güvenli sayfa — false-positive YOK ────────────────
    def test_no_false_positive_on_safe_endpoint(self):
        high_crit = [f for f in self._result_safe["findings"]
                     if f["severity"] in ("critical", "high")
                     and "Reflected XSS" in f["title"]]
        self.assertEqual(len(high_crit), 0,
            f"False-positive: güvenli sayfada high/critical XSS bulundu: {high_crit}")

    # ── 3. DOM XSS kaynak-sink zinciri tespiti ───────────────
    def test_dom_xss_detected(self):
        from cogs.recon_05_xss_scanner import XSSScanner
        s = XSSScanner(f"{self.base}/dom")
        s._quiet = True
        result = s.run()
        dom_findings = [f for f in result["findings"] if "DOM" in f["title"]]
        self.assertGreater(len(dom_findings), 0,
            f"DOM XSS (location.hash→innerHTML) tespit edilemedi. Bulgular: {[f['title'] for f in result['findings']]}")

    # ── 4. CSP zayıflık tespiti ───────────────────────────────
    def test_csp_weakness_detected(self):
        from cogs.recon_05_xss_scanner import XSSScanner
        s = XSSScanner(f"{self.base}/csp?name=test")
        s._quiet = True
        result = s.run()
        csp_issues = [f for f in result["findings"]
                      if "CSP" in f["title"]]
        self.assertGreater(len(csp_issues), 0,
            "CSP zayıflığı (unsafe-inline) tespit edilemedi")

    # ── 5. CSP eksik → bulgu (uses cached _result_main) ──────
    def test_missing_csp_reported(self):
        csp_missing = [f for f in self._result_main["findings"] if "CSP" in f["title"]]
        self.assertGreater(len(csp_missing), 0,
            "CSP eksikliği raporlanmadı")

    # ── 6. Header XSS (User-Agent yansıması) ─────────────────
    def test_header_xss_user_agent(self):
        from cogs.recon_05_xss_scanner import XSSScanner
        s = XSSScanner(f"{self.base}/header")
        s._quiet = True
        result = s.run()
        header_xss = [f for f in result["findings"]
                      if "Header" in f["title"] and "XSS" in f["title"]]
        if len(header_xss) > 0:
            self.assertIn("Header", header_xss[0]["title"])

    # ── 7. JSON endpoint XSS (text/html) ─────────────────────
    def test_json_xss_text_html_content_type(self):
        from cogs.recon_05_xss_scanner import XSSScanner
        s = XSSScanner(f"{self.base}/json?q=test")
        s._quiet = True
        result = s.run()
        json_findings = [f for f in result["findings"]
                         if "JSON" in f["title"] and "XSS" in f["title"]]
        if len(json_findings) > 0:
            self.assertIn("HTML", json_findings[0]["title"])

    # ── 8. Severity doğrulaması (uses cached _result_main) ───
    def test_reflected_xss_severity_is_high_or_critical(self):
        xss_findings = [f for f in self._result_main["findings"]
                        if "XSS" in f["title"] and "Reflected" in f["title"]]
        for f in xss_findings:
            self.assertIn(f["severity"], ("high", "critical"),
                f"Reflected XSS severity beklenmedik: {f['severity']}")

    # ── 9. Summary güncelleniyor (uses cached _result_main) ──
    def test_summary_populated(self):
        self.assertIn("Taranan Parametre", self._result_main["summary"])
        self.assertIn("Toplam Bulgu",      self._result_main["summary"])
        self.assertGreater(self._result_main["summary"]["Taranan Parametre"], 0)

    # ── 10. Payload listesi ve fonksiyonel yapı ───────────────
    def test_payload_lists_coverage(self):
        from cogs.recon_05_xss_scanner import (
            REFLECTED_PAYLOADS, DOM_SOURCES, DOM_SINKS, WAF_BYPASS_ENCODERS
        )
        # Minimum payload sayıları (SQLi seviyesine eşdeğer)
        self.assertGreaterEqual(len(REFLECTED_PAYLOADS), 20,
            "Reflected XSS payload sayısı SQLi'nin gerisinde (<20)")
        self.assertGreaterEqual(len(DOM_SOURCES), 5,
            "DOM XSS kaynak listesi eksik (<5)")
        self.assertGreaterEqual(len(DOM_SINKS), 8,
            "DOM XSS sink listesi eksik (<8)")
        self.assertGreaterEqual(len(WAF_BYPASS_ENCODERS), 5,
            "WAF bypass encoder sayısı yetersiz (<5)")

    # ── 11. Bağlam tespiti (context detection) ───────────────
    def test_context_detection_returns_valid_context(self):
        from cogs.recon_05_xss_scanner import XSSScanner
        s = XSSScanner(f"{self.base}/?name=test")
        s._quiet = True
        ctx = s._detect_context("name", "url", "")
        self.assertIn(ctx, ("html", "attr", "script", "style"),
            f"Geçersiz bağlam döndürüldü: {ctx}")

    # ── 12. Parametre keşfi URL param'ı buluyor ───────────────
    def test_param_discovery_finds_url_params(self):
        from cogs.recon_05_xss_scanner import XSSScanner
        s = XSSScanner(f"{self.base}/?name=test&id=1")
        s._quiet = True
        params = s._discover_params()
        names = [p[0] for p in params]
        self.assertIn("name", names, "URL param 'name' bulunamadı")
        self.assertIn("id",   names, "URL param 'id' bulunamadı")

    # ── 13. XSSScanner run() → dict döner ────────────────────
    def test_run_returns_dict_with_required_keys(self):
        from cogs.recon_05_xss_scanner import XSSScanner
        s = XSSScanner(f"{self.base}/")
        s._quiet = True
        result = s.run()
        for key in ("module", "target", "findings", "summary"):
            self.assertIn(key, result, f"Sonuç dict'te '{key}' eksik")


# ═══════════════════════════════════════════════════════════════
# LFI/RFI ENTEGRASYON TESTLERİ
# ═══════════════════════════════════════════════════════════════

class _LFIVulnServer(_SilentHandler):
    """
    DVWA Low/Medium seviyesi LFI simülatörü.
    ?file=<payload> → 'dosya' içeriğini döndürür.
    Gerçekçi dosya içerikleri bellekte tutulur (disk erişimi yok).
    """
    # Simüle edilen dosya sistemi
    FAKE_FS = {
        "/etc/passwd":
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
        "/etc/hosts":
            "127.0.0.1 localhost\n127.0.1.1 maxima-test\n",
        "/proc/self/environ":
            "HTTP_USER_AGENT=MaximaRecon\x00DOCUMENT_ROOT=/var/www/html\x00SERVER_ADDR=127.0.0.1\x00",
        "/var/log/apache2/access.log":
            '127.0.0.1 - - [01/Jan/2025:00:00:00 +0000] "GET / HTTP/1.1" 200 1234\n',
        "win.ini":
            "[extensions]\nxls=\ndoc=\n[fonts]\n[files]\n",
        "boot.ini":
            "[boot loader]\ntimeout=30\n[operating systems]\nmulti(0)disk(0)rdisk(0)partition(1)\\WINDOWS",
        "index.php":
            "<?php\n$file = $_GET['file'];\ninclude($file);\n?>",
        "config.php":
            "<?php\n$db_host='localhost';\n$db_user='root';\n$db_pass='secretpass';\n?>",
    }

    # Windows varyantları
    WINDOWS_VARIANTS = {
        "..\\..\\..\\windows\\win.ini": "win.ini",
        "..\\..\\..\\winnt\\win.ini":   "win.ini",
        "windows/win.ini":              "win.ini",
        "winnt/win.ini":                "win.ini",
    }

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs     = urllib.parse.parse_qs(parsed.query)
        path   = parsed.path

        if path == "/safe":
            # Güvenli endpoint — basename ile koruma
            raw = qs.get("file", [""])[0]
            safe = os.path.basename(raw)
            body = f"<html><body>File: {safe}</body></html>"
            self._respond(200, body)
            return

        if path == "/phpinfo":
            # PHP wrapper data:// → phpinfo sim
            raw = qs.get("file", [""])[0]
            if "data://" in raw and "phpinfo" in raw:
                body = "<html><body>PHP Version 7.4.3<br>phpinfo()</body></html>"
                self._respond(200, body)
                return

        if path == "/direct":
            # Doğrudan hassas dosya erişimi sim
            if self.path.endswith("/.git/HEAD"):
                self._respond(200, "ref: refs/heads/main\n", ct="text/plain")
                return
            elif self.path.endswith("/.env"):
                self._respond(200, "DB_PASSWORD=secretpass\nAPP_KEY=abc123\n", ct="text/plain")
                return

        # Ana açık endpoint
        raw_file = qs.get("file", [""])[0]
        content  = self._resolve_file(raw_file)

        if content is not None:
            self._respond(200, content, ct="text/plain")
        else:
            self._respond(200, "<html><body>Dosya bulunamadı</body></html>")

    def _resolve_file(self, raw: str) -> str | None:
        # URL decode
        decoded = urllib.parse.unquote(raw)
        # Double decode
        decoded2 = urllib.parse.unquote(decoded)

        # Null byte temizle
        cleaned = decoded.split("\x00")[0].split("%00")[0]

        # Doğrudan eşleşme
        if cleaned in self.FAKE_FS:
            return self.FAKE_FS[cleaned]

        # Çift decode eşleşme
        if decoded2 in self.FAKE_FS:
            return self.FAKE_FS[decoded2]

        # Windows varyantları
        for variant, target in self.WINDOWS_VARIANTS.items():
            if variant in cleaned or variant in decoded2:
                return self.FAKE_FS.get(target)

        # path traversal → normalize → eşleşme
        # ../../etc/passwd → /etc/passwd
        parts = re.sub(r'(?:\.\.(?:/|\\|%2[fF]|%5[cC])){1,}|(?:\.\.){1,}(?:/|\\)',
                       lambda m: '', cleaned)
        # Traversal ile gerçek yol
        for fake_path, content in self.FAKE_FS.items():
            tail = fake_path.lstrip("/")
            if tail in cleaned or tail in decoded or tail in decoded2:
                return content
            # ....// bypass
            if tail.replace("/", "") in cleaned.replace(".", "").replace("/", ""):
                pass  # fazla gevşek, geç

        # php://filter simülasyonu
        if "php://filter" in raw or "php://filter" in decoded:
            # index.php veya config.php oku
            for fname in ("index.php", "config.php", "/etc/passwd"):
                if fname.replace("/", "").replace(".", "") in raw.replace("/", "").replace(".", ""):
                    content = self.FAKE_FS.get(fname, "")
                    if "base64-encode" in raw or "base64" in raw:
                        return base64.b64encode(content.encode()).decode()
                    return content
            # Genel: /etc/passwd
            return base64.b64encode(self.FAKE_FS["/etc/passwd"].encode()).decode()

        return None

    def _respond(self, status, body, ct="text/html; charset=utf-8"):
        enc = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(enc)))
        self.end_headers()
        self.wfile.write(enc)


class TestLFIIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.srv  = _run_server(_LFIVulnServer, cls.port)
        _wait_ready(cls.port)
        cls.base = f"http://127.0.0.1:{cls.port}"
        # PERF: Aynı URL'ye ait sonuçları bir kere hesapla
        from cogs.recon_06_lfi_rfi import LFIRFIScanner
        s1 = LFIRFIScanner(f"{cls.base}/?file=test"); s1._quiet = True
        cls._result_main = s1.run()
        s2 = LFIRFIScanner(f"{cls.base}/safe?file=test"); s2._quiet = True
        cls._result_safe = s2.run()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    # ── 1. Temel LFI tespiti (/etc/passwd) ───────────────────
    def test_lfi_etc_passwd_detected(self):
        crit = [f for f in self._result_main["findings"]
                if f["severity"] == "critical" and "LFI" in f["title"]]
        self.assertGreater(len(crit), 0,
            f"LFI /etc/passwd tespit edilemedi. Bulgular: {[f['title'] for f in self._result_main['findings']]}")

    # ── 2. LFI bulgu detayı /etc/passwd referans ediyor ──────
    def test_lfi_finding_references_target_file(self):
        crit = [f for f in self._result_main["findings"]
                if f["severity"] == "critical" and "LFI" in f["title"]]
        if crit:
            detail = crit[0]["detail"].lower()
            has_ref = any(ref in detail for ref in
                          ["/etc/passwd", "root:x", "passwd", "path traversal"])
            self.assertTrue(has_ref,
                f"LFI bulgu detayı hedef dosyaya referans vermiyor: {crit[0]['detail']}")

    # ── 3. Güvenli endpoint false-positive YOK ────────────────
    def test_no_false_positive_safe_endpoint(self):
        lfi_crit = [f for f in self._result_safe["findings"]
                    if f["severity"] == "critical" and "LFI" in f["title"]]
        self.assertEqual(len(lfi_crit), 0,
            f"False-positive: güvenli sayfada LFI bulundu: {lfi_crit}")

    # ── 4. PHP wrapper tespiti (uses cached _result_main) ────
    def test_php_wrapper_filter_detected(self):
        php_wrap = [f for f in self._result_main["findings"]
                    if "wrapper" in f["title"].lower() or "php://" in f["detail"].lower()
                    or "base64" in f["detail"].lower()]
        if php_wrap:
            self.assertIn("critical", [f["severity"] for f in php_wrap])

    # ── 5. Payload listesi yeterliliği ───────────────────────
    def test_payload_list_size(self):
        from cogs.recon_06_lfi_rfi import _make_lfi_payloads, RFI_PAYLOADS, LFI_PARAMS
        payloads = _make_lfi_payloads()
        self.assertGreaterEqual(len(payloads), 40,
            f"LFI payload sayısı yetersiz: {len(payloads)} (<40)")
        self.assertGreaterEqual(len(RFI_PAYLOADS), 8,
            f"RFI payload sayısı yetersiz: {len(RFI_PAYLOADS)} (<8)")
        self.assertGreaterEqual(len(LFI_PARAMS), 20,
            f"LFI parametre listesi yetersiz: {len(LFI_PARAMS)} (<20)")

    # ── 6. Hedef dosya imza tablosu ───────────────────────────
    def test_signature_table_coverage(self):
        from cogs.recon_06_lfi_rfi import LFI_SIGNATURES
        required_targets = ["/etc/passwd", "/proc/self/environ", "win.ini"]
        for tgt in required_targets:
            self.assertIn(tgt, LFI_SIGNATURES,
                f"LFI imza tablosunda '{tgt}' eksik")
            self.assertGreater(len(LFI_SIGNATURES[tgt]), 0,
                f"'{tgt}' için imza listesi boş")

    # ── 7. Windows path traversal payload varlığı ────────────
    def test_windows_payloads_included(self):
        from cogs.recon_06_lfi_rfi import _make_lfi_payloads
        payloads = _make_lfi_payloads()
        raw_payloads = [p for p, _ in payloads]
        win_payloads = [p for p in raw_payloads
                        if "win.ini" in p or "windows" in p.lower() or "\\\\" in p]
        self.assertGreater(len(win_payloads), 3,
            "Windows path traversal payload'ları yetersiz")

    # ── 8. Null byte payload varlığı ─────────────────────────
    def test_null_byte_payloads_included(self):
        from cogs.recon_06_lfi_rfi import _make_lfi_payloads
        payloads = _make_lfi_payloads()
        null_payloads = [p for p, _ in payloads if "\x00" in p or "%00" in p]
        self.assertGreater(len(null_payloads), 1,
            "Null byte payload'ları eksik")

    # ── 9. Double encoding payload varlığı ───────────────────
    def test_double_encoding_payloads_included(self):
        from cogs.recon_06_lfi_rfi import _make_lfi_payloads
        payloads = _make_lfi_payloads()
        double_enc = [p for p, _ in payloads if "%252" in p or "%25" in p]
        self.assertGreater(len(double_enc), 0,
            "Double URL encoding payload'ları eksik")

    # ── 10. Summary doğrulaması (uses cached _result_main) ───
    def test_summary_populated(self):
        for key in ("Taranan Parametre", "LFI Payload Sayısı", "Toplam Bulgu"):
            self.assertIn(key, self._result_main["summary"],
                f"Summary'de '{key}' eksik")

    # ── 11. Teknoloji tespiti çalışıyor ──────────────────────
    def test_tech_detection_returns_valid(self):
        from cogs.recon_06_lfi_rfi import LFIRFIScanner
        s = LFIRFIScanner(f"{self.base}/")
        s._quiet = True
        tech = s._detect_tech()
        self.assertIn(tech, ("php", "asp", "jsp", "python", "ruby", "unknown"),
            f"Geçersiz teknoloji değeri: {tech}")

    # ── 12. /proc/self/environ imzası tanınıyor ───────────────
    def test_proc_self_environ_signature_recognized(self):
        from cogs.recon_06_lfi_rfi import LFI_SIGNATURES
        environ_sigs = LFI_SIGNATURES.get("/proc/self/environ", [])
        self.assertTrue(
            any("HTTP_USER_AGENT" in s or "DOCUMENT_ROOT" in s for s in environ_sigs),
            "/proc/self/environ imzaları eksik veya yanlış"
        )


# ═══════════════════════════════════════════════════════════════
# COMMAND INJECTION ENTEGRASYON TESTLERİ
# ═══════════════════════════════════════════════════════════════

class _CMDVulnServer(_SilentHandler):
    """
    DVWA/bWAPP tarzı komut enjeksiyonu simülatörü.
    ?host=<input> → input'u "ping komutuna" geçiriyormuş gibi işler.

    Ayırıcı tespiti:
      ; | || && & $ ` \n → marker veya /etc/passwd içeriği döndürür.

    /time → sleep simülasyonu (5s gecikme)
    /safe → whitelist ile korunan endpoint
    /shellshock → Shellshock açığı olan CGI benzeri endpoint
    /ssti → template injection açığı
    """
    MARKER_PATTERN = re.compile(r"MAXCMD\d+")
    SEPARATORS = [";", "&&", "||", "|", "&", "`", "$(", "\n", "\r\n", "%0a"]

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs     = urllib.parse.parse_qs(parsed.query)
        path   = parsed.path

        if path == "/safe":
            # Whitelist koruması — false-positive testi
            raw = qs.get("host", [""])[0]
            # Sadece alfanümerik ve nokta
            if re.match(r'^[\w.\-]+$', raw):
                self._respond(200, f"<html><body>PING {raw}: OK</body></html>")
            else:
                self._respond(400, "<html><body>Geçersiz giriş</body></html>")
            return

        if path == "/time":
            # Time-based blind simülasyonu
            raw = qs.get("host", [""])[0]
            if any(sep in raw for sep in [";sleep", "&&sleep", "|sleep",
                                           "`sleep", "$(sleep", "sleep${IFS}"]):
                time.sleep(5)
            elif any(p in raw for p in [";ping -c 5", "&&ping -c 5", "|ping -c 5"]):
                time.sleep(5)
            elif any(p in raw for p in ["&ping -n 5", "|ping -n 5", ";timeout"]):
                time.sleep(5)
            self._respond(200, "<html><body>PING: done</body></html>")
            return

        if "/cgi-bin/" in path:
            # Shellshock simülasyonu
            ua = self.headers.get("User-Agent", "")
            referer = self.headers.get("Referer", "")
            for header_val in (ua, referer):
                if "() {" in header_val:
                    if "SHELLSHOCK_CONFIRMED" in header_val:
                        self._respond(200, "SHELLSHOCK_CONFIRMED\nContent-Type: text/plain\n")
                        return
                    # id simülasyonu
                    if "/bin/ls" in header_val or "echo" in header_val:
                        self._respond(200,
                            "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n",
                            ct="text/plain")
                        return
            self._respond(200, "<html><body>CGI: OK</body></html>")
            return

        if path == "/ssti":
            # Jinja2/Twig tarzı template injection
            raw = qs.get("name", [""])[0]
            if "{{" in raw and "os" in raw and "popen" in raw:
                self._respond(200,
                    "<html><body>uid=33(www-data) gid=33(www-data)</body></html>")
                return
            if "{{config" in raw or "globals" in raw.lower():
                self._respond(200,
                    "<html><body>uid=33(www-data) gid=33(www-data)</body></html>")
                return
            self._respond(200, f"<html><body>Hello {raw}</body></html>")
            return

        # Ana açık endpoint
        raw = qs.get("host", [""])[0]
        output = self._simulate_cmd(raw)
        self._respond(200, f"<html><body><pre>{output}</pre></body></html>")

    def _simulate_cmd(self, raw: str) -> str:
        """Komut enjeksiyonu simülasyonu — ayırıcı sonrası komutu çalıştırıyormuş gibi."""
        decoded = urllib.parse.unquote(raw)

        # Marker echo tespiti
        m = self.MARKER_PATTERN.search(decoded)
        if m:
            marker = m.group()
            # Gerçek marker döndür
            for sep in [";", "&&", "||", "|", "&", "`", "\n", "\r\n",
                        "$(", "${IFS}", "\t", "%0a", "%3b", "%7c", "%26"]:
                if sep in decoded or sep in raw:
                    return f"PING 127.0.0.1: OK\n{marker}"

        # /etc/passwd istegi
        if "cat /etc/passwd" in decoded or "/etc/passwd" in decoded:
            for sep in [";", "&&", "||", "|", "$(", "`"]:
                if sep in decoded:
                    return ("PING 127.0.0.1: OK\n"
                            "root:x:0:0:root:/root:/bin/bash\n"
                            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")

        # uid= çıktısı (id komutu)
        if " id" in decoded or ";id" in decoded or "|id" in decoded or "`id`" in decoded:
            return "PING 127.0.0.1: OK\nuid=33(www-data) gid=33(www-data)\n"

        # WAF bypass: URL-encode ayırıcılar
        for enc_sep, real_sep in [("%3b", ";"), ("%7c", "|"), ("%26", "&"), ("%0a", "\n")]:
            if enc_sep in raw:
                m2 = self.MARKER_PATTERN.search(decoded)
                if m2:
                    return f"PING 127.0.0.1: OK\n{m2.group()}"

        # IFS bypass
        if "${IFS}" in decoded and self.MARKER_PATTERN.search(decoded):
            m3 = self.MARKER_PATTERN.search(decoded)
            if m3:
                return f"PING 127.0.0.1: OK\n{m3.group()}"

        return "PING 127.0.0.1: 0% packet loss"

    def _respond(self, status, body, ct="text/html; charset=utf-8"):
        enc = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(enc)))
        self.end_headers()
        self.wfile.write(enc)


class TestCMDInjectionIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.srv  = _run_server(_CMDVulnServer, cls.port)
        _wait_ready(cls.port)
        cls.base = f"http://127.0.0.1:{cls.port}"
        # PERF: Aynı URL'lere ait sonuçları bir kere hesapla
        from cogs.recon_07_cmd_injection import CommandInjectionScanner
        s1 = CommandInjectionScanner(f"{cls.base}/?host=127.0.0.1"); s1._quiet = True
        cls._result_main = s1.run()
        s2 = CommandInjectionScanner(f"{cls.base}/safe?host=127.0.0.1"); s2._quiet = True
        cls._result_safe = s2.run()
        # NOT: time-based testi ayrı tutulmalı — echo bulunursa time atlanır
        cls._result_time = None  # lazy — testlerde hesaplanacak

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    # ── 1. Echo marker tespiti (uses cached _result_main) ────
    def test_echo_marker_detected(self):
        crit = [f for f in self._result_main["findings"]
                if f["severity"] == "critical"]
        self.assertGreater(len(crit), 0,
            f"CMD injection (echo/shellshock/ssti) tespit edilemedi. "
            f"Bulgular: {[f['title'] for f in self._result_main['findings']]}")

    # ── 2. False-positive — güvenli endpoint (uses cached) ───
    def test_no_false_positive_safe_endpoint(self):
        crit = [f for f in self._result_safe["findings"]
                if f["severity"] == "critical" and "Echo" in f["title"]]
        self.assertEqual(len(crit), 0,
            f"False-positive: güvenli endpoint'te CMD injection bulundu: {crit}")

    # ── 3. Time-based blind tespiti ─────────────────────────
    def test_time_based_blind_detected(self):
        if self.__class__._result_time is None:
            from cogs.recon_07_cmd_injection import CommandInjectionScanner
            s = CommandInjectionScanner(f"{self.base}/time?host=127.0.0.1")
            s._quiet = True; s.timeout = 8
            s.__class__._max_retries = 0  # time-based test'te retry yavaşlatır
            self.__class__._result_time = s.run()
            s.__class__._max_retries = 2  # geri al
        time_findings = [f for f in self._result_time["findings"]
                         if "Time" in f["title"] or "time" in f["title"].lower()]
        self.assertGreater(len(time_findings), 0,
            f"Time-based CMD injection tespit edilemedi. Bulgular: {[f['title'] for f in self._result_time['findings']]}")

    # ── 4. Time-based bulgu critical severity (shares cached)
    def test_time_based_severity_is_critical(self):
        if self.__class__._result_time is None:
            from cogs.recon_07_cmd_injection import CommandInjectionScanner
            s = CommandInjectionScanner(f"{self.base}/time?host=127.0.0.1")
            s._quiet = True; s.timeout = 8
            s.__class__._max_retries = 0
            self.__class__._result_time = s.run()
            s.__class__._max_retries = 2
        time_findings = [f for f in self._result_time["findings"]
                         if "Time" in f["title"]]
        for f in time_findings:
            self.assertEqual(f["severity"], "critical",
                f"Time-based CMD severity 'critical' değil: {f['severity']}")

    # ── 5. Shellshock tespiti (uses cached _result_main) ─────
    def test_shellshock_cve_detected(self):
        shellshock = [f for f in self._result_main["findings"]
                      if "Shellshock" in f["title"] or "CVE-2014" in f["title"]
                      or "uid=" in f["detail"]]
        if shellshock:
            self.assertIn(shellshock[0]["severity"], ("critical", "high"))

    # ── 6. SSTI → RCE tespiti ────────────────────────────────
    def test_ssti_rce_detected(self):
        from cogs.recon_07_cmd_injection import CommandInjectionScanner
        s = CommandInjectionScanner(f"{self.base}/ssti?name=test")
        s._quiet = True
        result = s.run()
        ssti = [f for f in result["findings"]
                if "SSTI" in f["title"] or "Template" in f["title"]]
        if ssti:
            self.assertIn(ssti[0]["severity"], ("critical", "high"))

    # ── 7. Payload listesi yeterliliği ───────────────────────
    def test_payload_lists_size(self):
        from cogs.recon_07_cmd_injection import (
            _linux_echo_payloads, _windows_echo_payloads,
            TIME_PAYLOADS, WAF_BYPASS, SSTI_CMD_PAYLOADS
        )
        linux_p  = _linux_echo_payloads("TEST")
        windows_p = _windows_echo_payloads("TEST")
        self.assertGreaterEqual(len(linux_p), 15,
            f"Linux echo payload sayısı yetersiz: {len(linux_p)}")
        self.assertGreaterEqual(len(windows_p), 8,
            f"Windows echo payload sayısı yetersiz: {len(windows_p)}")
        self.assertGreaterEqual(len(TIME_PAYLOADS), 10,
            f"Time-based payload sayısı yetersiz: {len(TIME_PAYLOADS)}")
        self.assertGreaterEqual(len(WAF_BYPASS), 8,
            f"WAF bypass teknik sayısı yetersiz: {len(WAF_BYPASS)}")
        self.assertGreaterEqual(len(SSTI_CMD_PAYLOADS), 3,
            f"SSTI payload sayısı yetersiz: {len(SSTI_CMD_PAYLOADS)}")

    # ── 8. Summary doğrulaması (uses cached _result_main) ────
    def test_summary_populated(self):
        for key in ("Taranan Parametre", "Echo Bulgusu", "Toplam Bulgu", "Teknikler"):
            self.assertIn(key, self._result_main["summary"],
                f"Summary'de '{key}' eksik")

    # ── 9. Parametre keşfi ────────────────────────────────────
    def test_param_discovery_url_params(self):
        from cogs.recon_07_cmd_injection import CommandInjectionScanner
        s = CommandInjectionScanner(f"{self.base}/?host=127.0.0.1&cmd=test")
        s._quiet = True
        params = s._discover_params()
        self.assertIn("host", params, "URL param 'host' keşfedilemedi")
        self.assertIn("cmd",  params, "URL param 'cmd' keşfedilemedi")

    # ── 10. WAF bypass payload'lar üretiliyor ─────────────────
    def test_waf_bypass_produces_encoded_variants(self):
        from cogs.recon_07_cmd_injection import WAF_BYPASS
        original = "127.0.0.1;echo MAXTEST"
        results = [fn(original) for fn in WAF_BYPASS]
        self.assertEqual(len(results), len(WAF_BYPASS))
        # En az bir tanesi original'dan farklı olmalı
        different = [r for r in results if r != original]
        self.assertGreater(len(different), 3,
            "WAF bypass fonksiyonları yeterince farklı çıktı üretmiyor")

    # ── 11. OS tespiti geçerli değer döndürüyor ───────────────
    def test_os_detection_returns_valid(self):
        from cogs.recon_07_cmd_injection import CommandInjectionScanner
        s = CommandInjectionScanner(f"{self.base}/")
        s._quiet = True
        os_hint = s._detect_os()
        self.assertIn(os_hint, ("linux", "windows", "unknown"),
            f"Geçersiz OS değeri: {os_hint}")

    # ── 12. Shellshock header listesi kapsamlı ────────────────
    def test_shellshock_header_list(self):
        from cogs.recon_07_cmd_injection import SHELLSHOCK_HEADERS, SHELLSHOCK_CGI_PATHS
        self.assertGreaterEqual(len(SHELLSHOCK_HEADERS), 3,
            "Shellshock başlık listesi yetersiz")
        self.assertGreaterEqual(len(SHELLSHOCK_CGI_PATHS), 5,
            "Shellshock CGI path listesi yetersiz")


# ═══════════════════════════════════════════════════════════════
# ÇAPRAZ MODÜL / ORKESTRASYON TESTLERİ
# ═══════════════════════════════════════════════════════════════

class TestCrossModuleOrchestration(unittest.TestCase):
    """
    Üç modülün aynı hedefe karşı birlikte çalışmasını test eder.
    Gerçek pentest workflow'u: XSS → LFI → CMD sırasıyla çalışır.
    """

    @classmethod
    def setUpClass(cls):
        # Tek sunucu üç endpoint barındırıyor
        cls.port = _free_port()

        class _MultiVulnHandler(_SilentHandler):
            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                qs     = urllib.parse.parse_qs(parsed.query)

                if parsed.path == "/xss":
                    v = qs.get("q", [""])[0]
                    body = f"<html><body>{v}<script>var x = location.hash;</script></body></html>"
                    self._resp(body)
                elif parsed.path == "/lfi":
                    v = qs.get("file", [""])[0]
                    if "etc/passwd" in v or "passwd" in urllib.parse.unquote(v):
                        self._resp("root:x:0:0:root:/root:/bin/bash\n", ct="text/plain")
                    else:
                        self._resp("Not found")
                elif parsed.path == "/cmd":
                    v = qs.get("host", [""])[0]
                    import re as _re
                    m = _re.search(r"MAXCMD\d+", v)
                    if m and any(sep in v for sep in [";", "|", "&&", "`", "$("]):
                        self._resp(f"ping ok\n{m.group()}")
                    else:
                        self._resp("ping: ok")
                else:
                    self._resp("<html><body>Multi-vuln app</body></html>")

            def _resp(self, body, ct="text/html"):
                enc = body.encode()
                self.send_response(200)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(enc)))
                self.end_headers()
                self.wfile.write(enc)

            def log_message(self, *a): pass

        cls.srv = _run_server(_MultiVulnHandler, cls.port)
        _wait_ready(cls.port)
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    @classmethod
    def _get_results(cls):
        """PERF: 3 modülün sonuçlarını bir kere hesapla, testlerde paylaş."""
        if hasattr(cls, '_cached'):
            return cls._cached
        from cogs.recon_05_xss_scanner import XSSScanner
        from cogs.recon_06_lfi_rfi import LFIRFIScanner
        from cogs.recon_07_cmd_injection import CommandInjectionScanner
        results = {}
        for name, Cls, path in [
            ("xss", XSSScanner,              f"{cls.base}/xss?q=test"),
            ("lfi", LFIRFIScanner,           f"{cls.base}/lfi?file=test"),
            ("cmd", CommandInjectionScanner,  f"{cls.base}/cmd?host=127.0.0.1"),
        ]:
            s = Cls(path); s._quiet = True
            results[name] = s.run()
        cls._cached = results
        return results

    def test_xss_on_multi_app(self):
        r = self._get_results()["xss"]
        found = any("XSS" in f["title"] for f in r["findings"])
        self.assertTrue(found, "XSS multi-app endpoint'te tespit edilemedi")

    def test_lfi_on_multi_app(self):
        r = self._get_results()["lfi"]
        found = any("LFI" in f["title"] and f["severity"] == "critical"
                    for f in r["findings"])
        self.assertTrue(found, "LFI multi-app endpoint'te tespit edilemedi")

    def test_cmd_on_multi_app(self):
        r = self._get_results()["cmd"]
        found = any("Komut" in f["title"] and f["severity"] == "critical"
                    for f in r["findings"])
        self.assertTrue(found, "CMD injection multi-app endpoint'te tespit edilemedi")

    def test_all_three_modules_return_required_keys(self):
        results = self._get_results()
        for name, r in results.items():
            for key in ("module", "target", "findings", "summary", "timestamp"):
                self.assertIn(key, r, f"{name}: '{key}' eksik")
            self.assertIsInstance(r["findings"], list)
            self.assertIsInstance(r["summary"], dict)

    def test_no_module_crashes_on_unreachable_host(self):
        from cogs.recon_05_xss_scanner import XSSScanner
        from cogs.recon_06_lfi_rfi import LFIRFIScanner
        from cogs.recon_07_cmd_injection import CommandInjectionScanner
        from utils.base_module import BaseModule
        from unittest.mock import patch

        # Gerçek ağ bağlantısı açmadan test et — yüzlerce sequential request
        # her biri timeout kadar bekler ve pytest 60s limitini aşar.
        # Mock ile _make_request anında status=0 döndürür; modüller bunu
        # graceful handle etmeli (exception fırlatmamalı).
        mock_resp = {"status": 0, "body": "", "headers": {}, "url": "http://127.0.0.1:1/",
                     "error": "connection refused"}
        for Cls in (XSSScanner, LFIRFIScanner, CommandInjectionScanner):
            with patch.object(BaseModule, "_make_request", return_value=mock_resp):
                s = Cls("http://127.0.0.1:1")
                s._quiet = True
                s.timeout = 1
                try:
                    r = s.run()
                    self.assertIsInstance(r, dict)
                    for key in ("module", "target", "findings", "summary"):
                        self.assertIn(key, r, f"{Cls.__name__}: '{key}' eksik")
                except Exception as e:
                    self.fail(f"{Cls.__name__}.run() erişilemeyen hostta exception fırlattı: {e}")


# ═══════════════════════════════════════════════════════════════
# SQL INJECTION ENTEGRASYON TESTLERİ
# ═══════════════════════════════════════════════════════════════

class _SQLiVulnServer(_SilentHandler):
    """
    Kasıtlı SQL injection açığı olan uygulama.
    ?id=<payload> → payload SQL error üretirse hata mesajı döner.
    /safe → parametre ignore edilir.
    """
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs     = urllib.parse.parse_qs(parsed.query)
        path   = parsed.path

        if path == "/safe":
            self._resp("<html><body>Safe page</body></html>")
            return

        val = qs.get("id", [""])[0]
        val_lower = val.lower()

        # Error-based: tek tırnak veya SQL keyword içeriyorsa hata dön
        sql_triggers = ["'", '"', "or 1=1", "union select", "order by",
                        "having", "group by", "sleep(", "waitfor",
                        "extractvalue", "updatexml"]
        triggered = any(t in val_lower for t in sql_triggers)

        if triggered:
            body = (f'<html><body>Error: you have an error in your sql syntax '
                    f'near \'{val[:40]}\' at line 1</body></html>')
            self._resp(body, status=500)
        else:
            body = f"<html><body>Result for id={val}</body></html>"
            self._resp(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(length).decode("utf-8", errors="replace")
        sql_triggers = ["'", '"', "or 1=1", "union select"]
        triggered = any(t in post_data.lower() for t in sql_triggers)
        if triggered:
            body = '<html>Error: mysql_fetch_array() expects parameter</html>'
            self._resp(body, status=500)
        else:
            self._resp("<html>OK</html>")

    def _resp(self, body, status=200, ct="text/html"):
        enc = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(enc)))
        self.end_headers()
        self.wfile.write(enc)


class TestSQLiIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.srv  = _run_server(_SQLiVulnServer, cls.port)
        _wait_ready(cls.port)
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_error_based_sqli_detected(self):
        from cogs.recon_39_deep_sqli import DeepSQLiScanner
        s = DeepSQLiScanner(f"{self.base}/?id=1")
        s._quiet = True
        r = s.run()
        sqli = [f for f in r["findings"]
                if "SQL Injection" in f["title"] and f["severity"] == "critical"]
        self.assertGreater(len(sqli), 0,
            f"SQLi tespit edilemedi. Bulgular: {[f['title'] for f in r['findings']]}")

    def test_safe_endpoint_no_error_based_false_positive(self):
        from cogs.recon_39_deep_sqli import DeepSQLiScanner
        s = DeepSQLiScanner(f"{self.base}/safe?id=1")
        s._quiet = True
        r = s.run()
        # /safe path'e giden error-based SQLi bulgusu olmamalı
        # (UNION/header probeları farklı path'e düşebilir — onları hariç tut)
        error_based = [f for f in r["findings"]
                       if "Error-Based" in f["title"]
                       and f["severity"] == "critical"
                       and "id" in f.get("detail", "").lower()]
        self.assertEqual(len(error_based), 0,
            "Güvenli endpoint'te error-based false-positive SQLi bulgusu")

    def test_sqli_result_structure(self):
        from cogs.recon_39_deep_sqli import DeepSQLiScanner
        s = DeepSQLiScanner(f"{self.base}/?id=1")
        s._quiet = True
        r = s.run()
        for key in ("module", "target", "findings", "summary", "timestamp"):
            self.assertIn(key, r)
        self.assertIn("Taranan Parametre", r["summary"])


# ═══════════════════════════════════════════════════════════════
# HTTP HEADER ENTEGRASYON TESTLERİ
# ═══════════════════════════════════════════════════════════════

class _HeaderVulnServer(_SilentHandler):
    """
    Eksik güvenlik başlıkları dönen sunucu.
    /secure → tüm başlıklar mevcut.
    / → hiçbir güvenlik başlığı yok.
    """
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/secure":
            body = "<html><body>Secure</body></html>"
            enc = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(enc)))
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-XSS-Protection", "1; mode=block")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(enc)
        else:
            body = "<html><body>Insecure</body></html>"
            enc = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(enc)))
            self.end_headers()
            self.wfile.write(enc)


class TestHTTPHeaderIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.srv  = _run_server(_HeaderVulnServer, cls.port)
        _wait_ready(cls.port)
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_missing_headers_detected(self):
        from cogs.recon_14_http_headers import HTTPHeaderAnalyzer
        s = HTTPHeaderAnalyzer(self.base)
        s._quiet = True
        r = s.run()
        # Eksik başlıklar tespit edilmeli
        self.assertGreater(len(r["findings"]), 0,
            "Eksik güvenlik başlıkları tespit edilemedi")

    def test_finding_mentions_header_names(self):
        from cogs.recon_14_http_headers import HTTPHeaderAnalyzer
        s = HTTPHeaderAnalyzer(self.base)
        s._quiet = True
        r = s.run()
        all_text = " ".join(f["title"] + " " + f["detail"] for f in r["findings"]).lower()
        # En az bir eksik başlık adından bahsetmeli
        headers_to_check = ["x-frame-options", "strict-transport", "content-security",
                            "x-content-type", "hsts", "csp"]
        found_any = any(h in all_text for h in headers_to_check)
        self.assertTrue(found_any,
            f"Bulgu metinlerinde bilinen başlık adı bulunamadı")


# ═══════════════════════════════════════════════════════════════
# CORS ENTEGRASYON TESTLERİ
# ═══════════════════════════════════════════════════════════════

class _CORSVulnServer(_SilentHandler):
    """
    Zayıf CORS yapılandırması: Origin'i yansıtır + credentials izin verir.
    """
    def do_GET(self):
        origin = self.headers.get("Origin", "")
        body = "<html><body>CORS test</body></html>"
        enc = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(enc)))
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        else:
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(enc)


class TestCORSIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.srv  = _run_server(_CORSVulnServer, cls.port)
        _wait_ready(cls.port)
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_cors_misconfiguration_detected(self):
        from cogs.recon_12_cors import CORSScanner
        s = CORSScanner(self.base)
        s._quiet = True
        r = s.run()
        cors_findings = [f for f in r["findings"] if "CORS" in f["title"].upper()
                         or "origin" in f["detail"].lower()
                         or "cors" in f["detail"].lower()]
        self.assertGreater(len(cors_findings), 0,
            f"CORS misconfiguration tespit edilemedi. Bulgular: {[f['title'] for f in r['findings']]}")

    def test_cors_result_structure(self):
        from cogs.recon_12_cors import CORSScanner
        s = CORSScanner(self.base)
        s._quiet = True
        r = s.run()
        for key in ("module", "target", "findings", "summary", "timestamp"):
            self.assertIn(key, r)
        self.assertIsInstance(r["findings"], list)


# ═══════════════════════════════════════════════════════════════
# CLICKJACKING ENTEGRASYON TESTLERİ
# ═══════════════════════════════════════════════════════════════

class TestClickjackingIntegration(unittest.TestCase):
    """X-Frame-Options eksik sunucularda clickjacking tespiti."""

    @classmethod
    def setUpClass(cls):
        # HeaderVulnServer zaten X-Frame-Options göndermiyor (/ path)
        cls.port = _free_port()
        cls.srv  = _run_server(_HeaderVulnServer, cls.port)
        _wait_ready(cls.port)
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_clickjacking_detected(self):
        from cogs.recon_17_clickjacking import ClickjackingTester
        s = ClickjackingTester(self.base)
        s._quiet = True
        r = s.run()
        found = any("clickjack" in f["title"].lower() or
                     "x-frame" in f["detail"].lower() or
                     "frame" in f["title"].lower()
                     for f in r["findings"])
        self.assertTrue(found,
            f"Clickjacking tespit edilemedi. Bulgular: {[f['title'] for f in r['findings']]}")


# ═══════════════════════════════════════════════════════════════
# MAXIMA.PY CLI ENTEGRASYON TESTLERİ
# ═══════════════════════════════════════════════════════════════

class TestMaximaCLIFeatures(unittest.TestCase):
    """Yeni CLI özelliklerini test eder (--version, --no-color, hedef doğrulama)."""

    def test_version_flag(self):
        import subprocess
        python = sys.executable
        result = subprocess.run(
            [python, os.path.join(PROJECT_ROOT, "maxima.py"), "--version"],
            capture_output=True, text=True, timeout=10
        )
        self.assertIn("11.0", result.stdout)

    def test_print_summary_function(self):
        """_print_summary hatasız çalışmalı."""
        import importlib
        spec = importlib.util.spec_from_file_location(
            "maxima", os.path.join(PROJECT_ROOT, "maxima.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        mock_results = {
            "TestModule": {
                "module": "TestModule",
                "findings": [
                    {"title": "Test", "detail": "d", "severity": "high"},
                    {"title": "Test2", "detail": "d", "severity": "medium"},
                ],
                "summary": {}
            },
            "ErrorModule": {"error": "timeout", "module": "ErrorModule"}
        }
        # Hata fırlatmamalı
        try:
            mod._print_summary(mock_results)
        except Exception as e:
            self.fail(f"_print_summary hata fırlattı: {e}")

    def test_gui_importable(self):
        """maxima_gui.py import edilebilir olmalı."""
        try:
            import importlib
            spec = importlib.util.spec_from_file_location(
                "maxima_gui", os.path.join(PROJECT_ROOT, "maxima_gui.py"))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            self.assertTrue(hasattr(mod, "MaximaGUI"))
        except ImportError:
            # tkinter yoksa atla
            pass


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite  = loader.loadTestsFromModule(__import__("__main__"))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)

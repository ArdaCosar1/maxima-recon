#!/usr/bin/env python3
"""
Maxima Cog: PageProbe — Kapsamlı Sayfa Analizi & Opsiyonel Ekran Görüntüsü
Module: PageProbe (alias: ScreenshotCapture)

Yetenekler: HTTP metadata, teknoloji parmak izi, güvenlik başlıkları,
form/çerez/harici kaynak analizi, yorum sızıntı tespiti, Playwright screenshot.
"""
import re
import os
import hashlib
from urllib.parse import urlparse
from utils.base_module import BaseModule, ModuleResult

HAS_PLAYWRIGHT = False
try:
    from playwright.sync_api import sync_playwright  # type: ignore
    HAS_PLAYWRIGHT = True
except ImportError:
    pass

# ── Teknoloji imza sözlükleri ────────────────────────────────
_CMS_SIGS = {
    "WordPress":  [r"wp-content/", r"wp-includes/", r"wp-json"],
    "Joomla":     [r"/components/com_", r"Joomla!", r"/media/jui/"],
    "Drupal":     [r"Drupal\.settings", r"sites/default/files"],
    "Magento":    [r"Mage\.Cookies", r"/skin/frontend/"],
}
_JS_SIGS = {
    "React":   [r"react\.production\.min\.js", r"__NEXT_DATA__", r"_reactRootContainer"],
    "Angular": [r"ng-version=", r"angular\.min\.js", r"ng-app="],
    "Vue":     [r"vue\.min\.js", r"vue\.runtime", r"__vue__"],
    "jQuery":  [r"jquery[\.-][\d\.]*\.min\.js", r"jquery\.js"],
}
_SRV_SIGS = {
    "PHP":     [r"\.php[\"\?]", r"X-Powered-By.*PHP"],
    "ASP.NET": [r"__VIEWSTATE", r"__EVENTVALIDATION", r"aspnet_client"],
    "Django":  [r"csrfmiddlewaretoken", r"django"],
    "Rails":   [r"csrf-token", r"action_dispatch", r"rails"],
    "Express": [r"X-Powered-By.*Express"],
}
_CDN_SIGS = {
    "CloudFlare": ["cf-ray", "cf-cache-status", "server:cloudflare"],
    "Akamai":     ["x-akamai-transformed"],
    "Fastly":     ["x-served-by", "x-cache:.*fastly"],
}
_SEC_HEADERS = [
    ("Content-Security-Policy",   "CSP"),
    ("X-Frame-Options",           "X-Frame-Options"),
    ("Strict-Transport-Security", "HSTS"),
    ("X-Content-Type-Options",    "X-Content-Type-Options"),
    ("Referrer-Policy",           "Referrer-Policy"),
    ("Permissions-Policy",        "Permissions-Policy"),
]
_LEAK_RE = re.compile(
    r"\b(TODO|FIXME|HACK|password|passwd|debug|secret|api[_-]?key|token|"
    r"credential|private[_-]?key|access[_-]?key)\b", re.I
)


class PageProbe(BaseModule):
    """PageProbe — Kapsamlı sayfa analizi ve opsiyonel ekran görüntüsü."""

    def run(self) -> ModuleResult:
        self.log("Kapsamlı sayfa analizi başlatılıyor...")

        resp = self.http_get(self.url)
        status = resp.get("status", 0)
        body = resp.get("body", "")
        headers = resp.get("headers", {})

        if status == 0:
            self.add_finding("Sayfa Erişilemiyor",
                             "Bağlantı hatası — analiz yapılamıyor", "medium")
            return self.results

        # Paralel ek kaynak kontrolleri
        parsed = urlparse(self.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        self.log("Favicon, robots.txt ve sitemap.xml paralel kontrol ediliyor...")
        par = self.parallel_get([f"{base}/favicon.ico",
                                 f"{base}/robots.txt",
                                 f"{base}/sitemap.xml"])
        extra = {urlparse(u).path: r for u, r in par}

        self._analyze_metadata(status, body, headers, extra)
        self._fingerprint_tech(body, headers)
        self._check_security_headers(headers)
        self._analyze_forms(body)
        self._enumerate_externals(body)
        self._analyze_cookies(headers)
        self._detect_comment_leaks(body)
        self._try_screenshot()

        self.log("Sayfa analizi tamamlandı.", "info")
        return self.results

    # ── 1. HTTP Metadata ──────────────────────────────────────
    def _analyze_metadata(self, status: int, body: str,
                          headers: dict, extra: dict) -> None:
        self.log("HTTP metadata çıkarılıyor...")
        title = self._re1(r"<title[^>]*>(.*?)</title>", body, 120)
        desc = self._re1(r'<meta\s+name=["\']description["\']\s+content=["\'](.*?)["\']', body, 200)
        keywords = self._re1(r'<meta\s+name=["\']keywords["\']\s+content=["\'](.*?)["\']', body, 200)
        canonical = self._re1(r'<link[^>]*rel=["\']canonical["\'][^>]*href=["\'](.*?)["\']', body, 0)

        favicon_hash = ""
        fav = extra.get("/favicon.ico", {})
        if fav.get("status") == 200 and fav.get("body"):
            favicon_hash = hashlib.md5(fav["body"].encode("utf-8", errors="replace")).hexdigest()

        robots_ok = extra.get("/robots.txt", {}).get("status") == 200
        sitemap_ok = extra.get("/sitemap.xml", {}).get("status") == 200
        server = headers.get("Server", headers.get("server", "Bilinmiyor"))
        clen = headers.get("Content-Length",
                           headers.get("content-length", f"{len(body)} (hesaplanan)"))

        s = self.results["summary"]
        s["HTTP Status"] = status
        s["Sayfa Başlığı"] = title or "(yok)"
        s["Meta Açıklama"] = desc or "(yok)"
        s["Meta Anahtar Kelimeler"] = keywords or "(yok)"
        s["Canonical URL"] = canonical or "(yok)"
        s["Favicon MD5"] = favicon_hash or "(yok)"
        s["Server"] = server
        s["İçerik Uzunluğu"] = clen
        s["robots.txt"] = "Mevcut" if robots_ok else "Yok"
        s["sitemap.xml"] = "Mevcut" if sitemap_ok else "Yok"
        self.add_finding("HTTP Metadata",
                         f"Başlık: {title or '(yok)'} | Status: {status} | Server: {server}", "info")

    @staticmethod
    def _re1(pattern: str, text: str, maxlen: int) -> str:
        m = re.search(pattern, text, re.I | re.S)
        if not m:
            return ""
        val = m.group(1).strip()
        return val[:maxlen] if maxlen else val

    # ── 2. Teknoloji Parmak İzi ───────────────────────────────
    def _fingerprint_tech(self, body: str, headers: dict) -> None:
        self.log("Teknoloji parmak izi taranıyor...")
        detected: list[str] = []
        hdr_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
        combined = body + "\n" + hdr_str

        for label, sigs in [("CMS", _CMS_SIGS), ("JS", _JS_SIGS), ("Backend", _SRV_SIGS)]:
            source = body if label == "JS" else combined
            for name, pats in sigs.items():
                if any(re.search(p, source, re.I) for p in pats):
                    detected.append(f"{label}: {name}")

        # CDN — header tabanlı
        hdrs_low = {k.lower(): v.lower() for k, v in headers.items()}
        for cdn, indicators in _CDN_SIGS.items():
            for ind in indicators:
                if ":" in ind:
                    hk, hp = ind.split(":", 1)
                    if re.search(hp.strip(), hdrs_low.get(hk.strip(), ""), re.I):
                        detected.append(f"CDN: {cdn}"); break
                elif any(ind in v for v in hdrs_low.values()):
                    detected.append(f"CDN: {cdn}"); break

        unique = list(dict.fromkeys(detected))
        self.results["summary"]["Tespit Edilen Teknolojiler"] = ", ".join(unique) or "(yok)"
        if unique:
            self.add_finding("Teknoloji Tespiti",
                             f"{len(unique)} teknoloji: {', '.join(unique)}", "info")
        else:
            self.log("Bilinen teknoloji imzası bulunamadı.", "info")

    # ── 3. Güvenlik Başlıkları ────────────────────────────────
    def _check_security_headers(self, headers: dict) -> None:
        self.log("Güvenlik başlıkları analiz ediliyor...")
        low = {k.lower(): v for k, v in headers.items()}
        present = [lb for h, lb in _SEC_HEADERS if h.lower() in low]
        missing = [lb for h, lb in _SEC_HEADERS if h.lower() not in low]

        self.results["summary"]["Güvenlik Başlıkları (mevcut)"] = ", ".join(present) or "(yok)"
        self.results["summary"]["Güvenlik Başlıkları (eksik)"] = ", ".join(missing) or "(yok)"

        if missing:
            self.add_finding("Eksik Güvenlik Başlıkları",
                             f"{len(missing)} eksik: {', '.join(missing)}",
                             "medium" if len(missing) >= 3 else "low")
        if present:
            self.add_finding("Mevcut Güvenlik Başlıkları",
                             f"{len(present)} mevcut: {', '.join(present)}", "info")

    # ── 4. Form Analizi ───────────────────────────────────────
    def _analyze_forms(self, body: str) -> None:
        self.log("Form analizi yapılıyor...")
        forms = re.findall(r"<form[\s\S]*?</form>", body, re.I)
        login_n = upload_n = hidden_n = 0

        for f in forms:
            if re.search(r'type=["\']password["\']', f, re.I) or \
               re.search(r'(login|signin|sign-in|auth)', f, re.I):
                login_n += 1
            if re.search(r'type=["\']file["\']', f, re.I):
                upload_n += 1
            hidden_n += len(re.findall(r'type=["\']hidden["\']', f, re.I))

        s = self.results["summary"]
        s["Toplam Form"] = len(forms)
        s["Giriş Formları"] = login_n
        s["Dosya Yükleme Formları"] = upload_n
        s["Gizli Input Alanları"] = hidden_n

        if login_n:
            self.add_finding("Giriş Formu Tespit Edildi",
                             f"{login_n} adet giriş formu bulundu", "info")
        if upload_n:
            self.add_finding("Dosya Yükleme Formu",
                             f"{upload_n} adet dosya yükleme formu", "low")
        if hidden_n > 5:
            self.add_finding("Çok Sayıda Gizli Alan",
                             f"{hidden_n} gizli input — bilgi sızıntısı riski", "low")

    # ── 5. Harici Kaynak Enumerasyonu ─────────────────────────
    def _enumerate_externals(self, body: str) -> None:
        self.log("Harici kaynaklar taranıyor...")
        target_dom = urlparse(self.url).netloc.lower()
        js_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.I)
        css_hrefs = re.findall(
            r'<link[^>]+rel=["\']stylesheet["\'][^>]+href=["\']([^"\']+)["\']', body, re.I)

        ext_domains: set[str] = set()
        ext_js = ext_css = 0
        for src in js_srcs:
            p = urlparse(src)
            if p.netloc and p.netloc.lower() != target_dom:
                ext_js += 1; ext_domains.add(p.netloc.lower())
        for href in css_hrefs:
            p = urlparse(href)
            if p.netloc and p.netloc.lower() != target_dom:
                ext_css += 1; ext_domains.add(p.netloc.lower())

        dl = sorted(ext_domains)
        self.results["summary"]["Harici JS Sayısı"] = ext_js
        self.results["summary"]["Harici CSS Sayısı"] = ext_css
        self.results["summary"]["Harici Domain'ler"] = ", ".join(dl) or "(yok)"
        if dl:
            self.add_finding("Harici Kaynak Domain'leri",
                             f"{len(dl)} harici domain: {', '.join(dl[:10])}", "info")

    # ── 6. Çerez Analizi ─────────────────────────────────────
    def _analyze_cookies(self, headers: dict) -> None:
        self.log("Çerez güvenlik analizi yapılıyor...")
        raw_cookies: list[str] = []
        for k, v in headers.items():
            if k.lower() == "set-cookie":
                raw_cookies.extend(v.split("\n"))

        if not raw_cookies:
            self.results["summary"]["Çerez Sayısı"] = 0
            self.log("Set-Cookie başlığı bulunamadı.", "info")
            return

        insecure: list[str] = []
        no_http: list[str] = []
        no_same: list[str] = []
        for rc in raw_cookies:
            rc = rc.strip()
            if not rc:
                continue
            name = rc.split("=")[0].strip()
            lo = rc.lower()
            if "secure" not in lo:
                insecure.append(name)
            if "httponly" not in lo:
                no_http.append(name)
            if "samesite" not in lo:
                no_same.append(name)

        self.results["summary"]["Çerez Sayısı"] = len(raw_cookies)
        if insecure:
            self.add_finding("Secure Bayrağı Eksik Çerezler",
                             ", ".join(insecure[:5]), "medium")
        if no_http:
            self.add_finding("HttpOnly Bayrağı Eksik Çerezler",
                             ", ".join(no_http[:5]), "medium")
        if no_same:
            self.add_finding("SameSite Bayrağı Eksik Çerezler",
                             ", ".join(no_same[:5]), "low")

    # ── 7. Yorum / Debug Sızıntı Tespiti ─────────────────────
    def _detect_comment_leaks(self, body: str) -> None:
        self.log("HTML yorumlarında bilgi sızıntısı taranıyor...")
        comments = re.findall(r"<!--([\s\S]*?)-->", body)
        leaks: list[str] = []
        for c in comments:
            hits = _LEAK_RE.findall(c)
            if hits:
                snip = c.strip()[:80].replace("\n", " ")
                leaks.append(f"[{', '.join(set(hits))}] {snip}")

        self.results["summary"]["HTML Yorum Sayısı"] = len(comments)
        self.results["summary"]["Sızıntı İçeren Yorumlar"] = len(leaks)
        if leaks:
            self.add_finding("HTML Yorum Sızıntısı",
                             f"{len(leaks)} şüpheli yorum: {' | '.join(leaks[:5])}",
                             "medium" if len(leaks) >= 3 else "low")

    # ── 8. Opsiyonel Playwright Ekran Görüntüsü ──────────────
    def _try_screenshot(self) -> None:
        if not HAS_PLAYWRIGHT:
            self.log("Playwright yüklü değil — ekran görüntüsü atlanıyor. "
                     "Kurulum: pip install playwright && playwright install chromium", "info")
            self.results["summary"]["Ekran Görüntüsü"] = "Atlandı (playwright yok)"
            return

        self.log("Playwright ile ekran görüntüsü alınıyor...")
        reports_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        safe = re.sub(r"[^\w\-.]", "_", urlparse(self.url).netloc)
        out = os.path.join(reports_dir, f"screenshot_{safe}.png")

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                page = browser.new_page(viewport={"width": 1280, "height": 720})
                page.goto(self.url, wait_until="domcontentloaded", timeout=15000)
                page.screenshot(path=out, full_page=False)
                browser.close()
            self.results["summary"]["Ekran Görüntüsü"] = out
            self.add_finding("Ekran Görüntüsü Alındı", f"Kaydedildi: {out}", "info")
            self.log(f"Ekran görüntüsü kaydedildi: {out}", "info")
        except Exception as exc:
            self.log(f"Playwright ekran görüntüsü başarısız: {exc}", "warning")
            self.results["summary"]["Ekran Görüntüsü"] = f"Hata: {exc}"


# Geriye dönük uyumluluk — maxima.py bu ismi import ediyor
ScreenshotCapture = PageProbe

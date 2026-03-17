#!/usr/bin/env python3
"""
Maxima Cog: HTTP Header Analyzer
FIX:
  - Expect-CT deprecated (Chrome 111+) kaldırıldı
  - Referrer-Policy ve Permissions-Policy severity düşürüldü (low)
  - HSTS sadece HTTPS'te kontrol ediliyor
  - Header değer kalite kontrolü eklendi (HSTS max-age, CSP unsafe-inline)
  - Remediation önerileri eklendi (v11.1)
"""
import os, re
from utils.base_module import BaseModule, ModuleResult


class HTTPHeaderAnalyzer(BaseModule):
    """HTTP Header Analyzer"""

    INFO_HEADERS = [
        "Server", "X-Powered-By", "Via",
        "X-AspNet-Version", "X-Generator", "X-Drupal-Cache",
    ]

    def run(self) -> ModuleResult:
        self.log("HTTP başlık analizi...")
        resp     = self.http_get(self.url)
        headers  = resp.get("headers", {})
        h_lower  = {k.lower(): v for k, v in headers.items()}
        is_https = self.url.startswith("https://")

        # ── Kritik güvenlik başlıkları ──
        if "content-security-policy" not in h_lower:
            self.add_finding("CSP Eksik",
                "Content-Security-Policy başlığı tanımlanmamış", "high",
                remediation="Web sunucu yapılandırmasına CSP header ekleyin: "
                            "Content-Security-Policy: default-src 'self'; script-src 'self'",
                evidence=f"Yanıt başlıkları: {', '.join(headers.keys())}")
        else:
            csp = h_lower["content-security-policy"]
            if "unsafe-inline" in csp:
                self.add_finding("CSP unsafe-inline",
                    "CSP 'unsafe-inline' içeriyor — XSS koruması zayıf", "medium",
                    remediation="unsafe-inline yerine nonce veya hash tabanlı CSP kullanın: "
                                "script-src 'nonce-{random}' 'strict-dynamic'",
                    evidence=f"CSP: {csp[:200]}")
            if "unsafe-eval" in csp:
                self.add_finding("CSP unsafe-eval",
                    "CSP 'unsafe-eval' içeriyor — XSS koruması zayıf", "medium",
                    remediation="eval() kullanımını kaldırın ve unsafe-eval direktifini silin",
                    evidence=f"CSP: {csp[:200]}")

        if "x-frame-options" not in h_lower and \
                "frame-ancestors" not in h_lower.get("content-security-policy",""):
            self.add_finding("X-Frame-Options Eksik",
                "Clickjacking koruması yok", "medium",
                remediation="X-Frame-Options: DENY veya CSP frame-ancestors 'self' ekleyin")

        if "x-content-type-options" not in h_lower:
            self.add_finding("X-Content-Type-Options Eksik",
                "MIME sniffing saldırılarına açık", "low",
                remediation="X-Content-Type-Options: nosniff ekleyin")

        # HSTS sadece HTTPS'te anlamlı
        if is_https:
            if "strict-transport-security" not in h_lower:
                self.add_finding("HSTS Eksik",
                    "HTTPS sitede HSTS başlığı yok", "medium",
                    remediation="Strict-Transport-Security: max-age=31536000; includeSubDomains; preload")
            else:
                hsts = h_lower["strict-transport-security"]
                m = re.search(r"max-age=(\d+)", hsts)
                if m:
                    age = int(m.group(1))
                    if age < 31536000:
                        self.add_finding("HSTS max-age Çok Kısa",
                            f"max-age={age} (önerilen: ≥31536000)", "low",
                            remediation=f"max-age değerini en az 31536000 (1 yıl) yapın: "
                                        f"Strict-Transport-Security: max-age=31536000")
                if "includeSubDomains" not in hsts:
                    self.add_finding("HSTS includeSubDomains Eksik",
                        "Alt domainler HSTS kapsamı dışında", "low",
                        remediation="includeSubDomains direktifini ekleyin")

        # Düşük öncelikli ama iyi pratik başlıklar
        if "referrer-policy" not in h_lower:
            self.add_finding("Referrer-Policy Eksik",
                "Referrer bilgisi üçüncü taraflarla paylaşılabilir", "low",
                remediation="Referrer-Policy: strict-origin-when-cross-origin ekleyin")

        if "permissions-policy" not in h_lower:
            self.add_finding("Permissions-Policy Eksik",
                "Tarayıcı API kısıtlamaları tanımlanmamış", "low",
                remediation="Permissions-Policy: camera=(), microphone=(), geolocation=() ekleyin")

        # ── Bilgi sızdıran başlıklar ──
        for h in self.INFO_HEADERS:
            val = h_lower.get(h.lower(), "")
            if val:
                self.add_finding(f"Bilgi Sızdıran Başlık: {h}",
                    f"{h}: {val}", "low",
                    remediation=f"Web sunucu yapılandırmasından '{h}' başlığını kaldırın veya gizleyin",
                    evidence=f"{h}: {val}")

        present = sum(1 for h in [
            "content-security-policy","x-frame-options",
            "x-content-type-options","strict-transport-security",
            "referrer-policy","permissions-policy"
        ] if h in h_lower)

        self.results["summary"]["Toplam Başlık"]      = len(headers)
        self.results["summary"]["Güvenlik Başlığı"]   = present
        self.results["summary"]["HTTPS"]              = "Evet" if is_https else "Hayır"
        return self.results

#!/usr/bin/env python3
"""
Maxima Cog: Clickjacking Tester
FIX: CSP frame-ancestors doğru parse ediliyor
     (sadece string geçmesi yeterli değil, "frame-ancestors 'none'" veya "frame-ancestors 'self'" olmalı)
"""
import os, re
from utils.base_module import BaseModule, ModuleResult


class ClickjackingTester(BaseModule):
    """Clickjacking Tester"""

    def run(self) -> ModuleResult:
        self.log("Clickjacking testi...")
        resp    = self.http_get(self.url)
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}

        xfo = headers.get("x-frame-options", "")
        csp = headers.get("content-security-policy", "")

        # CSP frame-ancestors doğru şekilde parse et
        # "frame-ancestors 'none'" veya "frame-ancestors 'self'" veya "frame-ancestors https://..." olmalı
        fa_match = re.search(r"frame-ancestors\s+([^;]+)", csp, re.I)
        has_fa   = bool(fa_match)
        fa_value = fa_match.group(1).strip() if fa_match else ""

        # frame-ancestors * ise koruma yok
        if has_fa and fa_value.strip() == "*":
            has_fa = False

        xfo_valid = xfo.upper() in ("DENY", "SAMEORIGIN")

        if not xfo_valid and not has_fa:
            self.add_finding(
                "Clickjacking Açığı",
                "X-Frame-Options veya CSP frame-ancestors tanımlı değil — "
                "sayfa iframe içine alınabilir.",
                "medium"
            )
        elif xfo and not xfo_valid:
            self.add_finding(
                "Geçersiz X-Frame-Options",
                f"Değer '{xfo}' tanınmıyor — DENY veya SAMEORIGIN kullanın.",
                "low"
            )
        else:
            self.log("Clickjacking koruması mevcut", "success")

        self.results["summary"]["X-Frame-Options"]     = xfo or "Yok"
        self.results["summary"]["CSP frame-ancestors"] = fa_value or "Yok"
        return self.results

#!/usr/bin/env python3
"""
Maxima Cog: Multi-Request WAF Detector
FIX:
  - 403/406 status kodu artık otomatik "WAF Engeli" üretmiyor
    (dizin izinleri, auth koruması da 403 döner)
  - WAF engeli tespiti: probe URL'leri için baseline farkına bakıyor
  - Normal URL'de 403 → probe URL'de de 403: sadece baseline
  - Normal URL'de 200 → probe URL'de 403: WAF engeli
"""
import os
from utils.base_module import BaseModule, ModuleResult


class WAFDetector(BaseModule):
    """Multi-Request WAF Detector"""

    WAF_SIGNATURES = {
        "Cloudflare":   ["cloudflare","cf-ray","__cfduid","cf-cache-status"],
        "Akamai":       ["akamai","x-akamai","x-check-cacheable","akamaighost"],
        "AWS WAF":      ["awswaf","x-amzn-requestid","x-amz-cf-id","x-amzn-trace-id"],
        "Imperva":      ["incapsula","x-iinfo","visid_incap","_incap_ses"],
        "Sucuri":       ["sucuri","x-sucuri-id","x-sucuri-cache"],
        "F5 BIG-IP":    ["bigipserver","x-wa-info","x-cnection"],
        "Barracuda":    ["barracuda_","barra_counter_session"],
        "ModSecurity":  ["mod_security","modsecurity","modsec"],
        "Fortinet":     ["fortigate","fortiweb"],
        "Radware":      ["x-sl-compstate","radware"],
    }

    def run(self) -> ModuleResult:
        self.log("WAF tespiti...")

        # Baseline: normal istek
        baseline_resp   = self.http_get(self.url)
        baseline_status = baseline_resp.get("status", 0)
        baseline_text   = (str(baseline_resp.get("headers", {})) +
                           baseline_resp.get("body", "")[:1000]).lower()

        # WAF probe'ları
        probes = [
            f"{self.url}?id=1' UNION SELECT 1,2,3--",
            f"{self.url}?q=<script>alert(1)</script>",
            f"{self.url}?file=../../../etc/passwd",
        ]

        detected_wafs = set()
        blocked_count = 0

        # Baseline header'larında WAF imzası var mı?
        for waf, signs in self.WAF_SIGNATURES.items():
            for sign in signs:
                if sign.lower() in baseline_text:
                    detected_wafs.add(waf)

        # Probe'larda ek imza veya status farkı
        for probe_url in probes:
            resp       = self.http_get(probe_url)
            probe_stat = resp.get("status", 0)
            all_text   = (str(resp.get("headers", {})) +
                          resp.get("body", "")[:1000]).lower()

            for waf, signs in self.WAF_SIGNATURES.items():
                for sign in signs:
                    if sign.lower() in all_text:
                        detected_wafs.add(waf)

            # FIX: Sadece baseline'dan farklı engel = WAF davranışı
            if probe_stat in (403, 406, 429, 501) and probe_stat != baseline_status:
                blocked_count += 1

        if blocked_count >= 2:
            self.add_finding(
                "WAF Engeli Tespit Edildi",
                f"{blocked_count} probe isteği engellendi (baseline: HTTP {baseline_status})",
                "info"
            )

        for waf in detected_wafs:
            self.add_finding(f"WAF Tespit: {waf}",
                             f"{waf} güvenlik duvarı aktif", "info")
            self.log(f"WAF: {waf}", "finding")

        self.results["summary"]["Tespit Edilen WAF"]  = ", ".join(detected_wafs) or "Yok / Bilinmiyor"
        self.results["summary"]["Engellenen Probe"]   = blocked_count
        return self.results

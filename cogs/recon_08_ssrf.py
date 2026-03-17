#!/usr/bin/env python3
"""
Maxima Cog: SSRF Scanner
PERF: parallel_get ile 80 sıralı istek → paralel batch
v10: Cloud metadata (AWS/GCP/Azure), severity ayrımı, param düzeltmesi
"""
import os, urllib.parse
from utils.base_module import BaseModule, ModuleResult


class SSRFScanner(BaseModule):
    PAYLOADS = [
        "http://127.0.0.1/", "http://localhost/",
        # AWS metadata
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/",
        # GCP metadata
        "http://metadata.google.internal/computeMetadata/v1/",
        # Azure metadata
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        # Bypass variants
        "http://[::1]/", "http://0.0.0.0/",
        "http://2130706433/", "http://0177.0.0.1/",
        "http://0x7f000001/",
    ]

    # İmza → severity eşlemesi: cloud metadata = high, local file = critical
    SSRF_SIGNATURES = {
        # AWS metadata (bilgi ifşası — high)
        "ami-id":                    "high",
        "instance-id":               "high",
        "instance-type":             "high",
        "local-hostname":            "high",
        "local-ipv4":                "high",
        "169.254.169.254":           "high",
        # GCP metadata
        "computemetadata":           "high",
        "metadata.google.internal":  "high",
        # Azure metadata
        "vmid":                      "high",
        "subscriptionid":            "high",
        # Local file / RCE potansiyeli — critical
        "root:x:0:0":               "critical",
    }

    PARAMS = ["url","redirect","next","link","src","target","dest","ref","fetch","uri",
              "path","file","page","load","data","return","returnUrl","callback"]

    def run(self) -> ModuleResult:
        self.log("SSRF taraması (paralel)...")
        baseline_body = self.http_get(
            f"{self.url}?url={urllib.parse.quote('https://example.com')}"
        ).get("body","").lower()

        # Tüm (param, payload) kombinasyonlarını tek batch'te gönder
        combos = [(p, pl) for p in self.PARAMS for pl in self.PAYLOADS]
        urls   = [f"{self.url}?{param}={urllib.parse.quote(payload)}"
                  for param, payload in combos]

        found = 0
        reported = set()
        for url, resp in self.parallel_get(urls, max_workers=12):
            body = resp.get("body","").lower()
            qs = urllib.parse.urlparse(url).query
            for sig, severity in self.SSRF_SIGNATURES.items():
                if sig.lower() in body and sig.lower() not in baseline_body:
                    # Parametre adını doğru çıkar
                    param = "?"
                    if "=" in qs:
                        param = qs.split("=")[0]
                    key = f"{param}:{sig}"
                    if key not in reported:
                        reported.add(key)
                        label = "SSRF — Cloud Metadata İfşası" if severity == "high" \
                                else "SSRF — Yerel Dosya/RCE"
                        rem = ("URL parametrelerini whitelist ile kısıtlayın. "
                               "İç ağ IP adreslerini (127.0.0.1, 169.254.x.x, 10.x.x.x) "
                               "sunucu tarafında engelleyin. Cloud metadata endpoint'leri "
                               "için IMDSv2 (token zorunlu) kullanın.")
                        self.add_finding(label,
                            f"Parametre: {param} | İmza: '{sig}'", severity,
                            remediation=rem,
                            evidence=f"URL: {url} → İmza bulundu: {sig}",
                            confidence="confirmed")
                        found += 1
                    break

        self.results["summary"]["Test Edilen"] = len(combos)
        self.results["summary"]["SSRF Adayı"]  = found
        return self.results

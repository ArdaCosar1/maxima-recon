#!/usr/bin/env python3
"""
Maxima Cog: Redirect-Aware Header Analysis
Module: RedirectAwareHeaderAnalysis
"""
import sys
import os
from utils.base_module import BaseModule, ModuleResult


class RedirectAwareHeaderAnalysis(BaseModule):
    """Redirect-Aware Header Analysis"""

    def run(self) -> ModuleResult:
        self.log("Yönlendirme-farkında başlık analizi...")
        urls_to_check = [self.url]
        if self.url.startswith("http://"):
            urls_to_check.append(self.url.replace("http://","https://",1))
        header_results = {}
        for url in urls_to_check:
            resp = self.http_get(url)
            headers = resp.get("headers",{})
            header_results[url] = headers
            # Check HSTS only on HTTPS
            if url.startswith("https://"):
                hsts = {k.lower():v for k,v in headers.items()}.get("strict-transport-security","")
                if not hsts:
                    self.add_finding("HSTS Eksik (HTTPS)", f"{url} için HSTS başlığı yok", "medium")
                elif "max-age=0" in hsts:
                    self.add_finding("HSTS Devre Dışı", f"max-age=0 tespit edildi", "high")
                elif "includeSubDomains" not in hsts:
                    self.add_finding("HSTS includeSubDomains Eksik", hsts, "low")
            # Check for info leakage
            for k,v in headers.items():
                if k.lower() in ["server","x-powered-by","x-aspnet-version","x-generator"]:
                    self.add_finding(f"Başlık Sızıntısı [{k}]", f"{k}: {v}", "low")
        self.results["summary"]["Kontrol Edilen URL"] = len(urls_to_check)
        return self.results


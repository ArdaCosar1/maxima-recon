#!/usr/bin/env python3
"""
Maxima Cog: Redirect Chain Analyzer
Module: RedirectChainAnalyzer
"""
import sys
import os
import ssl
from urllib.parse import urljoin
from utils.base_module import BaseModule, ModuleResult
import urllib.request


class RedirectChainAnalyzer(BaseModule):
    """Redirect Chain Analyzer"""

    def run(self) -> ModuleResult:
        self.log("Yönlendirme zinciri analizi...")
        chain = []
        url = self.url
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        for _ in range(10):
            try:
                req = urllib.request.Request(url, headers={"User-Agent":"MaximaRecon/1.0"})
                opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
                opener.addheaders = []
                class NoRedirect(urllib.request.HTTPErrorProcessor):
                    def http_response(self, request, response):
                        return response
                    https_response = http_response
                opener2 = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
                resp = opener2.open(req, timeout=self.timeout)
                chain.append((resp.status, url))
                loc = resp.headers.get("Location","")
                if not loc: break
                if not loc.startswith("http"):
                    from urllib.parse import urljoin
                    loc = urljoin(url, loc)
                url = loc
            except Exception as e:
                chain.append((0, url))
                break
        if len(chain) > 3:
            self.add_finding("Uzun Yönlendirme Zinciri", f"{len(chain)} adım", "low")
        http_to_https = any(u.startswith("http://") for _, u in chain) and any(u.startswith("https://") for _, u in chain)
        if http_to_https:
            self.add_finding("HTTP->HTTPS Yönlendirme", "Güvenli yönlendirme mevcut", "info")
        self.results["summary"]["Zincir Uzunluğu"] = len(chain)
        self.results["summary"]["Son URL"]          = url[:80]
        return self.results

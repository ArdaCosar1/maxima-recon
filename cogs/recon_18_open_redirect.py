#!/usr/bin/env python3
"""
Maxima Cog: Open Redirect Scanner
PERF: 13 params × 6 payloads = 78 sıralı → paralel batch
"""
import os, urllib.parse
from utils.base_module import BaseModule, ModuleResult


class OpenRedirectScanner(BaseModule):
    EVIL_DOMAIN = "evil-redir-test.example.com"
    PAYLOADS = [
        f"https://evil-redir-test.example.com",
        f"//evil-redir-test.example.com",
        f"https://evil-redir-test.example.com%2F",
        f"https:evil-redir-test.example.com",
        f"/\\evil-redir-test.example.com",
        f"https://evil-redir-test.example.com%00",
    ]
    PARAMS = ["redirect","next","url","return","returnurl","goto","target","dest",
              "destination","redir","redirect_uri","return_url","callback"]

    def run(self) -> ModuleResult:
        self.log("Açık yönlendirme taraması (paralel)...")

        combos   = [(p, pl) for p in self.PARAMS for pl in self.PAYLOADS]
        urls     = [f"{self.url}?{param}={urllib.parse.quote(payload)}"
                    for param, payload in combos]
        combo_map = dict(zip(urls, combos))

        found    = 0
        reported = set()

        for url, resp in self.parallel_get(urls, max_workers=12):
            param, payload = combo_map[url]
            if param in reported:
                continue

            headers = {k.lower(): v for k, v in resp.get("headers",{}).items()}
            loc     = headers.get("location","")
            fin_url = resp.get("url","")

            if self.EVIL_DOMAIN in loc or (self.EVIL_DOMAIN in fin_url and self.EVIL_DOMAIN != self.host):
                dest = loc or fin_url
                if self.host in dest and self.EVIL_DOMAIN not in dest:
                    continue
                self.add_finding("Açık Yönlendirme",
                    f"Parametre: {param} | Payload: {payload[:50]} | Hedef: {dest[:60]}",
                    "medium", confidence="confirmed",
                    evidence=f"Location: {dest[:200]}")
                found += 1
                reported.add(param)

        self.results["summary"]["Test Edilen Param"] = len(self.PARAMS)
        self.results["summary"]["Açık Yönlendirme"]  = found
        return self.results

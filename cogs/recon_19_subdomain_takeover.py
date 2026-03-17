#!/usr/bin/env python3
"""
Maxima Cog: Subdomain Takeover Check
PERF: DNS resolve + HTTP check paralel (ThreadPoolExecutor)
"""
import os, socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.base_module import BaseModule, ModuleResult


class SubdomainTakeoverCheck(BaseModule):
    DANGLING_PATTERNS = {
        "GitHub Pages":    "There isn't a GitHub Pages site here",
        "Heroku":          "No such app",
        "AWS S3":          "NoSuchBucket",
        "AWS CloudFront":  "ERROR: The request could not be satisfied",
        "Shopify":         "Sorry, this shop is currently unavailable",
        "Tumblr":          "There's nothing here.",
        "Fastly":          "Fastly error: unknown domain",
        "Azure":           "404 Web Site not found",
        "Netlify":         "Not Found - Request ID",
        "Surge.sh":        "project not found",
        "Zendesk":         "Help Center Closed",
    }
    SUBDOMAINS = ["www","mail","blog","api","dev","staging","test","shop",
                  "cdn","static","media","app","beta","secure","portal",
                  "help","support","docs","status"]

    def _has_wildcard_dns(self, domain):
        probe = f"maxima-wildcard-{abs(hash(domain)) % 99999}.{domain}"
        try:
            socket.gethostbyname(probe)
            return True
        except socket.gaierror:
            return False

    def _check_sub(self, sub, domain):
        fqdn = f"{sub}.{domain}"
        try:
            socket.gethostbyname(fqdn)
        except socket.gaierror:
            return None
        resp = self.http_get(f"http://{fqdn}")
        body = resp.get("body","")
        for service, pattern in self.DANGLING_PATTERNS.items():
            if pattern.lower() in body.lower():
                return (fqdn, service)
        return None

    def run(self) -> ModuleResult:
        self.log("Subdomain takeover kontrolü (paralel)...")
        parts  = self.host.split(".")
        domain = ".".join(parts[-2:]) if len(parts) > 2 else self.host

        if self._has_wildcard_dns(domain):
            self.add_finding("Wildcard DNS Aktif",
                f"{domain} için wildcard DNS — takeover testi güvenilir değil.", "info")
            self.results["summary"]["Wildcard DNS"] = "Var"
            return self.results

        hits = 0
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(self._check_sub, sub, domain): sub
                       for sub in self.SUBDOMAINS}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    fqdn, service = result
                    self.add_finding("Subdomain Takeover Riski",
                        f"{fqdn} → {service} sahipsiz hata sayfası", "critical")
                    hits += 1

        self.results["summary"]["Kontrol Edilen"] = len(self.SUBDOMAINS)
        self.results["summary"]["Takeover Adayı"] = hits
        return self.results

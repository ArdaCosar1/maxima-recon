#!/usr/bin/env python3
"""
Maxima Cog: Full Reconnaissance Scan
FIX: resp.get() — KeyError önlendi
"""
import os
from utils.base_module import BaseModule, ModuleResult


class FullReconScan(BaseModule):
    """Full Reconnaissance Scan"""

    def run(self) -> ModuleResult:
        self.log("Tam rekon taraması başlatılıyor...")
        ip = self.resolve_ip()
        if ip:
            self.log(f"IP: {ip}", "success")
            self.results["summary"]["IP"] = ip

        resp   = self.http_get(self.url)
        status = resp.get("status", 0)

        if status > 0:
            self.log(f"HTTP durum: {status}", "success")
            self.results["summary"]["HTTP Status"] = status

            headers = resp.get("headers", {})
            server  = headers.get("Server") or headers.get("server", "")
            powered = headers.get("X-Powered-By") or headers.get("x-powered-by", "")

            if server:
                self.results["summary"]["Server"] = server
                self.add_finding("Sunucu Bilgisi Açık", f"Server: {server}", "low",
                                 confidence="confirmed")
            if powered:
                self.add_finding("Teknoloji Açıklandı", f"X-Powered-By: {powered}", "low",
                                 confidence="confirmed")
        else:
            self.add_finding("Hedefe Ulaşılamadı",
                             f"HTTP yanıtı alınamadı — {resp.get('error','')}", "info",
                             confidence="confirmed")

        self.results["summary"]["Hedef"]        = self.target
        self.results["summary"]["Tarama Zamanı"] = self.results["timestamp"]
        return self.results

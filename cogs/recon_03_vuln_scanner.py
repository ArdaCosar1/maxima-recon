#!/usr/bin/env python3
"""
Maxima Cog: Vulnerability Scanner
FIX:
  - HSTS sadece HTTPS üzerinde kontrol ediliyor
  - X-XSS-Protection deprecated — severity düşürüldü, açıklama güncellendi
  - WordPress/Drupal tespiti daha spesifik imzalarla
  - header check case-insensitive düzeltildi
"""
import os
from utils.base_module import BaseModule, ModuleResult


class VulnerabilityScanner(BaseModule):
    """Vulnerability Scanner"""

    def run(self) -> ModuleResult:
        self.log("Güvenlik açığı taraması...")
        resp    = self.http_get(self.url)
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        is_https = self.url.startswith("https://")

        # ── Güvenlik başlıkları ──
        if is_https and "strict-transport-security" not in headers:
            self.add_finding("HSTS Eksik",
                "HTTPS kullanılmasına rağmen Strict-Transport-Security başlığı yok — MITM riski.",
                "medium", confidence="confirmed")

        if "x-frame-options" not in headers and \
                "frame-ancestors" not in headers.get("content-security-policy", ""):
            self.add_finding("Clickjacking Koruması Yok",
                "X-Frame-Options veya CSP frame-ancestors tanımlı değil.", "medium",
                confidence="confirmed")

        if "x-content-type-options" not in headers:
            self.add_finding("MIME Sniffing Açığı",
                "X-Content-Type-Options: nosniff başlığı eksik.", "low",
                confidence="confirmed")

        if "content-security-policy" not in headers:
            self.add_finding("CSP Eksik",
                "Content-Security-Policy tanımlanmamış — XSS saldırılarına ek savunma yok.", "high",
                confidence="confirmed")

        # X-XSS-Protection deprecated (Chrome 111+) — sadece bilgi
        if "x-xss-protection" not in headers:
            self.add_finding("X-XSS-Protection Eksik (Deprecated)",
                "Bu başlık modern tarayıcılarda etkisizdir. CSP ile koruma sağlayın.", "info",
                confidence="confirmed")

        # ── CMS tespiti — spesifik imzalar ──
        body = resp.get("body", "")
        # WordPress: wp-content/plugins, wp-json/wp/v2 gibi spesifik path'ler
        if '/wp-content/plugins' in body or '/wp-content/themes' in body or \
                '"generator":"WordPress' in body or 'wp-json/wp/v2' in body:
            self.add_finding("WordPress Tespit Edildi",
                "WordPress CMS kullanılıyor — yama durumunu kontrol edin.", "low",
                confidence="firm")

        # Drupal: drupal.js veya Drupal.settings spesifik
        if 'Drupal.settings' in body or '/sites/default/files' in body or \
                '"generator" content="Drupal' in body:
            self.add_finding("Drupal Tespit Edildi",
                "Drupal CMS kullanılıyor — güncel sürümü kontrol edin.", "low",
                confidence="firm")

        self.results["summary"]["HTTPS"] = "Evet" if is_https else "Hayır"
        self.results["summary"]["Kontrol Edilen Başlık"] = 5
        return self.results

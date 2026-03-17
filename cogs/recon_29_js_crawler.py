#!/usr/bin/env python3
"""
Maxima Cog: JavaScript Crawler & Secret Scanner
FIX:
  - "password" pattern çok geniş — placeholder, label, form field'larını yakalar
    Artık value/assignment context zorunlu
  - Bearer token regex daraltıldı — gerçek token formatı
  - secret/key pattern'larına minimum uzunluk ve karakter seti kısıtı eklendi
  - Duplicate findings önlendi
"""
import os, re
from utils.base_module import BaseModule, ModuleResult


class JSCrawlerSecretScanner(BaseModule):
    """JavaScript Crawler & Secret Scanner"""

    SECRET_PATTERNS = {
        # API Key: "apiKey": "..." veya apikey = "..."
        "API Key": re.compile(
            r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', re.I),
        # AWS Access Key
        "AWS Key": re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
        # Private Key başlığı
        "Private Key": re.compile(r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'),
        # JWT token (3 parçalı, gerçek format)
        "JWT": re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'),
        # Şifre: assignment context zorunlu, placeholder/label değil
        "Hardcoded Password": re.compile(
            r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^\'"]{6,50})["\']'
            r'(?!\s*(?:placeholder|label|type|name|id|class))', re.I),
        # Secret: assignment context, uzun değer
        "Secret Key": re.compile(
            r'(?:secret|client_secret|app_secret)\s*[=:]\s*["\']([a-zA-Z0-9_\-+/]{16,})["\']', re.I),
        # Bearer token: Authorization başlığında veya JS'te
        "Bearer Token": re.compile(
            r'["\']?Authorization["\']?\s*[=:]\s*["\']Bearer\s+([A-Za-z0-9\-._~+\/]{20,})["\']', re.I),
        # GitHub token
        "GitHub Token": re.compile(r'\bghp_[A-Za-z0-9]{36}\b|\bgho_[A-Za-z0-9]{36}\b'),
        # Stripe key
        "Stripe Key": re.compile(r'\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b'),
        # Google API key
        "Google API Key": re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b'),
    }

    def run(self) -> ModuleResult:
        self.log("JavaScript tarayıcısı ve sır tespiti...")
        resp = self.http_get(self.url)
        body = resp.get("body", "")

        # JS dosyalarını bul
        js_urls = re.findall(r'src=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', body, re.I)
        all_text = body

        for js_url in js_urls[:8]:
            if not js_url.startswith("http"):
                js_url = self.url.rstrip("/") + "/" + js_url.lstrip("/")
            try:
                js_resp = self.http_get(js_url)
                all_text += "\n" + js_resp.get("body", "")
            except Exception:
                pass

        found_types = set()
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            matches = pattern.findall(all_text)
            if not matches:
                continue
            # Duplicate type önleme
            if secret_type in found_types:
                continue

            # FIX v9: re.findall() grup içerdiğinde tuple listesi döndürür
            # Örnek: [(group1, group2), ...] veya [str, str, ...]
            raw = matches[0]
            if isinstance(raw, tuple):
                # Boş olmayan ilk grubu al
                val = next((g for g in raw if g), "")
            else:
                val = raw

            # Çok kısa değerleri filtrele (placeholder vb.)
            if not val or len(val) < 8:
                continue

            found_types.add(secret_type)
            self.add_finding(
                f"Potansiyel Sır: {secret_type}",
                f"Eşleşme: {str(val)[:80]}",
                "high"
            )
            self.log(f"Sır: {secret_type}", "finding")

        self.results["summary"]["Taranan JS"] = len(js_urls)
        self.results["summary"]["Bulunan Sır"] = len(found_types)
        return self.results

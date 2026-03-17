#!/usr/bin/env python3
"""
Maxima Cog: Payload Fuzzing Engine
FIX:
  - Buffer overflow URL payloadları 414 URI Too Long döndürür — kaldırıldı, body'ye taşındı
  - Format string URL encode sonrası etkisiz — raw POST ile gönderiliyor
  - SSTI: "49" izole kontrolü korundu, ek doğrulama eklendi (payload ham yansıdıysa say)
  - 500 hata baseline kontrolü: sitede zaten 500 varsa raporlanmıyor
"""
import os, re, urllib.parse
from utils.base_module import BaseModule, ModuleResult


class PayloadFuzzingEngine(BaseModule):
    """Payload Fuzzing Engine — gelişmiş false-positive filtresi"""

    FUZZ_PAYLOADS = {
        "Path Traversal":   ["../", "..\\", "%2e%2e/", "....//....//"],
        "Null Byte":        ["%00", "%00.jpg", "file%00"],
        "SSTI":             ["{{7*7}}", "${7*7}", "<%=7*7%>", "#{7*7}"],
        "SQLi Probe":       ["'", "\"", "1 OR 1=1", "'; DROP TABLE users--"],
        "XSS Probe":        ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"],
    }

    BUFFER_OVERFLOW_PAYLOADS = ["A" * 512, "A" * 2048]

    def run(self) -> ModuleResult:
        self.log("Payload fuzzing motoru...")

        # Baseline: normal istek
        baseline = self.http_get(self.url)
        baseline_status = baseline.get("status", 0)
        baseline_body = baseline.get("body", "")
        found = []

        # ── URL-based fuzzing (paralel) ──────────────────────
        # Tüm URL'leri ön-hesapla, meta bilgiyi sakla
        url_meta = []  # [(url, fuzz_type, payload), ...]
        for fuzz_type, payloads in self.FUZZ_PAYLOADS.items():
            for payload in payloads:
                url = f"{self.url}?q={urllib.parse.quote(payload)}&id={urllib.parse.quote(payload)}"
                url_meta.append((url, fuzz_type, payload))

        urls = [u for u, _, _ in url_meta]
        url_to_meta = {u: (ft, p) for u, ft, p in url_meta}

        self.log(f"Paralel tarama: {len(urls)} URL...", "info")
        results_map = {}
        for url, resp in self.parallel_get(urls, max_workers=8):
            results_map[url] = resp

        # Sonuçları sıralı analiz et (type_hit mantığını koru)
        type_hit_set = set()
        for url, fuzz_type, payload in url_meta:
            if fuzz_type in type_hit_set:
                continue
            resp = results_map.get(url, {})
            body = resp.get("body", "")
            status = resp.get("status", 0)

            # 500 sadece baseline farklıysa raporla
            if status >= 500 and baseline_status < 500:
                self.add_finding(
                    f"Server Error: {fuzz_type}",
                    f"Payload: {payload[:40]} → HTTP {status}",
                    "high"
                )
                found.append(fuzz_type)
                type_hit_set.add(fuzz_type)
                continue

            # SSTI: 7*7=49 izole tespit
            if fuzz_type == "SSTI":
                # Ham payload yansıdıysa template işlenmemiş
                if payload in body:
                    continue
                # İzole 49 (word boundary)
                if re.search(r'(?<![0-9])49(?![0-9])', body):
                    # Baseline'da da "49" var mı?
                    if not re.search(r'(?<![0-9])49(?![0-9])', baseline_body):
                        self.add_finding(
                            "Server-Side Template Injection",
                            f"7*7=49 izole yanıtı. Payload: {payload}",
                            "critical"
                        )
                        found.append("SSTI")
                        type_hit_set.add(fuzz_type)

        # ── Buffer overflow POST body (paralel) ─────────────
        bo_requests = [
            (self.url, payload.encode(), {"Content-Type": "application/x-www-form-urlencoded"})
            for payload in self.BUFFER_OVERFLOW_PAYLOADS
        ]
        self.log(f"Paralel tarama: {len(bo_requests)} POST payload...", "info")
        for url, resp in self.parallel_post(bo_requests, max_workers=8):
            try:
                s = resp.get("status", 0)
                if s >= 500 and baseline_status < 500:
                    body_len = len(resp.get("body", ""))
                    self.add_finding(
                        "Buffer Overflow — Server Error",
                        f"POST payload → HTTP {s}",
                        "high"
                    )
                    found.append("BufferOverflow")
                    break
            except Exception:
                pass

        self.results["summary"]["Test Tipi"]       = len(self.FUZZ_PAYLOADS) + 1
        self.results["summary"]["Tetiklenen Hata"] = len(found)
        return self.results

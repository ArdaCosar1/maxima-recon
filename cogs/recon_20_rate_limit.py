#!/usr/bin/env python3
"""
Maxima Cog: Rate Limit & Throttling Analyzer
Çok katmanlı rate limit tespiti: HTTP 429, header analizi,
progresif yük testi, bypass denemeleri, endpoint bazlı analiz.
"""
import time
import threading
from typing import Dict, List, Optional, Tuple
from utils.base_module import BaseModule, ModuleResult


# Test edilecek endpoint'ler (öncelik sırasına göre)
_ENDPOINTS = [
    ("/login",        "Auth",    30),   # (path, category, request_count)
    ("/api/auth",     "Auth",    30),
    ("/api/login",    "Auth",    30),
    ("/api/v1",       "API",     25),
    ("/api",          "API",     25),
    ("/search",       "Search",  20),
    ("/api/users",    "API",     20),
    ("",              "Root",    20),   # root path
]

# Rate limit header'ları
_RATE_HEADERS = {
    "x-ratelimit-limit":     "İzin verilen istek sayısı",
    "x-ratelimit-remaining": "Kalan istek sayısı",
    "x-ratelimit-reset":     "Sıfırlanma zamanı",
    "retry-after":           "Yeniden deneme süresi (sn)",
    "x-rate-limit-limit":    "İzin verilen istek sayısı",
    "x-rate-limit-remaining":"Kalan istek sayısı",
    "ratelimit-limit":       "İzin verilen (draft-ietf)",
    "ratelimit-remaining":   "Kalan (draft-ietf)",
    "ratelimit-reset":       "Sıfırlanma (draft-ietf)",
}

# Bypass header'ları — rate limit atlatma denemeleri
_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "1.2.3.4"},
    {"True-Client-IP": "1.2.3.4"},
]


class RateLimitTester(BaseModule):
    """Rate Limit & Throttling Analyzer"""

    def run(self) -> ModuleResult:
        self.log("Rate limit ve throttling analizi başlatılıyor...")
        base = self.url.rstrip("/")

        # ── 1. Endpoint keşfi — hangileri aktif? ──
        active_endpoints: List[Tuple[str, str, int]] = []
        probe_urls = [base + ep[0] for ep in _ENDPOINTS]
        url_map = {base + ep[0]: ep for ep in _ENDPOINTS}

        for url, resp in self.parallel_get(probe_urls, max_workers=8):
            status = resp.get("status", 0)
            if status > 0 and status != 404:
                ep = url_map[url]
                active_endpoints.append(ep)

        if not active_endpoints:
            active_endpoints = [("", "Root", 20)]

        self.log(f"{len(active_endpoints)} aktif endpoint bulundu", "info")

        # ── 2. Her aktif endpoint'te rate limit testi ──
        total_tested = 0
        rate_limited_eps = 0
        no_limit_eps = 0

        for path, category, req_count in active_endpoints[:5]:  # max 5 endpoint
            url = base + path
            display = path or "/"
            self.log(f"  Test: {display} ({category}) — {req_count} istek...", "info")

            result = self._test_endpoint(url, display, category, req_count)
            total_tested += 1

            if result == "limited":
                rate_limited_eps += 1
            elif result == "no_limit":
                no_limit_eps += 1

        # ── 3. Rate limit header analizi (ilk yanıttan) ──
        self._analyze_rate_headers(base)

        # ── 4. Rate limit bypass denemeleri ──
        if rate_limited_eps > 0:
            self._test_bypass(base + (active_endpoints[0][0] if active_endpoints else ""))

        # ── Özet ──
        self.results["summary"].update({
            "Test Edilen Endpoint": total_tested,
            "Rate Limited":        rate_limited_eps,
            "Korumasız":           no_limit_eps,
        })
        return self.results

    def _test_endpoint(self, url: str, display: str, category: str,
                       req_count: int) -> str:
        """Bir endpoint'e yoğun istek göndererek rate limit davranışını test et."""
        statuses: List[int] = []
        response_times: List[float] = []
        headers_seen: Dict[str, str] = {}
        lock = threading.Lock()

        def _req(idx, ep=url):
            try:
                t0 = time.time()
                resp = self.http_get(ep)
                elapsed = time.time() - t0
                with lock:
                    statuses.append(resp.get("status", 0))
                    response_times.append(elapsed)
                    # Rate limit header'larını topla
                    for h in resp.get("headers", {}):
                        if h.lower() in _RATE_HEADERS:
                            headers_seen[h.lower()] = resp["headers"][h]
            except Exception:
                with lock:
                    statuses.append(0)
                    response_times.append(0)

        # Paralel istek gönder
        threads = [threading.Thread(target=_req, args=(i,)) for i in range(req_count)]
        t_start = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=max(self.timeout + 2, 12))
        total_time = time.time() - t_start

        # Analiz
        valid = [s for s in statuses if s > 0]
        zeros = statuses.count(0)
        rate_codes = [s for s in statuses if s in (429, 503)]

        # Ulaşılamıyor
        if zeros > req_count * 0.7:
            self.log(f"  {display}: ulaşılamıyor ({zeros}/{req_count} timeout)", "warning")
            return "unreachable"

        # Yetersiz yanıt
        if len(valid) < 5:
            self.log(f"  {display}: yetersiz yanıt ({len(valid)}/{req_count})", "warning")
            return "insufficient"

        # Rate limited
        if rate_codes:
            ratio = len(rate_codes) / len(valid) * 100
            self.add_finding(
                f"Rate Limit Aktif: {display}",
                f"Kategori: {category} | {len(rate_codes)}/{len(valid)} istek "
                f"429/503 döndü ({ratio:.0f}%) | Süre: {total_time:.1f}sn",
                "info"
            )
            self.log(f"  {display}: rate limit AKTİF ({len(rate_codes)} × 429)", "success")

            # Header bilgisi
            for h, v in headers_seen.items():
                desc = _RATE_HEADERS.get(h, h)
                self.add_finding(f"Rate Limit Header: {h}",
                                 f"{desc}: {v}", "info")

            self.results["summary"][f"Rate limit — {display}"] = \
                f"AKTİF ({len(rate_codes)}/{len(valid)} × 429)"
            return "limited"

        # Progresif yavaşlama tespiti
        if len(response_times) >= 10:
            first_half = response_times[:len(response_times)//2]
            second_half = response_times[len(response_times)//2:]
            avg_first = sum(first_half) / len(first_half) if first_half else 0
            avg_second = sum(second_half) / len(second_half) if second_half else 0
            if avg_second > avg_first * 2 and avg_second > 1.0:
                self.add_finding(
                    f"Progresif Yavaşlama: {display}",
                    f"İlk yarı ort: {avg_first:.2f}sn → İkinci yarı ort: {avg_second:.2f}sn | "
                    f"Throttling olabilir",
                    "info"
                )
                self.results["summary"][f"Rate limit — {display}"] = \
                    f"THROTTLING ({avg_first:.1f}→{avg_second:.1f}sn)"
                return "throttled"

        # Rate limit header'ı var ama 429 almadık
        if headers_seen:
            remaining = headers_seen.get("x-ratelimit-remaining",
                        headers_seen.get("ratelimit-remaining", ""))
            limit_val = headers_seen.get("x-ratelimit-limit",
                        headers_seen.get("ratelimit-limit", ""))
            info_parts = []
            if limit_val:
                info_parts.append(f"Limit: {limit_val}")
            if remaining:
                info_parts.append(f"Kalan: {remaining}")
            self.add_finding(
                f"Rate Limit Header Mevcut: {display}",
                f"{' | '.join(info_parts)} — ancak {req_count} istekte 429 alınmadı",
                "info"
            )
            self.results["summary"][f"Rate limit — {display}"] = \
                f"HEADER VAR (limit:{limit_val or '?'})"
            return "header_only"

        # Koruma yok
        unique_statuses = sorted(set(valid))
        self.add_finding(
            f"Rate Limit Eksik: {display}",
            f"Kategori: {category} | {len(valid)} geçerli yanıttan "
            f"throttling tespit edilmedi (kodlar: {unique_statuses}) | "
            f"Süre: {total_time:.1f}sn",
            "medium" if category == "Auth" else "low"
        )
        self.log(f"  {display}: rate limit YOK", "warning")
        self.results["summary"][f"Rate limit — {display}"] = "YOK"
        return "no_limit"

    def _analyze_rate_headers(self, base_url: str):
        """İlk yanıttaki rate limit header'larını analiz et."""
        resp = self.http_get(base_url)
        headers = resp.get("headers", {})
        found = False
        for h, v in headers.items():
            if h.lower() in _RATE_HEADERS:
                found = True
                desc = _RATE_HEADERS[h.lower()]
                self.results["summary"][f"Header: {h}"] = v

        if not found:
            self.results["summary"]["Rate Limit Header"] = "Bulunamadı"

    def _test_bypass(self, url: str):
        """Rate limit bypass header'larını dene."""
        self.log("Rate limit bypass denemeleri...", "info")
        bypassed = []

        for bypass_hdr in _BYPASS_HEADERS:
            resp = self.http_get(url, headers=bypass_hdr)
            status = resp.get("status", 0)
            if status in (200, 201, 301, 302):
                hdr_name = list(bypass_hdr.keys())[0]
                hdr_val = list(bypass_hdr.values())[0]
                bypassed.append(f"{hdr_name}: {hdr_val}")

        # Bypass testi: eğer rate limited olduğumuz halde bu header'larla
        # geçebiliyorsak sorun var — ama burada sadece bilgi veriyoruz
        if bypassed:
            self.add_finding(
                "Rate Limit Bypass Header Testi",
                f"Şu header'larla istek kabul edildi: {', '.join(bypassed[:3])}. "
                f"Bunların gerçek bypass olup olmadığı manuel doğrulama gerektirir.",
                "info"
            )

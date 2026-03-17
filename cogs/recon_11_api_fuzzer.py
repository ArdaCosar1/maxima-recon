#!/usr/bin/env python3
"""
Maxima Cog: API Fuzzer (Gelişmiş)
60+ endpoint, parametre fuzzing, Content-Type confusion, auth bypass,
GraphQL introspection, API versioning, CORS, bilgi sızıntısı tespiti.
PERF: Tüm probe'lar paralel.
"""
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.base_module import BaseModule, ModuleResult


class APIFuzzer(BaseModule):

    # ── 60+ API Yolları (kategoriye göre) ─────────────────────
    REST_COMMON = [
        "/api", "/api/v1", "/api/v2", "/api/v3", "/api/users", "/api/user",
        "/api/products", "/api/items", "/api/orders", "/api/search",
        "/api/data", "/api/list", "/api/status", "/api/info",
        "/api/settings", "/api/config", "/api/profile",
    ]
    AUTH_PATHS = [
        "/api/login", "/api/auth", "/api/token", "/api/refresh",
        "/api/register", "/api/oauth", "/api/session", "/api/logout",
        "/api/keys", "/api/apikey", "/api/credentials",
    ]
    ADMIN_PATHS = [
        "/api/admin", "/admin/api", "/api/admin/users", "/api/admin/config",
        "/api/admin/settings", "/api/internal", "/api/manage",
        "/api/console", "/api/dashboard",
    ]
    DEBUG_PATHS = [
        "/api/debug", "/api/test", "/api/dev", "/api/trace",
        "/api/log", "/api/logs", "/debug", "/trace",
    ]
    DOCS_PATHS = [
        "/swagger.json", "/openapi.json", "/api-docs", "/swagger-ui.html",
        "/swagger/v1/swagger.json", "/redoc", "/api/docs", "/api/schema",
    ]
    GRAPHQL_PATHS = ["/graphql", "/graphiql", "/api/graphql", "/gql"]
    HEALTH_METRICS = [
        "/api/health", "/health", "/healthz", "/ready", "/readyz",
        "/metrics", "/api/metrics", "/api/ping", "/api/version",
    ]
    FILE_OPS = ["/api/upload", "/api/download", "/api/files",
                "/api/export", "/api/import", "/api/backup"]
    USER_MGMT = ["/api/users/me", "/api/users/1", "/api/account",
                 "/api/roles", "/api/permissions"]
    PAYMENT = ["/api/payment", "/api/billing", "/api/invoice",
               "/api/checkout", "/api/transactions"]
    CLOUD_METADATA = [
        "http://169.254.169.254/latest/meta-data/",            # AWS
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP
        "http://169.254.169.254/metadata/instance",             # Azure
    ]

    ALL_PATHS = (REST_COMMON + AUTH_PATHS + ADMIN_PATHS + DEBUG_PATHS +
                 DOCS_PATHS + GRAPHQL_PATHS + HEALTH_METRICS + FILE_OPS +
                 USER_MGMT + PAYMENT)

    DANGER_METHODS = ["PUT", "DELETE", "PATCH", "OPTIONS"]
    FUZZ_PARAMS = ["id", "user", "admin", "debug", "test", "token",
                   "key", "page", "limit", "offset", "format", "callback"]
    AUTH_BYPASS_HEADERS = [
        {"X-Forwarded-For": "127.0.0.1"}, {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"}, {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"}, {"X-Real-IP": "127.0.0.1"},
    ]
    INFO_LEAK_KW = ["stack", "trace", "debug", "internal", "password",
                    "secret", "key", "token", "exception", "error_message"]
    CONTENT_TYPES = [
        ("application/json", b'{"test":true}'),
        ("application/xml", b'<test>true</test>'),
        ("application/x-www-form-urlencoded", b'test=true'),
    ]

    # ══════════════════════════════════════════════════════════
    def run(self) -> ModuleResult:
        self.log("Gelişmiş API fuzzing başlatılıyor (paralel)...")
        base = self.url.rstrip("/")

        # ── 1) API Endpoint Keşfi ────────────────────────────
        self.log("Adım 1/7: API endpoint keşfi...")
        urls = [base + p for p in self.ALL_PATHS]
        path_map = {base + p: p for p in self.ALL_PATHS}
        active_urls, found = [], 0

        for url, resp in self.parallel_get(urls, max_workers=12):
            s = resp.get("status", 0)
            if s == 0:
                continue
            path = path_map.get(url, url)
            if s in (200, 201):
                self.add_finding(f"Aktif API: {path}", f"HTTP {s} — açık erişim", "high")
                active_urls.append(url); found += 1
                self._check_info_leak(resp.get("body", ""), path)
            elif s in (400, 401, 403):
                self.add_finding(f"API Endpoint: {path}", f"HTTP {s} — korumalı", "medium")
                found += 1
            elif s == 405:
                self.add_finding(f"API Endpoint: {path}", f"HTTP {s} — metod kısıtlı", "low")
                active_urls.append(url); found += 1

        # ── 2) API Versiyon Keşfi (/api/v1..v10) ────────────
        self.log("Adım 2/7: API versiyon keşfi...")
        ver_urls = [f"{base}/api/v{i}" for i in range(1, 11)]
        ver_map = {u: u.replace(base, "") for u in ver_urls}
        ver_found = 0
        for url, resp in self.parallel_get(ver_urls, max_workers=10):
            s = resp.get("status", 0)
            if s in (200, 201, 301, 302, 403):
                self.add_finding(f"API Versiyon: {ver_map[url]}", f"HTTP {s}", "info")
                ver_found += 1
                if s in (200, 201) and url not in active_urls:
                    active_urls.append(url)

        # ── 3) Tehlikeli Metod Testi ─────────────────────────
        self.log("Adım 3/7: Tehlikeli HTTP metod testi...")
        method_findings = self._test_dangerous_methods(base, active_urls)

        # ── 4) Parametre Fuzzing ─────────────────────────────
        self.log("Adım 4/7: Parametre fuzzing...")
        param_findings = 0
        if active_urls:
            fuzz_urls, fuzz_meta = [], {}
            for url in active_urls[:15]:
                for param in self.FUZZ_PARAMS:
                    sep = "&" if "?" in url else "?"
                    fu = f"{url}{sep}{param}=test123"
                    fuzz_urls.append(fu); fuzz_meta[fu] = (url, param)
            for fu, resp in self.parallel_get(fuzz_urls, max_workers=12):
                s, body = resp.get("status", 0), resp.get("body", "")
                orig_url, param = fuzz_meta.get(fu, (fu, "?"))
                path = orig_url.replace(base, "")
                if s == 200 and "test123" in body:
                    self.add_finding(f"Parametre Yansıması: {path}?{param}",
                                     "Parametre değeri yanıtta yansıyor — XSS/injection riski", "high")
                    param_findings += 1
                elif s == 200 and len(body) > 50:
                    self._check_info_leak(body, f"{path}?{param}")
                    param_findings += 1

        # ── 5) Content-Type Confusion ────────────────────────
        self.log("Adım 5/7: Content-Type confusion testi...")
        ct_findings = 0
        if active_urls:
            post_reqs = []
            for url in active_urls[:10]:
                for ct, bd in self.CONTENT_TYPES:
                    post_reqs.append((url, bd, {"Content-Type": ct}))
            for url, resp in self.parallel_post(post_reqs, max_workers=8):
                s = resp.get("status", 0)
                path = url.replace(base, "")
                if s == 500:
                    self.add_finding(f"Content-Type Confusion: {path}",
                                     "Farklı Content-Type ile 500 — parser confusion olabilir", "medium")
                    ct_findings += 1
                elif s in (200, 201):
                    ct_findings += 1

        # ── 6) Auth Bypass + CORS + GraphQL ──────────────────
        self.log("Adım 6/7: Auth bypass, CORS ve GraphQL probeleri...")
        bypass_findings = self._test_auth_bypass(base, active_urls)
        cors_findings = self._test_cors(active_urls)
        graphql_findings = self._test_graphql(base)

        # ── 7) Cloud Metadata (SSRF tespiti) ─────────────────
        self.log("Adım 7/7: Cloud metadata endpoint kontrolü...")
        cloud_findings = 0
        for url, resp in self.parallel_get(self.CLOUD_METADATA, max_workers=3):
            if resp.get("status", 0) == 200:
                self.add_finding(f"Cloud Metadata Erişimi: {url}",
                                 "Metadata endpoint erişilebilir — SSRF riski", "critical")
                cloud_findings += 1

        # ── Özet ─────────────────────────────────────────────
        s = self.results["summary"]
        s["Taranan Endpoint"] = len(self.ALL_PATHS)
        s["Aktif Endpoint"] = len(active_urls)
        s["Bulunan Endpoint"] = found
        s["API Versiyon"] = ver_found
        s["Tehlikeli Metod"] = method_findings
        s["Parametre Fuzzing"] = param_findings
        s["Content-Type Confusion"] = ct_findings
        s["Auth Bypass"] = bypass_findings
        s["CORS Sorunları"] = cors_findings
        s["GraphQL"] = graphql_findings
        s["Cloud Metadata"] = cloud_findings
        self.log(f"API fuzzing tamamlandı — {len(self.results['findings'])} bulgu", "success")
        return self.results

    # ── Yardımcı: Tehlikeli Metod Testi ──────────────────────
    def _test_dangerous_methods(self, base: str, active_urls: list) -> int:
        count = 0
        reqs = [(u, m) for u in active_urls[:15] for m in self.DANGER_METHODS]
        if not reqs:
            return 0

        def _test(args):
            url, method = args
            return url, method, self._make_request(url, method=method)

        with ThreadPoolExecutor(max_workers=10) as pool:
            futs = {pool.submit(_test, r): r for r in reqs}
            for fut in as_completed(futs):
                try:
                    url, method, r = fut.result()
                    s, path = r.get("status", 0), url.replace(base, "")
                    if method == "OPTIONS":
                        allow = (r.get("headers", {}).get("Allow", "") or
                                 r.get("headers", {}).get("Access-Control-Allow-Methods", ""))
                        if allow:
                            self.add_finding(f"Metod Keşfi: {path}",
                                             f"Desteklenen: {allow}", "info")
                    elif s in (200, 201, 204):
                        self.add_finding(f"Tehlikeli Metod: {method} {path}",
                                         f"HTTP {s} — {method} ile erişim sağlandı", "high")
                        count += 1
                except Exception:
                    pass
        return count

    # ── Yardımcı: Auth Bypass ────────────────────────────────
    def _test_auth_bypass(self, base: str, active_urls: list) -> int:
        count = 0
        targets = [u for u in active_urls
                    if any(k in u for k in ("/admin", "/internal", "/manage", "/console"))]
        if not targets:
            targets = active_urls[:5]
        for url in targets[:8]:
            for hdr in self.AUTH_BYPASS_HEADERS:
                resp = self.http_get(url, headers=hdr)
                if resp.get("status", 0) in (200, 201):
                    hk = list(hdr.keys())[0]
                    self.add_finding(f"Auth Bypass Olasılığı: {url.replace(base, '')}",
                                     f"{hk}: {hdr[hk]} ile erişim — bypass riski", "high")
                    count += 1
        return count

    # ── Yardımcı: CORS Testi ─────────────────────────────────
    def _test_cors(self, active_urls: list) -> int:
        count = 0
        if not active_urls:
            return 0
        for url, resp in self.parallel_get(active_urls[:15], max_workers=10,
                                           headers={"Origin": "https://evil.com"}):
            acao = resp.get("headers", {}).get("Access-Control-Allow-Origin", "")
            path = url.split("//", 1)[-1].split("/", 1)[-1] if "/" in url else url
            if acao == "*":
                self.add_finding(f"CORS Wildcard: /{path}",
                                 "Access-Control-Allow-Origin: * — hassas veri sızabilir", "medium")
                count += 1
            elif "evil.com" in acao:
                self.add_finding(f"CORS Origin Yansıması: /{path}",
                                 "Origin yansıtılıyor — CORS bypass riski", "high")
                count += 1
        return count

    # ── Yardımcı: GraphQL Introspection ──────────────────────
    def _test_graphql(self, base: str) -> int:
        count = 0
        gql_data = json.dumps({"query": "{__schema{types{name}}}"}).encode()
        gql_hdrs = {"Content-Type": "application/json"}
        for gql_path in self.GRAPHQL_PATHS:
            resp = self.http_post(base + gql_path, data=gql_data, headers=gql_hdrs)
            s, body = resp.get("status", 0), resp.get("body", "")
            if s == 200 and "__schema" in body:
                self.add_finding(f"GraphQL Introspection Açık: {gql_path}",
                                 "Schema bilgileri ifşa — tüm API yapısı görünür", "high")
                count += 1
            elif s == 200:
                self.add_finding(f"GraphQL Aktif: {gql_path}",
                                 "GraphQL endpoint erişilebilir", "medium")
                count += 1
        return count

    # ── Yardımcı: Bilgi Sızıntısı Tespiti ───────────────────
    def _check_info_leak(self, body: str, path: str) -> None:
        if not body:
            return
        bl = body.lower()
        leaked = [kw for kw in self.INFO_LEAK_KW if kw in bl]
        if leaked:
            self.add_finding(f"Bilgi Sızıntısı: {path}",
                             f"Hassas anahtar kelimeler: {', '.join(leaked[:5])}", "medium")

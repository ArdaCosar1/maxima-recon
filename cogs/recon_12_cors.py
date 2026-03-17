#!/usr/bin/env python3
"""
Maxima Cog: CORS Misconfiguration Scanner
FIX: Wildcard * artık tek başına kritik değil (credentials olmadan güvenli),
     CORS olmayan yanıtlarda false-positive önlendi
v11.1: Remediation önerileri + evidence eklendi
"""
import sys, os
from utils.base_module import BaseModule, ModuleResult

_CORS_REM = ("Access-Control-Allow-Origin header'ını güvenilir domainlerle sınırlayın. "
             "Wildcard (*) yerine spesifik origin kullanın. "
             "Allow-Credentials: true kullanıyorsanız origin'i dinamik whitelist ile doğrulayın.")

class CORSScanner(BaseModule):
    """CORS Misconfiguration Scanner — false-positive azaltılmış"""

    TEST_ORIGINS = [
        "https://evil.com",
        "null",
        "https://attacker.com",
        "https://evil.sub.TARGET.com",  # Subdomain bypass
        "https://TARGET.evil.com",      # Prefix bypass
    ]

    def run(self) -> ModuleResult:
        self.log("CORS yanlış yapılandırma taraması...")
        hits = 0

        for origin_tpl in self.TEST_ORIGINS:
            origin = origin_tpl.replace("TARGET", self.host)
            resp   = self.http_get(self.url, headers={"Origin": origin})
            acao   = (resp.get("headers", {}).get("Access-Control-Allow-Origin", "") or
                      resp.get("headers", {}).get("access-control-allow-origin", ""))
            acac   = (resp.get("headers", {}).get("Access-Control-Allow-Credentials", "") or
                      resp.get("headers", {}).get("access-control-allow-credentials", ""))

            credentials = acac.strip().lower() == "true"
            ev = f"Origin: {origin} → ACAO: {acao}, ACAC: {acac}"

            if acao == "*":
                if credentials:
                    self.add_finding(
                        "CORS Yanlış Yapılandırma — Wildcard + Credentials",
                        "Access-Control-Allow-Origin: * ile Allow-Credentials: true "
                        "geçersiz kombinasyon (tarayıcılar reddeder ama sunucu yanlış ayarlı)",
                        "medium", remediation=_CORS_REM, evidence=ev)
                else:
                    self.add_finding(
                        "CORS Wildcard (*) Tespit Edildi",
                        "Tüm originlere izin veriliyor. Public API ise normaldir; "
                        "kimlik doğrulama gerektiren endpoint'lerde risk oluşturur.",
                        "low", evidence=ev)
                hits += 1

            elif acao == origin and origin != "null":
                if credentials:
                    self.add_finding(
                        "CORS Kritik — Origin Yansıtma + Credentials",
                        f"Saldırgan origin yansıtılıyor ({origin}) ve "
                        f"Allow-Credentials: true — kimlik bilgileri çalınabilir",
                        "critical", remediation=_CORS_REM, evidence=ev)
                else:
                    self.add_finding(
                        "CORS — Origin Yansıtma (Credentials Yok)",
                        f"Origin yansıtılıyor: {origin}. "
                        f"Credentials olmadan düşük risk, dikkat önerilir.",
                        "medium", remediation=_CORS_REM, evidence=ev)
                hits += 1

            elif acao == "null":
                if credentials:
                    self.add_finding(
                        "CORS — null Origin + Credentials",
                        "null origin kabul ediliyor ve credentials aktif — "
                        "sandboxed iframe saldırısına açık",
                        "high",
                        remediation="null origin'i ACAO whitelist'inden kaldırın. "
                                    "Credentials ile null origin asla kabul edilmemeli.",
                        evidence=ev)
                    hits += 1

        self.results["summary"]["Test Edilen Origin"] = len(self.TEST_ORIGINS)
        self.results["summary"]["CORS Bulgusu"]       = hits
        return self.results

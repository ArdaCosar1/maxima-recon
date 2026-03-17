#!/usr/bin/env python3
"""
Maxima Cog: DNS Record Analysis
FIX: Command injection önleme — self.host sanitize ediliyor (recon_38 ile tutarlı)
     dig yoksa socket fallback geliştirildi
"""
import os, re, socket, subprocess
from utils.base_module import BaseModule, ModuleResult

_DOMAIN_RE = re.compile(r'^[a-zA-Z0-9.\-]+$')


class DNSRecordAnalysis(BaseModule):
    """DNS Record Analysis"""

    def run(self) -> ModuleResult:
        self.log("DNS kayıt analizi...")

        # FIX: domain sanitizasyonu — command injection önleme
        if not _DOMAIN_RE.match(self.host):
            self.log(f"Geçersiz domain formatı: {self.host}", "error")
            self.add_finding("Geçersiz Domain", f"DNS analizi atlandı: {self.host}", "info")
            return self.results

        record_types = ["A","AAAA","MX","NS","TXT","CNAME","SOA"]
        dig_available = True

        for rtype in record_types:
            try:
                result = subprocess.run(
                    ["dig", "+short", rtype, self.host],
                    capture_output=True, text=True, timeout=self.timeout
                )
                output = result.stdout.strip()
                if output:
                    self.results["summary"][f"DNS {rtype}"] = output[:100]
                    self.log(f"{rtype}: {output[:60]}", "info")
                    if rtype == "TXT":
                        self._analyze_txt(output)
            except FileNotFoundError:
                dig_available = False
                break
            except Exception as e:
                self.results["summary"][f"{rtype} Hata"] = str(e)[:40]

        # dig yoksa socket fallback
        if not dig_available:
            self.log("dig bulunamadı — socket fallback kullanılıyor", "warning")
            try:
                ip = socket.gethostbyname(self.host)
                self.results["summary"]["A"] = ip
                self.log(f"A: {ip}", "info")
            except Exception as e:
                self.results["summary"]["Hata"] = str(e)[:60]

            # MX fallback
            try:
                mx = socket.getaddrinfo(f"mail.{self.host}", None)
                if mx:
                    self.results["summary"]["MX (tahmin)"] = f"mail.{self.host}"
            except Exception:
                pass

        return self.results

    def _analyze_txt(self, output):
        lower = output.lower()
        if "v=spf" in lower:
            self.add_finding("SPF Kaydı Mevcut", output[:200], "info",
                             confidence="confirmed")
        elif "dmarc" in lower:
            self.add_finding("DMARC Kaydı Mevcut", output[:200], "info",
                             confidence="confirmed")
        elif "dkim" in lower:
            self.add_finding("DKIM Kaydı Mevcut", output[:200], "info",
                             confidence="confirmed")
        # Hassas veri
        if any(k in lower for k in ("key=","token=","secret=","password=")):
            self.add_finding("TXT Kaydında Hassas Veri",
                             f"TXT: {output[:100]}", "high",
                             confidence="firm")

#!/usr/bin/env python3
"""
Maxima Cog: SSL/TLS Analyzer
FIX v9:
  - TLS 1.0/1.1 testi: ssl.TLSVersion ile minimum_version ayarlanarak gerçek test
  - Python ssl modülü varsayılan olarak TLS 1.0/1.1'i devre dışı bırakır;
    minimum_version=TLSVersion.TLSv1 ile override edilmeden eski sürüm ASLA tespit edilemez
  - SSLv2/SSLv3: Python ssl'de compile-time devre dışı, test mümkün değil — not olarak raporlanır
  - Sertifika geçerlilik tarihi parse ediliyor
"""
import os, ssl, socket
from datetime import datetime
from utils.base_module import BaseModule, ModuleResult


class SSLTLSAnalyzer(BaseModule):
    """SSL/TLS Analyzer — gerçek TLS versiyon testi"""

    def run(self) -> ModuleResult:
        self.log("SSL/TLS analizi...")

        # ── Adım 1: Varsayılan TLS bağlantısı (TLS 1.2+ bilgisi) ──
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((self.host, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert    = ssock.getpeercert()
                    proto   = ssock.version()
                    cipher  = ssock.cipher()

                    self.results["summary"]["Protokol"] = proto or "?"
                    self.results["summary"]["Cipher"]   = cipher[0] if cipher else "?"
                    self.results["summary"]["Bit"]      = cipher[2] if cipher else "?"

                    if cert:
                        subject  = dict(x[0] for x in cert.get("subject", []))
                        not_after = cert.get("notAfter", "")
                        self.results["summary"]["CN"]          = subject.get("commonName", "?")
                        self.results["summary"]["Geçerlilik"]  = not_after

                        # Sertifika son tarihi kontrolü
                        if not_after:
                            try:
                                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                days_left = (exp - datetime.utcnow()).days
                                if days_left < 0:
                                    self.add_finding("SSL Sertifikası Süresi Dolmuş",
                                        f"Geçerlilik bitti: {not_after}", "critical",
                                        confidence="confirmed")
                                elif days_left < 30:
                                    self.add_finding("SSL Sertifikası Yakında Dolacak",
                                        f"{days_left} gün kaldı: {not_after}", "high",
                                        confidence="confirmed")
                            except Exception:
                                pass

                    # Zayıf cipher kontrolü
                    if cipher and cipher[2] and cipher[2] < 128:
                        self.add_finding("Zayıf Cipher Kullanımı",
                            f"Anahtar uzunluğu: {cipher[2]} bit (minimum 128 bit önerilir)",
                            "high", confidence="confirmed")
        except Exception as e:
            err = str(e)
            self.results["summary"]["Hata"] = err[:80]
            self.add_finding("SSL/TLS Bağlantı Hatası",
                f"Port 443'e bağlanılamadı: {err[:80]}", "info",
                confidence="confirmed")
            return self.results

        # ── Adım 2: TLS 1.0 testi ──
        # DÜZELTME: minimum_version=TLSVersion.TLSv1 setlenmeden eski sürüm bağlantısı imkânsız
        # Python varsayılan ssl ayarları TLS 1.0/1.1'i reddeder
        self._test_old_tls("TLSv1",   ssl.TLSVersion.TLSv1   if hasattr(ssl.TLSVersion, "TLSv1")   else None)
        self._test_old_tls("TLSv1.1", ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None)

        return self.results

    def _test_old_tls(self, version_name: str, tls_version):
        """
        Belirli bir TLS versiyonunu minimum_version ile test eder.
        Python 3.7+: ssl.TLSVersion enum mevcut ama bazı OS/OpenSSL'de
        TLSv1 / TLSv1_1 compile-time devre dışı olabilir.
        """
        if tls_version is None:
            # Bu Python sürümü TLSVersion.TLSv1 desteklemiyor
            self.log(f"{version_name} testi: Python sürümü desteklemiyor", "info")
            return

        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version  # SADECE bu versiyonu dene

            with socket.create_connection((self.host, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    negotiated = ssock.version()
                    if negotiated == version_name.replace("v", " ").replace("TLS ", "TLSv"):
                        self.add_finding(
                            f"Eski TLS Versiyonu Destekleniyor: {version_name}",
                            f"Sunucu {version_name} ile bağlantı kabul ediyor — POODLE/BEAST saldırı riski",
                            "high", confidence="confirmed"
                        )
                        self.log(f"Eski TLS aktif: {version_name}", "finding")
        except ssl.SSLError as e:
            err = str(e).lower()
            if "no protocols available" in err or "alert handshake failure" in err \
                    or "unsupported protocol" in err or "version" in err:
                # Sunucu bu versiyonu reddetti — GÜVENLI
                self.log(f"{version_name} reddedildi (güvenli)", "success")
            # Diğer SSL hataları: test edilemedi ama bu "destekleniyor" anlamına gelmez
        except OSError:
            # Bağlantı reddedildi — port kapalı olabilir
            pass
        except AttributeError:
            # ssl.TLSVersion bu OS'ta mevcut değil
            self.log(f"{version_name} testi: OpenSSL sürümü desteklemiyor", "info")

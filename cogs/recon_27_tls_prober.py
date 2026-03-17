#!/usr/bin/env python3
"""
Maxima Cog: TLS Version Prober
FIX v9:
  - PROTOCOL_TLS_CLIENT varsayılan olarak TLS 1.0/1.1 bağlantısını reddeder
  - minimum_version + maximum_version = TLSVersion.X ile gerçek versiyon testi
  - "supported" listesi gerçekten negotiate edilen versiyonları gösteriyor
  - SSLv2/SSLv3: Python ssl'de compile-time kapalı, test edilemez — not eklendi
"""
import os, ssl, socket
from utils.base_module import BaseModule, ModuleResult


class TLSVersionProber(BaseModule):
    """TLS Version Prober — gerçek min/max version testi"""

    # (isim, TLSVersion attr adı, eski mi?)
    VERSIONS_TO_TEST = [
        ("TLS 1.3",  "TLSv1_3",  False),
        ("TLS 1.2",  "TLSv1_2",  False),
        ("TLS 1.1",  "TLSv1_1",  True),
        ("TLS 1.0",  "TLSv1",    True),
    ]

    def run(self) -> ModuleResult:
        self.log("TLS versiyon analizi (gerçek min/max testi)...")
        supported = []
        unsupported = []

        for name, attr_name, is_legacy in self.VERSIONS_TO_TEST:
            tls_ver = getattr(ssl.TLSVersion, attr_name, None)
            if tls_ver is None:
                self.log(f"{name}: Python/OpenSSL bu sürümde mevcut değil", "info")
                continue

            result = self._test_version(name, tls_ver)
            if result == "supported":
                supported.append(name)
                if is_legacy:
                    self.add_finding(
                        f"Eski TLS Versiyonu Aktif: {name}",
                        f"Sunucu {name} ile bağlantıyı kabul ediyor. "
                        f"POODLE, BEAST, SWEET32 saldırı riski. TLS 1.2+ tercih edin.",
                        "high"
                    )
                    self.log(f"Eski TLS aktif: {name}", "finding")
                else:
                    self.log(f"{name} destekleniyor", "success")
            elif result == "rejected":
                unsupported.append(name)
                self.log(f"{name} reddedildi (güvenli)", "success")
            else:
                # test edilemedi (hata)
                self.log(f"{name} test edilemedi: {result}", "warning")

        # SSLv2/SSLv3: Python stdlib'de her zaman devre dışı — bilgi notu
        self.log("SSLv2/SSLv3: Python ssl modülü compile-time kapalı, test edilemez", "info")
        self.results["summary"]["Desteklenen"]   = ", ".join(supported) or "Hiç bağlantı kurulamadı"
        self.results["summary"]["Reddedilen"]    = ", ".join(unsupported) or "—"
        self.results["summary"]["SSLv2/v3 Test"] = "Python ssl modülünde mümkün değil"
        return self.results

    def _test_version(self, name: str, tls_version: ssl.TLSVersion) -> str:
        """
        Döndürür:
          "supported" — sunucu bu versiyon ile bağlantı kabul etti
          "rejected"  — sunucu reddetti (handshake hatası)
          str(hata)   — başka bir hata
        """
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version

            with socket.create_connection((self.host, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host):
                    return "supported"

        except ssl.SSLError as e:
            err = str(e).lower()
            if any(k in err for k in ("handshake failure", "unsupported protocol",
                                       "no protocols available", "alert", "version")):
                return "rejected"
            return f"ssl_error: {str(e)[:60]}"
        except OSError:
            return "rejected"   # Bağlantı reddedildi
        except AttributeError as e:
            return f"not_supported: {e}"

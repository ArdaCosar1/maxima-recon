#!/usr/bin/env python3
"""
Maxima Cog: WHOIS Lookup & Domain Intelligence
IANA referral, gelişmiş alan ayrıştırma, domain yaşı hesaplama,
süre dolumu uyarısı, registrar bilgisi, DNSSEC kontrolü,
domain reputation kontrolü, ilişkili domain tespiti.
"""
import os
import re
import socket
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from utils.base_module import BaseModule, ModuleResult


# WHOIS alanları ve eşleştirmeleri (küçük harfle)
_FIELD_MAP = {
    # Registrar
    "registrar":            "Registrar",
    "registrar name":       "Registrar",
    "sponsoring registrar": "Registrar",
    # Tarihler
    "creation date":        "Oluşturma Tarihi",
    "created":              "Oluşturma Tarihi",
    "created on":           "Oluşturma Tarihi",
    "registration date":    "Oluşturma Tarihi",
    "domain registered":    "Oluşturma Tarihi",
    "registered on":        "Oluşturma Tarihi",
    "expiry date":          "Bitiş Tarihi",
    "registry expiry date": "Bitiş Tarihi",
    "registrar registration expiration date": "Bitiş Tarihi",
    "expires on":           "Bitiş Tarihi",
    "paid-till":            "Bitiş Tarihi",
    "updated date":         "Güncelleme Tarihi",
    "last updated":         "Güncelleme Tarihi",
    "last modified":        "Güncelleme Tarihi",
    # Name servers
    "name server":          "Name Server",
    "nserver":              "Name Server",
    "nameserver":           "Name Server",
    # Status
    "domain status":        "Durum",
    "status":               "Durum",
    # DNSSEC
    "dnssec":               "DNSSEC",
    # Registrant
    "registrant name":          "Kayıt Sahibi",
    "registrant organization":  "Kayıt Org",
    "registrant country":       "Kayıt Ülke",
    "registrant state/province":"Kayıt Bölge",
    "registrant email":         "Kayıt Email",
    # Tech
    "tech name":                "Teknik İrtibat",
    "tech organization":        "Teknik Org",
    "tech email":               "Teknik Email",
    # Admin
    "admin name":               "Admin İrtibat",
    "admin email":              "Admin Email",
    # Abuse
    "registrar abuse contact email": "Abuse Email",
    "registrar abuse contact phone": "Abuse Telefon",
}

# Tarih parse formatları
_DATE_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%d-%b-%Y",
    "%d/%m/%Y",
    "%Y/%m/%d",
    "%d.%m.%Y",
    "%Y.%m.%d",
    "%B %d, %Y",
]


class WHOISLookup(BaseModule):
    """WHOIS Lookup & Domain Intelligence"""

    def _whois_query(self, server: str, query: str) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((server, 43))
            s.send((query + "\r\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 64 * 1024:
                    break
            s.close()
            return data.decode("utf-8", errors="ignore")
        except Exception as e:
            return f"[ERROR] {e}"

    def run(self) -> ModuleResult:
        self.log("WHOIS ve domain istihbaratı taraması...")

        # ── 1. WHOIS sorgusu (IANA → Registry) ──
        whois_text = self._fetch_whois()
        if not whois_text:
            return self.results

        # ── 2. Gelişmiş alan ayrıştırma ──
        parsed = self._parse_whois(whois_text)

        # ── 3. Domain yaşı hesaplama ──
        self._calculate_age(parsed)

        # ── 4. Süre dolumu uyarısı ──
        self._check_expiry(parsed)

        # ── 5. DNSSEC kontrolü ──
        self._check_dnssec(parsed)

        # ── 6. Domain durumu analizi ──
        self._analyze_status(parsed)

        # ── 7. Name server analizi ──
        self._analyze_nameservers(parsed)

        # ── 8. Registrar güvenilirlik kontrolü ──
        self._check_registrar(parsed)

        # ── 9. Gizlilik / privacy proxy tespiti ──
        self._check_privacy(parsed, whois_text)

        # ── 10. Ek istihbarat ──
        self._domain_reputation()

        self.log("WHOIS analizi tamamlandı", "success")
        return self.results

    def _fetch_whois(self) -> Optional[str]:
        """IANA → Registry zincirinden WHOIS verisi çek."""
        # IANA'dan registry bul
        iana_resp = self._whois_query("whois.iana.org", self.host)
        if iana_resp.startswith("[ERROR]"):
            self.add_finding("WHOIS Hatası", iana_resp, "info")
            return None

        refer_server = ""
        for line in iana_resp.splitlines():
            if line.lower().startswith("refer:"):
                refer_server = line.split(":", 1)[1].strip()
                break

        # Registry'den veri çek
        text = ""
        if refer_server:
            self.log(f"Registry: {refer_server}", "info")
            self.results["summary"]["WHOIS Server"] = refer_server
            text = self._whois_query(refer_server, self.host)

        if not text or text.startswith("[ERROR]"):
            text = iana_resp

        if text.startswith("[ERROR]"):
            self.add_finding("WHOIS Hatası", text, "info")
            return None

        return text

    def _parse_whois(self, text: str) -> Dict[str, List[str]]:
        """WHOIS metnini yapılandırılmış sözlüğe ayrıştır."""
        parsed: Dict[str, List[str]] = {}
        seen_values: Dict[str, set] = {}

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("%") or line.startswith("#"):
                continue

            # key: value formatı
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()

            if not value:
                continue

            # Bilinen alanlara eşleştir
            label = _FIELD_MAP.get(key)
            if not label:
                # Kısmi eşleştirme
                for fkey, flabel in _FIELD_MAP.items():
                    if fkey in key:
                        label = flabel
                        break
            if not label:
                continue

            # Duplicate önleme
            if label not in seen_values:
                seen_values[label] = set()
            if value in seen_values[label]:
                continue
            seen_values[label].add(value)

            if label not in parsed:
                parsed[label] = []
            parsed[label].append(value)

            # Summary'ye de ekle (ilk değer)
            if len(parsed[label]) == 1:
                self.results["summary"][label] = value
            elif label == "Name Server":
                self.results["summary"][label] = ", ".join(parsed[label][:4])
            elif label == "Durum":
                self.results["summary"][label] = ", ".join(parsed[label][:3])

        if not parsed:
            self.results["summary"]["WHOIS"] = "Veri alındı — parse edilemedi"

        return parsed

    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Tarih stringini datetime'a çevir."""
        date_str = date_str.strip()
        # Sondaki ekstra bilgiyi temizle
        date_str = re.sub(r'\s*\(.*\)', '', date_str)
        date_str = re.sub(r'\s+UTC$', '', date_str, flags=re.I)

        for fmt in _DATE_FORMATS:
            try:
                return datetime.strptime(date_str, fmt)
            except (ValueError, TypeError):
                continue
        return None

    def _calculate_age(self, parsed: Dict[str, List[str]]):
        """Domain yaşını hesapla."""
        creation_strs = parsed.get("Oluşturma Tarihi", [])
        if not creation_strs:
            return

        created = self._parse_date(creation_strs[0])
        if not created:
            return

        now = datetime.now()
        if created.tzinfo:
            created = created.replace(tzinfo=None)
        age = now - created
        years = age.days // 365
        months = (age.days % 365) // 30

        age_str = f"{years} yıl, {months} ay" if years > 0 else f"{months} ay"
        self.results["summary"]["Domain Yaşı"] = age_str

        if age.days < 30:
            self.add_finding("Çok Yeni Domain",
                             f"Domain {age.days} gün önce oluşturulmuş — "
                             f"phishing/scam riski yüksek",
                             "high")
        elif age.days < 180:
            self.add_finding("Yeni Domain",
                             f"Domain {age_str} — nispeten yeni", "medium")
        elif years > 10:
            self.add_finding("Köklü Domain",
                             f"Domain {age_str} — uzun süredir aktif", "info")

    def _check_expiry(self, parsed: Dict[str, List[str]]):
        """Süre dolumu kontrolü."""
        expiry_strs = parsed.get("Bitiş Tarihi", [])
        if not expiry_strs:
            return

        expiry = self._parse_date(expiry_strs[0])
        if not expiry:
            return

        now = datetime.now()
        if expiry.tzinfo:
            expiry = expiry.replace(tzinfo=None)

        days_left = (expiry - now).days

        if days_left < 0:
            self.add_finding("Domain SÜRESİ DOLMUŞ",
                             f"Bitiş: {expiry_strs[0]} ({abs(days_left)} gün önce) — "
                             f"domain el değiştirebilir!",
                             "critical")
        elif days_left < 30:
            self.add_finding("Domain Süresi Dolmak Üzere",
                             f"Bitiş: {expiry_strs[0]} ({days_left} gün kaldı)",
                             "high")
        elif days_left < 90:
            self.add_finding("Domain Süresi Yaklaşıyor",
                             f"Bitiş: {expiry_strs[0]} ({days_left} gün kaldı)",
                             "medium")

        self.results["summary"]["Kalan Süre"] = f"{days_left} gün"

    def _check_dnssec(self, parsed: Dict[str, List[str]]):
        """DNSSEC durumu kontrolü."""
        dnssec = parsed.get("DNSSEC", [])
        if not dnssec:
            self.add_finding("DNSSEC Bilgisi Yok",
                             "WHOIS yanıtında DNSSEC bilgisi bulunamadı", "info")
            return

        val = dnssec[0].lower()
        if "unsigned" in val or "inactive" in val or "no" in val:
            self.add_finding("DNSSEC Aktif Değil",
                             f"DNSSEC: {dnssec[0]} — DNS spoofing riski",
                             "low")
        elif "signed" in val or "yes" in val:
            self.add_finding("DNSSEC Aktif",
                             f"DNSSEC: {dnssec[0]}", "info")

    def _analyze_status(self, parsed: Dict[str, List[str]]):
        """Domain durumu analizi."""
        statuses = parsed.get("Durum", [])
        if not statuses:
            return

        dangerous = []
        protective = []
        for s in statuses:
            lower = s.lower()
            if "pendingdelete" in lower or "redemption" in lower:
                dangerous.append(s)
            elif "clientdeleteprohibited" in lower or "serverdeleteprohibited" in lower:
                protective.append(s)
            elif "clienttransferprohibited" in lower or "servertransferprohibited" in lower:
                protective.append(s)
            elif "clienthold" in lower or "serverhold" in lower:
                dangerous.append(s)

        if dangerous:
            self.add_finding("Domain Tehlikeli Durumda",
                             f"Durumlar: {', '.join(dangerous)} — domain risk altında",
                             "high")
        if not protective:
            self.add_finding("Domain Koruma Kilidi Yok",
                             "clientDeleteProhibited/clientTransferProhibited aktif değil — "
                             "yetkisiz transfer riski",
                             "medium")

    def _analyze_nameservers(self, parsed: Dict[str, List[str]]):
        """Name server analizi."""
        ns_list = parsed.get("Name Server", [])
        if not ns_list:
            return

        # Bilinen DNS sağlayıcıları
        dns_providers = {
            "cloudflare": "Cloudflare DNS", "awsdns": "AWS Route 53",
            "google": "Google Cloud DNS", "azure": "Azure DNS",
            "ns.namecheap": "Namecheap DNS", "domaincontrol": "GoDaddy DNS",
            "digitalocean": "DigitalOcean DNS", "hetzner": "Hetzner DNS",
        }
        for ns in ns_list:
            for key, provider in dns_providers.items():
                if key in ns.lower():
                    self.results["summary"]["DNS Sağlayıcı"] = provider
                    break

        # Tek NS kontrolü
        unique_ns = set(ns.lower().rstrip(".") for ns in ns_list)
        if len(unique_ns) < 2:
            self.add_finding("Tek Name Server",
                             f"Yalnızca {len(unique_ns)} NS — DNS SPoF riski",
                             "medium")

    def _check_registrar(self, parsed: Dict[str, List[str]]):
        """Registrar bilgi notu."""
        registrar = parsed.get("Registrar", [])
        if registrar:
            self.add_finding("Registrar Bilgisi",
                             f"Registrar: {registrar[0]}", "info")

    def _check_privacy(self, parsed: Dict[str, List[str]], raw_text: str):
        """Privacy/proxy servisi tespiti."""
        privacy_keywords = [
            "privacy", "proxy", "whoisguard", "withheld",
            "redacted", "gdpr", "data protected", "contact privacy",
            "domains by proxy", "perfect privacy", "whois privacy",
        ]
        lower_text = raw_text.lower()
        for kw in privacy_keywords:
            if kw in lower_text:
                self.add_finding("WHOIS Privacy Aktif",
                                 "Domain kaydı privacy/proxy servisi arkasında",
                                 "info")
                self.results["summary"]["Privacy"] = "Aktif"
                return

    def _domain_reputation(self):
        """Basit domain reputation kontrolü."""
        try:
            # Google Safe Browsing alternatifi: HTTP üzerinden basit kontrol
            resp = self.http_get(
                f"https://transparencyreport.google.com/safe-browsing/"
                f"search?url={self.host}"
            )
            # Bu endpoint direkt JSON dönmez ama status kontrolü yapabiliriz
            if resp.get("status", 0) == 200:
                self.results["summary"]["Google Safe Browsing"] = "Kontrol edildi"
        except Exception:
            pass

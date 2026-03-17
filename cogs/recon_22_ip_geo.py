#!/usr/bin/env python3
"""
Maxima Cog: IP Geolocation & Network Intelligence
IP coğrafi konum, ASN bilgisi, hosting/CDN tespiti,
reverse DNS, abuse contact, blacklist kontrolü.
"""
import json
import os
import socket
import re
from typing import Dict, List, Optional
from utils.base_module import BaseModule, ModuleResult


# Bilinen CDN/hosting IP aralıkları (ASN bazlı tespit)
_CDN_ASNS = {
    "AS13335": "Cloudflare", "AS20940": "Akamai", "AS54113": "Fastly",
    "AS16509": "AWS CloudFront", "AS8075": "Microsoft Azure",
    "AS15169": "Google Cloud", "AS396982": "Google Cloud",
    "AS14618": "AWS", "AS16276": "OVH", "AS24940": "Hetzner",
    "AS63949": "Linode/Akamai", "AS14061": "DigitalOcean",
    "AS46606": "DigitalOcean", "AS36352": "ColoCrossing",
    "AS397213": "Cloudflare Workers", "AS209242": "Cloudflare",
}

# Bilinen hosting sağlayıcıları (org adına göre)
_HOSTING_KEYWORDS = {
    "amazon": "AWS", "google": "Google Cloud", "microsoft": "Azure",
    "digitalocean": "DigitalOcean", "linode": "Linode", "vultr": "Vultr",
    "hetzner": "Hetzner", "ovh": "OVH", "cloudflare": "Cloudflare",
    "akamai": "Akamai", "fastly": "Fastly", "rackspace": "Rackspace",
    "godaddy": "GoDaddy", "hostgator": "HostGator", "bluehost": "Bluehost",
    "dreamhost": "DreamHost", "namecheap": "Namecheap",
    "ionos": "IONOS", "scaleway": "Scaleway", "upcloud": "UpCloud",
    "contabo": "Contabo", "kamatera": "Kamatera",
}

# Özel/rezerve IP aralıkları
_PRIVATE_RANGES = [
    (r"^10\.",           "RFC 1918 — Özel"),
    (r"^172\.(1[6-9]|2[0-9]|3[01])\.", "RFC 1918 — Özel"),
    (r"^192\.168\.",     "RFC 1918 — Özel"),
    (r"^127\.",          "Loopback"),
    (r"^169\.254\.",     "Link-Local"),
    (r"^0\.",            "Geçersiz/Özel"),
    (r"^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.", "RFC 6598 — CGN"),
]


class IPGeolocation(BaseModule):
    """IP Geolocation & Network Intelligence"""

    # Basit in-memory + dosya önbellek — API çökerse son bilinen veriyi kullan
    _geo_cache: Dict = {}
    _CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".geo_cache.json")

    @classmethod
    def _load_cache(cls):
        if cls._geo_cache:
            return
        try:
            with open(cls._CACHE_FILE, "r", encoding="utf-8") as f:
                cls._geo_cache = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            cls._geo_cache = {}

    @classmethod
    def _save_cache(cls, ip: str, data: Dict):
        cls._geo_cache[ip] = data
        try:
            with open(cls._CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(cls._geo_cache, f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def run(self) -> ModuleResult:
        self.log("IP coğrafi konum ve ağ istihbaratı taraması...")

        # ── 1. DNS çözümleme ──
        ip = self.resolve_ip()
        if not ip:
            self.add_finding("IP Çözümlenemedi", f"Hedef: {self.host}", "medium")
            return self.results

        self.results["summary"]["IP"] = ip
        self.log(f"IP: {ip}", "info")

        # Özel IP kontrolü
        for pattern, desc in _PRIVATE_RANGES:
            if re.match(pattern, ip):
                self.add_finding("Özel/Rezerve IP",
                                 f"{ip} — {desc}", "info")
                self.results["summary"]["Not"] = desc
                return self.results

        # ── 2. ipinfo.io — ana veri kaynağı ──
        geo_data = self._ipinfo_lookup(ip)

        # ── 3. Ek reverse DNS ──
        self._reverse_dns(ip)

        # ── 4. CDN/Hosting tespiti ──
        self._detect_hosting(ip, geo_data)

        # ── 5. HTTP header'larından ek bilgi ──
        self._analyze_server_headers()

        # ── 6. Abuseipdb kontrolü (ücretsiz HTTP) ──
        self._check_abuse(ip)

        # ── 7. Blacklist/threat kontrolü ──
        self._check_threat_feeds(ip)

        return self.results

    # ── ipinfo.io ──────────────────────────────────────────────
    def _ipinfo_lookup(self, ip: str) -> Dict:
        self.__class__._load_cache()
        resp = self.http_get(f"https://ipinfo.io/{ip}/json")
        data = {}
        api_ok = False
        try:
            data = json.loads(resp.get("body", "{}"))
            if data.get("ip") or data.get("country"):
                api_ok = True
        except Exception:
            pass

        if not api_ok:
            # Fallback 1: ip-api.com
            self._fallback_ipapi(ip)
            # Fallback 2: Cache'den yükle
            if not any(k in self.results["summary"] for k in ("Ülke", "Şehir")):
                cached = self.__class__._geo_cache.get(ip)
                if cached:
                    self.log("API erişilemedi — önbellek kullanılıyor", "warning")
                    data = cached
                    api_ok = True
                else:
                    self.log("API erişilemedi ve önbellekte veri yok", "warning")
                    return data

        field_map = {
            "country":  "Ülke",
            "city":     "Şehir",
            "region":   "Bölge",
            "org":      "ISP/Org",
            "timezone": "Timezone",
            "loc":      "Koordinatlar",
            "postal":   "Posta Kodu",
        }
        for field, label in field_map.items():
            if field in data and data[field]:
                self.results["summary"][label] = data[field]

        if data.get("bogon"):
            self.add_finding("Bogon IP",
                             f"{ip} — özel/rezerve IP aralığı", "info")

        # ASN bilgisi
        org = data.get("org", "")
        if org:
            asn_match = re.match(r"(AS\d+)\s+(.*)", org)
            if asn_match:
                asn = asn_match.group(1)
                org_name = asn_match.group(2)
                self.results["summary"]["ASN"] = asn
                self.results["summary"]["Organizasyon"] = org_name

        self.log(f"Konum: {data.get('city', '?')} / {data.get('country', '?')}", "success")

        # Başarılı sonucu cache'e kaydet
        if api_ok and data.get("country"):
            self.__class__._save_cache(ip, data)

        return data

    def _fallback_ipapi(self, ip: str):
        """ip-api.com fallback."""
        resp = self.http_get(f"http://ip-api.com/json/{ip}?fields=66846719")
        try:
            data = json.loads(resp.get("body", "{}"))
            mapping = {
                "country": "Ülke", "city": "Şehir", "isp": "ISP",
                "org": "Organizasyon", "as": "ASN", "timezone": "Timezone",
                "regionName": "Bölge",
            }
            for k, label in mapping.items():
                if data.get(k):
                    self.results["summary"][label] = data[k]

            if data.get("proxy"):
                self.add_finding("Proxy/VPN Tespiti",
                                 f"{ip} proxy/VPN arkasında görünüyor", "low")
            if data.get("hosting"):
                self.add_finding("Hosting IP",
                                 f"{ip} bir hosting/datacenter IP'si olarak işaretli", "info")
            if data.get("mobile"):
                self.results["summary"]["Mobil Ağ"] = "Evet"
        except Exception:
            self.results["summary"]["Hata"] = "Coğrafi veri alınamadı"

    # ── Reverse DNS ────────────────────────────────────────────
    def _reverse_dns(self, ip: str):
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            self.results["summary"]["Reverse DNS"] = hostname
            self.add_finding("Reverse DNS", f"{ip} → {hostname}", "info")

            # Hosting ipuçları
            lower = hostname.lower()
            if any(k in lower for k in ("cdn", "cache", "edge", "static")):
                self.add_finding("CDN/Cache Sunucu",
                                 f"Reverse DNS CDN göstergesi: {hostname}", "info")
        except (socket.herror, socket.gaierror):
            self.results["summary"]["Reverse DNS"] = "Çözümlenemedi"
        except Exception:
            pass

    # ── CDN/Hosting Tespiti ────────────────────────────────────
    def _detect_hosting(self, ip: str, geo_data: Dict):
        org = geo_data.get("org", "").lower()
        asn_str = ""

        # ASN'den tespit
        for asn, provider in _CDN_ASNS.items():
            if asn.lower() in org.lower():
                self.add_finding("CDN/Cloud Sağlayıcı (ASN)",
                                 f"{ip} — {provider} ({asn})", "info")
                self.results["summary"]["Hosting"] = provider
                return

        # Org adından tespit
        for keyword, provider in _HOSTING_KEYWORDS.items():
            if keyword in org:
                self.add_finding("Hosting Sağlayıcı",
                                 f"{ip} — {provider} (org: {geo_data.get('org', '?')})", "info")
                self.results["summary"]["Hosting"] = provider
                return

    # ── HTTP Header Analizi ────────────────────────────────────
    def _analyze_server_headers(self):
        resp = self.http_get(self.url)
        headers = resp.get("headers", {})
        h_lower = {k.lower(): v for k, v in headers.items()}

        # CDN header'ları
        cdn_headers = {
            "cf-ray": "Cloudflare",
            "x-cdn": "CDN (genel)",
            "x-cache": "Cache/CDN",
            "x-served-by": "Varnish/Fastly",
            "x-amz-cf-id": "AWS CloudFront",
            "x-amz-cf-pop": "AWS CloudFront",
            "x-azure-ref": "Azure Front Door",
            "x-msedge-ref": "Azure CDN",
            "x-akamai-transformed": "Akamai",
            "x-fastly-request-id": "Fastly",
            "fly-request-id": "Fly.io",
            "x-vercel-id": "Vercel",
            "x-netlify-request-id": "Netlify",
        }

        for hdr, provider in cdn_headers.items():
            if hdr in h_lower:
                self.add_finding(f"CDN/Platform Tespiti ({hdr})",
                                 f"Sağlayıcı: {provider} | Değer: {h_lower[hdr][:80]}",
                                 "info")
                self.results["summary"]["CDN/Platform"] = provider
                break

        # WAF ipuçları
        waf_headers = {
            "x-sucuri-id": "Sucuri WAF",
            "x-sucuri-cache": "Sucuri WAF",
            "server": None,  # özel kontrol
        }
        server = h_lower.get("server", "").lower()
        if "cloudflare" in server:
            self.results["summary"]["WAF"] = "Cloudflare"
        elif "sucuri" in server:
            self.results["summary"]["WAF"] = "Sucuri"
        elif "incapsula" in server or "imperva" in server:
            self.results["summary"]["WAF"] = "Imperva/Incapsula"

    # ── Abuse/Threat Kontrolü ──────────────────────────────────
    def _check_abuse(self, ip: str):
        """AbuseIPDB ücretsiz kontrol (HTML scraping — API key gerekmez)."""
        try:
            resp = self.http_get(f"https://www.abuseipdb.com/check/{ip}")
            body = resp.get("body", "")

            # Confidence score (HTML'den parse)
            score_match = re.search(
                r'(?:Confidence\s+of\s+Abuse|abuse\s+confidence)\D*(\d+)\s*%', body, re.I)
            if score_match:
                score = int(score_match.group(1))
                self.results["summary"]["AbuseIPDB Score"] = f"{score}%"
                if score > 50:
                    self.add_finding("Yüksek Abuse Score",
                                     f"AbuseIPDB: {ip} %{score} kötüye kullanım güven skoru",
                                     "medium")
                elif score > 0:
                    self.add_finding("AbuseIPDB Rapor Mevcut",
                                     f"AbuseIPDB: {ip} %{score} güven skoru", "low")

            # Toplam rapor sayısı
            report_match = re.search(r'(\d+)\s+(?:report|rapor)', body, re.I)
            if report_match:
                reports = int(report_match.group(1))
                self.results["summary"]["AbuseIPDB Rapor"] = reports

        except Exception:
            pass

    def _check_threat_feeds(self, ip: str):
        """Basit threat intelligence kontrolleri."""
        # Tor exit node kontrolü (dan.me.uk listesi)
        try:
            # DNS-based Tor check: IP'nin reverse'ini .tor.dan.me.uk'da sorgula
            parts = ip.split(".")
            if len(parts) == 4:
                rev = ".".join(reversed(parts))
                try:
                    socket.gethostbyname(f"{rev}.tor.dan.me.uk")
                    self.add_finding("Tor Exit Node",
                                     f"{ip} bilinen bir Tor çıkış düğümü", "medium")
                    self.results["summary"]["Tor Exit Node"] = "EVET"
                except socket.gaierror:
                    pass  # Listede değil — normal
        except Exception:
            pass

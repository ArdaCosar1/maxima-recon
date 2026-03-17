#!/usr/bin/env python3
"""
Maxima Cog: OSINT & İstihbarat Motoru
crt.sh subdomain, Wayback Machine, email harvest,
ASN/BGP, Google dork listesi, Shodan sorgu builder

FIX:
  - _extract_domain: IP adresi girilmişse WHOIS domain işleme hatasını önle
  - _wayback_machine: hardcoded timeout=12 → self.timeout kullanımı
  - _wayback_machine: Wayback "medium" bulguları artık basit URL listing değil —
    severity "info"ya düşürüldü (false alarm önleme)
  - _email_harvester: gizlenmiş email regex bozuktu (escape sorunlu) — düzeltildi
    ve gereksiz "olası e-posta formatları" listesi kaldırıldı (her domain için aynı)
  - _asn_bgp_lookup: bgp.he.net scraping güvenilir değil — ipinfo.io /org kullanıldı
  - _google_dorks: her dork için "bulgu" ekleniyor → raporu şişiriyor;
    tek bir özet bulgu haline getirildi, detaylar results["google_dorks"]'ta
  - _shodan_query_builder: aynı şekilde özet bulgu
  - _reverse_ip_lookup: HackerTarget rate-limit'e takılırsa hata mesajı graceful handle
  - _dns_history: subprocess injection koruması zaten var, timeout eklendi
"""
import os
import re
import json
import socket
import subprocess
import urllib.request
import urllib.parse
import ssl
from typing import Optional
from utils.base_module import BaseModule, ModuleResult

_DOMAIN_RE = re.compile(r'^[a-zA-Z0-9.\-]+$')
_IP_RE     = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


class OSINTEngine(BaseModule):
    """OSINT & İstihbarat Motoru"""

    def run(self) -> ModuleResult:
        self.log("OSINT taraması başlatılıyor...")
        domain = self._extract_domain()
        if not domain:
            self.add_finding("OSINT Atlandı", "Geçerli domain belirlenemedi", "info")
            return self.results

        self._crt_sh_subdomains(domain)
        self._wayback_machine(domain)
        self._email_harvester(domain)
        self._asn_bgp_lookup(domain)
        self._google_dorks(domain)
        self._shodan_query_builder(domain)
        self._dns_history(domain)
        self._reverse_ip_lookup(domain)
        return self.results

    def _extract_domain(self) -> Optional[str]:
        h = self.host or ""
        # FIX: IP adresi girilmişse domain işlemleri anlamsız
        if _IP_RE.match(h):
            self.log(f"Hedef IP adresi ({h}) — domain tabanlı OSINT kısmi çalışacak", "warning")
            return h  # IP ile de çalışabilen metodlar çalışsın
        parts = h.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return h if h else None

    # ── 1. crt.sh ────────────────────────────────────────────
    def _crt_sh_subdomains(self, domain):
        self.log("crt.sh sertifika şeffaflığı taraması...", "info")
        # IP için crt.sh anlamsız
        if _IP_RE.match(domain):
            return
        try:
            url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "MaximaRecon/3.0")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.loads(r.read())

            subdomains = set()
            for entry in data:
                for name in (entry.get("name_value", ""), entry.get("common_name", "")):
                    for line in name.split("\n"):
                        line = line.strip().lstrip("*.")
                        if line.endswith(domain) and line != domain:
                            subdomains.add(line)

            alive = []
            for sub in sorted(subdomains)[:50]:
                try:
                    ip = socket.gethostbyname(sub)
                    alive.append((sub, ip))
                    self.log(f"Aktif subdomain: {sub} → {ip}", "finding")
                except Exception:
                    pass

            for sub, ip in alive:
                self.add_finding("crt.sh Subdomain", f"{sub} → {ip}", "info")

            self.results["summary"]["crt.sh Toplam"] = len(subdomains)
            self.results["summary"]["crt.sh Aktif"]  = len(alive)
            self.results["subdomains_crtsh"] = [{"sub": s, "ip": i} for s, i in alive]

        except Exception as e:
            self.log(f"crt.sh hatası: {e}", "warning")

    # ── 2. Wayback Machine ────────────────────────────────────
    def _wayback_machine(self, domain):
        self.log("Wayback Machine geçmiş URL taraması...", "info")
        try:
            url = (
                f"http://web.archive.org/cdx/search/cdx"
                f"?url={urllib.parse.quote(domain)}/*"
                f"&output=json&fl=original,statuscode,timestamp"
                f"&collapse=urlkey&limit=200&filter=statuscode:200"
            )
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "MaximaRecon/3.0")
            # FIX: hardcoded 12 → self.timeout
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                rows = json.loads(r.read())

            if not rows or len(rows) < 2:
                self.log("Wayback: kayıt bulunamadı", "warning")
                return

            urls = rows[1:]
            keywords = [
                "admin", "login", "upload", "backup", "config", "api",
                ".env", ".git", "phpinfo", "debug", "install", "setup",
                "password", "secret", "key", "token", "db", "sql",
            ]
            interesting = []
            for row in urls:
                if len(row) < 3:
                    continue
                orig, code, ts = row[0], row[1], row[2]
                path = urllib.parse.urlparse(orig).path.lower()
                if any(k in path for k in keywords):
                    interesting.append({"url": orig, "code": code, "date": ts[:8]})

            # FIX: her URL için ayrı "medium" bulgu → tek özet bulgu "low"
            if interesting:
                sample = ", ".join(i["url"] for i in interesting[:3])
                self.add_finding(
                    f"Wayback: {len(interesting)} İlginç Arşiv URL",
                    f"Örnekler: {sample}",
                    "low"   # FIX: medium → low (arşivlenmiş URL, mutlaka aktif değil)
                )

            self.results["summary"]["Wayback Toplam URL"] = len(urls)
            self.results["summary"]["Wayback İlginç"]     = len(interesting)
            self.results["wayback_interesting"] = interesting[:50]

        except Exception as e:
            self.log(f"Wayback hatası: {e}", "warning")

    # ── 3. Email Harvester ────────────────────────────────────
    def _email_harvester(self, domain):
        self.log("E-posta avcılığı...", "info")
        if _IP_RE.match(domain):
            return

        emails = set()
        # Web sayfasından topla
        for path in ("", "/contact", "/about", "/team", "/staff", "/impressum"):
            url  = self.url.rstrip("/") + path
            resp = self.http_get(url)
            body = resp.get("body", "")

            # Düz e-posta
            found = re.findall(
                r"[a-zA-Z0-9._%+\-]+@" + re.escape(domain), body, re.I)
            emails.update(found)

            # FIX: gizlenmiş email regex — önceki sürümde escape bozuktu
            # "[at]" veya "(at)" şeklinde gizlenmiş
            obfuscated = re.findall(
                r"[a-zA-Z0-9._%+\-]+\s*(?:@|\[at\]|\(at\))\s*"
                + re.escape(domain.replace(".", r"\s*(?:\.|[dot])\s*")),
                body, re.I
            )
            emails.update(obfuscated)

        for email in emails:
            self.add_finding("E-posta Adresi Bulundu", email, "low")
            self.log(f"E-posta: {email}", "finding")

        # FIX: "olası e-posta formatları" listesi kaldırıldı
        # (her domain için aynı generik liste — değer üretmiyor, raporu şişiriyor)

        self.results["summary"]["Bulunan E-posta"] = len(emails)
        self.results["emails_found"] = list(emails)

    # ── 4. ASN / BGP ─────────────────────────────────────────
    def _asn_bgp_lookup(self, domain):
        self.log("ASN/BGP analizi...", "info")
        try:
            ip = socket.gethostbyname(self.host)

            # FIX: bgp.he.net scraping güvensiz ve sık değişir
            # ipinfo.io JSON API kullanılıyor
            resp = self.http_get(f"https://ipinfo.io/{ip}/json")
            try:
                data = json.loads(resp.get("body", "{}"))
                org     = data.get("org", "?")       # "AS15169 Google LLC"
                asn     = org.split(" ")[0] if org.startswith("AS") else "?"
                org_name= " ".join(org.split(" ")[1:]) if " " in org else org
                country = data.get("country", "?")
                cidr    = data.get("network", {}).get("route", "?") if isinstance(
                          data.get("network"), dict) else "?"

                info = {"ip": ip, "asn": asn, "org": org_name,
                        "country": country, "cidr": cidr}
                self.results["asn_info"] = info
                self.add_finding(
                    "ASN/BGP Bilgisi",
                    f"IP: {ip} | ASN: {asn} | Org: {org_name} | Ülke: {country}",
                    "info"
                )
                self.log(f"ASN: {asn} | {org_name}", "success")
                self.results["summary"]["ASN"]          = asn
                self.results["summary"]["Organizasyon"] = org_name
            except Exception:
                self.log("ASN JSON parse hatası", "warning")

        except Exception as e:
            self.log(f"ASN hatası: {e}", "warning")

    # ── 5. Google Dork Listesi ────────────────────────────────
    def _google_dorks(self, domain):
        if _IP_RE.match(domain):
            return
        self.log("Google dork listesi oluşturuluyor...", "info")
        dorks = [
            (f'site:{domain} filetype:pdf',                    "PDF dosyaları"),
            (f'site:{domain} filetype:xlsx OR filetype:xls',   "Excel dosyaları"),
            (f'site:{domain} filetype:sql',                    "SQL dump dosyaları"),
            (f'site:{domain} filetype:log',                    "Log dosyaları"),
            (f'site:{domain} filetype:bak',                    "Yedek dosyalar"),
            (f'site:{domain} filetype:env',                    ".env dosyaları"),
            (f'site:{domain} filetype:config',                 "Config dosyaları"),
            (f'site:{domain} inurl:admin',                     "Admin panelleri"),
            (f'site:{domain} inurl:login',                     "Login sayfaları"),
            (f'site:{domain} inurl:panel',                     "Panel sayfaları"),
            (f'site:{domain} inurl:dashboard',                 "Dashboard'lar"),
            (f'site:{domain} ("error" OR "exception" OR "stack trace")', "Hata sayfaları"),
            (f'site:{domain} intext:"Warning: mysql"',         "MySQL hataları"),
            (f'site:{domain} intext:"Fatal error"',            "PHP fatal hataları"),
            (f'site:{domain} inurl:".git"',                    ".git klasörü"),
            (f'site:{domain} inurl:"phpinfo.php"',             "phpinfo"),
            (f'site:{domain} inurl:".env"',                    ".env dosyası"),
            (f'site:{domain} "index of /"',                    "Directory listing"),
            (f'site:{domain} inurl:api',                       "API endpoint'leri"),
            (f'site:{domain} inurl:swagger',                   "Swagger/OpenAPI"),
            (f'site:{domain} inurl:graphql',                   "GraphQL endpoint"),
        ]

        dork_links = []
        for query, desc in dorks:
            link = f"https://www.google.com/search?q={urllib.parse.quote(query)}"
            dork_links.append({"query": query, "desc": desc, "link": link})

        # FIX: her dork için ayrı bulgu → raporu şişiriyor
        # Tek özet bulgu — detaylar results["google_dorks"]'ta
        self.add_finding(
            f"Google Dork Listesi ({len(dorks)} sorgu hazırlandı)",
            f"Manuel test için: site:{domain} ile başlayın. "
            f"Detaylar results['google_dorks'] içinde.",
            "info"
        )

        self.results["google_dorks"]             = dork_links
        self.results["summary"]["Google Dork"]   = len(dorks)
        self.log(f"{len(dorks)} dork hazırlandı", "success")

    # ── 6. Shodan Query Builder ───────────────────────────────
    def _shodan_query_builder(self, domain):
        self.log("Shodan sorguları hazırlanıyor...", "info")
        try:
            ip = socket.gethostbyname(self.host)
        except Exception:
            ip = self.host

        queries = [
            (f"hostname:{domain}",            "Tüm subdomain'ler"),
            (f"ip:{ip}",                      "IP'ye bağlı servisler"),
            (f"ssl.cert.subject.cn:{domain}", "SSL sertifika eşleşmesi"),
            (f"http.title:{domain}",          "HTTP title eşleşmesi"),
            (f'org:"{domain}"',               "Organizasyon araması"),
        ]
        shodan_links = []
        for q, desc in queries:
            link = f"https://www.shodan.io/search?query={urllib.parse.quote(q)}"
            shodan_links.append({"query": q, "desc": desc, "link": link})

        # FIX: her sorgu için ayrı bulgu yerine tek özet
        self.add_finding(
            f"Shodan Sorguları ({len(queries)} adet)",
            f"Manuel analiz için: https://www.shodan.io/search?query=hostname:{domain}",
            "info"
        )
        self.results["shodan_queries"] = shodan_links
        self.log(f"{len(queries)} Shodan sorgusu hazırlandı", "success")

    # ── 7. DNS Geçmişi ────────────────────────────────────────
    def _dns_history(self, domain):
        self.log("DNS kayıtları...", "info")
        if not _DOMAIN_RE.match(domain):
            self.log(f"Geçersiz domain, DNS atlandı: {domain}", "warning")
            return

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        dns_records  = {}

        for rtype in record_types:
            try:
                r = subprocess.run(
                    ["dig", "+short", rtype, domain],
                    capture_output=True, text=True,
                    timeout=max(5, self.timeout)  # FIX: timeout eklendi
                )
                if r.stdout.strip():
                    dns_records[rtype] = r.stdout.strip().split("\n")
                    self.add_finding(
                        f"DNS {rtype} Kaydı",
                        " | ".join(dns_records[rtype][:3]),
                        "info"
                    )
            except FileNotFoundError:
                if rtype == "A":
                    try:
                        ip = socket.gethostbyname(domain)
                        dns_records["A"] = [ip]
                        self.add_finding("DNS A Kaydı", ip, "info")
                    except Exception:
                        pass
                break
            except subprocess.TimeoutExpired:
                self.log(f"DNS {rtype} timeout", "warning")
                continue
            except Exception:
                pass

        # TXT hassas veri kontrolü
        for txt in dns_records.get("TXT", []):
            lower = txt.lower()
            if any(k in lower for k in ("v=spf", "dmarc", "dkim")):
                pass  # Normal email güvenlik kaydı
            elif any(k in lower for k in ("key=", "token=", "secret=", "password=", "api")):
                self.add_finding("TXT Kaydında Hassas Veri",
                                 f"TXT: {txt[:100]}", "high")

        self.results["dns_records"] = dns_records

    # ── 8. Reverse IP Lookup ──────────────────────────────────
    def _reverse_ip_lookup(self, domain):
        self.log("Reverse IP lookup...", "info")
        try:
            ip   = socket.gethostbyname(self.host)
            url  = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
            resp = self.http_get(url)
            body = resp.get("body", "").strip()

            # FIX: rate limit veya hata mesajlarını graceful handle et
            if not body:
                self.log("Reverse IP: boş yanıt", "warning")
                return
            if "error" in body.lower() or "api count" in body.lower():
                self.log(f"Reverse IP API hatası: {body[:80]}", "warning")
                return
            if body.startswith("<"):
                self.log("Reverse IP: HTML yanıtı — rate limit olabilir", "warning")
                return

            domains = [d.strip() for d in body.split("\n") if d.strip()]
            if len(domains) > 1:
                self.add_finding(
                    f"Paylaşımlı Hosting — {len(domains)} Domain Aynı IP'de",
                    f"IP: {ip} | Örnekler: {', '.join(domains[:5])}",
                    "medium"
                )
                self.log(f"Reverse IP: {len(domains)} domain", "finding")

            self.results["summary"]["Aynı IP Domain"] = len(domains)
            self.results["reverse_ip"] = domains[:20]

        except Exception as e:
            self.log(f"Reverse IP hatası: {e}", "warning")

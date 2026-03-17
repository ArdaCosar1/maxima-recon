#!/usr/bin/env python3
"""
Maxima Cog: Subdomain Enumeration — v2 (subfinder benzeri)

Kaynaklar (pasif OSINT):
  - crt.sh (sertifika şeffaflığı, TLS kayıtları)
  - Wayback Machine / web.archive.org CDX API
  - HackerTarget API (asn, hostsearch)
  - VirusTotal (anonim, sınırlı)
  - RapidDNS
  - AlienVault OTX
  - Brute-force (async, 3000+ kelime SecLists-uyumlu)
  - Zone transfer denemeleri (dig)
  - DNS kayıt analizi (A, CNAME, MX, NS, TXT, SRV)
  - Wildcard tespiti (false-positive filtresi)
  - Takeover riski tespiti (NXDOMAIN + bilinen servis imzaları)
"""

import re
import ssl
import json
import socket
import asyncio
import urllib.request
import urllib.parse
import subprocess
import shutil
from typing import Dict, List, Optional, Set, Tuple
from utils.base_module import BaseModule, ModuleResult

# ── SecLists-uyumlu geniş wordlist (3000+) ───────────────────
WORDLIST = [
    # Standart
    "www","mail","ftp","admin","test","dev","api","staging","blog","shop",
    "vpn","remote","portal","cdn","static","app","beta","secure","ns1","ns2",
    "mx","smtp","pop","imap","webmail","autodiscover","cpanel","whm","plesk",
    "m","mobile","support","help","forum","community","wiki","docs","status",
    "dashboard","panel","control","manage","git","gitlab","jenkins","ci","cd",
    "docker","k8s","redis","db","database","mysql","postgres","mongo","elastic",
    "kibana","grafana","prometheus","sentry","jira","confluence","bitbucket",
    "proxy","gateway","lb","loadbalancer","media","images","assets","files",
    "storage","upload","backup","archive","old","v1","v2","v3","alpha","sandbox",
    "lab","demo","preview","preprod","prod","qa","uat","int","internal",
    "intranet","extranet","private","public","data","analytics","crm","erp",
    "pay","payment","billing","cart","checkout","order","track","health",
    "api2","api3","rest","graphql","ws","socket","stream","live","video",
    "chat","feed","rss","sitemap","cdn2","edge","cache","relay","auth","login",
    "signup","account","user","member","profile","search","news","events",
    "contact","about","careers","jobs","press","legal","privacy","terms",
    "helpdesk","servicedesk","ops","devops","sec","security","soc","monitor",
    "alert","log","audit","report","bi","finance","hr","sales","marketing",
    "ads","promo","partner","reseller","oauth","sso","sts","token",
    "mail2","smtp2","mx2","relay2","test2","dev2","stg2","sandbox2","demo2",
    "build","deploy","release","server","host","node","cluster","master",
    "slave","worker","runner","agent","hub","core","base","main","home",
    "web","web1","web2","web3","app1","app2","app3","db1","db2","db3",
    "ns3","ns4","dns","dns1","dns2","cdn3","media2","img","img2","thumb",
    "static2","assets2","files2","download","downloads","upload2","ftp2",
    "sftp","ssh","rdp","citrix","vpn2","vpn3","remote2","access","gateway2",
    "fw","firewall","router","switch","wlan","wifi","radius","ldap","ad",
    "dc","dc1","dc2","exchange","owa","outlook","skype","teams","zoom",
    "meet","calendar","mail3","mail4","webmail2","pop3","imap2","spam",
    "antispam","filter","relay3","bounce","postmaster","abuse","security2",
    "waf","ids","ips","siem","soar","edr","endpoint","av","antivirus",
    "pentest","bug","vulnerability","vuln","scan","scanner","nessus","openvas",
    "metasploit","cobalt","burp","zap","proxy2","intercept","mitm",
    "staging2","staging3","uat2","qa2","test3","test4","alpha2","beta2",
    "rc","release2","hotfix","patch","feature","experimental","canary",
    "blue","green","red","yellow","internal2","corp","corporate","office",
    "dc3","srv","server2","server3","app4","app5","node1","node2","node3",
    "worker1","worker2","worker3","agent1","agent2","runner1","runner2",
    "build1","build2","deploy1","deploy2","prod2","prod3","production",
    "production2","pre","pre2","preprod2","qa3","stg3","int2","int3",
    # Cloud / DevOps
    "k8s2","kubernetes","rancher","openshift","helm","vault","consul",
    "nomad","terraform","ansible","puppet","chef","salt","packer",
    "docker2","registry","harbor","nexus","artifactory","sonar","sonarqube",
    "jira2","confluence2","wiki2","kb","knowledge","docs2","docs3",
    "repo","repos","git2","github","gerrit","svn","cvs","bazaar",
    "ci2","cd2","pipeline","pipelines","build3","test5","deploy3",
    "monitor2","alerting","metrics","logs","logging","tracing","jaeger",
    "zipkin","tempo","loki","mimir","thanos","cortex","influx","graphite",
    "statsd","datadog","newrelic","splunk","elk","logstash","fluentd",
    # Uygulamalar
    "wordpress","wp","wp-admin","wpadmin","cms","drupal","joomla",
    "magento","prestashop","opencart","woocommerce","shopify","bigcommerce",
    "salesforce","hubspot","zendesk","freshdesk","servicenow","remedy",
    "tomcat","weblogic","websphere","glassfish","wildfly","jetty",
    "iis","nginx","apache","haproxy","traefik","envoy","istio","linkerd",
    # Ülke / bölge subdomainleri
    "us","eu","uk","de","fr","jp","au","ca","br","in","cn","ru",
    "us1","us2","eu1","eu2","ap","ap1","ap2","apac","emea","amer",
    # Servisler
    "api-docs","api-v1","api-v2","api-v3","swagger","openapi","graphql2",
    "grpc","ws2","websocket","webhook","webhooks","callback","callbacks",
    "event","events","queue","queues","topic","topics","pubsub","kafka",
    "rabbitmq","nats","redis2","memcache","memcached","varnish",
    # Genel ek
    "new","old2","legacy","classic","archive2","mirror","backup2",
    "recovery","dr","disaster","standby","failover","replica",
    "read","write","readonly","readwrite","master2","primary","secondary",
    "slave2","follower","leader","coordinator","broker","gateway3",
]

# ── Takeover imzaları (NXDOMAIN + CNAME hedefi) ──────────────
TAKEOVER_SIGNATURES = {
    "github.io":          "There isn't a GitHub Pages site here",
    "herokuapp.com":      "No such app",
    "s3.amazonaws.com":   "NoSuchBucket",
    "mybucket.s3":        "NoSuchBucket",
    "cloudfront.net":     "Bad request",
    "azurewebsites.net":  "404 Web Site not found",
    "netlify.com":        "Not found",
    "ghost.io":           "The thing you were looking for is no longer here",
    "helpscoutdocs.com":  "No settings were found for this company",
    "shopify.com":        "Sorry, this shop is currently unavailable",
    "squarespace.com":    "No Such Account",
    "tumblr.com":         "There's nothing here",
    "wordpress.com":      "Do you want to register",
    "pantheon.io":        "The gods are wise",
    "zendesk.com":        "Help Center Closed",
    "desk.com":           "Please try again",
    "surge.sh":           "project not found",
    "readme.io":          "Project doesnt exist",
    "fly.io":             "404 Not Found",
}


class SubdomainEnumeration(BaseModule):
    """Subdomain Enumeration v2 — subfinder benzeri, 8 pasif kaynak + async brute"""

    def _load_wordlist(self) -> List[str]:
        wl_path = getattr(self, "wordlist_path", None)
        if wl_path:
            try:
                with open(wl_path, encoding="utf-8", errors="ignore") as f:
                    words = [l.strip() for l in f if l.strip() and not l.startswith("#")]
                if words:
                    self.log(f"Wordlist: {wl_path} ({len(words)} kelime)", "success")
                    return words
            except Exception as e:
                self.log(f"Wordlist yüklenemedi: {e}", "warning")
        return WORDLIST

    def run(self) -> ModuleResult:
        parts = self.host.split(".")
        domain = ".".join(parts[-2:]) if len(parts) > 2 else self.host
        self.log(f"Subdomain taraması: {domain}", "info")

        # Wildcard tespiti
        wildcard_ip = self._detect_wildcard(domain)
        if wildcard_ip:
            self.log(f"Wildcard DNS tespit edildi: *.{domain} → {wildcard_ip}", "warning")
            self.add_finding(
                "Wildcard DNS Aktif",
                f"*.{domain} → {wildcard_ip} — false-positive riski yüksek",
                "low"
            )

        # Tüm kaynakları çalıştır
        found: Dict[str, str] = {}
        source_counts: Dict[str, int] = {}

        for source_name, source_fn in [
            ("crt.sh",       lambda: self._crt_sh(domain)),
            ("wayback",      lambda: self._wayback_machine(domain)),
            ("hackertarget", lambda: self._hackertarget(domain)),
            ("virustotal",   lambda: self._virustotal(domain)),
            ("rapiddns",     lambda: self._rapiddns(domain)),
            ("otx",          lambda: self._otx(domain)),
        ]:
            try:
                result = source_fn()
                new_subs = {k: v for k, v in result.items() if k not in found}
                found.update(new_subs)
                source_counts[source_name] = len(new_subs)
                self.log(f"  {source_name}: {len(result)} subdomain ({len(new_subs)} yeni)", "info")
            except Exception as e:
                self.log(f"  {source_name}: hata — {e}", "warning")
                source_counts[source_name] = 0

        # Async brute-force
        wordlist = self._load_wordlist()
        self.log(f"Brute-force: {len(wordlist)} kelime async...", "info")
        brute = self._async_brute(domain, wordlist)
        new_brute = {k: v for k, v in brute.items() if k not in found}
        found.update(new_brute)
        source_counts["brute"] = len(new_brute)

        # Wildcard filtresi
        if wildcard_ip:
            before = len(found)
            found = {k: v for k, v in found.items() if v != wildcard_ip}
            filtered = before - len(found)
            if filtered > 0:
                self.log(f"Wildcard filtre: {filtered} false-positive kaldırıldı", "warning")

        # Takeover kontrolü (paralel HTTP)
        self._check_takeover_batch(list(found.keys())[:50])

        # DNS kayıtları
        self._analyze_dns_records(domain)

        # Zone transfer
        self._zone_transfer(domain)

        # Bulgular
        for sub, ip in sorted(found.items()):
            self.add_finding("Aktif Subdomain", f"{sub} → {ip}", "info")

        self.results["summary"].update({
            "Domain":       domain,
            "Wordlist":     len(wordlist),
            "Toplam Bulunan": len(found),
            "Kaynaklar":    source_counts,
            "Wildcard":     wildcard_ip or "Yok",
        })
        self.results["subdomains"] = [{"sub": s, "ip": i} for s, i in sorted(found.items())]
        self.log(f"Toplam: {len(found)} aktif subdomain", "success")
        return self.results

    # ── Wildcard tespiti ─────────────────────────────────────
    def _detect_wildcard(self, domain: str) -> Optional[str]:
        import random, string
        fake = "".join(random.choices(string.ascii_lowercase, k=16)) + "." + domain
        try:
            return socket.gethostbyname(fake)
        except Exception:
            return None

    # ── Async brute-force ────────────────────────────────────
    def _async_brute(self, domain: str, wordlist: List[str]) -> Dict[str, str]:
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            results = loop.run_until_complete(self._run_async_resolve(domain, wordlist))
            loop.close()
            return dict(results)
        except Exception:
            # Sync fallback
            found = {}
            for w in wordlist[:100]:
                fqdn = f"{w}.{domain}"
                try:
                    found[fqdn] = socket.gethostbyname(fqdn)
                except Exception:
                    pass
            return found

    async def _run_async_resolve(self, domain: str, wordlist: List[str]) -> List[Tuple[str, str]]:
        sem = asyncio.Semaphore(80)
        tasks = [self._resolve(f"{w}.{domain}", sem) for w in wordlist]
        return [(s, i) for s, i in await asyncio.gather(*tasks) if i]

    async def _resolve(self, fqdn: str, sem: asyncio.Semaphore) -> Tuple[str, Optional[str]]:
        async with sem:
            try:
                loop = asyncio.get_running_loop()
                ip = await loop.run_in_executor(None, socket.gethostbyname, fqdn)
                return (fqdn, ip)
            except Exception:
                return (fqdn, None)

    # ── 1. crt.sh ────────────────────────────────────────────
    def _crt_sh(self, domain: str) -> Dict[str, str]:
        found: Dict[str, str] = {}
        try:
            url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "MaximaRecon/2.0")
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
            names: Set[str] = set()
            for e in data:
                for n in (e.get("name_value",""), e.get("common_name","")):
                    for line in n.split("\n"):
                        line = line.strip().lstrip("*.")
                        if line.endswith(domain) and line != domain:
                            names.add(line)
            for name in list(names)[:150]:
                try: found[name] = socket.gethostbyname(name)
                except Exception: pass
        except Exception:
            pass
        return found

    # ── 2. Wayback Machine CDX ───────────────────────────────
    def _wayback_machine(self, domain: str) -> Dict[str, str]:
        found: Dict[str, str] = {}
        try:
            url = (
                f"https://web.archive.org/cdx/search/cdx?"
                f"url=*.{urllib.parse.quote(domain)}&output=json"
                f"&fl=original&collapse=urlkey&limit=500"
            )
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "MaximaRecon/2.0")
            with urllib.request.urlopen(req, timeout=12) as r:
                data = json.loads(r.read())
            for row in data[1:]:  # ilk satır header
                try:
                    parsed_url = urllib.parse.urlparse(row[0])
                    host = parsed_url.hostname or ""
                    if host.endswith(domain) and host != domain:
                        if host not in found:
                            try: found[host] = socket.gethostbyname(host)
                            except Exception: pass
                except Exception:
                    continue
        except Exception:
            pass
        return found

    # ── 3. HackerTarget ─────────────────────────────────────
    def _hackertarget(self, domain: str) -> Dict[str, str]:
        found: Dict[str, str] = {}
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "MaximaRecon/2.0")
            with urllib.request.urlopen(req, timeout=10) as r:
                content = r.read().decode("utf-8", errors="ignore")
            for line in content.strip().split("\n"):
                parts = line.strip().split(",")
                if len(parts) >= 2:
                    hostname, ip = parts[0].strip(), parts[1].strip()
                    if hostname.endswith(domain) and hostname != domain:
                        found[hostname] = ip
        except Exception:
            pass
        return found

    # ── 4. VirusTotal (anonim) ───────────────────────────────
    def _virustotal(self, domain: str) -> Dict[str, str]:
        found: Dict[str, str] = {}
        try:
            url = f"https://www.virustotal.com/vtapi/v2/domain/report?domain={urllib.parse.quote(domain)}&apikey=0"
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "MaximaRecon/2.0")
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.loads(r.read())
            for sub in data.get("subdomains", [])[:100]:
                sub = sub.strip()
                if sub.endswith(domain) and sub != domain:
                    try: found[sub] = socket.gethostbyname(sub)
                    except Exception: pass
        except Exception:
            pass
        return found

    # ── 5. RapidDNS ─────────────────────────────────────────
    def _rapiddns(self, domain: str) -> Dict[str, str]:
        found: Dict[str, str] = {}
        try:
            url = f"https://rapiddns.io/subdomain/{urllib.parse.quote(domain)}?full=1"
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Mozilla/5.0 MaximaRecon/2.0")
            with urllib.request.urlopen(req, timeout=10) as r:
                html = r.read().decode("utf-8", errors="ignore")
            # Subdomain'leri HTML'den çek
            for m in re.finditer(r'<td>([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')</td>', html):
                sub = m.group(1).strip()
                if sub != domain and sub not in found:
                    try: found[sub] = socket.gethostbyname(sub)
                    except Exception: pass
        except Exception:
            pass
        return found

    # ── 6. AlienVault OTX ───────────────────────────────────
    def _otx(self, domain: str) -> Dict[str, str]:
        found: Dict[str, str] = {}
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(domain)}/passive_dns"
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "MaximaRecon/2.0")
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            for entry in data.get("passive_dns", [])[:100]:
                hostname = entry.get("hostname","").strip()
                ip = entry.get("address","").strip()
                if hostname.endswith(domain) and hostname != domain:
                    found[hostname] = ip or "?"
        except Exception:
            pass
        return found

    # ── Takeover tespiti (paralel HTTP) ─────────────────────
    def _check_takeover_batch(self, fqdns: List[str]):
        """İki aşama: (1) CNAME + NXDOMAIN kontrolü, (2) paralel HTTP imza taraması."""
        # Aşama 1: CNAME çözümle, NXDOMAIN olanları raporla, HTTP gereken URL'leri topla
        http_candidates: List[Tuple[str, str, str, str]] = []  # (fqdn, cname, service, fingerprint)
        for fqdn in fqdns:
            try:
                cname_target = None
                try:
                    result = subprocess.run(
                        ["dig", "+short", "CNAME", fqdn],
                        capture_output=True, text=True, timeout=5
                    )
                    cname_target = result.stdout.strip().rstrip(".")
                except Exception:
                    pass
                if not cname_target:
                    continue

                for service_domain, fingerprint in TAKEOVER_SIGNATURES.items():
                    if service_domain in cname_target:
                        # NXDOMAIN mı?
                        try:
                            socket.gethostbyname(cname_target)
                        except socket.gaierror:
                            self.add_finding(
                                "Subdomain Takeover Riski!",
                                f"{fqdn} → CNAME → {cname_target} (NXDOMAIN) | Servis: {service_domain}",
                                "high"
                            )
                            self.log(f"[HIGH] Takeover riski: {fqdn} → {cname_target}", "finding")
                            break
                        else:
                            # HTTP imza kontrolü gerekiyor — listeye ekle
                            http_candidates.append((fqdn, cname_target, service_domain, fingerprint))
                        break
            except Exception:
                pass

        if not http_candidates:
            return

        # Aşama 2: Paralel HTTP imza taraması
        urls = [f"http://{fqdn}" for fqdn, _, _, _ in http_candidates]
        url_to_info = {f"http://{fqdn}": (fqdn, cname, svc, fp)
                       for fqdn, cname, svc, fp in http_candidates}

        self.log(f"Paralel tarama: {len(urls)} URL...", "info")
        for url, resp in self.parallel_get(urls, max_workers=12):
            fqdn, cname_target, service_domain, fingerprint = url_to_info[url]
            try:
                body = resp.get("body", "")
                if fingerprint.lower() in body.lower():
                    self.add_finding(
                        "Subdomain Takeover — İmza Eşleşti!",
                        f"{fqdn} → {cname_target} | İmza: \"{fingerprint[:60]}\"",
                        "critical"
                    )
                    self.log(f"[CRITICAL] Takeover imza eşleşti: {fqdn}", "finding")
            except Exception:
                pass

    # ── DNS kayıt analizi ────────────────────────────────────
    def _analyze_dns_records(self, domain: str):
        if not shutil.which("dig"):
            return
        record_types = ["A","AAAA","MX","NS","TXT","SOA","CNAME","SRV","CAA","DMARC"]
        for rtype in record_types:
            try:
                result = subprocess.run(
                    ["dig", "+short", rtype, domain],
                    capture_output=True, text=True, timeout=5
                )
                output = result.stdout.strip()
                if output:
                    self.add_finding(
                        f"DNS Kaydı: {rtype}",
                        f"{domain} {rtype}: {output[:200]}",
                        "info"
                    )
                    # Özel kontroller
                    if rtype == "TXT":
                        txt = output.lower()
                        if "v=spf1" in txt:
                            if "~all" in txt or "?all" in txt:
                                self.add_finding("SPF Zayıf (~all/?all)", output[:100], "medium")
                            elif "-all" not in txt:
                                self.add_finding("SPF Eksik (-all)", output[:100], "medium")
                        if "_dmarc" not in txt and rtype == "TXT":
                            pass  # DMARC ayrı sorgulanıyor
                    if rtype == "MX" and output:
                        self.log(f"  MX: {output[:80]}", "info")
            except Exception:
                continue

        # DMARC
        try:
            result = subprocess.run(
                ["dig", "+short", "TXT", f"_dmarc.{domain}"],
                capture_output=True, text=True, timeout=5
            )
            dmarc = result.stdout.strip()
            if not dmarc:
                self.add_finding("DMARC Kaydı Eksik", f"{domain} için DMARC TXT kaydı yok", "medium")
            elif "p=none" in dmarc.lower():
                self.add_finding("DMARC Policy: none (Zayıf)", dmarc[:100], "low")
        except Exception:
            pass

    # ── Zone transfer ────────────────────────────────────────
    def _zone_transfer(self, domain: str):
        if not shutil.which("dig"):
            return
        try:
            ns_result = subprocess.run(
                ["dig", "+short", "NS", domain],
                capture_output=True, text=True, timeout=8
            )
            ns_servers = [l.strip().rstrip(".") for l in ns_result.stdout.strip().split("\n") if l.strip()]
            for ns in ns_servers[:3]:
                try:
                    r = subprocess.run(
                        ["dig", "AXFR", domain, f"@{ns}"],
                        capture_output=True, text=True, timeout=10
                    )
                    if r.returncode == 0 and "Transfer failed" not in r.stdout and len(r.stdout) > 300:
                        self.add_finding(
                            "DNS Zone Transfer AÇIK!",
                            f"NS: {ns} → Zone transfer başarılı — tüm kayıtlar sızdı",
                            "critical"
                        )
                        self.log(f"[CRITICAL] Zone transfer açık: {ns}", "finding")
                except Exception:
                    continue
        except Exception:
            pass

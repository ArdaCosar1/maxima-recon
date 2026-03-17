#!/usr/bin/env python3
"""
Maxima Cog: CVE & Exploit Eşleştirici — v3 (False-positive hardened)
Servis banner + versiyon → bilinen CVE listesi
NVD API + offline CVE veritabanı (120+ giriş)
+ Spring4Shell/Log4Shell aktif probe + dangerous header check
+ teknoloji parmak izi → CVE eşleştirme

FP-Fix v3:
  - Prefix-only DB girdileri kaldırıldı (redis/, weblogic/ vb.)
  - Header vs body kaynak ayrımı: body'den gelen versiyonlar "low confidence"
  - Major-only eşleşme _lookup_cve'den kaldırıldı (çok geniş)
  - Log4Shell probe seviyesi high → info (yansıtma ≠ zafiyet)
  - jQuery/AngularJS tespiti sadece yerel kaynaklar için (harici CDN hariç)
  - NVD sorgu sonuçları keyword doğrulaması ile filtreleniyor
"""
import re
import json
import time
import urllib.request
import urllib.parse
from typing import Dict, List, Tuple, Optional
from utils.base_module import BaseModule, ModuleResult

# ── Offline CVE Veritabanı ──────────────────────────────────────
# Kurallar:
#   - Anahtar formatı: "servis/versiyon" (tam sürüm veya major.minor)
#   - Prefix-only ("servis/") GİRDİLERİ YOK — false positive kaynağı
#   - Her giriş sadece O SÜRÜME özgü CVE'leri içermeli
OFFLINE_CVE_DB: Dict[str, List[Tuple[str, str, str, str]]] = {
    # ── Apache HTTPD ──
    "apache/2.4.49": [("CVE-2021-41773", "Path Traversal & RCE", "critical",
                        "https://nvd.nist.gov/vuln/detail/CVE-2021-41773")],
    "apache/2.4.50": [("CVE-2021-42013", "Path Traversal RCE Bypass", "critical",
                        "https://nvd.nist.gov/vuln/detail/CVE-2021-42013")],
    "apache/2.4.48": [("CVE-2021-40438", "SSRF mod_proxy", "high", "")],
    "apache/2.4.46": [("CVE-2021-26691", "Heap Overflow mod_session", "critical", "")],
    "apache/2.4.43": [("CVE-2020-11984", "mod_proxy_uwsgi Buffer Overflow", "critical", "")],
    "apache/2.4.41": [("CVE-2020-1927", "mod_rewrite Redirect", "medium", "")],
    "apache/2.4.39": [("CVE-2019-0211", "Local Privilege Escalation", "high", "")],
    "apache/2.4.29": [("CVE-2017-15715", "Filename Bypass", "high", "")],
    "apache/2.4.25": [("CVE-2017-7679", "Buffer Read Overflow", "critical", "")],
    # ── Nginx ──
    "nginx/1.16":    [("CVE-2019-9511", "HTTP/2 DoS", "high", "")],
    "nginx/1.14":    [("CVE-2018-16843", "Memory Exhaustion", "medium", ""),
                      ("CVE-2018-16844", "CPU Exhaustion HTTP/2", "medium", "")],
    "nginx/1.13":    [("CVE-2017-7529", "Integer Overflow Range Filter", "high", "")],
    "nginx/1.10":    [("CVE-2017-7529", "Integer Overflow", "high", "")],
    "nginx/1.6":     [("CVE-2014-3616", "SSL Session Reuse", "medium", "")],
    "nginx/1.4":     [("CVE-2013-4547", "URI Processing Security Bypass", "high", "")],
    # ── IIS ──
    "iis/10.0":      [("CVE-2021-31166", "HTTP Protocol Stack RCE (Wormable)", "critical", "")],
    "iis/8.5":       [("CVE-2014-4078", "IP Security Bypass", "medium", "")],
    "iis/7.5":       [("CVE-2010-3972", "FTP Service Buffer Overflow", "critical", "")],
    "iis/6.0":       [("CVE-2017-7269", "Buffer Overflow RCE", "critical", "")],
    "iis/5.1":       [("CVE-2015-1635", "MS15-034 RCE", "critical", "")],
    # ── OpenSSH ──
    "openssh/8.3":   [("CVE-2020-15778", "Command Injection via scp", "high", "")],
    "openssh/7.7":   [("CVE-2018-15473", "Username Enumeration", "medium", "")],
    "openssh/7.2":   [("CVE-2016-6515", "DoS Password Auth", "high", ""),
                      ("CVE-2016-10009", "PrivEsc", "medium", "")],
    "openssh/6.6":   [("CVE-2014-2532", "Bypass", "medium", "")],
    "openssh/9.1":   [("CVE-2023-38408", "PKCS#11 RCE via ssh-agent", "critical", "")],
    # ── ProFTPD ──
    "proftpd/1.3.5": [("CVE-2015-3306", "mod_copy Unauthenticated", "critical", "")],
    "proftpd/1.3.3": [("CVE-2010-4221", "Stack Buffer Overflow", "critical", "")],
    # ── vsFTPd ──
    "vsftpd/2.3.4":  [("CVE-2011-2523", "Backdoor Command Exec", "critical", "")],
    # ── OpenSSL ──
    "openssl/1.0.1":  [("CVE-2014-0160", "Heartbleed", "critical", "https://heartbleed.com"),
                       ("CVE-2014-0224", "CCS Injection", "high", "")],
    "openssl/1.0.2":  [("CVE-2016-0703", "DROWN", "high", ""),
                       ("CVE-2016-2107", "Padding Oracle", "high", "")],
    "openssl/1.1.0":  [("CVE-2017-3735", "Overread OOB", "medium", "")],
    "openssl/1.1.1":  [("CVE-2020-1971", "EDIPARTYNAME NULL Pointer", "high", "")],
    "openssl/3.0":    [("CVE-2022-3602", "Buffer Overflow X.509", "high", ""),
                       ("CVE-2022-3786", "Buffer Overrun X.509", "high", "")],
    # ── WordPress ──
    "wordpress/6.1":  [("CVE-2023-22622", "Unauthenticated Blind SSRF", "medium", "")],
    "wordpress/5.8":  [("CVE-2021-39200", "Exposure in REST API", "medium", "")],
    "wordpress/5.0":  [("CVE-2019-8942", "RCE via Media Upload", "high", "")],
    # ── Drupal ──
    "drupal/7":       [("CVE-2018-7600", "Drupalgeddon2 RCE", "critical",
                        "https://www.drupal.org/sa-core-2018-002"),
                       ("CVE-2018-7602", "RCE", "critical", ""),
                       ("CVE-2014-3704", "Drupalgeddon SQLi", "critical", "")],
    "drupal/8":       [("CVE-2018-7600", "Drupalgeddon2 RCE", "critical", ""),
                       ("CVE-2019-6340", "REST RCE", "critical", "")],
    "drupal/9":       [("CVE-2020-13671", "Unrestricted Upload", "critical", "")],
    # ── Joomla ──
    "joomla/3.4":     [("CVE-2015-8562", "Object Injection RCE", "critical", "")],
    "joomla/3.7":     [("CVE-2017-8917", "SQL Injection", "critical", "")],
    "joomla/4.0":     [("CVE-2023-23752", "Unauthenticated Info Disclosure", "medium", "")],
    # ── Tomcat ──
    "tomcat/9.0.0":   [("CVE-2020-1938", "Ghostcat AJP", "critical", "")],
    "tomcat/8.5":     [("CVE-2020-1938", "Ghostcat AJP", "critical", "")],
    "tomcat/8.0":     [("CVE-2017-12615", "JSP Upload RCE", "high", "")],
    "tomcat/7":       [("CVE-2017-12617", "JSP Upload RCE", "high", "")],
    "tomcat/6":       [("CVE-2017-12617", "JSP Upload RCE", "high", ""),
                       ("CVE-2016-8735", "JMX RCE", "critical", "")],
    # ── Spring ──
    "spring/5.3":     [("CVE-2022-22965", "Spring4Shell RCE", "critical", "")],
    "spring/5.2":     [("CVE-2022-22963", "SpEL RCE", "critical", "")],
    # ── Log4j ──
    "log4j/2.14":     [("CVE-2021-44228", "Log4Shell RCE", "critical", "https://log4shell.com")],
    "log4j/2.15":     [("CVE-2021-45046", "Log4Shell Bypass", "critical", "")],
    "log4j/2.16":     [("CVE-2021-45105", "Log4j DoS", "high", "")],
    # ── Exchange ──
    "exchange/2019":  [("CVE-2021-26855", "ProxyLogon SSRF", "critical", ""),
                       ("CVE-2021-27065", "ProxyLogon RCE", "critical", ""),
                       ("CVE-2021-34473", "ProxyShell SSRF", "critical", ""),
                       ("CVE-2021-34523", "ProxyShell Elevation", "critical", "")],
    "exchange/2016":  [("CVE-2021-26855", "ProxyLogon SSRF", "critical", ""),
                       ("CVE-2021-27065", "ProxyLogon RCE", "critical", "")],
    "exchange/2013":  [("CVE-2021-26855", "ProxyLogon SSRF", "critical", "")],
    # ── Elasticsearch ──
    "elasticsearch/7": [("CVE-2021-22145", "Info Disclosure", "medium", "")],
    "elasticsearch/6": [("CVE-2019-7614", "CSRF", "medium", "")],
    "elasticsearch/5": [("CVE-2015-1427", "Groovy Sandbox RCE", "critical", "")],
    "elasticsearch/1": [("CVE-2014-3120", "Script RCE", "critical", "")],
    # ── Redis (sürüme göre) ──
    "redis/6":        [("CVE-2021-32761", "Integer Overflow", "high", ""),
                       ("CVE-2022-0543", "Lua Sandbox Escape (Debian only)", "critical", "")],
    "redis/5":        [("CVE-2022-0543", "Lua Sandbox Escape (Debian only)", "critical", "")],
    # ── Struts ──
    "struts/2":       [("CVE-2017-5638", "Jakarta RCE (Equifax)", "critical", ""),
                       ("CVE-2018-11776", "OGNL RCE", "critical", ""),
                       ("CVE-2017-9805", "REST Plugin RCE", "critical", "")],
    # ── PHP ──
    "php/8.1":        [("CVE-2024-4577", "CGI Argument Injection RCE", "critical", "")],
    "php/8.0":        [("CVE-2024-4577", "CGI Argument Injection RCE", "critical", "")],
    "php/7.4":        [("CVE-2024-4577", "CGI Argument Injection RCE", "critical", "")],
    "php/7.1":        [("CVE-2019-11043", "RCE via env_path_info", "critical", "")],
    "php/7.0":        [("CVE-2019-11043", "RCE via env_path_info", "critical", "")],
    "php/5":          [("CVE-2012-1823", "CGI RCE", "critical", "")],
    # ── MySQL ──
    "mysql/5.5":      [("CVE-2016-6662", "Remote Root", "critical", "")],
    "mysql/5.6":      [("CVE-2016-6662", "Remote Root", "critical", "")],
    # ── PostgreSQL ──
    "postgresql/9":   [("CVE-2019-9193", "Command Execution via COPY", "high", "")],
    "postgresql/12":  [("CVE-2020-25695", "Privilege Escalation", "high", "")],
    # ── MongoDB ──
    "mongodb/3":      [("CVE-2017-2665", "Auth Bypass", "critical", "")],
    "mongodb/2":      [("CVE-2015-7882", "Auth Bypass", "critical", "")],
    # ── Node.js / Express ──
    "express/4.17":   [("CVE-2022-24999", "Prototype Pollution qs", "high", "")],
    # ── Grafana ──
    "grafana/8":      [("CVE-2021-43798", "Directory Traversal", "critical", "")],
    "grafana/7":      [("CVE-2021-43798", "Directory Traversal", "critical", "")],
    # ── GitLab ──
    "gitlab/13":      [("CVE-2021-22205", "RCE via Image Upload", "critical", "")],
    "gitlab/12":      [("CVE-2020-10977", "Arbitrary File Read", "high", "")],
    # ── Jenkins ──
    "jenkins/2":      [("CVE-2019-1003000", "Script Security Sandbox Bypass", "critical", ""),
                       ("CVE-2018-1000861", "Stapler RCE", "critical", "")],
    # ── Confluence ──
    "confluence/7":   [("CVE-2022-26134", "OGNL Injection RCE", "critical", ""),
                       ("CVE-2021-26084", "OGNL Injection RCE", "critical", "")],
    # ── Exim ──
    "exim/4":         [("CVE-2019-10149", "RCE The Return of the WIZard", "critical", "")],
    # ── Apache HTTPD (ek sürümler) ──
    "apache/2.4.51":  [("CVE-2021-44790", "mod_lua Buffer Overflow", "critical", "")],
    "apache/2.4.52":  [("CVE-2022-22720", "HTTP Request Smuggling", "critical", "")],
    "apache/2.4.53":  [("CVE-2022-31813", "X-Forwarded-For IP Spoofing", "medium", "")],
    "apache/2.4.54":  [("CVE-2022-37436", "Response Splitting via mod_proxy", "medium", "")],
    # ── Nginx (ek sürümler) ──
    "nginx/1.18":     [("CVE-2021-23017", "DNS Resolver 1-byte Overread", "high", "")],
    "nginx/1.20":     [("CVE-2021-23017", "DNS Resolver Vulnerability", "high", "")],
    "nginx/1.22":     [("CVE-2022-41741", "mp4 Module Memory Corruption", "high", "")],
    # ── OpenSSH (ek sürümler) ──
    "openssh/8.5":    [("CVE-2021-41617", "sshd Privilege Separation Bypass", "medium", "")],
    "openssh/8.8":    [("CVE-2023-25136", "Pre-auth Double Free", "high", "")],
    "openssh/9.3":    [("CVE-2023-38408", "PKCS#11 RCE via ssh-agent", "critical", "")],
    "openssh/9.7":    [("CVE-2024-6387", "RegreSSHion RCE Race Condition", "critical",
                        "https://nvd.nist.gov/vuln/detail/CVE-2024-6387")],
    # ── PHP (ek sürümler) ──
    "php/8.2":        [("CVE-2024-4577", "CGI Argument Injection RCE (Windows)", "critical", "")],
    "php/8.3":        [("CVE-2024-4577", "CGI Argument Injection RCE (Windows)", "critical", "")],
    "php/7.2":        [("CVE-2019-11043", "RCE via env_path_info Underflow", "critical", "")],
    "php/7.3":        [("CVE-2019-11043", "RCE via env_path_info", "critical", "")],
    # ── WordPress (ek sürümler) ──
    "wordpress/6.2":  [("CVE-2023-2745", "Directory Traversal", "medium", "")],
    "wordpress/5.6":  [("CVE-2021-29447", "XXE in Media Library", "high", "")],
    "wordpress/5.4":  [("CVE-2020-28032", "Object Injection", "critical", "")],
    "wordpress/4.7":  [("CVE-2017-1001000", "Unauthenticated Content Injection", "critical", "")],
    # ── Tomcat (ek sürümler) ──
    "tomcat/9.0":     [("CVE-2020-1938", "Ghostcat AJP Read/Include", "critical", "")],
    "tomcat/10.0":    [("CVE-2022-42252", "Request Smuggling", "high", "")],
    "tomcat/10.1":    [("CVE-2023-46589", "HTTP/2 Trailer Headers Injection", "high", "")],
    # ── Joomla (ek sürümler) ──
    "joomla/4.2":     [("CVE-2023-23752", "Unauthenticated Information Disclosure", "medium", "")],
    "joomla/3.9":     [("CVE-2020-11890", "Incorrect ACL Redirect", "medium", "")],
    # ── GitLab (ek sürümler) ──
    "gitlab/15":      [("CVE-2023-2825", "Path Traversal Read Arbitrary File", "critical", "")],
    "gitlab/16":      [("CVE-2023-5009", "Scan Execution Policy Bypass", "critical", "")],
    # ── Jenkins (ek sürümler) ──
    "jenkins/2.441":  [("CVE-2024-23897", "Arbitrary File Read via CLI", "critical", "")],
    # ── Grafana (ek sürümler) ──
    "grafana/9":      [("CVE-2023-3128", "Azure AD Auth Bypass", "critical", "")],
    "grafana/10":     [("CVE-2023-6152", "Email Verification Bypass", "medium", "")],
    # ── Confluence (ek sürümler) ──
    "confluence/8":   [("CVE-2023-22515", "Broken Access Control (Admin Create)", "critical", ""),
                       ("CVE-2023-22518", "Improper Authorization", "critical", "")],
    # ── Redis (ek sürümler) ──
    "redis/7":        [("CVE-2023-28856", "Insufficient ACL Enforcement", "medium", "")],
    # ── PostgreSQL (ek sürümler) ──
    "postgresql/13":  [("CVE-2021-23214", "SSL MitM Cleartext", "high", "")],
    "postgresql/14":  [("CVE-2022-2625", "Extension Script Replacement", "high", "")],
    "postgresql/15":  [("CVE-2023-5868", "Aggregate Function Memory Disclosure", "medium", "")],
    # ── MySQL (ek sürümler) ──
    "mysql/8.0":      [("CVE-2023-21912", "Server: Security: Encryption Unspecified", "medium", "")],
    "mysql/5.7":      [("CVE-2020-14812", "Server: Locking Unspecified", "medium", "")],
    # ── MongoDB (ek sürümler) ──
    "mongodb/4":      [("CVE-2021-20330", "Wire Protocol Out of Range", "medium", "")],
    "mongodb/5":      [("CVE-2023-1409", "TLS Certificate Verification Bypass", "high", "")],
    # ── vsFTPd (ek sürüm) ──
    "vsftpd/3.0.3":   [("CVE-2021-3618", "ALPACA Attack TLS Cross-Protocol", "medium", "")],
    # ── Elasticsearch (ek sürümler) ──
    "elasticsearch/8": [("CVE-2023-31419", "Stack Overflow in Search API", "medium", "")],
}

# Versiyon tespiti regex'leri — sadece güvenilir kaynaklardan
# header: Server, X-Powered-By (yüksek güven)
# body: CMS meta tagları (orta güven — doğrulama gerekli)
VERSION_PATTERNS_HEADER = [
    (r"Apache/(\d+\.\d+\.\d+)",       "apache"),
    (r"Apache/(\d+\.\d+)",            "apache"),
    (r"nginx/(\d+\.\d+(?:\.\d+)?)",   "nginx"),
    (r"Microsoft-IIS/(\d+\.\d+)",     "iis"),
    (r"OpenSSH[_/](\d+\.\d+)",        "openssh"),
    (r"ProFTPD\s+(\d+\.\d+\.\d+)",    "proftpd"),
    (r"vsftpd\s+(\d+\.\d+\.\d+)",     "vsftpd"),
    (r"PHP/(\d+\.\d+)",               "php"),
    (r"Tomcat/(\d+\.\d+)",            "tomcat"),
    (r"OpenSSL/(\d+\.\d+\.\d+)",      "openssl"),
    (r"OpenSSL/(\d+\.\d+)",           "openssl"),
    (r"Express/(\d+\.\d+)",           "express"),
    (r"Exim\s+(\d+\.\d+)",            "exim"),
    (r"Grafana\s+v?(\d+\.\d+)",       "grafana"),
    (r"Jenkins\s+ver\.?\s*(\d+\.\d+)", "jenkins"),
    (r"Elasticsearch/(\d+\.\d+)",      "elasticsearch"),
]

VERSION_PATTERNS_BODY = [
    (r'<meta[^>]+generator[^>]+WordPress\s+(\d+\.\d+)', "wordpress"),
    (r'"wordpress_version"\s*:\s*"(\d+\.\d+)',          "wordpress"),
    (r'Drupal\s+(\d+)\.',                               "drupal"),
    (r'Joomla!\s+(\d+\.\d+)',                           "joomla"),
    (r'<meta[^>]+generator[^>]+Drupal\s+(\d+)',         "drupal"),
    (r'Spring\s+(?:Boot\s+)?(\d+\.\d+)',                "spring"),
    (r'Confluence.*?(\d+\.\d+)',                         "confluence"),
    (r'GitLab.*?(\d+\.\d+)',                             "gitlab"),
]

# Log4Shell probe
LOG4SHELL_PAYLOAD = "${jndi:ldap://127.0.0.1:1389/a}"
LOG4SHELL_HEADERS = ["User-Agent", "X-Forwarded-For", "X-Api-Version",
                     "Referer", "X-Forwarded-Host"]

# Spring4Shell probe paths
SPRING4SHELL_PATHS = [
    "/?class.module.classLoader.URLs%5B0%5D=0",
    "/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=test",
]


class CVEMatcher(BaseModule):
    """CVE & Exploit Eşleştirici — v3 FP-Hardened"""

    def run(self) -> ModuleResult:
        self.log("CVE eşleştirme taraması başlatılıyor (FP-hardened)...")
        found_cves: List[Tuple] = []

        # 1. HTTP header'dan versiyon çek (yüksek güven)
        resp = self.http_get(self.url)
        headers = resp.get("headers", {})
        body = resp.get("body", "")
        header_text = " ".join(str(v) for v in headers.values())

        self.log("Header'dan versiyon tespiti (yüksek güven)...", "info")
        header_versions = self._extract_versions(header_text, VERSION_PATTERNS_HEADER)

        # 2. Body + ek sayfalardan versiyon (düşük güven — doğrulama gerekli)
        extra_urls = [
            self.url + "/wp-json/wp/v2",
            self.url + "/wp-includes/version.php",
        ]
        body_text = body
        for eurl, eresp in self.parallel_get(extra_urls, max_workers=4):
            if eresp.get("status", 0) == 200:
                body_text += " " + eresp.get("body", "")

        body_versions = self._extract_versions(body_text, VERSION_PATTERNS_BODY)

        # Deduplicate — header sürümü öncelikli
        seen = set()
        all_versions: List[Tuple[str, str, str]] = []  # (svc, ver, source)
        for svc, ver in header_versions:
            key = f"{svc}/{ver}"
            if key not in seen:
                seen.add(key)
                all_versions.append((svc, ver, "header"))
        for svc, ver in body_versions:
            key = f"{svc}/{ver}"
            if key not in seen:
                seen.add(key)
                all_versions.append((svc, ver, "body"))

        # 3. Offline CVE eşleştirme
        for svc, ver, source in all_versions:
            confidence = "yüksek" if source == "header" else "orta"
            self.log(f"Versiyon: {svc}/{ver} (kaynak: {source}, güven: {confidence})", "finding")
            cves = self._lookup_cve(svc, ver)
            for cve_id, desc, sev, link in cves:
                # Body kaynaklı sürümler için severity bir kademe düşür
                effective_sev = sev
                if source == "body" and sev in ("critical", "high"):
                    effective_sev = "high" if sev == "critical" else "medium"
                    desc += " [body kaynaklı — doğrulama önerilir]"

                found_cves.append((cve_id, svc, ver, desc, effective_sev, link))
                self.add_finding(
                    f"CVE: {cve_id} [{effective_sev.upper()}]",
                    f"{svc}/{ver} — {desc}{' | ' + link if link else ''}",
                    effective_sev
                )

        # 4. Log4Shell probe
        self.log("Log4Shell probe testi...", "info")
        self._probe_log4shell()

        # 5. Spring4Shell probe
        self.log("Spring4Shell probe testi...", "info")
        self._probe_spring4shell()

        # 6. NVD API'den ek CVE (online)
        if all_versions:
            self.log("NVD API sorgulanıyor...", "info")
            # Sadece header kaynaklı sürümleri NVD'de sorgula (güvenilir)
            nvd_candidates = [(s, v) for s, v, src in all_versions if src == "header"][:3]
            for svc, ver in nvd_candidates:
                nvd_cves = self._query_nvd(svc, ver)
                for c in nvd_cves:
                    if c["id"] not in [x[0] for x in found_cves]:
                        self.add_finding(
                            f"NVD CVE: {c['id']} [CVSS:{c.get('cvss', '?')}]",
                            f"{svc}/{ver} — {c['desc'][:100]}",
                            c.get("sev", "medium")
                        )

        # 7. Dangerous headers
        self._check_dangerous_headers(headers)

        # 8. Teknoloji parmak izi → ek CVE ipuçları
        self._check_technology_cves(body, headers)

        self.results["summary"].update({
            "Bulunan Versiyon": len(all_versions),
            "Header Versiyon": sum(1 for *_, s in all_versions if s == "header"),
            "Body Versiyon": sum(1 for *_, s in all_versions if s == "body"),
            "Eşleşen CVE": len(found_cves),
            "Kritik CVE": sum(1 for *_, s, _ in found_cves if s == "critical"),
            "Offline DB Boyutu": f"{len(OFFLINE_CVE_DB)} giriş",
        })
        return self.results

    def _extract_versions(self, text: str, patterns: list):
        found = []
        for pattern, svc in patterns:
            for m in re.finditer(pattern, text, re.I):
                found.append((svc, m.group(1)))
        return found

    @staticmethod
    def _normalize_version(ver: str) -> str:
        """Distro/OS eklerini temizle: '2.4.49-ubuntu1' → '2.4.49'"""
        # İlk '-' veya '+' veya '~' sonrasını kes (distro suffix)
        return re.split(r'[-+~]', ver)[0]

    def _lookup_cve(self, svc: str, ver: str):
        """Tam sürüm → major.minor eşleşme. Prefix-only eşleşme YOK.
        Distro suffix'leri normalize edilir (örn: 2.4.49-ubuntu1 → 2.4.49)."""
        ver = self._normalize_version(ver)
        results = []

        # 1. Tam sürüm eşleşme (en güvenilir)
        key_full = f"{svc}/{ver}"
        if key_full in OFFLINE_CVE_DB:
            results.extend(OFFLINE_CVE_DB[key_full])
            return results

        # 2. Major.minor eşleşme (makul güvenilirlik)
        parts = ver.split(".")
        if len(parts) >= 2:
            key_short = f"{svc}/{parts[0]}.{parts[1]}"
            if key_short in OFFLINE_CVE_DB:
                results.extend(OFFLINE_CVE_DB[key_short])
                return results

        # 3. Major eşleşme — SADECE CMS'ler ve bilinen stabil major sürümler için
        #    (Apache/Nginx gibi sık yamalananlar HARIÇ)
        major_safe = {"drupal", "tomcat", "elasticsearch", "mongodb",
                      "postgresql", "grafana", "gitlab", "jenkins",
                      "confluence", "exim", "php", "redis", "struts"}
        if svc in major_safe:
            key_major = f"{svc}/{parts[0]}"
            if key_major in OFFLINE_CVE_DB:
                results.extend(OFFLINE_CVE_DB[key_major])

        return results

    def _probe_log4shell(self):
        """Log4Shell probe — JNDI payload gönder, davranış farkı gözlemle."""
        baseline = self.http_get(self.url)
        baseline_status = baseline.get("status", 0)
        baseline_len = len(baseline.get("body", ""))

        anomalies = []
        for header in LOG4SHELL_HEADERS:
            resp = self.http_get(self.url, headers={header: LOG4SHELL_PAYLOAD})
            status = resp.get("status", 0)
            body = resp.get("body", "")
            resp_len = len(body)

            # Anomali: status değişti veya body uzunluğu %20+ farklı
            if status != baseline_status:
                anomalies.append(f"{header} (status {baseline_status}→{status})")
            elif baseline_len > 0 and abs(resp_len - baseline_len) / max(baseline_len, 1) > 0.2:
                anomalies.append(f"{header} (body boyutu değişti)")

        if anomalies:
            self.add_finding(
                "Log4Shell Probe — Davranış Anomalisi",
                f"JNDI payload sonrası farklı davranış: {', '.join(anomalies)}. "
                f"Kesin tespit için OOB/DNS callback gereklidir.",
                "medium"
            )
        else:
            self.add_finding(
                "Log4Shell Probe Tamamlandı",
                "HTTP probe'da anomali yok — kesin tespit OOB callback gerektirir.",
                "info"
            )

    def _probe_spring4shell(self):
        """Spring4Shell (CVE-2022-22965) probe."""
        base = self.url.rstrip("/")
        for path in SPRING4SHELL_PATHS:
            resp = self.http_get(base + path)
            status = resp.get("status", 0)
            if status == 500:
                body = resp.get("body", "").lower()
                # Hem 500 hem de Java-specific anahtar kelimeler olmalı
                java_indicators = ("classloader", "spring", "java.lang",
                                   "springframework", "classnotfound")
                matches = [k for k in java_indicators if k in body]
                if len(matches) >= 2:
                    self.add_finding(
                        "Spring4Shell Olası Etki (CVE-2022-22965)",
                        f"ClassLoader erişim denemesi 500 + {matches} — "
                        f"Manuel doğrulama gerekli.",
                        "high"
                    )
                    return

    # NVD API rate limit
    _nvd_last_call = 0.0
    _nvd_call_count = 0
    _NVD_RATE_WINDOW = 30.0
    _NVD_RATE_LIMIT = 4

    def _nvd_rate_wait(self):
        now = time.time()
        if now - self.__class__._nvd_last_call > self.__class__._NVD_RATE_WINDOW:
            self.__class__._nvd_call_count = 0
            self.__class__._nvd_last_call = now
        if self.__class__._nvd_call_count >= self.__class__._NVD_RATE_LIMIT:
            wait = self.__class__._NVD_RATE_WINDOW - (now - self.__class__._nvd_last_call) + 1
            if wait > 0:
                self.log(f"NVD rate limit — {wait:.0f}sn bekleniyor...", "warning")
                time.sleep(wait)
            self.__class__._nvd_call_count = 0
            self.__class__._nvd_last_call = time.time()
        self.__class__._nvd_call_count += 1

    def _query_nvd(self, svc, ver, retries=2):
        results = []
        for attempt in range(retries + 1):
            try:
                self._nvd_rate_wait()
                keyword = urllib.parse.quote(f"{svc} {ver}")
                url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                       f"?keywordSearch={keyword}&resultsPerPage=5")
                req = urllib.request.Request(url)
                req.add_header("User-Agent", "MaximaRecon/3.0")
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    if r.status == 429:
                        wait = 35 * (attempt + 1)
                        self.log(f"NVD 429 — {wait}sn bekleniyor", "warning")
                        time.sleep(wait)
                        continue
                    data = json.loads(r.read())
            except Exception as e:
                if "429" in str(e):
                    wait = 35 * (attempt + 1)
                    time.sleep(wait)
                    continue
                break

            # NVD sonuçlarını servis adı ile doğrula (alakasız CVE'leri filtrele)
            svc_lower = svc.lower()
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cid = cve.get("id", "")
                desc = next((d["value"] for d in cve.get("descriptions", [])
                             if d.get("lang") == "en"), "")
                desc_lower = desc.lower()

                # Alakalılık kontrolü: CVE açıklaması servis adını içermeli
                if svc_lower not in desc_lower and svc_lower.replace("-", "") not in desc_lower:
                    continue

                metrics = cve.get("metrics", {})
                cvss = "?"
                sev = "medium"
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    m_list = metrics.get(key, [])
                    if m_list:
                        score = m_list[0].get("cvssData", {}).get("baseScore", "?")
                        cvss = str(score)
                        try:
                            s = float(score)
                            sev = ("critical" if s >= 9 else "high" if s >= 7
                                   else "medium" if s >= 4 else "low")
                        except Exception:
                            pass
                        break
                if cid:
                    results.append({"id": cid, "desc": desc, "cvss": cvss, "sev": sev})
            break
        return results

    def _check_dangerous_headers(self, headers):
        h_lower = {k.lower(): v for k, v in headers.items()}
        for hdr in ("server", "x-powered-by", "x-aspnet-version",
                     "x-aspnetmvc-version", "x-generator"):
            if hdr in h_lower:
                self.add_finding(f"Versiyon Bilgisi Açık ({hdr})",
                                 f"Değer: {h_lower[hdr]}", "low")
        for hdr in ("x-debug-token", "x-debug-token-link", "x-runtime",
                     "x-development-mode"):
            if hdr in h_lower:
                self.add_finding(f"Debug Başlığı ({hdr})",
                                 f"Değer: {h_lower[hdr]}", "medium")

    def _check_technology_cves(self, body: str, headers: Dict):
        """HTML/header'daki teknoloji ipuçlarından ek CVE kontrolü."""
        lower = body.lower()
        h_lower = {k.lower(): v for k, v in headers.items()}

        # jQuery — SADECE yerel kaynaklar (harici CDN'ler false positive)
        # Yerel: src="/js/jquery-3.2.1.min.js" veya src="jquery.min.js"
        # Harici: src="https://cdn.jsdelivr.net/..." → ATLA
        local_jq_pattern = re.compile(
            r'<script[^>]+src=["\'](?!https?://)[^"\']*jquery[.-]?(\d+\.\d+\.\d+)',
            re.I
        )
        jq = local_jq_pattern.search(body)
        if jq:
            ver = jq.group(1)
            parts = [int(x) for x in ver.split(".")]
            if parts[0] < 3 or (len(parts) >= 2 and parts[0] == 3 and parts[1] < 5):
                self.add_finding("Eski jQuery Versiyonu (Yerel)",
                                 f"jQuery {ver} — bilinen XSS güvenlik açıkları mevcut",
                                 "medium")

        # AngularJS 1.x — SADECE yerel kaynak
        local_ng = re.search(
            r'<script[^>]+src=["\'](?!https?://)[^"\']*angular(?:\.min)?\.js',
            body, re.I
        )
        if local_ng and re.search(r'angular(?:\.min)?\.js.*?1\.\d+', lower):
            self.add_finding("AngularJS 1.x (EOL, Yerel)",
                             "AngularJS 1.x güvenlik yaması almıyor — "
                             "XSS template injection riski",
                             "medium")

        # Apache server-status/server-info — sadece Server header apache ise
        server = h_lower.get("server", "")
        if "apache" in server.lower():
            for path in ["/server-status", "/server-info"]:
                resp = self.http_get(self.url + path)
                rbody = resp.get("body", "")
                if (resp.get("status", 0) == 200 and len(rbody) > 500
                        and "apache" in rbody.lower()):
                    self.add_finding(f"Apache {path} Açık",
                                     f"Sunucu bilgileri herkese açık — bilgi sızıntısı",
                                     "high")

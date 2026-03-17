#!/usr/bin/env python3
"""
Maxima Cog: Directory Enumeration (v2)
200+ yol, recursive alt-dizin taraması, uzantı bruteforce,
soft-404 algılama, severity mapping.
PERF: parallel_get ile paralel batch (max_workers=15)
"""
from __future__ import annotations
import os
from utils.base_module import BaseModule, ModuleResult

# severity: (sev_200, sev_403, sev_401)
_CRITICAL = ("critical", "high",   "medium")
_HIGH     = ("high",     "medium", "medium")
_MEDIUM   = ("medium",   "low",    "low")
_LOW      = ("low",      "info",   "info")
_INFO     = ("info",     "info",   "info")

# ── Master wordlist by category ──────────────────────────────────
PATHS: list[tuple[str, tuple[str, str, str]]] = [
    # ── CMS: WordPress ──
    ("/wp-admin",                      _HIGH),
    ("/wp-login.php",                  _HIGH),
    ("/wp-content/uploads",            _MEDIUM),
    ("/wp-json",                       _MEDIUM),
    ("/wp-json/wp/v2/users",           _HIGH),
    ("/xmlrpc.php",                    _HIGH),
    ("/wp-config.php",                 _CRITICAL),
    ("/wp-config.php.bak",             _CRITICAL),
    ("/wp-includes",                   _LOW),
    ("/wp-cron.php",                   _LOW),
    ("/wp-content/debug.log",          _CRITICAL),
    # ── CMS: Joomla ──
    ("/administrator",                 _HIGH),
    ("/administrator/index.php",       _HIGH),
    ("/configuration.php",             _CRITICAL),
    ("/components",                    _LOW),
    # ── CMS: Drupal ──
    ("/user/login",                    _MEDIUM),
    ("/admin/config",                  _HIGH),
    ("/core/install.php",              _HIGH),
    ("/sites/default/settings.php",    _CRITICAL),
    ("/CHANGELOG.txt",                 _LOW),
    # ── CMS: Laravel / PHP frameworks ──
    ("/.env",                          _CRITICAL),
    ("/telescope",                     _HIGH),
    ("/horizon",                       _HIGH),
    ("/horizon/api",                   _HIGH),
    ("/storage/logs/laravel.log",      _CRITICAL),
    ("/vendor",                        _LOW),
    ("/artisan",                       _MEDIUM),
    # ── Config / secrets ──
    ("/.git",                          _CRITICAL),
    ("/.git/config",                   _CRITICAL),
    ("/.git/HEAD",                     _CRITICAL),
    ("/.gitignore",                    _LOW),
    ("/.svn/entries",                  _CRITICAL),
    ("/.svn/wc.db",                    _CRITICAL),
    ("/.hg",                           _CRITICAL),
    ("/.htaccess",                     _HIGH),
    ("/.htpasswd",                     _CRITICAL),
    ("/web.config",                    _CRITICAL),
    ("/config.php",                    _HIGH),
    ("/config.yml",                    _HIGH),
    ("/config.json",                   _HIGH),
    ("/configuration.php",             _CRITICAL),
    ("/settings.py",                   _CRITICAL),
    ("/settings.ini",                  _CRITICAL),
    ("/docker-compose.yml",            _HIGH),
    ("/docker-compose.yaml",           _HIGH),
    ("/Dockerfile",                    _MEDIUM),
    ("/.dockerenv",                    _MEDIUM),
    ("/composer.json",                 _LOW),
    ("/composer.lock",                 _LOW),
    ("/package.json",                  _LOW),
    ("/package-lock.json",             _LOW),
    ("/yarn.lock",                     _LOW),
    ("/Gemfile",                       _LOW),
    ("/Gemfile.lock",                  _LOW),
    ("/Makefile",                      _LOW),
    ("/Gruntfile.js",                  _LOW),
    ("/Gulpfile.js",                   _LOW),
    ("/webpack.config.js",             _LOW),
    ("/tsconfig.json",                 _LOW),
    ("/Procfile",                      _LOW),
    ("/requirements.txt",              _LOW),
    ("/Pipfile",                       _LOW),
    ("/setup.py",                      _LOW),
    # ── Admin panels ──
    ("/admin",                         _HIGH),
    ("/admin/login",                   _HIGH),
    ("/administrator",                 _HIGH),
    ("/cpanel",                        _HIGH),
    ("/phpmyadmin",                    _HIGH),
    ("/pma",                           _HIGH),
    ("/adminer",                       _HIGH),
    ("/adminer.php",                   _HIGH),
    ("/manager",                       _HIGH),
    ("/manager/html",                  _HIGH),
    ("/console",                       _HIGH),
    ("/dashboard",                     _MEDIUM),
    ("/panel",                         _HIGH),
    ("/webadmin",                      _HIGH),
    ("/sysadmin",                      _HIGH),
    ("/controlpanel",                  _HIGH),
    ("/admin-console",                 _HIGH),
    ("/login",                         _MEDIUM),
    ("/signin",                        _MEDIUM),
    ("/auth/login",                    _MEDIUM),
    # ── API endpoints ──
    ("/api",                           _LOW),
    ("/api/v1",                        _LOW),
    ("/api/v2",                        _LOW),
    ("/api/v3",                        _LOW),
    ("/graphql",                       _MEDIUM),
    ("/graphiql",                      _HIGH),
    ("/swagger",                       _MEDIUM),
    ("/swagger-ui",                    _MEDIUM),
    ("/swagger-ui.html",               _MEDIUM),
    ("/api-docs",                      _MEDIUM),
    ("/openapi.json",                  _MEDIUM),
    ("/swagger.json",                  _MEDIUM),
    ("/swagger.yaml",                  _MEDIUM),
    ("/redoc",                         _MEDIUM),
    ("/.well-known/openid-configuration", _MEDIUM),
    ("/oauth/token",                   _MEDIUM),
    ("/oauth/authorize",               _MEDIUM),
    ("/api/config",                    _HIGH),
    ("/api/debug",                     _HIGH),
    ("/api/admin",                     _HIGH),
    # ── Backup files ──
    ("/backup.zip",                    _CRITICAL),
    ("/backup.tar.gz",                 _CRITICAL),
    ("/backup.sql",                    _CRITICAL),
    ("/db.sql",                        _CRITICAL),
    ("/database.sql",                  _CRITICAL),
    ("/dump.sql",                      _CRITICAL),
    ("/site.tar.gz",                   _CRITICAL),
    ("/site.zip",                      _CRITICAL),
    ("/www.zip",                       _CRITICAL),
    ("/data.sql",                      _CRITICAL),
    ("/old.zip",                       _HIGH),
    ("/archive.zip",                   _HIGH),
    ("/backup.bak",                    _CRITICAL),
    ("/db_backup.sql",                 _CRITICAL),
    # ── Debug / dev ──
    ("/debug",                         _HIGH),
    ("/trace",                         _HIGH),
    ("/server-status",                 _HIGH),
    ("/server-info",                   _HIGH),
    ("/phpinfo.php",                   _CRITICAL),
    ("/info.php",                      _CRITICAL),
    ("/test",                          _MEDIUM),
    ("/test.php",                      _HIGH),
    ("/test.html",                     _LOW),
    ("/_debug",                        _HIGH),
    ("/_profiler",                     _HIGH),
    ("/actuator",                      _HIGH),
    ("/actuator/health",               _LOW),
    ("/actuator/env",                  _CRITICAL),
    ("/actuator/configprops",          _CRITICAL),
    ("/actuator/mappings",             _HIGH),
    ("/actuator/beans",                _HIGH),
    ("/actuator/heapdump",             _CRITICAL),
    ("/actuator/threaddump",           _HIGH),
    ("/metrics",                       _MEDIUM),
    ("/health",                        _LOW),
    ("/healthcheck",                   _LOW),
    ("/status",                        _LOW),
    ("/trace.axd",                     _HIGH),
    ("/elmah.axd",                     _HIGH),
    ("/error_log",                     _HIGH),
    # ── Cloud / CI ──
    ("/.aws/credentials",              _CRITICAL),
    ("/.aws/config",                   _CRITICAL),
    ("/.azure",                        _HIGH),
    ("/Jenkinsfile",                   _MEDIUM),
    ("/.circleci/config.yml",          _MEDIUM),
    ("/.github",                       _LOW),
    ("/.github/workflows",             _MEDIUM),
    ("/.gitlab-ci.yml",                _MEDIUM),
    ("/kubernetes",                    _MEDIUM),
    ("/.kube/config",                  _CRITICAL),
    ("/.terraform",                    _HIGH),
    ("/terraform.tfstate",             _CRITICAL),
    ("/terraform.tfvars",              _CRITICAL),
    # ── Common files ──
    ("/robots.txt",                    _LOW),
    ("/sitemap.xml",                   _INFO),
    ("/crossdomain.xml",               _MEDIUM),
    ("/clientaccesspolicy.xml",        _MEDIUM),
    ("/security.txt",                  _INFO),
    ("/.well-known/security.txt",      _INFO),
    ("/humans.txt",                    _INFO),
    ("/favicon.ico",                   _INFO),
    ("/license.txt",                   _INFO),
    ("/readme.html",                   _LOW),
    ("/README.md",                     _LOW),
    ("/INSTALL.txt",                   _LOW),
    ("/UPGRADE.txt",                   _LOW),
    # ── Misc / known vulns ──
    ("/cgi-bin/",                      _MEDIUM),
    ("/cgi-bin/test-cgi",              _HIGH),
    ("/server",                        _MEDIUM),
    ("/.DS_Store",                     _MEDIUM),
    ("/Thumbs.db",                     _LOW),
    ("/WEB-INF/web.xml",              _CRITICAL),
    ("/META-INF/MANIFEST.MF",         _MEDIUM),
    ("/solr/admin",                    _HIGH),
    ("/jenkins",                       _HIGH),
    ("/jolokia",                       _HIGH),
    ("/jmx-console",                   _HIGH),
    ("/axis2-admin",                   _HIGH),
    ("/invoker/readonly",              _CRITICAL),
    ("/portal",                        _MEDIUM),
    ("/filemanager",                   _HIGH),
]

# Paths worth trying with extra extensions
_EXT_CANDIDATES = {
    "/admin", "/login", "/test", "/config", "/dashboard", "/panel",
    "/index", "/default", "/home", "/main", "/app", "/portal",
    "/manager", "/server", "/api", "/console", "/backup",
}
_EXTENSIONS = [".php", ".asp", ".aspx", ".jsp", ".html", ".bak", ".old", ".txt"]

# Sub-paths to try when a directory responds 200/301/302
_RECURSIVE_SUBS = ["login", "config", "users", "settings", "api",
                   "admin", "index.php", "index.html", "dashboard"]

# Soft-404 body size threshold (bytes)
_SOFT_404_THRESHOLD = 150


class DirectoryEnumeration(BaseModule):

    def _load_paths(self):
        """Custom wordlist veya built-in path listesini yükle."""
        wl_path = getattr(self, "wordlist_path", None)
        if wl_path:
            try:
                with open(wl_path, encoding="utf-8", errors="ignore") as f:
                    paths = [("/" + ln.strip().lstrip("/"), _MEDIUM)
                             for ln in f if ln.strip() and not ln.startswith("#")]
                if paths:
                    self.log(f"Wordlist: {len(paths)} yol", "success")
                    return paths
            except Exception as ex:
                self.log(f"Wordlist hata: {ex} — builtin kullanılıyor", "warning")
        return list(PATHS)

    # ── helpers ────────────────────────────────────────────────
    @staticmethod
    def _sev(sev_tuple, status):
        """Status koduna göre severity döndür."""
        if status == 200:
            return sev_tuple[0]
        if status == 403:
            return sev_tuple[1]
        return sev_tuple[2]  # 401

    def _baseline_404(self, base_url: str) -> int:
        """Bilinen-olmayan bir path'e istek atarak soft-404 body uzunluğunu öğren."""
        resp = self.http_get(base_url + "/Mx_rand_404_test_92f1")
        return len(resp.get("body", ""))

    def _is_soft_404(self, body: str, baseline_len: int) -> bool:
        """Cevap gövdesi baseline ile çok yakınsa soft-404 sayar."""
        blen = len(body)
        if blen < _SOFT_404_THRESHOLD:
            return True
        if baseline_len > 0 and abs(blen - baseline_len) < max(50, baseline_len * 0.05):
            return True
        return False

    # ── main ──────────────────────────────────────────────────
    def run(self) -> ModuleResult:
        paths = self._load_paths()
        base_url = self.url.rstrip("/")

        # Extension bruteforce: generate extra entries
        for p, sev in list(paths):
            bare = p.rstrip("/")
            if bare in _EXT_CANDIDATES:
                for ext in _EXTENSIONS:
                    paths.append((bare + ext, sev))

        # Deduplicate while preserving order
        seen: set[str] = set()
        deduped = []
        for p, s in paths:
            if p not in seen:
                seen.add(p)
                deduped.append((p, s))
        paths = deduped

        self.log(f"Dizin taraması — {len(paths)} yol (paralel)...")

        # Soft-404 baseline
        baseline_len = self._baseline_404(base_url)

        url_map: dict[str, tuple[str, tuple[str, str, str]]] = {}
        for p, sev in paths:
            url_map[base_url + p] = (p, sev)
        urls = list(url_map.keys())

        found = forbidden = auth_req = 0
        recursive_dirs: list[tuple[str, tuple[str, str, str]]] = []

        for url, resp in self.parallel_get(urls, max_workers=15):
            path, sev = url_map[url]
            status = resp.get("status", 0)
            body = resp.get("body", "")
            headers = resp.get("headers", {})

            if status == 200:
                if self._is_soft_404(body, baseline_len):
                    continue
                found += 1
                size_kb = f"{len(body)/1024:.1f}KB"
                self.add_finding(
                    f"Erişilebilir: {path}",
                    f"HTTP 200 — {url} ({size_kb})",
                    self._sev(sev, 200))
                # Queue for recursive scan if looks like a directory
                if path.endswith("/") or "." not in path.split("/")[-1]:
                    recursive_dirs.append((path, sev))

            elif status in (301, 302):
                location = headers.get("location", headers.get("Location", "?"))
                found += 1
                self.add_finding(
                    f"Yönlendirme: {path}",
                    f"HTTP {status} → {location}",
                    self._sev(sev, 200))
                recursive_dirs.append((path, sev))

            elif status == 403:
                forbidden += 1
                sev_val = self._sev(sev, 403)
                if sev_val != "info":
                    self.add_finding(
                        f"Erişim Engellendi (Var): {path}",
                        f"HTTP 403 — mevcut ama kısıtlı",
                        sev_val)

            elif status == 401:
                auth_req += 1
                self.add_finding(
                    f"Kimlik Doğrulama Gerekli: {path}",
                    f"HTTP 401 — auth required",
                    self._sev(sev, 401))

        # ── Recursive sub-path scan ──────────────────────────
        sub_url_map: dict[str, tuple[str, tuple[str, str, str]]] = {}
        if recursive_dirs:
            for dir_path, sev in recursive_dirs:
                base = dir_path.rstrip("/")
                for sub in _RECURSIVE_SUBS:
                    full = f"{base}/{sub}"
                    if full not in seen:
                        seen.add(full)
                        sub_url_map[base_url + full] = (full, sev)

            if sub_url_map:
                self.log(f"Recursive tarama — {len(sub_url_map)} alt yol...")
                for url, resp in self.parallel_get(list(sub_url_map.keys()),
                                                   max_workers=15):
                    path, sev = sub_url_map[url]
                    status = resp.get("status", 0)
                    body = resp.get("body", "")
                    headers = resp.get("headers", {})

                    if status == 200 and not self._is_soft_404(body, baseline_len):
                        found += 1
                        self.add_finding(
                            f"Erişilebilir (recursive): {path}",
                            f"HTTP 200 — {url} ({len(body)/1024:.1f}KB)",
                            self._sev(sev, 200))
                    elif status in (301, 302):
                        loc = headers.get("location", headers.get("Location", "?"))
                        found += 1
                        self.add_finding(
                            f"Yönlendirme (recursive): {path}",
                            f"HTTP {status} → {loc}",
                            self._sev(sev, 200))
                    elif status == 403:
                        s = self._sev(sev, 403)
                        if s != "info":
                            forbidden += 1
                            self.add_finding(
                                f"Engellendi (recursive): {path}",
                                f"HTTP 403", s)
                    elif status == 401:
                        auth_req += 1
                        self.add_finding(
                            f"Auth Gerekli (recursive): {path}",
                            f"HTTP 401", self._sev(sev, 401))

        self.results["summary"]["Taranan"]          = len(paths) + len(sub_url_map)
        self.results["summary"]["Erişilebilir"]     = found
        self.results["summary"]["Engelli (403)"]    = forbidden
        self.results["summary"]["Auth Gerekli (401)"] = auth_req
        self.results["summary"]["Soft-404 baseline"] = f"{baseline_len}B"
        return self.results

#!/usr/bin/env python3
"""
Maxima Cog: Kimlik Doğrulama Testi (Gelişmiş)
Login form tespiti, default credential testi,
account lockout analizi, credential stuffing simülasyonu
"""
import sys
import os
import re
import time
import json
import base64
import urllib.parse
import urllib.request
from utils.base_module import BaseModule, ModuleResult

# ── Default Credential Listesi ────────────────────────────────
DEFAULT_CREDS = [
    # (username, password, açıklama)
    ("admin",       "admin",          "Generic default"),
    ("admin",       "password",       "Generic default"),
    ("admin",       "admin123",       "Generic default"),
    ("admin",       "123456",         "Generic default"),
    ("admin",       "",               "Boş şifre"),
    ("root",        "root",           "Linux default"),
    ("root",        "toor",           "Kali default"),
    ("root",        "",               "Boş şifre"),
    ("administrator","administrator", "Windows default"),
    ("administrator","password",      "Windows default"),
    ("guest",       "guest",          "Guest hesabı"),
    ("test",        "test",           "Test hesabı"),
    ("user",        "user",           "Generic user"),
    ("demo",        "demo",           "Demo hesabı"),
    ("superadmin",  "superadmin",     "CMS default"),
    ("admin",       "1234",           "Kısa şifre"),
    ("admin",       "12345678",       "Yaygın şifre"),
    ("admin",       "qwerty",         "Yaygın şifre"),
    # Uygulama özelinde
    ("tomcat",      "tomcat",         "Apache Tomcat"),
    ("tomcat",      "s3cret",         "Apache Tomcat"),
    ("manager",     "manager",        "Apache Tomcat"),
    ("elastic",     "",               "Elasticsearch"),
    ("kibana",      "changeme",       "Kibana default"),
    ("pi",          "raspberry",      "Raspberry Pi"),
    ("ubnt",        "ubnt",           "Ubiquiti"),
    ("cisco",       "cisco",          "Cisco"),
    ("admin",       "cisco",          "Cisco"),
    ("admin",       "1234567890",     "Yaygın şifre"),
    ("wordpress",   "wordpress",      "WordPress"),
]

# ── Login Form Tespiti ────────────────────────────────────────
LOGIN_PATHS = [
    "/login", "/admin", "/admin/login", "/wp-admin",
    "/wp-login.php", "/administrator", "/user/login",
    "/auth/login", "/signin", "/account/login",
    "/panel", "/cpanel", "/control", "/manager",
    "/phpmyadmin", "/pma", "/adminer",
    "/api/login", "/api/auth", "/api/v1/login",
    "/login.php", "/login.aspx", "/login.jsp",
]

# Şifre gücü kuralları
WEAK_PATTERNS = [
    (r"^.{1,7}$",              "Çok kısa (< 8 karakter)",          "high"),
    (r"^[0-9]+$",              "Sadece rakam",                      "high"),
    (r"^[a-z]+$",              "Sadece küçük harf",                 "high"),
    (r"^(password|pass|1234|qwerty|abc123|letmein|admin|test)$",
                               "En yaygın şifrelerden biri",        "critical"),
    (r"(.)\1{3,}",             "Tekrarlayan karakter",              "medium"),
    (r"^(19|20)\d{2}$",        "Sadece yıl",                       "high"),
]

class AuthTester(BaseModule):
    """Kimlik Doğrulama & Credential Testi"""

    def run(self) -> ModuleResult:
        self.log("Kimlik doğrulama testi başlatılıyor...")

        # 1. Login endpoint'lerini bul
        login_forms = self._find_login_forms()

        # 2. Her form için default credential testi
        for form_info in login_forms[:3]:  # Max 3 form
            self._test_credentials(form_info)

        # 3. API endpoint auth testi
        self._test_api_auth()

        # 4. Account lockout politikası testi
        for form_info in login_forms[:1]:
            self._test_lockout(form_info)

        # 5. HTTP Basic Auth testi
        self._test_basic_auth()

        # 6. Şifre politikası analizi (register form)
        self._analyze_password_policy()

        # 7. Session güvenliği
        self._check_session_security()

        return self.results

    def _find_login_forms(self):
        found = []
        self.log("Login form tespiti...", "info")
        for path in LOGIN_PATHS:
            url  = self.url.rstrip("/") + path
            resp = self.http_get(url, follow_redirects=True)
            code = resp.get("status", 0)
            body = resp.get("body", "").lower()

            if code not in (200, 405): continue

            # Form içeriği kontrolü
            has_pass  = bool(re.search(r'input[^>]+type=["\']password', body))
            has_user  = bool(re.search(r'input[^>]+(?:name|id)=["\'](?:user|login|email|username)', body))
            has_form  = "<form" in body

            if has_pass or (has_form and has_user):
                # Form field'larını çıkar
                user_fields = re.findall(
                    r'input[^>]+name=["\']([\w\-]+)["\']', body)
                method = "POST"
                if re.search(r'method=["\']get', body, re.I):
                    method = "GET"

                form_info = {
                    "url":          url,
                    "path":         path,
                    "fields":       user_fields,
                    "method":       method,
                    "has_password": has_pass,
                }
                found.append(form_info)
                self.add_finding(
                    f"Login Formu Bulundu: {path}",
                    f"URL: {url} | Method: {method} | Fields: {user_fields}",
                    "info"
                )
                self.log(f"Login form: {path}", "finding")

        self.results["summary"]["Login Form Sayısı"] = len(found)
        return found

    def _test_credentials(self, form_info):
        url    = form_info["url"]
        fields = form_info.get("fields", [])
        self.log(f"Credential testi: {form_info['path']}", "info")

        # Field adlarını akıllıca eşleştir
        user_field = next((f for f in fields if any(k in f.lower()
            for k in ("user","login","email","name","account"))), "username")
        pass_field = next((f for f in fields if "pass" in f.lower()), "password")

        successes = []
        failures  = 0
        baseline_len  = 0
        baseline_code = 0

        # Baseline al (yanlış cred)
        base_resp = self._post_form(url, {user_field: "notexist_xyz", pass_field: "wrongpass123"})
        baseline_code = base_resp.get("status", 0)
        baseline_body = base_resp.get("body", "").lower()  # BUG FIX: baseline body'si ayrıca saklanıyor
        baseline_len  = len(baseline_body)
        baseline_url  = base_resp.get("url", "")

        consecutive_401 = 0
        for idx, (username, password, desc) in enumerate(DEFAULT_CREDS[:20]):
            # Adaptive throttle: her 5 denemede bekleme süresini artır
            delay = 0.5 if idx < 5 else 1.0 if idx < 10 else 1.5
            time.sleep(delay)

            resp = self._post_form(url, {user_field: username, pass_field: password})
            code = resp.get("status", 0)
            body = resp.get("body", "").lower()
            rurl = resp.get("url", "")

            # Lockout / rate-limit tespiti → erken dur
            if code == 429 or any(t in body for t in ("locked", "blocked", "too many",
                                                       "çok fazla", "kilitlend", "rate limit")):
                self.add_finding("Hesap Kilitleme / Rate Limit Tetiklendi",
                                 f"{idx+1}. denemede engelleme tespit edildi — test durduruluyor",
                                 "info")
                self.log("Rate limit/lockout tespit edildi, credential testi durduruluyor", "warning")
                break

            # Art arda 401 sayısı — sunucu tutarlı reddetiyorsa (form doğru çalışıyor)
            if code == 401:
                consecutive_401 += 1
            else:
                consecutive_401 = 0

            # Başarı tespiti
            success = self._detect_login_success(
                code, body, rurl, baseline_code, baseline_len, baseline_url, baseline_body)

            if success:
                successes.append((username, password, desc))
                self.add_finding(
                    f"Zayıf Kimlik Bilgisi: {username}:{password}",
                    f"Açıklama: {desc} | URL: {url}",
                    "critical"
                )
                self.log(f"[!] BAŞARILI: {username}:{password}", "finding")
                break  # İlk başarılı yeterli
            else:
                failures += 1

        self.results["summary"][f"{form_info['path']} — Denenen"]  = failures + len(successes)
        self.results["summary"][f"{form_info['path']} — Başarılı"] = len(successes)

    def _detect_login_success(self, code, body, url,
                               base_code, base_len, base_url, base_body=""):
        """Giriş başarısını çok yönlü tespit et"""
        # Redirect değişimi
        if code in (301, 302) and base_code not in (301, 302): return True
        if url != base_url and "logout" in url.lower():        return True
        if url != base_url and "dashboard" in url.lower():     return True
        if url != base_url and "panel" in url.lower():         return True
        # Body belirteçleri
        success_tokens = ["dashboard","logout","welcome","signed in",
                          "hoş geldiniz","çıkış","panel","my account",
                          "profile","başarı"]
        for token in success_tokens:
            if token in body: return True
        # Cevap boyutu çok farklıysa (içerik değişti)
        cur_len = len(body)
        if base_len > 0 and abs(cur_len - base_len) > base_len * 0.6 and cur_len > 200: return True
        # BUG FIX: Hata mesajı baseline'da VAR ama şimdiki yanıtta YOK — gerçek başarı sinyali
        # Eski hatalı kod: base_has_error = any(t in body ...) — body yerine base_body kontrol edilmeliydi
        # Eski hatalı kod: "not base_has_error and code == 200" — her 200'ü true yapıyordu
        error_tokens = ["invalid","wrong","incorrect","failed","hatalı","yanlış"]
        baseline_had_error  = any(t in base_body for t in error_tokens)  # baseline'da hata var mıydı?
        current_has_error   = any(t in body      for t in error_tokens)  # şimdiki yanıtta hata var mı?
        if baseline_had_error and not current_has_error and code == 200:
            return True  # Baseline'da hata vardı, şimdi yok → giriş başarılı
        return False

    def _post_form(self, url, data):
        """Form POST gönder"""
        encoded = urllib.parse.urlencode(data).encode()
        return self.http_post(url, encoded,
                               headers={"Content-Type":"application/x-www-form-urlencoded"})

    def _test_api_auth(self):
        """REST API auth endpoint testi"""
        self.log("API auth endpoint testi...", "info")
        api_paths = [
            "/api/login", "/api/auth", "/api/v1/auth",
            "/api/v1/login", "/api/token", "/oauth/token",
        ]
        for path in api_paths:
            url  = self.url.rstrip("/") + path
            resp = self.http_get(url)
            if resp.get("status", 0) in (200, 401, 405):
                self.log(f"API endpoint: {path} [{resp['status']}]", "info")
                # JSON credential testi
                for user, pwd, desc in DEFAULT_CREDS[:5]:
                    payload = json.dumps({"username": user, "password": pwd}).encode()
                    r = self.http_post(url, payload,
                                       headers={"Content-Type":"application/json"})
                    body   = r.get("body","")
                    code_r = r.get("status", 0)
                    # FIX v9: "token" kelimesi login/CSRF formlarında da geçer → false positive
                    # Gerçek başarı: "access_token" veya "auth_token" + HTTP 200/201,
                    # VEYA response body'de "token" + "expires" birlikte
                    is_success = (
                        code_r in (200, 201) and (
                            "access_token" in body.lower() or
                            "auth_token"   in body.lower() or
                            ("token" in body.lower() and "expires" in body.lower()) or
                            ('"token"' in body and len(body) > 50)
                        )
                    )
                    if is_success:
                        self.add_finding(
                            f"API Default Credential: {user}:{pwd}",
                            f"JSON auth başarılı (access_token alındı): {path}",
                            "critical"
                        )
                        self.log(f"API başarılı: {user}:{pwd} @ {path}", "finding")
                        break

    def _test_lockout(self, form_info):
        """Hesap kilitleme politikası var mı?"""
        self.log("Hesap kilitleme testi...", "info")
        url     = form_info["url"]
        fields  = form_info.get("fields", [])
        u_field = next((f for f in fields if "user" in f.lower()), "username")
        p_field = next((f for f in fields if "pass" in f.lower()), "password")

        codes = []
        for i in range(6):  # 6 yanlış deneme
            time.sleep(0.2)
            r = self._post_form(url, {u_field: "admin", p_field: f"wrongpass_{i}"})
            codes.append(r.get("status", 0))
            body = r.get("body","").lower()
            if any(t in body for t in ("locked","blocked","too many","çok fazla","kilitlend")):
                self.add_finding(
                    "Hesap Kilitleme Aktif",
                    f"{i+1}. denemede hesap kilitlendi.",
                    "info"
                )
                self.log("Hesap kilitleme tespit edildi", "success")
                return

        # 6 denemede kilitlenme yoksa
        self.add_finding(
            "Hesap Kilitleme Yok",
            "6 başarısız denemede hesap kilitlenmedi — Brute force riski!",
            "high"
        )
        self.log("Hesap kilitleme tespit EDİLEMEDİ!", "warning")

    def _test_basic_auth(self):
        """HTTP Basic Auth testi"""
        self.log("HTTP Basic Auth testi...", "info")
        resp = self.http_get(self.url)
        if "www-authenticate" in {k.lower() for k in resp.get("headers",{}).keys()}:
            self.add_finding("HTTP Basic Auth Aktif",
                             "Sunucu HTTP Basic Auth kullanıyor", "medium")
            for user, pwd, _ in DEFAULT_CREDS[:10]:
                cred   = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                r      = self.http_get(self.url,
                                       headers={"Authorization": f"Basic {cred}"})
                if r.get("status", 0) not in (401, 403):
                    self.add_finding(
                        f"Basic Auth Default Cred: {user}:{pwd}",
                        f"HTTP {r['status']} — Giriş başarılı",
                        "critical"
                    )
                    self.log(f"Basic Auth kırıldı: {user}:{pwd}", "finding")
                    break

    def _analyze_password_policy(self):
        """Register sayfasından şifre politikası analizi"""
        for path in ("/register", "/signup", "/user/register", "/create-account"):
            url  = self.url.rstrip("/") + path
            resp = self.http_get(url)
            if resp.get("status",0) != 200: continue
            body = resp.get("body","").lower()
            if "password" not in body: continue

            hints = []
            if re.search(r"minimum.{0,20}(\d+).{0,10}character", body):
                hints.append("Minimum karakter kuralı var")
            if re.search(r"uppercase|büyük harf", body):
                hints.append("Büyük harf zorunlu")
            if re.search(r"number|rakam|digit", body):
                hints.append("Rakam zorunlu")
            if re.search(r"special|özel karakter|symbol", body):
                hints.append("Özel karakter zorunlu")

            if hints:
                self.add_finding("Şifre Politikası Tespit Edildi",
                                 " | ".join(hints), "info")
            else:
                self.add_finding("Şifre Politikası Belirsiz",
                                 f"Register sayfasında kural bulunamadı: {path}", "medium")
            break

    def _check_session_security(self):
        """Session cookie güvenliği"""
        self.log("Session güvenliği kontrolü...", "info")
        resp    = self.http_get(self.url)
        cookies = resp.get("headers",{}).get("set-cookie","")
        if not cookies: return

        if "httponly" not in cookies.lower():
            self.add_finding("Cookie HttpOnly Eksik",
                             "Session cookie HttpOnly flag yok — XSS ile çalınabilir", "high")
        if "secure" not in cookies.lower():
            self.add_finding("Cookie Secure Flag Eksik",
                             "HTTP üzerinden cookie gönderilebilir", "medium")
        if "samesite" not in cookies.lower():
            self.add_finding("Cookie SameSite Eksik",
                             "CSRF saldırılarına açık olabilir", "medium")

        # Session ID entropi tahmini
        session_vals = re.findall(r"(?:PHPSESSID|JSESSIONID|session|sess)[=:]\s*([a-zA-Z0-9+/=_\-]{8,})",
                                  cookies, re.I)
        for sv in session_vals:
            if len(sv) < 16:
                self.add_finding("Kısa Session ID",
                                 f"Session ID çok kısa ({len(sv)} karakter): {sv[:20]}",
                                 "high")

    # http_post BaseModule'den miras alınıyor (utils/base_module.py)

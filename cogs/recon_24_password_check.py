#!/usr/bin/env python3
"""
Maxima Cog: Password Strength & Auth Policy Analyzer
Login formu tespiti, şifre politikası analizi, hesap kilitleme testi,
CAPTCHA tespiti, autocomplete kontrolü, güvenli iletim analizi.
"""
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple
from utils.base_module import BaseModule, ModuleResult


# Yaygın zayıf şifreler (genişletilmiş — credential stuffing listelerinden)
COMMON_PASSWORDS = [
    "123456", "password", "admin", "test", "1234", "qwerty",
    "abc123", "letmein", "admin123", "password1", "test123", "12345678",
    "root", "toor", "pass", "master", "login", "welcome", "monkey",
    "dragon", "1234567890", "123123", "654321", "password123",
    "iloveyou", "sunshine", "princess", "football", "shadow",
    "trustno1", "passw0rd", "P@ssw0rd", "admin1", "user",
]

# Login form tespiti için path'ler
LOGIN_PATHS = [
    "/login", "/signin", "/auth/login", "/account/login",
    "/wp-login.php", "/admin", "/admin/login", "/user/login",
    "/panel/login", "/auth", "/session/new", "/api/auth/login",
    "/oauth/authorize", "/sso/login",
]

# Form field adları — login formu tespiti
_LOGIN_FIELDS = re.compile(
    r'name=["\']?(username|user|email|login|usr|uname|password|passwd|pwd|pass)["\']?',
    re.I,
)
_PASSWORD_FIELD = re.compile(
    r'<input[^>]+type=["\']password["\'][^>]*>', re.I
)
_HIDDEN_FIELD = re.compile(
    r'<input[^>]+type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*'
    r'(?:value=["\']([^"\']*)["\'])?', re.I
)
_FORM_ACTION = re.compile(
    r'<form[^>]+action=["\']([^"\']+)["\'][^>]*', re.I
)
_CAPTCHA_RE = re.compile(
    r'captcha|recaptcha|hcaptcha|g-recaptcha|cf-turnstile|'
    r'data-sitekey|data-captcha|securimage|captcha_image',
    re.I,
)


class PasswordStrengthChecker(BaseModule):
    """Şifre Politikası & Kimlik Doğrulama Analizi"""

    def run(self) -> ModuleResult:
        self.log("Şifre politikası ve kimlik doğrulama analizi başlatılıyor...")
        base = self.url.rstrip("/")

        # ── 1. Login sayfası keşfi (paralel) ──
        urls = [base + p for p in LOGIN_PATHS]
        path_map = {base + p: p for p in LOGIN_PATHS}

        login_pages: List[Tuple[str, str, str]] = []  # (url, path, body)

        for url, resp in self.parallel_get(urls, max_workers=8):
            s = resp.get("status", 0)
            body = resp.get("body", "")
            path = path_map[url]
            if s not in (200, 301, 302):
                continue
            if not _PASSWORD_FIELD.search(body):
                continue
            login_pages.append((url, path, body))

        # Ana sayfada da login formu olabilir
        main_resp = self.http_get(base)
        if _PASSWORD_FIELD.search(main_resp.get("body", "")):
            login_pages.append((base, "/", main_resp.get("body", "")))

        if not login_pages:
            self.add_finding("Login Formu Bulunamadı",
                             "Bilinen login path'lerinde şifre alanı tespit edilmedi", "info")
            self.results["summary"]["Login Sayfası"] = "Bulunamadı"
            return self.results

        self.log(f"{len(login_pages)} login sayfası bulundu", "success")

        # İlk bulunan login sayfasını detaylı analiz et
        login_url, login_path, login_body = login_pages[0]
        self.results["summary"]["Login Sayfası"] = f"{login_path} — HTTP 200"
        self.add_finding("Login Formu Tespit Edildi", f"Adres: {login_url}", "info")

        # ── 2. Şifre politikası analizi ──
        self._analyze_password_policy(login_body)

        # ── 3. Form güvenlik analizi ──
        self._analyze_form_security(login_url, login_body)

        # ── 4. CAPTCHA tespiti ──
        self._check_captcha(login_body)

        # ── 5. Hesap kilitleme / brute-force koruması ──
        self._check_lockout(login_url, login_body)

        # ── 6. Güvenli iletim (HTTPS) kontrolü ──
        self._check_secure_transport(login_url, login_body)

        # ── 7. Hata mesajı analizi (username enumeration) ──
        self._check_error_messages(login_url, login_body)

        # ── 8. Registration form analizi ──
        self._check_registration(base)

        self.results["summary"]["Ortak Şifre Listesi"] = len(COMMON_PASSWORDS)
        self.results["summary"]["Analiz Edilen Sayfa"] = len(login_pages)
        return self.results

    # ── Şifre Politikası ───────────────────────────────────────
    def _analyze_password_policy(self, body: str):
        lower = body.lower()
        hints = []

        patterns = [
            (r"minimum.{0,20}(\d+).{0,10}(?:char|karakter|length)", "Min. karakter: {}"),
            (r"(?:at\s*least|en\s*az)\s*(\d+)\s*(?:char|karakter)", "Min. karakter: {}"),
            (r"maximum.{0,20}(\d+).{0,10}(?:char|karakter|length)", "Max. karakter: {}"),
        ]
        for pat, fmt in patterns:
            m = re.search(pat, lower)
            if m:
                hints.append(fmt.format(m.group(1)))

        checks = [
            (r"uppercase|büyük\s*harf|upper.?case", "Büyük harf zorunlu"),
            (r"lowercase|küçük\s*harf|lower.?case", "Küçük harf zorunlu"),
            (r"(?:number|digit|rakam|numeric)", "Rakam zorunlu"),
            (r"(?:special|özel.*karakter|symbol|[!@#$%^&*])", "Özel karakter zorunlu"),
        ]
        for pat, label in checks:
            if re.search(pat, lower):
                hints.append(label)

        if hints:
            self.add_finding("Şifre Politikası Tespit Edildi",
                             " | ".join(hints), "info")
        else:
            self.add_finding("Şifre Politikası Belirsiz",
                             "Sayfada açık kural belirtilmemiş — zayıf politika olabilir", "low")

    # ── Form Güvenlik Analizi ──────────────────────────────────
    def _analyze_form_security(self, url: str, body: str):
        # Autocomplete kontolü
        pwd_fields = _PASSWORD_FIELD.findall(body)
        for field in pwd_fields:
            if 'autocomplete=' not in field.lower():
                self.add_finding("Şifre Alanında Autocomplete Açık",
                                 "autocomplete=\"off\" veya \"new-password\" ayarlanmamış",
                                 "low")
                break
            elif 'autocomplete="on"' in field.lower() or "autocomplete='on'" in field.lower():
                self.add_finding("Şifre Alanında Autocomplete Açık",
                                 'autocomplete="on" olarak ayarlanmış', "low")
                break

        # CSRF token kontrolü
        hidden_fields = _HIDDEN_FIELD.findall(body)
        csrf_found = False
        for name, value in hidden_fields:
            if any(k in name.lower() for k in ("csrf", "token", "_token", "nonce",
                                                 "__requestverificationtoken", "authenticity")):
                csrf_found = True
                break
        if not csrf_found:
            self.add_finding("Login Formunda CSRF Token Eksik",
                             "Hidden CSRF/token alanı bulunamadı — CSRF saldırısı riski",
                             "medium")

        # Form action HTTPS kontrolü
        actions = _FORM_ACTION.findall(body)
        for action in actions:
            if action.startswith("http://"):
                self.add_finding("Form Action HTTP (Güvensiz)",
                                 f"Form verisi şifrelenmemiş gönderiliyor: {action[:100]}",
                                 "high")

    # ── CAPTCHA Tespiti ────────────────────────────────────────
    def _check_captcha(self, body: str):
        if _CAPTCHA_RE.search(body):
            self.add_finding("CAPTCHA Tespit Edildi",
                             "Login formunda CAPTCHA/reCAPTCHA mevcut", "info")
            self.results["summary"]["CAPTCHA"] = "Var"
        else:
            self.add_finding("CAPTCHA Yok",
                             "Login formunda CAPTCHA koruması bulunamadı — brute-force riski",
                             "medium")
            self.results["summary"]["CAPTCHA"] = "Yok"

    # ── Hesap Kilitleme Testi ──────────────────────────────────
    def _check_lockout(self, login_url: str, body: str):
        """3 başarısız denemeyle lockout davranışı kontrol et."""
        # Form action bul
        action_match = _FORM_ACTION.search(body)
        if not action_match:
            return

        action = action_match.group(1)
        if not action.startswith("http"):
            base = self.url.rstrip("/")
            action = base + "/" + action.lstrip("/")

        # Username ve password field adlarını bul
        username_field = "username"
        password_field = "password"
        for m in _LOGIN_FIELDS.finditer(body):
            name = m.group(1).lower()
            if name in ("password", "passwd", "pwd", "pass"):
                password_field = m.group(1)
            else:
                username_field = m.group(1)

        # Hidden fields (CSRF token vb.)
        hidden_data = {}
        for name, value in _HIDDEN_FIELD.findall(body):
            hidden_data[name] = value

        # 3 hatalı giriş denemesi
        responses = []
        for i in range(3):
            post_data = dict(hidden_data)
            post_data[username_field] = f"maxima_test_user_{i}"
            post_data[password_field] = f"wrong_password_{i}"
            encoded = urllib.parse.urlencode(post_data).encode("utf-8")
            resp = self.http_post(action, data=encoded, headers={
                "Content-Type": "application/x-www-form-urlencoded"
            })
            responses.append(resp)

        # Analiz: lockout belirtileri
        last_status = responses[-1].get("status", 0)
        last_body = responses[-1].get("body", "").lower()

        lockout_indicators = [
            "locked", "kilitlendi", "too many", "çok fazla",
            "try again later", "daha sonra", "temporarily blocked",
            "geçici olarak engellendi", "rate limit", "captcha",
        ]

        if last_status == 429:
            self.add_finding("Hesap Kilitleme Aktif (HTTP 429)",
                             "3 başarısız denemeden sonra rate limit uygulandı", "info")
            self.results["summary"]["Brute-Force Koruması"] = "Aktif (429)"
        elif any(ind in last_body for ind in lockout_indicators):
            self.add_finding("Hesap Kilitleme Belirtisi",
                             "3 başarısız denemeden sonra kilitleme mesajı tespit edildi", "info")
            self.results["summary"]["Brute-Force Koruması"] = "Muhtemelen Aktif"
        else:
            # Yanıtlar arasında fark yoksa — kilitleme yok
            if all(r.get("status", 0) == responses[0].get("status", 0) for r in responses):
                self.add_finding("Hesap Kilitleme Yok",
                                 "3 başarısız giriş denemesinde kilitleme/throttling tespit edilmedi",
                                 "medium")
                self.results["summary"]["Brute-Force Koruması"] = "Tespit Edilmedi"

    # ── HTTPS Kontrolü ─────────────────────────────────────────
    def _check_secure_transport(self, login_url: str, body: str):
        if login_url.startswith("http://"):
            self.add_finding("Login Sayfası HTTP Üzerinden Erişilebilir",
                             "Kimlik bilgileri şifrelenmemiş ağ üzerinden iletilebilir",
                             "high")

        # HSTS header kontrolü
        resp = self.http_get(login_url)
        headers = resp.get("headers", {})
        hsts = headers.get("Strict-Transport-Security",
                           headers.get("strict-transport-security", ""))
        if not hsts:
            self.add_finding("Login Sayfasında HSTS Eksik",
                             "Strict-Transport-Security header'ı yok — downgrade saldırısı riski",
                             "medium")

    # ── Hata Mesajı Analizi (Username Enumeration) ─────────────
    def _check_error_messages(self, login_url: str, body: str):
        """Login hata mesajlarının kullanıcı adı sızdırıp sızdırmadığını kontrol et."""
        lower = body.lower()
        # Tipik enumeration-prone mesajlar
        enum_patterns = [
            r"user(?:name)?\s+(?:not\s+found|does\s*n[o']t\s+exist|bulunamadı|yok)",
            r"no\s+(?:such\s+)?(?:user|account)",
            r"invalid\s+username",
            r"geçersiz\s+kullanıcı",
        ]
        for pat in enum_patterns:
            if re.search(pat, lower):
                self.add_finding("Kullanıcı Adı Sızdırma Riski",
                                 "Hata mesajı kullanıcı adının var/yok olduğunu açıklıyor — "
                                 "username enumeration mümkün",
                                 "medium")
                break

    # ── Registration Analizi ───────────────────────────────────
    def _check_registration(self, base: str):
        reg_paths = ["/register", "/signup", "/sign-up", "/join",
                     "/account/register", "/auth/register", "/kayit"]
        urls = [base + p for p in reg_paths]

        for url, resp in self.parallel_get(urls, max_workers=6):
            if resp.get("status", 0) not in (200, 301, 302):
                continue
            body = resp.get("body", "").lower()
            if "password" in body or "şifre" in body:
                self.add_finding("Kayıt Formu Tespit Edildi",
                                 f"Adres: {url}", "info")
                # Email doğrulama kontrolü
                if not re.search(r"verif|doğrula|confirm|onay", body):
                    self.add_finding("Email Doğrulama Belirsiz",
                                     "Kayıt formunda email doğrulama adımı tespit edilmedi",
                                     "low")
                break

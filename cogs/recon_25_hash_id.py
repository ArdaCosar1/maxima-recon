#!/usr/bin/env python3
"""
Maxima Cog: Gelişmiş Hash Identifier & Analiz Motoru
  - 20+ hash tipi regex tespiti
  - Çoklu sayfa taraması (ana sayfa + /login + /admin + /api)
  - JavaScript kaynak taraması (inline <script> + harici .js dosyaları)
  - Sözlük hash eşleştirmesi (20 yaygın parola, MD5+SHA1+SHA256)
  - Bağlam duyarlı severity: password alanı → critical, yorum/hidden → high
  - Zayıf hash algoritması uyarısı (MD5/SHA1 parola bağlamında)
"""
import re, hashlib, base64
from utils.base_module import BaseModule, ModuleResult


class HashIdentifier(BaseModule):
    """Gelişmiş Hash Identifier — 20+ hash tipi, çoklu sayfa, JS tarama"""

    # ── Hash Regex Desenleri ──────────────────────────────────
    HASH_PATTERNS = {
        "SHA512":        (re.compile(r'\b[a-f0-9]{128}\b', re.I), 128),
        "SHA384":        (re.compile(r'\b[a-f0-9]{96}\b', re.I), 96),
        "SHA256":        (re.compile(r'\b[a-f0-9]{64}\b', re.I), 64),
        "SHA224":        (re.compile(r'\b[a-f0-9]{56}\b', re.I), 56),
        "SHA1":          (re.compile(r'\b[a-f0-9]{40}\b', re.I), 40),
        "MD5":           (re.compile(r'\b[a-f0-9]{32}\b', re.I), 32),
        "CRC32":         (re.compile(r'\b[a-f0-9]{8}\b', re.I), 8),
        "bcrypt":        (re.compile(r'\$2[ayb]\$\d{2}\$.{53}'), 0),
        "Argon2":        (re.compile(r'\$argon2(?:id|i|d)\$[^\s"\'<>]{20,}'), 0),
        "scrypt":        (re.compile(r'\$scrypt\$[^\s"\'<>]{20,}'), 0),
        "MySQL_old":     (re.compile(r'\b[a-f0-9]{16}\b', re.I), 16),
        "MySQL41":       (re.compile(r'\*[A-F0-9]{40}\b'), 0),
        "PostgreSQL_MD5":(re.compile(r'\bmd5[a-f0-9]{32}\b', re.I), 0),
        "NTLM":          (re.compile(r'\b[A-F0-9]{32}\b'), 32),
        "LM":            (re.compile(r'\b[A-F0-9]{32}\b'), 32),
        "Django_PBKDF2":  (re.compile(r'pbkdf2_sha256\$\d+\$[^\s"\'<>]+'), 0),
        "PHPass":         (re.compile(r'\$[PH]\$[^\s"\'<>]{31,}'), 0),
        "Apache_APR1":    (re.compile(r'\$apr1\$[^\s"\'<>]+'), 0),
        "Unix_MD5":       (re.compile(r'\$1\$[^\s"\'<>]+'), 0),
        "SHA256_crypt":   (re.compile(r'\$5\$[^\s"\'<>]+'), 0),
        "SHA512_crypt":   (re.compile(r'\$6\$[^\s"\'<>]+'), 0),
        "JWT":            (re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'), 0),
    }

    CONTEXT_RE = re.compile(
        r'(?:hash|password|passwd|pwd|digest|checksum|md5|sha|token|secret|key|nonce|salt|hmac)'
        r'["\']?\s*[:=]\s*["\']?([a-f0-9]{8,128})', re.I)

    PASSWORD_CTX_RE = re.compile(
        r'(?:type\s*=\s*["\']?password|name\s*=\s*["\']?(?:pass|pwd|password))', re.I)

    HIDDEN_CTX_RE = re.compile(r'(?:<!--.*?-->|type\s*=\s*["\']?hidden)', re.I | re.S)

    API_KEY_RE = re.compile(
        r'(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)'
        r'["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})', re.I)

    BASE64_RE = re.compile(r'\b[A-Za-z0-9+/]{20,}={0,2}\b')
    SCRIPT_INLINE_RE = re.compile(r'<script[^>]*>(.*?)</script>', re.I | re.S)
    JS_SRC_RE = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+\.js[^"\']*)["\']', re.I)

    COMMON_PASSWORDS = [
        "password", "123456", "12345678", "admin", "qwerty",
        "letmein", "welcome", "monkey", "dragon", "master",
        "login", "abc123", "111111", "password1", "iloveyou",
        "sunshine", "princess", "football", "shadow", "trustno1",
    ]

    EXTRA_PATHS = ["/login", "/admin", "/api"]

    SPECIAL_TYPES = [
        "bcrypt", "Argon2", "scrypt", "MySQL41", "PostgreSQL_MD5",
        "Django_PBKDF2", "PHPass", "Apache_APR1", "Unix_MD5",
        "SHA256_crypt", "SHA512_crypt", "JWT",
    ]

    # ── Ana Tarama ───────────────────────────────────────────
    def run(self) -> ModuleResult:
        self.log("Gelişmiş hash tespit ve analiz taraması başlatılıyor...")

        urls = [self.url] + [self.url + p for p in self.EXTRA_PATHS]
        page_results = self.parallel_get(urls, max_workers=4)

        all_bodies = []
        for url, resp in page_results:
            if resp.get("status", 0) in range(200, 400) and resp.get("body"):
                all_bodies.append((url, resp["body"]))

        if not all_bodies:
            self.log("Hiçbir sayfadan içerik alınamadı.", "warning")
            self.results["summary"]["Durum"] = "Erişim yok"
            return self.results

        self.log(f"{len(all_bodies)} sayfa içeriği toplandı.")
        seen, total_found, js_scanned = set(), 0, 0

        for page_url, body in all_bodies:
            total_found += self._scan_body(body, page_url, seen, is_js=False)

            for m in self.SCRIPT_INLINE_RE.finditer(body):
                sc = m.group(1).strip()
                if len(sc) > 10:
                    total_found += self._scan_body(sc, f"{page_url} [inline-js]", seen, is_js=True)
                    js_scanned += 1

            js_urls = []
            for m in self.JS_SRC_RE.finditer(body):
                src = m.group(1)
                if src.startswith("//"): src = "https:" + src
                elif src.startswith("/"): src = self.url + src
                elif not src.startswith("http"): src = self.url + "/" + src
                js_urls.append(src)

            if js_urls:
                for js_url, js_resp in self.parallel_get(js_urls[:10], max_workers=5):
                    if js_resp.get("status") == 200 and js_resp.get("body"):
                        total_found += self._scan_body(js_resp["body"], js_url, seen, is_js=True)
                        js_scanned += 1

        dict_matches = self._dictionary_check(all_bodies, seen)
        total_found += dict_matches

        self.log(f"Tarama tamamlandı: {total_found} hash/token, {js_scanned} JS tarandı.", "success")
        self.results["summary"]["Bulunan Hash/Token"] = total_found
        self.results["summary"]["Taranan Sayfa"] = len(all_bodies)
        self.results["summary"]["Taranan JS"] = js_scanned
        self.results["summary"]["Sözlük Eşleşme"] = dict_matches
        return self.results

    # ── Gövde Tarama ─────────────────────────────────────────
    def _scan_body(self, body: str, source: str, seen: set, is_js: bool = False) -> int:
        found = 0
        label = "JS kaynağında" if is_js else "sayfada"

        # Özel format hash'leri (bcrypt, argon2, scrypt, JWT, Django, PHPass, crypt vb.)
        for htype in self.SPECIAL_TYPES:
            pattern, _ = self.HASH_PATTERNS[htype]
            for m in pattern.finditer(body):
                h = m.group(0)
                key = f"{htype}:{h[:64]}"
                if key in seen:
                    continue
                seen.add(key)
                sev = self._assess_severity(body, m.start(), htype)
                self.add_finding(f"{htype} Hash/Token Bulundu",
                                 f"Kaynak: {source} — {label} — Değer: {h[:48]}...", sev)
                found += 1

        # Bağlam duyarlı hex hash tarama
        for m in self.CONTEXT_RE.finditer(body):
            h = m.group(1).lower()
            if h in seen:
                continue
            htype = self._identify_hex_hash(h)
            if not htype:
                continue
            seen.add(h)
            sev = self._assess_severity(body, m.start(), htype)
            self.add_finding(f"Hash Bulundu (Bağlam): {htype}",
                             f"Kaynak: {source} — Değer: {h[:48]}...", sev)
            found += 1

        # API key / secret tarama
        for m in self.API_KEY_RE.finditer(body):
            val = m.group(1)
            key = f"apikey:{val[:32]}"
            if key in seen:
                continue
            seen.add(key)
            self.add_finding("API Anahtarı / Secret Sızıntısı",
                             f"Kaynak: {source} — Değer: {val[:40]}...", "critical")
            found += 1

        # Base64 encoded hash tespiti
        for m in self.BASE64_RE.finditer(body):
            b64val = m.group(0)
            if len(b64val) < 24 or len(b64val) > 200:
                continue
            b64key = f"b64:{b64val[:32]}"
            if b64key in seen:
                continue
            try:
                decoded = base64.b64decode(b64val)
                dlen = len(decoded)
                if dlen in (16, 20, 28, 32, 48, 64):
                    seen.add(b64key)
                    lmap = {16:"MD5", 20:"SHA1", 28:"SHA224",
                            32:"SHA256", 48:"SHA384", 64:"SHA512"}
                    self.add_finding(f"Base64 Kodlu Hash ({lmap.get(dlen, '?')})",
                                     f"Kaynak: {source} — Decode uzunluk: {dlen} byte", "medium")
                    found += 1
            except Exception:
                pass
        return found

    # ── Hex Hash Tipi Tanımlama ──────────────────────────────
    def _identify_hex_hash(self, h: str) -> str:
        return {128:"SHA512", 96:"SHA384", 64:"SHA256", 56:"SHA224",
                40:"SHA1", 32:"MD5", 16:"MySQL_old", 8:"CRC32"}.get(len(h), "")

    # ── Bağlam Duyarlı Severity ──────────────────────────────
    def _assess_severity(self, body: str, pos: int, htype: str) -> str:
        ctx = body[max(0, pos - 200):pos + 20]
        if self.PASSWORD_CTX_RE.search(ctx):
            return "critical"
        if self.HIDDEN_CTX_RE.search(ctx):
            return "high"
        if re.search(r'(?:passw|pwd|login|auth|credential)', ctx, re.I) \
                and htype in ("MD5", "SHA1", "CRC32"):
            self.add_finding(f"Zayıf Hash Algoritması Uyarısı: {htype}",
                             "Parola bağlamında zayıf hash algoritması kullanılıyor", "high")
            return "high"
        return "medium"

    # ── Sözlük Hash Eşleştirme ───────────────────────────────
    def _dictionary_check(self, pages: list, seen: set) -> int:
        found = 0
        precomputed = {}
        for word in self.COMMON_PASSWORDS:
            wb = word.encode()
            precomputed[word] = [
                ("MD5",    hashlib.md5(wb).hexdigest()),
                ("SHA1",   hashlib.sha1(wb).hexdigest()),
                ("SHA256", hashlib.sha256(wb).hexdigest()),
            ]
        for page_url, body in pages:
            blower = body.lower()
            for word, hashes in precomputed.items():
                for alg, digest in hashes:
                    dkey = f"dict:{digest[:32]}"
                    if dkey in seen:
                        continue
                    if digest in blower:
                        seen.add(dkey)
                        self.add_finding(f"Sözlük Eşleşmesi: {alg}('{word}')",
                                         f"Kaynak: {page_url} — Yaygın parola hash'i bulundu", "high")
                        found += 1
        return found

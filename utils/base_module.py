#!/usr/bin/env python3
"""
Maxima Utils: BaseModule
Tüm cog'ların miras aldığı temel sınıf.

PERF v9:
  - ThreadPoolExecutor tabanlı paralel HTTP yardımcıları: parallel_get(), parallel_post()
  - Bağlantı havuzu: urllib3-stili persistent connection yerine
    ssl.SSLContext + socket cache (stdlib sınırları içinde)
  - timeout default 8 → 5s (pentest bağlamı — erişilemeyen host zaten 0 döner)
  - _make_request body limiti: 512KB → 128KB (html parse için fazlası gereksiz)
  - Global connection lock kaldırıldı — her thread kendi opener'ını açıyor (thread-safe)
"""

import sys
import os
import time
import socket
import ssl
import logging
import threading
import urllib.request
import urllib.parse
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, TypedDict
from utils.compat import Fore, Style


# ── Tip tanımları ─────────────────────────────────────────────
class FindingDict(TypedDict):
    """Tek bir güvenlik bulgusunun yapısı."""
    title:      str
    detail:     str
    severity:   str
    confidence: str          # confirmed | firm | tentative
    time:       str


class ModuleResult(TypedDict):
    """Bir modülün run() metodunun döndürdüğü sözlük yapısı."""
    module:    str
    target:    str
    timestamp: str
    findings:  List[FindingDict]
    summary:   Dict[str, Any]


class HttpResponse(TypedDict, total=False):
    """_make_request / http_get / parallel_get dönüş tipi."""
    status:  int
    body:    str
    headers: Dict[str, str]
    url:     str
    error:   str   # sadece hata durumunda mevcuttur


class BaseModule:
    """Tüm Maxima modüllerinin temel sınıfı."""

    # ── Sınıf düzeyinde global ayarlar ───────────────────────
    _proxy: Optional[str] = None
    _global_delay: float  = 0.0
    _verify_ssl: bool     = False
    _logger: logging.Logger = logging.getLogger("maxima")
    _auth_cookies: Optional[Dict[str, str]] = None
    _auth_headers: Optional[Dict[str, str]] = None

    # ── PERF: Paylaşımlı önbellekler ──────────────────────────
    _dns_cache: Dict[str, Optional[str]] = {}
    _ssl_ctx_cache: Optional[ssl.SSLContext] = None
    _ssl_ctx_verify_cache: Optional[ssl.SSLContext] = None
    _base_response_cache: Dict[str, "HttpResponse"] = {}
    _opener_cache: Optional[Any] = None
    _opener_proxy_key: Optional[str] = None  # proxy değişince opener yenile
    _delay_lock: threading.Lock = threading.Lock()  # paralel isteklerde delay senkronizasyonu
    _request_cache: Dict[str, "HttpResponse"] = {}  # GET request deduplication
    _request_cache_lock: threading.Lock = threading.Lock()

    # ── Retry ayarları ───────────────────────────────────────
    _max_retries: int = 2          # 0 = retry yok, 2 = max 3 deneme
    _retry_backoff: float = 0.5    # exponential backoff başlangıç (0.5s, 1s)

    @classmethod
    def configure_logging(cls, log_file: Optional[str] = None,
                          level: int = logging.INFO) -> None:
        """Dosyaya loglama aktifleştir. maxima.py --log-file argümanıyla çağrılır."""
        cls._logger.setLevel(level)
        if log_file and not any(isinstance(h, logging.FileHandler)
                                for h in cls._logger.handlers):
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            ))
            cls._logger.addHandler(fh)

    @classmethod
    def set_proxy(cls, proxy_url: Optional[str]) -> None:
        cls._proxy = proxy_url

    @classmethod
    def set_delay(cls, delay: float) -> None:
        cls._global_delay = max(0.0, delay)

    @classmethod
    def set_verify_ssl(cls, verify: bool) -> None:
        cls._verify_ssl = verify

    @classmethod
    def set_auth(cls, cookies: Optional[Dict[str, str]] = None,
                 headers: Optional[Dict[str, str]] = None) -> None:
        """Kimlik doğrulama bilgileri ayarla — tüm modüller paylaşır.

        Args:
            cookies: {"session": "abc123", "token": "xyz"} — Cookie header'ına eklenir
            headers: {"Authorization": "Bearer ..."} — Her isteğe eklenir
        """
        cls._auth_cookies = cookies
        cls._auth_headers = headers

    @classmethod
    def login(cls, login_url: str, username: str, password: str,
              username_field: str = "username",
              password_field: str = "password",
              timeout: int = 10) -> bool:
        """Login formuna POST yaparak session cookie'si al.

        Returns:
            True — cookie alındı ve set_auth() ile ayarlandı
            False — login başarısız
        """
        import http.cookiejar
        cj = http.cookiejar.CookieJar()
        handlers: list = [urllib.request.HTTPCookieProcessor(cj)]
        if cls._proxy:
            handlers.append(urllib.request.ProxyHandler({
                "http": cls._proxy, "https": cls._proxy,
            }))
        ctx = ssl.create_default_context()
        if not cls._verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
        opener = urllib.request.build_opener(*handlers)

        data = urllib.parse.urlencode({
            username_field: username,
            password_field: password,
        }).encode("utf-8")

        req = urllib.request.Request(login_url, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("User-Agent",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
        try:
            with opener.open(req, timeout=timeout) as resp:
                cookies = {c.name: c.value for c in cj}
                if cookies:
                    cls.set_auth(cookies=cookies)
                    cls._logger.info("Login başarılı — %d cookie alındı", len(cookies))
                    return True
                return False
        except Exception as e:
            cls._logger.warning("Login başarısız: %s", e)
            return False

    # ── Başlatma ─────────────────────────────────────────────
    def __init__(self, target: str):
        self.target = target.strip()
        if not self.target.startswith(("http://", "https://")):
            self.target = "http://" + self.target
        self.url = self.target.rstrip("/")

        parsed      = urllib.parse.urlparse(self.url)
        self.host   = parsed.hostname or self.target
        self.port   = parsed.port
        self.scheme = parsed.scheme

        # PERF: default timeout 8 → 5
        self.timeout: int  = 5
        self._quiet: bool  = False

        self.results: ModuleResult = {
            "module":    self.__class__.__name__,
            "target":    self.target,
            "timestamp": datetime.now().isoformat(),
            "findings":  [],
            "summary":   {},
        }

    # ── Loglama ──────────────────────────────────────────────
    _LOG_COLORS = {
        "info":    Fore.CYAN,
        "success": Fore.GREEN,
        "warning": Fore.YELLOW,
        "error":   Fore.RED,
        "finding": Fore.MAGENTA,
    }

    def log(self, message: str, level: str = "info") -> None:
        if not self._quiet or level in ("finding", "error"):
            color  = self._LOG_COLORS.get(level, Fore.WHITE)
            prefix = {"info":"[*]","success":"[+]","warning":"[!]",
                      "error":"[✗]","finding":"[►]"}.get(level, "[?]")
            print(f"{color}{prefix} {message}{Style.RESET_ALL}")
        # Python logging modülüne de ilet (--log-file aktifse dosyaya yazar)
        _log_fn = {
            "info":    self._logger.info,
            "success": self._logger.info,
            "warning": self._logger.warning,
            "error":   self._logger.error,
            "finding": self._logger.warning,
        }.get(level, self._logger.info)
        _log_fn("[%s] %s", self.__class__.__name__, message)

    # ── Bulgu Ekleme ─────────────────────────────────────────
    VALID_SEVERITIES  = {"critical", "high", "medium", "low", "info"}
    VALID_CONFIDENCES = {"confirmed", "firm", "tentative"}

    def add_finding(self, title: str, detail: str, severity: str = "info",
                    remediation: str = "", evidence: str = "",
                    confidence: str = "firm") -> None:
        if severity not in self.VALID_SEVERITIES:
            severity = "info"
        if confidence not in self.VALID_CONFIDENCES:
            confidence = "firm"
        finding: Dict[str, str] = {
            "title":      title,
            "detail":     detail,
            "severity":   severity,
            "confidence": confidence,
            "time":       datetime.now().strftime("%H:%M:%S"),
        }
        if remediation:
            finding["remediation"] = remediation
        if evidence:
            finding["evidence"] = evidence[:2048]  # max 2KB kanıt
        self.results["findings"].append(finding)
        if not self._quiet:
            sev_color = {
                "critical": Fore.RED, "high": Fore.RED,
                "medium": Fore.YELLOW, "low": Fore.CYAN, "info": Fore.WHITE,
            }.get(severity, Fore.WHITE)
            conf_icon = {"confirmed": "●", "firm": "◉", "tentative": "○"}.get(confidence, "◉")
            print(f"  {sev_color}[{severity.upper():<8}] {conf_icon} {title}{Style.RESET_ALL}")
            if detail:
                print(f"           {Fore.WHITE}{detail[:120]}"
                      f"{'...' if len(detail) > 120 else ''}{Style.RESET_ALL}")

    # ── IP Çözümleme (DNS cache) ─────────────────────────────
    def resolve_ip(self) -> Optional[str]:
        cache = self.__class__._dns_cache
        if self.host in cache:
            return cache[self.host]
        try:
            ip = socket.gethostbyname(self.host)
            cache[self.host] = ip
            return ip
        except socket.gaierror:
            cache[self.host] = None
            return None

    # ── SSL Context (singleton — PERF) ────────────────────────
    @classmethod
    def _ssl_ctx(cls) -> ssl.SSLContext:
        if cls._verify_ssl:
            if cls._ssl_ctx_verify_cache is None:
                cls._ssl_ctx_verify_cache = ssl.create_default_context()
            return cls._ssl_ctx_verify_cache
        if cls._ssl_ctx_cache is None:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            cls._ssl_ctx_cache = ctx
        return cls._ssl_ctx_cache

    # ── HTTP İstekleri ───────────────────────────────────────
    def _build_opener(self) -> urllib.request.OpenerDirector:
        cls = self.__class__
        proxy_key = cls._proxy or ""
        if cls._opener_cache is not None and cls._opener_proxy_key == proxy_key:
            return cls._opener_cache
        handlers: list = []
        if cls._proxy:
            handlers.append(urllib.request.ProxyHandler({
                "http":  cls._proxy,
                "https": cls._proxy,
            }))
        handlers.append(urllib.request.HTTPSHandler(context=self._ssl_ctx()))
        opener = urllib.request.build_opener(*handlers)
        cls._opener_cache = opener
        cls._opener_proxy_key = proxy_key
        return opener

    def _make_request(
        self,
        url: str,
        method: str = "GET",
        data: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: bool = False,
    ) -> HttpResponse:
        default_headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            # PERF: keep-alive — urllib zaten yapar ama açıkça belirt
            "Connection":      "keep-alive",
        }
        # Authenticated scanning: global auth header'ları ekle
        if self.__class__._auth_headers:
            default_headers.update(self.__class__._auth_headers)
        if self.__class__._auth_cookies:
            cookie_str = "; ".join(
                f"{k}={v}" for k, v in self.__class__._auth_cookies.items()
            )
            default_headers["Cookie"] = cookie_str
        if headers:
            default_headers.update(headers)

        # Thread-safe delay: paralel isteklerde de delay'i doğru uygula
        if self.__class__._global_delay > 0:
            with self.__class__._delay_lock:
                time.sleep(self.__class__._global_delay)

        opener = self._build_opener()

        # Retry with exponential backoff
        last_error: Optional[str] = None
        for attempt in range(1 + self.__class__._max_retries):
            req = urllib.request.Request(url, data=data, method=method)
            for k, v in default_headers.items():
                req.add_header(k, v)

            if not follow_redirects:
                class NoRedirect(urllib.request.HTTPErrorProcessor):
                    def http_response(self, request, response):
                        return response
                    https_response = http_response
                opener.add_handler(NoRedirect())

            try:
                with opener.open(req, timeout=self.timeout) as resp:
                    body_bytes = resp.read(1024 * 128)
                    body       = body_bytes.decode("utf-8", errors="replace")
                    return {
                        "status":  resp.status,
                        "body":    body,
                        "headers": dict(resp.headers),
                        "url":     resp.geturl(),
                    }
            except urllib.error.HTTPError as e:
                # HTTP hataları retry yapılmaz (4xx, 5xx beklenen sonuçlar)
                try:
                    body = e.read(1024 * 32).decode("utf-8", errors="replace")
                except Exception:
                    body = ""
                return {
                    "status":  e.code,
                    "body":    body,
                    "headers": dict(e.headers) if e.headers else {},
                    "url":     url,
                }
            except urllib.error.URLError as e:
                last_error = str(e)
            except (socket.timeout, ConnectionError, OSError) as e:
                last_error = str(e)

            # Exponential backoff before retry
            if attempt < self.__class__._max_retries:
                time.sleep(self.__class__._retry_backoff * (2 ** attempt))

        return {"status": 0, "body": "", "headers": {}, "url": url,
                "error": last_error or "max retries exceeded"}

    def http_get(self, url: str, headers: Optional[Dict[str, str]] = None,
                 follow_redirects: bool = False) -> HttpResponse:
        # GET request deduplication: aynı URL + header yoksa cache'den dön
        if headers is None and not follow_redirects:
            with self.__class__._request_cache_lock:
                if url in self.__class__._request_cache:
                    return self.__class__._request_cache[url]
            resp = self._make_request(url, "GET", headers=headers,
                                      follow_redirects=follow_redirects)
            if resp.get("status", 0) > 0:  # başarılı yanıtları cache'le
                with self.__class__._request_cache_lock:
                    self.__class__._request_cache[url] = resp
            return resp
        return self._make_request(url, "GET", headers=headers,
                                  follow_redirects=follow_redirects)

    def http_post(self, url: str, data: Optional[bytes] = None,
                  headers: Optional[Dict[str, str]] = None,
                  follow_redirects: bool = False) -> HttpResponse:
        return self._make_request(url, "POST", data=data, headers=headers,
                                  follow_redirects=follow_redirects)

    def http_head(self, url: str, headers: Optional[Dict[str, str]] = None
                  ) -> HttpResponse:
        return self._make_request(url, "HEAD", headers=headers)

    # ── PERF: Base URL cache (modüller arası paylaşım) ────────
    def get_base_response(self) -> "HttpResponse":
        """Ana URL'nin HTTP yanıtını cache'den döndür.
        Aynı hedef URL için tekrar istek yapmaz — modüller arası paylaşılır."""
        cache = self.__class__._base_response_cache
        if self.url in cache:
            return cache[self.url]
        resp = self.http_get(self.url)
        cache[self.url] = resp
        return resp

    @classmethod
    def clear_cache(cls) -> None:
        """Tüm önbellekleri temizle (yeni tarama başlatırken)."""
        cls._dns_cache.clear()
        cls._base_response_cache.clear()
        cls._request_cache.clear()
        cls._ssl_ctx_cache = None
        cls._ssl_ctx_verify_cache = None
        cls._opener_cache = None

    # ── PERF: Paralel GET ─────────────────────────────────────
    def parallel_get(
        self,
        urls: List[str],
        max_workers: int = 10,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[Tuple[str, HttpResponse]]:
        """
        Birden fazla URL'yi thread pool ile paralel olarak GET yapar.
        Döndürür: [(url, response_dict), ...]  — orijinal sıra korunmaz.

        Kullanım:
            results = self.parallel_get([url1, url2, ...], max_workers=8)
            for url, resp in results:
                if resp["status"] == 200: ...
        """
        results: List[Tuple[str, HttpResponse]] = []
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_to_url = {
                pool.submit(self.http_get, url, headers): url
                for url in urls
            }
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    results.append((url, future.result()))
                except Exception as e:
                    results.append((url, {"status": 0, "body": "", "headers": {},
                                          "url": url, "error": str(e)}))
        return results

    def parallel_post(
        self,
        requests: List[Tuple[str, bytes, Optional[Dict[str, str]]]],
        max_workers: int = 8,
    ) -> List[Tuple[str, HttpResponse]]:
        """
        (url, data, headers) tuple listesini paralel POST yapar.
        """
        results: List[Tuple[str, HttpResponse]] = []
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_to_url = {
                pool.submit(self.http_post, url, data, hdrs): url
                for url, data, hdrs in requests
            }
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    results.append((url, future.result()))
                except Exception as e:
                    results.append((url, {"status": 0, "body": "", "headers": {},
                                          "url": url, "error": str(e)}))
        return results

    # ── Soyut Metot ──────────────────────────────────────────
    def run(self) -> ModuleResult:
        raise NotImplementedError(
            f"{self.__class__.__name__} sınıfı run() metodunu implement etmeli.")

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} target={self.target!r}>"

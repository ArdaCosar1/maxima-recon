# CLAUDE.md — Maxima Recon Framework v11.0

Bu dosya Claude Code'un projeyi anlaması için hazırlanmıştır.

---

## Proje Özeti

**Maxima**, Python 3.8+ ile yazılmış modüler bir web/ağ penetrasyon testi çerçevesidir.
- **41 modül (cog)**, BaseModule'den miras alır
- **Türkçe** kullanıcı arayüzü, yasal uyarılar (TCK 243/244)
- **Yalnızca yetkili** güvenlik testleri için kullanılır

---

## Dizin Yapısı

```
maxima_v11_final/
├── maxima.py                  # Ana orkestratör — CLI, interaktif menü, MENU/SCAN_PROFILES
├── requirements.txt           # pip bağımlılıkları
├── install.sh                 # Linux kurulum betiği (/opt/maxima)
├── README.md
├── CLAUDE.md                  # Bu dosya
├── utils/
│   ├── base_module.py         # BaseModule + TypedDict'ler (ModuleResult, FindingDict, HttpResponse)
│   ├── compat.py              # Colorama shim (yoksa boş string döner)
│   ├── report_generator.py    # HTML + PDF rapor üretici
│   └── __init__.py
├── cogs/                      # 41 güvenlik tarama modülü
│   ├── __init__.py            # Tüm 41 sınıf + __all__ + load_plugins()
│   ├── recon_01_full_scan.py  … recon_41_advanced_reporter.py
├── plugins/                   # Kullanıcı tanımlı eklenti modülleri (otomatik keşif)
│   └── __init__.py            # Örnek kullanım dokümantasyonu
├── setup.cfg                  # pytest + coverage.py yapılandırması
└── tests/
    ├── test_maxima.py         # 48 birim testi
    └── test_integration.py    # 53 entegrasyon testi (gerçek HTTP sunucu)
```

---

## Temel Mimari

### BaseModule (`utils/base_module.py`)
Tüm cog'ların temel sınıfı. Şunları sağlar:
- `http_get()`, `http_post()`, `http_head()` → `HttpResponse` — urllib tabanlı HTTP
- `parallel_get()`, `parallel_post()` → `List[Tuple[str, HttpResponse]]` — ThreadPoolExecutor paralel istekler
- `add_finding(title, detail, severity)` — bulgu kaydı; severity: `critical|high|medium|low|info`
- `resolve_ip()` — DNS çözümleme
- `log(message, level)` — renkli konsol çıktısı + Python `logging` modülüne iletim
- `configure_logging(log_file, level)` — dosyaya loglama aktifleştir (`--log-file` argümanıyla)
- Sınıf düzeyinde `_proxy`, `_global_delay`, `_logger` (tüm modüller paylaşır)
- `results: ModuleResult` — tip güvenli sözlük

### TypedDict'ler (`utils/base_module.py`)
```python
from utils.base_module import BaseModule, ModuleResult, FindingDict, HttpResponse
```
- `FindingDict` — `{title, detail, severity, time}`
- `ModuleResult` — `{module, target, timestamp, findings, summary}`
- `HttpResponse` — `{status, body, headers, url, error?}` (`total=False` — error opsiyonel)

### Versiyon Sabiti (`maxima.py`)
```python
VERSION = "11.0"  # Banner, menü, argparse buradan okur
```

### Yeni Modül Yazma Kuralı
```python
from utils.base_module import BaseModule, ModuleResult

class BenimModulüm(BaseModule):
    def run(self) -> ModuleResult:
        resp = self.http_get(self.url)
        if resp["status"] == 200:
            self.add_finding("Başlık", "Detay", "medium")
        self.results["summary"]["Anahtar"] = "Değer"
        return self.results
```
`run()` her zaman `self.results` döndürmeli, dönüş tipi `ModuleResult` olmalı.

### cogs/__init__.py
Tüm 41 sınıf `__all__` ile export edilmiş:
```python
from cogs import XSSScanner, LFIRFIScanner  # doğrudan kullanılabilir
```

---

## Modül Listesi (41 modül)

| ID | Modül | Sınıf | Etiket |
|----|-------|-------|--------|
| 1 | Full Reconnaissance Scan | FullReconScan | web, full |
| 2 | Quick Port Scanner (top-100 TCP) | PortScanner | network, full |
| 3 | Vulnerability Scanner | VulnerabilityScanner | web, vuln, full |
| 4 | SQL Injection (→39 alias) | SQLInjectionScanner | web, vuln, full |
| 5 | XSS Scanner | XSSScanner | web, vuln, full |
| 6 | LFI/RFI Scanner | LFIRFIScanner | web, vuln |
| 7 | Command Injection Scanner | CommandInjectionScanner | web, vuln |
| 8 | SSRF Scanner | SSRFScanner | web, vuln |
| 9 | Subdomain Enumeration | SubdomainEnumeration | web, osint, full |
| 10 | Directory Enumeration | DirectoryEnumeration | web, full |
| 11 | API Fuzzer | APIFuzzer | web |
| 12 | CORS Scanner | CORSScanner | web, vuln |
| 13 | SSL/TLS Analyzer | SSLTLSAnalyzer | web, network |
| 14 | HTTP Header Analyzer | HTTPHeaderAnalyzer | web, full |
| 15 | Technology Detector | TechnologyDetector | web, osint, full |
| 16 | JWT Analyzer | JWTAnalyzer | web, vuln |
| 17 | Clickjacking Tester | ClickjackingTester | web |
| 18 | Open Redirect Scanner | OpenRedirectScanner | web, vuln |
| 19 | Subdomain Takeover Check | SubdomainTakeoverCheck | web, vuln |
| 20 | Rate Limit Tester | RateLimitTester | web |
| 21 | WHOIS Lookup | WHOISLookup | osint, full |
| 22 | IP Geolocation | IPGeolocation | osint, network |
| 23 | DNS Record Analysis | DNSRecordAnalysis | osint, network, full |
| 24 | Password Strength Checker | PasswordStrengthChecker | osint |
| 25 | Hash Identifier | HashIdentifier | osint |
| 26 | WAF Detector | WAFDetector | web, network |
| 27 | TLS Version Prober | TLSVersionProber | network, web |
| 28 | Redirect Chain Analyzer | RedirectChainAnalyzer | web |
| 29 | JS Crawler & Secret Scanner | JSCrawlerSecretScanner | web, vuln |
| 30 | HTTP/2 Probe | HTTP2Probe | network |
| 31 | Payload Fuzzing Engine | PayloadFuzzingEngine | web, vuln |
| 32 | Screenshot Capture / PageProbe | ScreenshotCapture | web |
| 33 | CVE Template Engine | CVETemplateEngine | vuln |
| 34 | Redirect-Aware Header Analysis | RedirectAwareHeaderAnalysis | web |
| 35 | **Async Port Scanner v2** | AsyncPortScanner | network, full-v2 |
| 36 | **CVE & Exploit Eşleştirici** | CVEMatcher | vuln, full-v2 |
| 37 | **Auth & Credential Tester** ⚠ | AuthTester | vuln, full-v2 |
| 38 | **OSINT & İstihbarat Motoru** | OSINTEngine | osint, full-v2 |
| 39 | **Deep SQLi Scanner** | DeepSQLiScanner | vuln, full-v2 |
| 40 | **SSTI+XXE+IDOR+GraphQL** | NewAttackVectors | vuln, full-v2 |
| 41 | **Gelişmiş Rapor & Risk** | AdvancedReporter | full-v2 |

---

## Tarama Profilleri (SCAN_PROFILES)

| Profil | Açıklama |
|--------|----------|
| `web` | HTTP başlıkları, XSS, SQLi, CORS, teknoloji |
| `osint` | WHOIS, DNS, subdomain, IP geo |
| `vuln` | SQLi, XSS, LFI, SSRF, CVE, SSTI, auth |
| `network` | Port tarama, TLS, DNS, WAF, HTTP/2 |
| `full` | 34 temel modülün tamamı |
| `full-v2` | Tüm 41 modül |

### Turbo Modu (`--turbo`)
Modülleri 4 dalga halinde paralel çalıştırır (ThreadPoolExecutor):
- **Wave 1**: Hızlı keşif (header, tech detect, WHOIS, DNS...)
- **Wave 2**: Ağ modülleri (port scanner, TLS, HTTP/2...)
- **Wave 3**: Web vuln (SQLi, XSS, LFI, CORS, JWT...)
- **Wave 4**: Ağır modüller (subdomain, dir enum, OSINT, CVE...)
- **Sıralı**: Auth Tester (37), Reporter (41) — etkileşimli/bağımlı

```bash
maxima https://hedef.com --all --turbo          # Tam tarama ~3-5x hızlı
maxima https://hedef.com --scan web --turbo     # Web profili paralel
```

### Performans Önbellekleri
`BaseModule` sınıf düzeyinde paylaşımlı cache'ler:
- `_dns_cache` — DNS çözümleme sonuçları (tüm modüller paylaşır)
- `_ssl_ctx_cache` — SSL context singleton (her istekte yeni oluşturulmaz)
- `_opener_cache` — urllib opener singleton
- `_base_response_cache` — `get_base_response()` ile ana URL yanıtı paylaşımı
- `clear_cache()` ile tüm cache'ler temizlenebilir

---

## Bağımlılıklar

```bash
pip install -r requirements.txt
```

| Paket | Zorunlu | Açıklama |
|-------|---------|----------|
| `colorama>=0.4.6` | Hayır | Renkli terminal (compat.py shim sayesinde opsiyonel) |
| `pytest>=7.0` | Test | Birim ve entegrasyon testleri |
| `pytest-timeout>=2.0` | Test | Test başına timeout sınırı |
| `pytest-cov>=4.0` | Test | Kod kapsam ölçümü (coverage.py) |
| `matplotlib>=3.5` | Hayır | Modül 41 grafik (HAS_MPL flag) |
| `reportlab>=3.6` | Hayır | PDF rapor (HAS_REPORTLAB flag) |
| `playwright` | Hayır | Modül 32 gerçek screenshot |

---

## Test Çalıştırma

```bash
# Python yolu (Windows)
PYTHON="/c/Users/ardac/AppData/Local/Programs/Python/Python312/python.exe"

# Birim testleri (hızlı, ~2sn)
$PYTHON -m pytest tests/test_maxima.py -v

# Entegrasyon testleri (~5dk)
$PYTHON -m pytest tests/test_integration.py -v --timeout=60

# Tümü
$PYTHON -m pytest tests/ -v --timeout=60

# Coverage ölçümü ile
$PYTHON -m pytest tests/ --cov --cov-report=term-missing --timeout=60

# HTML coverage raporu
$PYTHON -m pytest tests/ --cov --cov-report=html --timeout=60
# Rapor: htmlcov/index.html

# Ağ bağımlı testleri atla
$PYTHON -m pytest tests/ -k "not unreachable" --timeout=60
```

---

## Dikkat Edilmesi Gereken Noktalar

### Özel Modüller
- **Modül 37 (AuthTester)**: Gerçek kimlik bilgileri dener — `_require_auth_consent()` interaktif onay ister. Otomatik akışa dahil etme.
- **Modül 41 (AdvancedReporter)**: `_run_reporter_module()` ile özel başlatılır; `imported_results` üzerinden önceki modül bulgularını toplar. Önce başka modüller çalıştırılmalı.
- **Modül 32 (PageProbe/ScreenshotCapture)**: HTTP metadata probe — gerçek screenshot değil. `shutil.which("playwright")` ile araç kontrolü yapar.

### GUI (maxima_gui.py)
- `maxima-gui` komutuyla veya `python maxima_gui.py` ile çalıştırılır
- tkinter tabanlı, dark tema
- Taramalar ayrı thread'de çalışır (GUI donmaz)
- stdout çıktısı metin alanına yönlendirilir

### maxima.py Fonksiyon Yapısı
```
main()
├── _require_auth_consent(target) → bool   # Modül 37 yasal onay
├── _run_reporter_module(...)     → dict   # Modül 41 özel başlatıcı
├── run_module(choice, ...)       → dict   # Standart modül çalıştırıcı
├── run_full_scan(...)                     # Tüm modüller sırayla (süre + bulgu özeti)
├── run_scan_profile(profile, ...)         # Paket bazlı tarama (süre + bulgu özeti)
├── _generate_reports(...)                 # HTML/PDF rapor üretimi
└── _print_summary(results_store)          # Tarama sonu özet tablosu
```

### Authenticated Scanning
BaseModule'de sınıf düzeyinde kimlik doğrulama desteği:
```python
# Cookie ile
BaseModule.set_auth(cookies={"PHPSESSID": "abc123"})

# Header ile
BaseModule.set_auth(headers={"Authorization": "Bearer token..."})

# Otomatik login
BaseModule.login("https://target/login", "admin", "pass123")
```
CLI argümanları: `--cookie`, `--auth-header`, `--login-url/--login-user/--login-pass`

### Plugin Sistemi
`plugins/` dizinine `.py` dosyaları bırakarak özel modül eklenebilir:
```python
# plugins/my_scanner.py
from utils.base_module import BaseModule, ModuleResult

class MyScanner(BaseModule):
    def run(self) -> ModuleResult:
        # ...
        return self.results
```
`load_plugins()` ile otomatik keşfedilir ve menüye eklenir.

### Sınıf Düzeyinde Durum
`BaseModule._proxy`, `_global_delay`, `_logger`, `_auth_cookies`, `_auth_headers` tüm cog'lar tarafından paylaşılan sınıf değişkenleridir.

### Async Port Scanner (modül 35)
`asyncio.new_event_loop()` kullanır — mevcut event loop ile çakışmaz. `_ports_arg` instance attribute'u ile custom port aralığı alır.

### NVD API Rate Limit (modül 36)
30 saniyede max 4 istek. `_nvd_last_call` ve `_nvd_call_count` sınıf değişkenleri ile rate limit yönetilir.

### OS Fingerprint (modül 35)
Windows'ta `ping -c 1` çalışmaz. `_os_fingerprint()` hata yakalar ve boş string döner — beklenen davranış.

### Rapor Üretici
`ReportGenerator` `output_dir` klasörünü otomatik oluşturur. `generate_all()` → `(html_path, pdf_path|None)`.

---

## Düzeltilen Bug'lar (Tüm Oturumlar)

| # | Dosya | Sorun | Durum |
|---|-------|-------|-------|
| 1 | `recon_06_lfi_rfi.py:32` | `"root:\$"` geçersiz escape — shadow imzası tetiklenmiyordu | ✅ Önceden düzeltilmiş |
| 2 | `recon_06_lfi_rfi.py` docstring | `\,` SyntaxWarning | ✅ Önceden düzeltilmiş |
| 3 | `maxima.py:586,588` | İnteraktif menüde `args.ports` eksikti | ✅ Düzeltildi |
| 4 | `recon_30_http2_probe.py:50` | Thread'lere `daemon=True` eksikti | ✅ Düzeltildi |
| 5 | `maxima.py` (4 yer) | `v7.0` → `v11.0` versiyon tutarsızlığı | ✅ Düzeltildi |
| 6 | `recon_09_subdomain_enum.py:259` | `asyncio.get_event_loop()` deprecated | ✅ Düzeltildi |
| 7 | `recon_41_advanced_reporter.py` | `_collect_all_findings()` imported_results kullanmıyordu | ✅ Düzeltildi |
| 8 | `recon_32_screenshot.py` | Harici araç kontrolü yoktu | ✅ Düzeltildi |
| 9 | `recon_07_cmd_injection.py` | `_discover_params()` URL param'ları öne taşımıyordu | ✅ Düzeltildi |
| 10 | `test_integration.py` | `test_no_module_crashes_on_unreachable_host` timeout | ✅ Mock ile düzeltildi |

---

## Kodlama Kuralları

- **Türkçe log mesajları** — `self.log()` çağrılarında Türkçe kullanılır
- **Dönüş tipleri** — tüm `run()` metodları `-> ModuleResult` döndürür
- **HTTP dönüşleri** — `-> HttpResponse` (TypedDict, `total=False`)
- **Encoding:** `utf-8` — tüm dosya okuma/yazma işlemlerinde açıkça belirtilir
- **SSL:** `ctx.verify_mode = ssl.CERT_NONE` — pentest bağlamı
- **Timeout:** Varsayılan 5 saniye; `--timeout` argümanıyla değiştirilebilir
- **Body limit:** 128KB (`_make_request` içinde `resp.read(1024 * 128)`)
- **Parallel istekler:** `ThreadPoolExecutor` — max_workers genellikle 8-12
- **Hata yakalama:** Geniş `except Exception` blokları — modül çökmesini önler
- **Loglama:** `--log-file` ile dosyaya yazılır; `BaseModule.configure_logging()` kullanılır

---

## SaaS Katmanı

### Dizin Yapısı
```
saas/
├── __init__.py
├── app.py              # FastAPI ana uygulama — REST API + SPA serve
├── auth.py             # JWT + API key kimlik doğrulama
├── config.py           # Plan limitleri, DB URL, secret key
├── models.py           # SQLAlchemy modelleri (User, Scan)
├── scan_engine.py      # Mevcut cogs modüllerini SaaS API üzerinden çalıştırır
├── schemas.py          # Pydantic request/response şemaları
└── templates/
    └── dashboard.html  # SPA web dashboard (vanilla JS)
```

### Çalıştırma
```bash
pip install -r requirements-saas.txt
cd maxima_v11_final
python -m saas.app
# http://localhost:8000 — Dashboard
# http://localhost:8000/api/docs — Swagger API docs
```

### API Endpoints
| Yol | Metod | Açıklama |
|-----|-------|----------|
| `/api/auth/register` | POST | Kullanıcı kaydı |
| `/api/auth/login` | POST | JWT token al |
| `/api/auth/me` | GET | Mevcut kullanıcı bilgisi |
| `/api/scans` | POST | Yeni tarama başlat |
| `/api/scans` | GET | Tarama listesi |
| `/api/scans/{id}` | GET | Tarama detayı + sonuçlar |
| `/api/scans/{id}/report/{format}` | GET | HTML/PDF/JSON rapor indir |
| `/api/dashboard` | GET | Dashboard istatistikleri |
| `/api/plans` | GET | Abonelik planları |
| `/api/modules` | GET | Kullanılabilir modüller |
| `/api/admin/users` | GET | Admin: kullanıcı listesi |
| `/api/admin/stats` | GET | Admin: platform istatistikleri |

### Abonelik Planları
| Plan | Fiyat | Tarama/Ay | Modül | Turbo | API | Rapor |
|------|-------|-----------|-------|-------|-----|-------|
| Free | $0 | 5 | İlk 20 | Yok | Yok | HTML |
| Pro | $49 | 100 | Tüm 41 | Var | Var | HTML+PDF+JSON |
| Enterprise | $199 | Sınırsız | Tüm 41 | Var | Var | HTML+PDF+JSON |

### Kimlik Doğrulama
- JWT Bearer token (login sonrası)
- API Key (`mx_` prefix) — Settings sayfasından alınır
- Her iki yöntem de `Authorization: Bearer <token/key>` header'ı ile kullanılır

### Veritabanı
- Varsayılan: SQLite (`maxima_saas.db`)
- Production: `DATABASE_URL` env ile PostgreSQL desteği
- `init_db()` otomatik olarak tabloları oluşturur

### Background Scan
- Taramalar `threading.Thread` ile background'da çalışır
- `MAX_CONCURRENT_SCANS` (varsayılan: 3) ile eşzamanlılık sınırlanır
- Modül 37 (Auth Tester) SaaS'ta otomatik olarak devre dışıdır
- Modül 41 (Reporter) sıralı çalışır, diğerleri turbo modda paralel

---

## Yasal Uyarı

Bu araç **yalnızca yetkili güvenlik testleri** için tasarlanmıştır.
Türk Ceza Kanunu 243. ve 244. maddeleri uyarınca yetkisiz kullanım suç teşkil eder.

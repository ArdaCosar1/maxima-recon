#!/usr/bin/env python3
"""
╔══════════════════════════════════════════╗
║         MAXIMA RECON FRAMEWORK           ║
║      Modular Reconnaissance Tool         ║
║                  v11.0                   ║
╚══════════════════════════════════════════╝
Usage:
  maxima <target>                        # Interaktif menü
  maxima <target> --all                  # Tüm modüller
  maxima <target> --module 14            # Tek modül
  maxima <target> --scan web             # Web tarama paketi
  maxima <target> --scan osint           # OSINT paketi
  maxima <target> --scan vuln            # Güvenlik açığı paketi
  maxima <target> --scan network         # Ağ keşif paketi
  maxima <target> --scan full-v2         # v7 tüm yeni modüller
  maxima --panel                         # Modül paneli (hedef gerekmez)
  maxima <target> --output json          # JSON çıktısı
  maxima <target> --timeout 15           # Özel timeout
"""

import sys
import os
import time
import json
import argparse
from typing import Any, Dict, List, Optional
from datetime import datetime

# ── Windows UTF-8 konsol düzeltmesi ──────────────────────────────
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        os.environ.setdefault("PYTHONIOENCODING", "utf-8")

from utils.compat import Fore, Back, Style

# ── Merkezi versiyon sabiti ────────────────────────────────────
VERSION = "11.0"

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cogs.recon_01_full_scan          import FullReconScan
from cogs.recon_02_port_scanner       import PortScanner
from cogs.recon_03_vuln_scanner       import VulnerabilityScanner
from cogs.recon_04_sql_injection      import SQLInjectionScanner
from cogs.recon_05_xss_scanner        import XSSScanner
from cogs.recon_06_lfi_rfi            import LFIRFIScanner
from cogs.recon_07_cmd_injection      import CommandInjectionScanner
from cogs.recon_08_ssrf               import SSRFScanner
from cogs.recon_09_subdomain_enum     import SubdomainEnumeration
from cogs.recon_10_dir_enum           import DirectoryEnumeration
from cogs.recon_11_api_fuzzer         import APIFuzzer
from cogs.recon_12_cors               import CORSScanner
from cogs.recon_13_ssl_tls            import SSLTLSAnalyzer
from cogs.recon_14_http_headers       import HTTPHeaderAnalyzer
from cogs.recon_15_tech_detect        import TechnologyDetector
from cogs.recon_16_jwt_analyzer       import JWTAnalyzer
from cogs.recon_17_clickjacking       import ClickjackingTester
from cogs.recon_18_open_redirect      import OpenRedirectScanner
from cogs.recon_19_subdomain_takeover import SubdomainTakeoverCheck
from cogs.recon_20_rate_limit         import RateLimitTester
from cogs.recon_21_whois              import WHOISLookup
from cogs.recon_22_ip_geo             import IPGeolocation
from cogs.recon_23_dns_records        import DNSRecordAnalysis
from cogs.recon_24_password_check     import PasswordStrengthChecker
from cogs.recon_25_hash_id            import HashIdentifier
from cogs.recon_26_waf_detector       import WAFDetector
from cogs.recon_27_tls_prober         import TLSVersionProber
from cogs.recon_28_redirect_chain     import RedirectChainAnalyzer
from cogs.recon_29_js_crawler         import JSCrawlerSecretScanner
from cogs.recon_30_http2_probe        import HTTP2Probe
from cogs.recon_31_payload_fuzzing    import PayloadFuzzingEngine
from cogs.recon_32_screenshot         import ScreenshotCapture
from cogs.recon_33_cve_template       import CVETemplateEngine
from cogs.recon_34_redirect_header    import RedirectAwareHeaderAnalysis
from cogs.recon_35_async_port_scanner import AsyncPortScanner
from cogs.recon_36_cve_matcher        import CVEMatcher
from cogs.recon_37_auth_tester        import AuthTester
from cogs.recon_38_osint_engine       import OSINTEngine
from cogs.recon_39_deep_sqli          import DeepSQLiScanner
from cogs.recon_40_new_vectors        import NewAttackVectors
from cogs.recon_41_advanced_reporter  import AdvancedReporter


# ── Banner ────────────────────────────────────────────────────
BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║  {Fore.MAGENTA}███╗   ███╗ █████╗ ██╗  ██╗██╗███╗   ███╗ █████╗ {Fore.CYAN}            ║
║  {Fore.MAGENTA}████╗ ████║██╔══██╗╚██╗██╔╝██║████╗ ████║██╔══██╗{Fore.CYAN}            ║
║  {Fore.MAGENTA}██╔████╔██║███████║ ╚███╔╝ ██║██╔████╔██║███████║{Fore.CYAN}            ║
║  {Fore.MAGENTA}██║╚██╔╝██║██╔══██║ ██╔██╗ ██║██║╚██╔╝██║██╔══██║{Fore.CYAN}            ║
║  {Fore.MAGENTA}██║ ╚═╝ ██║██║  ██║██╔╝ ██╗██║██║ ╚═╝ ██║██║  ██║{Fore.CYAN}            ║
║  {Fore.MAGENTA}╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚═╝  ╚═╝{Fore.CYAN}           ║
║             {Fore.YELLOW}▲ Authorized Use Only ▲{Fore.CYAN}                              ║
║          {Fore.WHITE}Modular Reconnaissance Framework v{VERSION}{Fore.CYAN}                ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# ── Modül Kayıt Defteri ───────────────────────────────────────
# (grup_adı, renk, {id: (ad, sınıf, [etiketler])})
MENU_GROUPS = [
    ("Web Scanners", Fore.GREEN, {
        1:  ("Full Reconnaissance Scan",            FullReconScan,           ["web", "full"]),
        2:  ("Port Scanner",                         PortScanner,             ["network", "full"]),
        3:  ("Vulnerability Scanner",               VulnerabilityScanner,    ["web", "vuln", "full"]),
        4:  ("SQL Injection Scanner",               SQLInjectionScanner,     ["web", "vuln", "full"]),
        5:  ("XSS Scanner",                         XSSScanner,              ["web", "vuln", "full"]),
        6:  ("LFI/RFI Scanner",                     LFIRFIScanner,           ["web", "vuln"]),
        7:  ("Command Injection Scanner",           CommandInjectionScanner, ["web", "vuln"]),
        8:  ("SSRF Scanner",                        SSRFScanner,             ["web", "vuln"]),
        9:  ("Subdomain Enumeration",               SubdomainEnumeration,    ["web", "osint", "full"]),
        10: ("Directory Enumeration",               DirectoryEnumeration,    ["web", "full"]),
        11: ("API Fuzzer",                           APIFuzzer,               ["web"]),
        12: ("CORS Misconfiguration Scanner",       CORSScanner,             ["web", "vuln"]),
        13: ("SSL/TLS Analyzer",                    SSLTLSAnalyzer,          ["web", "network"]),
        14: ("HTTP Header Analyzer",                HTTPHeaderAnalyzer,      ["web", "full"]),
        15: ("Technology Detector",                 TechnologyDetector,      ["web", "osint", "full"]),
        16: ("JWT Analyzer",                        JWTAnalyzer,             ["web", "vuln"]),
        17: ("Clickjacking Tester",                 ClickjackingTester,      ["web"]),
        18: ("Open Redirect Scanner",               OpenRedirectScanner,     ["web", "vuln"]),
        19: ("Subdomain Takeover Check",            SubdomainTakeoverCheck,  ["web", "vuln"]),
        20: ("Rate Limit Tester",                   RateLimitTester,         ["web"]),
    }),
    ("OSINT & Info", Fore.CYAN, {
        21: ("WHOIS Lookup",                        WHOISLookup,             ["osint", "full"]),
        22: ("IP Geolocation Info",                 IPGeolocation,           ["osint", "network"]),
        23: ("DNS Record Analysis",                 DNSRecordAnalysis,       ["osint", "network", "full"]),
        24: ("Password Strength Checker",           PasswordStrengthChecker, ["osint"]),
        25: ("Hash Identifier & Cracker",           HashIdentifier,          ["osint"]),
    }),
    ("Advanced Modules", Fore.YELLOW, {
        26: ("Multi-Request WAF Detector",          WAFDetector,             ["web", "network"]),
        27: ("TLS Version Prober",                  TLSVersionProber,        ["network", "web"]),
        28: ("Redirect Chain Analyzer",             RedirectChainAnalyzer,   ["web"]),
        29: ("JavaScript Crawler & Secret Scanner", JSCrawlerSecretScanner,  ["web", "vuln"]),
        30: ("HTTP/2 Probe & Async Port Scan",      HTTP2Probe,              ["network"]),
        31: ("Payload Fuzzing Engine",              PayloadFuzzingEngine,    ["web", "vuln"]),
        32: ("Screenshot Capture",                 ScreenshotCapture,       ["web"]),
        33: ("CVE Template Engine",                CVETemplateEngine,       ["vuln"]),
        34: ("Redirect-Aware Header Analysis",     RedirectAwareHeaderAnalysis, ["web"]),
    }),
    ("v2 Modules", Fore.MAGENTA, {
        35: ("Async Port Scanner (Gelismiş)",       AsyncPortScanner,        ["network", "full-v2"]),
        36: ("CVE & Exploit Esleştirici",           CVEMatcher,              ["vuln", "full-v2"]),
        37: ("Auth & Credential Tester",            AuthTester,              ["vuln", "full-v2"]),
        38: ("OSINT & Istihbarat Motoru",           OSINTEngine,             ["osint", "full-v2"]),
        39: ("Deep SQLi Scanner",                   DeepSQLiScanner,         ["vuln", "full-v2"]),
        40: ("SSTI + XXE + IDOR + GraphQL",         NewAttackVectors,        ["vuln", "full-v2"]),
        41: ("Gelişmiş Rapor & Risk Analizi",       AdvancedReporter,        ["full-v2"]),
    }),
]

# Düz MENU ve etiket sözlükleri (hızlı erişim)
MENU = {}
MODULE_TAGS = {}
for _gname, _gcol, _gmods in MENU_GROUPS:
    for _mid, (_mname, _mcls, _mtags) in _gmods.items():
        MENU[_mid] = (_mname, _mcls)
        MODULE_TAGS[_mid] = _mtags

# ── Plugin sistemi: plugins/ dizininden otomatik yükle ──────────
from cogs import load_plugins as _load_plugins
_PLUGINS = _load_plugins()
_next_id = max(MENU.keys()) + 1 if MENU else 42
for _pname, _pcls in _PLUGINS.items():
    MENU[_next_id] = (_pname, _pcls)
    MODULE_TAGS[_next_id] = ["plugin"]
    _next_id += 1

# ── Tarama Paketleri ──────────────────────────────────────────
SCAN_PROFILES = {
    "web":     ("🌐 Web Tarama Paketi",
                "HTTP başlıkları, XSS, SQLi, CORS, teknoloji tespiti ve daha fazlası",
                sorted(m for m, tags in MODULE_TAGS.items() if "web" in tags)),
    "osint":   ("🔍 OSINT & İstihbarat Paketi",
                "WHOIS, DNS, subdomain, IP cografya, crt.sh, Wayback Machine",
                sorted(m for m, tags in MODULE_TAGS.items() if "osint" in tags)),
    "vuln":    ("🐛 Güvenlik Açığı Tarama Paketi",
                "SQLi, XSS, LFI, SSRF, CVE, SSTI, XXE, auth testi",
                sorted(m for m, tags in MODULE_TAGS.items() if "vuln" in tags)),
    "network": ("📡 Ağ Keşif Paketi",
                "Port tarama, TLS, DNS, WAF, HTTP/2, IP geolocation",
                sorted(m for m, tags in MODULE_TAGS.items() if "network" in tags)),
    "full":    ("⚡ Tam Tarama (v1 Modüller)",
                "Temel 34 modülün tamamı",
                sorted(m for m, tags in MODULE_TAGS.items() if "full" in tags and m <= 34)),
    "full-v2": ("🚀 v2 Tam Tarama (Tüm 41 Modül)",
                "41 modülün tamamı — async port, deep SQLi, OSINT engine dahil",
                sorted(MENU.keys())),
}


# ── Panel ─────────────────────────────────────────────────────
def print_panel():
    W = 72

    print(BANNER)
    print(f"{Fore.CYAN}{'═' * W}")
    print(f"{Fore.YELLOW}{'MAXIMA MODULE PANEL':^{W}}")
    print(f"{Fore.CYAN}{'═' * W}{Style.RESET_ALL}\n")

    for gname, gcol, gmods in MENU_GROUPS:
        dash_count = max(1, W - len(gname) - 8)
        print(f"{gcol}  ◈  {gname}  {'─' * dash_count}{Style.RESET_ALL}")

        items = list(gmods.items())
        col_w = (W - 6) // 2
        for i in range(0, len(items), 2):
            lid, (lname, _, ltags) = items[i]
            lbadge = "⚠ " if lid == 37 else "↑ " if lid >= 35 else "  "
            left_str = f"  {gcol}[{lid:2d}]{Style.RESET_ALL} {lbadge}{lname}"

            if i + 1 < len(items):
                rid, (rname, _, rtags) = items[i + 1]
                rbadge = "⚠ " if rid == 37 else "↑ " if rid >= 35 else "  "
                right_str = f"{gcol}[{rid:2d}]{Style.RESET_ALL} {rbadge}{rname}"
                pad = max(1, col_w - (len(f"[{lid:2d}] {lbadge}{lname}") + 2))
                print(f"{left_str}{' ' * pad}  {right_str}")
            else:
                print(left_str)
        print()

    # Tarama paketleri tablosu
    print(f"{Fore.CYAN}{'═' * W}")
    print(f"{Fore.YELLOW}{'TARAMA PAKETLERİ  (--scan <paket>)':^{W}}")
    print(f"{Fore.CYAN}{'═' * W}{Style.RESET_ALL}\n")

    profile_colors = {
        "web": Fore.GREEN, "osint": Fore.CYAN, "vuln": Fore.RED,
        "network": Fore.BLUE, "full": Fore.YELLOW, "full-v2": Fore.MAGENTA,
    }

    for pkey, (ptitle, pdesc, pmods) in SCAN_PROFILES.items():
        pc = profile_colors.get(pkey, Fore.WHITE)
        mod_ids = ", ".join(str(m) for m in pmods)
        print(f"  {pc}▶  --scan {pkey:<12}{Style.RESET_ALL}  {ptitle}")
        print(f"       {Fore.WHITE}{pdesc}{Style.RESET_ALL}")
        print(f"       {Fore.CYAN}Modüller ({len(pmods)}): {mod_ids}{Style.RESET_ALL}")
        print()

    # Komut referansı
    print(f"{Fore.CYAN}{'═' * W}")
    print(f"{Fore.YELLOW}{'KOMUT REFERANSI':^{W}}")
    print(f"{Fore.CYAN}{'═' * W}{Style.RESET_ALL}\n")

    cmds = [
        ("maxima --panel",                "Bu paneli göster (hedef gerekmez)"),
        ("maxima <hedef>",                "İnteraktif menüyü aç"),
        ("maxima <hedef> --all",          "Tüm 41 modülü çalıştır"),
        ("maxima <hedef> --scan web",     "Web tarama paketini çalıştır"),
        ("maxima <hedef> --scan vuln",    "Güvenlik açığı paketini çalıştır"),
        ("maxima <hedef> --scan osint",   "OSINT paketini çalıştır"),
        ("maxima <hedef> --scan network", "Ağ keşif paketini çalıştır"),
        ("maxima <hedef> --scan full-v2", "Tüm v2 modülleri çalıştır"),
        ("maxima <hedef> --module 35",    "Tek modül çalıştır (1-41)"),
        ("maxima <hedef> --modules 3,14,36", "Virgülle ayrılmış modül listesi"),
        ("maxima <hedef> --output json",  "Sonuçları JSON olarak kaydet"),
        ("maxima <hedef> --timeout 20",   "HTTP timeout süresini ayarla (varsayılan: 8s)"),
        ("maxima <hedef> --quiet",        "Sessiz mod: sadece bulgular görünür"),
        ("maxima <hedef> --all --turbo",  "TURBO: Modülleri paralel dalgalar halinde çalıştır"),
        ("maxima <hedef> --scan web --turbo", "Profil taramasını paralel çalıştır"),
        ("maxima <hedef> --cookie 'X=Y'", "Session cookie ile tarama"),
        ("maxima <hedef> --auth-header 'Bearer ...'", "Auth header ile tarama"),
        ("[Menüde] 98",                   "Paneli menü içinden aç"),
        ("[Menüde] 99",                   "Tüm modülleri menü içinden çalıştır"),
    ]
    for cmd, desc in cmds:
        print(f"  {Fore.GREEN}{cmd:<40}{Style.RESET_ALL}  {desc}")

    print(f"\n  {Fore.RED}⚠  [37] Auth Tester{Style.RESET_ALL} — gerçek kimlik bilgileri deniyor, onay ister.")
    print(f"  {Fore.RED}⚠  [41] Advanced Reporter{Style.RESET_ALL} — diğer modüllerin sonuçlarını kullanır; "
          f"önce başka modül çalıştırın.")
    print(f"  {Fore.YELLOW}↑  = v2 yeni modül{Style.RESET_ALL}\n")
    print(f"{Fore.CYAN}{'═' * W}{Style.RESET_ALL}\n")


# ── İnteraktif Menü ───────────────────────────────────────────
def print_menu():
    W = 66
    print(f"\n{Fore.CYAN}{'═' * W}")
    print(f"{Fore.MAGENTA}{f'MAXIMA MAIN MENU  v{VERSION}':^{W}}")
    print(f"{Fore.CYAN}{'═' * W}{Style.RESET_ALL}\n")

    for gname, gcol, gmods in MENU_GROUPS:
        dashes = '─' * max(1, 44 - len(gname))
        print(f"  {Fore.YELLOW}── {gname} {dashes}{Style.RESET_ALL}")
        for mid, (mname, _, _) in gmods.items():
            warn = f" {Fore.RED}⚠ YETKİLİ KULLANIM{Style.RESET_ALL}" if mid == 37 else ""
            v2   = f" {Fore.MAGENTA}[v2]{Style.RESET_ALL}" if mid >= 35 else ""
            print(f"  {gcol}[{mid:2d}]{Style.RESET_ALL} {mname}{v2}{warn}")
        print()

    print(f"  {Fore.CYAN}[98]{Style.RESET_ALL} Modül Panelini Göster")
    print(f"  {Fore.CYAN}[99]{Style.RESET_ALL} Tüm Modülleri Çalıştır")
    print(f"  {Fore.RED}[ 0]{Style.RESET_ALL} Çıkış\n")
    print(f"{Fore.CYAN}{'═' * W}{Style.RESET_ALL}")


# ── Modül 37 — Yasal onay kontrolü ───────────────────────────
def _require_auth_consent(target: str) -> bool:
    """Auth Tester (modül 37) için interaktif yasal uyarı + onay.
    True → onay alındı, False → iptal edildi."""
    print(f"\n{Fore.RED}{'═' * 58}")
    print(f"  ⚠   KİMLİK DOĞRULAMA TESTI — YASAL UYARI   ⚠")
    print(f"{'═' * 58}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}")
    print(f"  Bu modül hedef sistemde şu işlemleri GERÇEKLEŞTIRIR:")
    print(f"    • 30+ yaygın kullanıcı adı/şifre kombinasyonu dener")
    print(f"    • HTTP Basic Auth brute-force uygular")
    print(f"    • API endpoint'lerine credential gönderir")
    print(f"    • Hesap kilitleme politikasını test eder (6 yanlış giriş)")
    print(f"")
    print(f"  YASAL UYARI:")
    print(f"    Yetkisiz sistemlerde kullanmak suç teşkil eder.")
    print(f"    Türk Ceza Kanunu Madde 243/244 kapsamında")
    print(f"    hapis cezasına yol açabilir.")
    print(f"")
    print(f"  Devam etmek için yazılı onay gereklidir.{Style.RESET_ALL}")
    print(f"{Fore.RED}{'═' * 58}{Style.RESET_ALL}\n")
    try:
        print(f"{Fore.WHITE}  Hedef: {Fore.CYAN}{target}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}  Bu sisteme karşı test yapmaya YETKİNİZ VAR MI?{Style.RESET_ALL}")
        onay = input(
            f"\n{Fore.YELLOW}  Onaylamak için tam olarak 'evet' yazın: {Style.RESET_ALL}"
        ).strip().lower()
    except KeyboardInterrupt:
        onay = ""
    if onay != "evet":
        print(f"\n{Fore.YELLOW}[!] Auth Tester iptal edildi. Onay alınamadı.{Style.RESET_ALL}\n")
        return False
    print(f"\n{Fore.GREEN}[✓] Onay alındı. Tarama başlıyor...{Style.RESET_ALL}\n")
    return True


# ── Modül 41 — Raporlayıcı özel başlatıcı ────────────────────
def _run_reporter_module(name: str, ModuleClass, target: str,
                         results_store: Dict[str, Any]) -> Optional[Dict]:
    """AdvancedReporter (modül 41) için önceki sonuçları aktararak çalıştır."""
    print(f"\n{Fore.CYAN}[*] Başlatılıyor: {Fore.YELLOW}{name}{Style.RESET_ALL}")
    if results_store:
        print(f"{Fore.CYAN}[*] {len(results_store)} modül sonucu raporlayıcıya aktarılıyor...{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[!] Önceki sonuç bulunamadı — modül yalnızca yüzey analizi yapacak.{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─' * 52}{Style.RESET_ALL}\n")
    try:
        module = ModuleClass(target)
        if results_store:
            module.results["imported_results"] = results_store
        module.results["_output_dir"] = os.path.join(
            "maxima_reports",
            target.replace("://", "_").replace("/", "_").replace(":", "_")
        )
        result = module.run()
        results_store[name] = result
        print(f"\n{Fore.GREEN}[✓] Tamamlandı: {name}{Style.RESET_ALL}")
        return result
    except (ConnectionError, TimeoutError, OSError) as e:
        print(f"{Fore.RED}[✗] Bağlantı hatası ({name}): {e}{Style.RESET_ALL}")
        results_store[name] = {"error": str(e), "module": name}
        return None
    except Exception as e:
        print(f"{Fore.RED}[✗] Beklenmeyen hata ({name}): {type(e).__name__}: {e}{Style.RESET_ALL}")
        results_store[name] = {"error": f"{type(e).__name__}: {e}", "module": name}
        return None


# ── Modül Çalıştırıcı ─────────────────────────────────────────
def run_module(choice, target, results_store, timeout=8, quiet=False, wordlist=None, ports=None):
    if choice not in MENU:
        print(f"{Fore.RED}[!] Geçersiz modül: {choice} (geçerli: 1-{max(MENU.keys())}){Style.RESET_ALL}")
        return None

    name, ModuleClass = MENU[choice]

    if choice == 37 and not _require_auth_consent(target):
        return None

    if choice == 41:
        return _run_reporter_module(name, ModuleClass, target, results_store)

    print(f"\n{Fore.CYAN}[*] Başlatılıyor: {Fore.YELLOW}{name}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Hedef        : {Fore.WHITE}{target}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─' * 52}{Style.RESET_ALL}\n")

    try:
        module = ModuleClass(target)
        module.timeout = _get_module_timeout(choice, timeout)
        if wordlist and (hasattr(module, "wordlist_path") or choice in (9, 10)):
            module.wordlist_path = wordlist
        if ports and choice == 35:
            module._ports_arg = ports
        if quiet:
            module._quiet = True
        result = module.run()
        results_store[name] = result
        print(f"\n{Fore.GREEN}[✓] Tamamlandı: {name}{Style.RESET_ALL}")
        return result
    except (ConnectionError, TimeoutError, OSError) as e:
        print(f"{Fore.RED}[✗] Bağlantı hatası ({name}): {e}{Style.RESET_ALL}")
        results_store[name] = {"error": str(e), "module": name}
        return None
    except (ValueError, KeyError, TypeError) as e:
        print(f"{Fore.RED}[✗] Veri hatası ({name}): {e}{Style.RESET_ALL}")
        results_store[name] = {"error": str(e), "module": name}
        return None
    except Exception as e:
        print(f"{Fore.RED}[✗] Beklenmeyen hata ({name}): {type(e).__name__}: {e}{Style.RESET_ALL}")
        results_store[name] = {"error": f"{type(e).__name__}: {e}", "module": name}
        return None

# ── Tarama Paketi ─────────────────────────────────────────────
def run_scan_profile(profile_key, target, results_store, timeout=8, quiet=False,
                     wordlist=None, ports=None, turbo=False):
    if profile_key not in SCAN_PROFILES:
        print(f"{Fore.RED}[!] Bilinmeyen paket: '{profile_key}'")
        print(f"    Geçerli paketler: {', '.join(SCAN_PROFILES.keys())}{Style.RESET_ALL}")
        return

    ptitle, pdesc, pmods = SCAN_PROFILES[profile_key]

    print(f"\n{Fore.MAGENTA}╔══════════════════════════════════════════╗")
    print(f"║  {ptitle:<40}║")
    print(f"╚══════════════════════════════════════════╝{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Açıklama   : {pdesc}")
    print(f"{Fore.CYAN}[*] Modül sayısı: {len(pmods)}")
    print(f"{Fore.CYAN}[*] Modüller   : {', '.join(str(m) for m in pmods)}")
    if turbo:
        print(f"{Fore.CYAN}[*] Mod        : TURBO (paralel)")
    print(f"{Style.RESET_ALL}\n")

    t0 = time.time()
    if turbo and len(pmods) > 2:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _run_one(choice):
            if choice not in MENU:
                return
            name, ModuleClass = MENU[choice]
            try:
                module = ModuleClass(target)
                module.timeout = timeout
                if wordlist and (hasattr(module, "wordlist_path") or choice in (9, 10)):
                    module.wordlist_path = wordlist
                if ports and choice == 35:
                    module._ports_arg = ports
                module._quiet = True
                result = module.run()
                results_store[name] = result
                fc = len(result.get("findings", []))
                print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} {name:<42} {Fore.CYAN}{fc} bulgu{Style.RESET_ALL}")
            except Exception as e:
                results_store[name] = {"error": str(e), "module": name}
                print(f"  {Fore.RED}[✗]{Style.RESET_ALL} {name:<42} {e}")

        # Modül 37 ve 41 sıralı, geri kalanı paralel
        parallel = [c for c in pmods if c not in (37, 41)]
        sequential = [c for c in pmods if c in (37, 41)]

        max_w = min(len(parallel), 6)
        with ThreadPoolExecutor(max_workers=max_w) as pool:
            futures = {pool.submit(_run_one, c): c for c in parallel}
            for f in as_completed(futures):
                pass
        for c in sequential:
            run_module(c, target, results_store, timeout, quiet, wordlist, ports)
    else:
        for choice in pmods:
            run_module(choice, target, results_store, timeout, quiet, wordlist, ports)

    elapsed = time.time() - t0
    total_findings = sum(
        len(r.get("findings", [])) for r in results_store.values()
        if isinstance(r, dict)
    )
    print(f"\n{Fore.GREEN}[★] Paket tamamlandı: {ptitle} — "
          f"{len(results_store)} modül, {total_findings} bulgu, "
          f"{elapsed:.1f}s{Style.RESET_ALL}")


# ── Tüm Modüller ──────────────────────────────────────────────
def run_full_scan(target, results_store, timeout=8, quiet=False, wordlist=None, ports=None,
                  turbo=False):
    print(f"\n{Fore.MAGENTA}[★] TAM TARAMA BAŞLATILIYOR — {len(MENU)} modül"
          f"{' (TURBO)' if turbo else ''}{Style.RESET_ALL}\n")
    t0 = time.time()

    if turbo:
        _run_turbo(target, results_store, timeout, quiet, wordlist, ports)
    else:
        for choice in sorted(MENU.keys()):
            run_module(choice, target, results_store, timeout, quiet, wordlist, ports)

    elapsed = time.time() - t0
    total_findings = sum(
        len(r.get("findings", [])) for r in results_store.values()
        if isinstance(r, dict)
    )
    print(f"\n{Fore.GREEN}[★] Tam tarama tamamlandı — "
          f"{len(results_store)} modül, {total_findings} bulgu, "
          f"{elapsed:.1f}s{Style.RESET_ALL}")


# ── Turbo Engine: Paralel modül çalıştırma ───────────────────
# ── Per-module timeout override (yavaş modüllere ek süre) ─────
_MODULE_TIMEOUT_OVERRIDE = {
    9:  20,  # Subdomain enum — API çağrıları
    10: 15,  # Directory enum — çok istek
    35: 20,  # Async port scanner — bağlantı beklemeleri
    36: 15,  # CVE matcher — NVD API
    38: 20,  # OSINT engine — harici API'ler
    41: 15,  # Advanced reporter — analiz
}

def _get_module_timeout(choice: int, base_timeout: int) -> int:
    """Per-module timeout: modül özel override'ı varsa onu, yoksa base'i kullan."""
    override = _MODULE_TIMEOUT_OVERRIDE.get(choice)
    if override and override > base_timeout:
        return override
    return base_timeout


def _run_turbo(target, results_store, timeout=8, quiet=False, wordlist=None, ports=None):
    """Modülleri bağımsız gruplara ayırıp ThreadPoolExecutor ile paralel çalıştır.

    Dalga yapısı:
      Wave 1: Ön-keşif (1, 14, 15, 17, 21, 22, 23, 32)  — bağımsız, hızlı
      Wave 2: Port tarama (2, 13, 27, 30, 35)              — ağ modülleri
      Wave 3: Vuln tarama (3-8, 12, 16, 18, 19, 26, 28, 29, 31, 33, 34) — web tarama
      Wave 4: Ağır modüller (9, 10, 11, 20, 24, 25, 36, 38, 39, 40) — yavaş/API
      Wave 5: Sıralı (37, 41) — etkileşimli / bağımlı
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    waves = [
        # Wave 1: Hızlı keşif
        [1, 14, 15, 17, 21, 22, 23, 32],
        # Wave 2: Ağ modülleri
        [2, 13, 27, 30, 35],
        # Wave 3: Web vuln tarama
        [3, 4, 5, 6, 7, 8, 12, 16, 18, 19, 26, 28, 29, 31, 33, 34],
        # Wave 4: Ağır / API bağımlı
        [9, 10, 11, 20, 24, 25, 36, 38, 39, 40],
    ]
    # Sıralı çalışması gerekenler
    sequential = [37, 41]

    def _run_single(choice):
        """Thread-safe tek modül çalıştırıcı."""
        if choice not in MENU:
            return
        name, ModuleClass = MENU[choice]
        try:
            module = ModuleClass(target)
            module.timeout = _get_module_timeout(choice, timeout)
            if wordlist and (hasattr(module, "wordlist_path") or choice in (9, 10)):
                module.wordlist_path = wordlist
            if ports and choice == 35:
                module._ports_arg = ports
            module._quiet = True  # turbo modda sessiz
            result = module.run()
            results_store[name] = result
            finding_count = len(result.get("findings", []))
            severity_counts = {}
            for f in result.get("findings", []):
                s = f.get("severity", "info")
                severity_counts[s] = severity_counts.get(s, 0) + 1
            sev_str = ", ".join(f"{k}:{v}" for k, v in severity_counts.items()) if severity_counts else "0"
            print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} {name:<42} "
                  f"{Fore.CYAN}{finding_count} bulgu{Style.RESET_ALL} ({sev_str})")
        except Exception as e:
            results_store[name] = {"error": str(e), "module": name}
            print(f"  {Fore.RED}[✗]{Style.RESET_ALL} {name:<42} {Fore.RED}{e}{Style.RESET_ALL}")

    # Dalga dalga çalıştır
    cancelled = False
    for wave_idx, wave in enumerate(waves, 1):
        if cancelled:
            break
        valid = [c for c in wave if c in MENU]
        if not valid:
            continue
        print(f"\n{Fore.YELLOW}── Wave {wave_idx}: {len(valid)} modül paralel ──{Style.RESET_ALL}")
        max_w = min(len(valid), 6)
        try:
            with ThreadPoolExecutor(max_workers=max_w) as pool:
                futures = {pool.submit(_run_single, c): c for c in valid}
                for f in as_completed(futures):
                    pass  # _run_single içinde yazdırılıyor
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Turbo iptal edildi — toplanan sonuçlar korunuyor.{Style.RESET_ALL}")
            cancelled = True

    # Sıralı modüller
    if not cancelled:
        for choice in sequential:
            if choice in MENU:
                run_module(choice, target, results_store, timeout, quiet, wordlist, ports)


# ── JSON Çıktı ────────────────────────────────────────────────
def save_json(results_store, output_dir, target):
    json_path = os.path.join(output_dir, "maxima_results.json")
    payload = {
        "target":       target,
        "timestamp":    datetime.now().isoformat(),
        "module_count": len(results_store),
        "results":      results_store,
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, default=str)
    return json_path


# ── Baseline Comparison (Scan Diff) ────────────────────────────
def compare_scans(current_store: dict, baseline_path: str) -> dict:
    """İki tarama sonucunu karşılaştır: yeni / düzeltilmiş / değişmeyen bulgular.

    Args:
        current_store: mevcut tarama sonuçları
        baseline_path: önceki taramanın JSON dosya yolu

    Returns:
        {"new": [...], "fixed": [...], "unchanged": [...]}
    """
    try:
        with open(baseline_path, "r", encoding="utf-8") as f:
            baseline = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"{Fore.RED}[!] Baseline dosyası okunamadı: {e}{Style.RESET_ALL}")
        return {"new": [], "fixed": [], "unchanged": []}

    def _extract_findings(store):
        """results_store'dan tüm bulguları (title, severity) set olarak çıkar."""
        findings = set()
        results = store.get("results", store)  # JSON vs dict uyumu
        for mod_result in results.values():
            if not isinstance(mod_result, dict):
                continue
            for f in mod_result.get("findings", []):
                findings.add((f.get("title", ""), f.get("severity", "info")))
        return findings

    old_findings = _extract_findings(baseline)
    new_findings = _extract_findings({"results": current_store})

    added   = new_findings - old_findings
    fixed   = old_findings - new_findings
    same    = new_findings & old_findings

    return {
        "new":       [{"title": t, "severity": s} for t, s in sorted(added)],
        "fixed":     [{"title": t, "severity": s} for t, s in sorted(fixed)],
        "unchanged": [{"title": t, "severity": s} for t, s in sorted(same)],
    }


def _print_diff(diff: dict):
    """Scan diff sonuçlarını ekrana yazdır."""
    W = 50
    print(f"\n{Fore.CYAN}{'═' * W}")
    print(f"{Fore.YELLOW}{'TARAMA KARŞILAŞTIRMASI':^{W}}")
    print(f"{Fore.CYAN}{'═' * W}{Style.RESET_ALL}")

    if diff["new"]:
        print(f"\n  {Fore.RED}▼ YENİ BULGULAR ({len(diff['new'])}){Style.RESET_ALL}")
        for f in diff["new"]:
            print(f"    {Fore.RED}+ [{f['severity'].upper():<8}] {f['title']}{Style.RESET_ALL}")

    if diff["fixed"]:
        print(f"\n  {Fore.GREEN}▲ DÜZELTİLEN BULGULAR ({len(diff['fixed'])}){Style.RESET_ALL}")
        for f in diff["fixed"]:
            print(f"    {Fore.GREEN}- [{f['severity'].upper():<8}] {f['title']}{Style.RESET_ALL}")

    if diff["unchanged"]:
        print(f"\n  {Fore.WHITE}● DEĞİŞMEYEN BULGULAR ({len(diff['unchanged'])}){Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'═' * W}{Style.RESET_ALL}")


# ── Rapor Üretici ─────────────────────────────────────────────
def _generate_reports(target, results_store, output_dir, extra_format=None):
    print(f"\n{Fore.CYAN}[*] Raporlar oluşturuluyor...{Style.RESET_ALL}")

    if extra_format == "json":
        json_path = save_json(results_store, output_dir, target)
        print(f"{Fore.GREEN}[✓] JSON Rapor : {Fore.WHITE}{json_path}{Style.RESET_ALL}")

    try:
        from utils.report_generator import ReportGenerator
        gen = ReportGenerator(target, results_store, output_dir)
        html_path, pdf_path, json_rpt_path = gen.generate_all()
        print(f"{Fore.GREEN}[✓] HTML Rapor : {Fore.WHITE}{html_path}{Style.RESET_ALL}")
        if pdf_path:
            print(f"{Fore.GREEN}[✓] PDF Rapor  : {Fore.WHITE}{pdf_path}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] PDF oluşturulamadı (reportlab eksik olabilir).{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[✓] JSON Rapor : {Fore.WHITE}{json_rpt_path}{Style.RESET_ALL}")
    except ImportError as e:
        print(f"{Fore.RED}[✗] Rapor modülü yüklenemedi: {e}{Style.RESET_ALL}")
    except (OSError, PermissionError) as e:
        print(f"{Fore.RED}[✗] Rapor dosyası yazılamadı: {e}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[✗] Rapor hatası ({type(e).__name__}): {e}{Style.RESET_ALL}")
    print()


# ── Ana Fonksiyon ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="maxima",
        description=f"Maxima Recon Framework v{VERSION} — Modüler Keşif Aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Örnekler:
  maxima --panel
  maxima https://hedef.com
  maxima https://hedef.com --scan web
  maxima https://hedef.com --scan vuln --output json --timeout 15
  maxima https://hedef.com --module 38
  maxima https://hedef.com --all
        """
    )
    parser.add_argument("target",    nargs="?",  help="Hedef URL veya IP")
    parser.add_argument("--all",     action="store_true",
                        help="Tüm 41 modülü sırayla çalıştır")
    parser.add_argument("--module",  type=int, metavar="N",
                        help="Tek modül numarası (1-41)")
    parser.add_argument("--modules", type=str, metavar="N,N,N",
                        help="Virgülle ayrılmış modül listesi — örn: 3,14,26,36")
    parser.add_argument("--scan",    type=str, metavar="PAKET",
                        choices=list(SCAN_PROFILES.keys()),
                        help="Paket: web / osint / vuln / network / full / full-v2")
    parser.add_argument("--panel",   action="store_true",
                        help="Tüm modülleri ve komutları panel halinde göster")
    parser.add_argument("--output",  type=str, choices=["json"],
                        help="Ek çıktı formatı (json)")
    parser.add_argument("--timeout", type=int, default=8, metavar="SN",
                        help="HTTP istek timeout süresi saniye cinsinden (varsayılan: 8)")
    parser.add_argument("--wordlist", type=str, default=None, metavar="DOSYA",
                        help="Subdomain/dizin taraması için harici wordlist dosyası")
    parser.add_argument("--quiet",   action="store_true",
                        help="Sessiz mod: sadece bulgular gösterilir, log mesajları gizlenir")
    parser.add_argument("--turbo",   action="store_true",
                        help="Turbo mod: modülleri paralel dalgalar halinde çalıştır (~3-5x hız)")
    parser.add_argument("--proxy",   type=str, default=None, metavar="URL",
                        help="HTTP/HTTPS proxy (örn: http://127.0.0.1:8080 veya socks5://...)")
    parser.add_argument("--delay",   type=float, default=0.0, metavar="SN",
                        help="Modüller arası istek bekleme süresi saniye cinsinden (örn: 0.5)")
    parser.add_argument("--ports",   type=str, default=None, metavar="PORTLAR",
                        help="recon_35 için taranacak portlar: '22,80,443' veya '1-1024' veya karma")
    parser.add_argument("--log-file", type=str, default=None, metavar="DOSYA",
                        help="Tüm log mesajlarını dosyaya yaz (örn: maxima.log)")
    parser.add_argument("--verify-ssl", action="store_true",
                        help="SSL sertifika doğrulamasını etkinleştir (varsayılan: devre dışı)")
    parser.add_argument("--no-color", action="store_true",
                        help="Renk kodlarını devre dışı bırak (pipe/dosya çıktısı için)")
    parser.add_argument("--cookie", type=str, default=None, metavar="COOKIE",
                        help="Session cookie (örn: 'PHPSESSID=abc123; token=xyz')")
    parser.add_argument("--auth-header", type=str, default=None, metavar="HEADER",
                        help="Auth header (örn: 'Bearer eyJhbGciOi...')")
    parser.add_argument("--login-url", type=str, default=None, metavar="URL",
                        help="Login form URL'si (--login-user ve --login-pass ile kullanılır)")
    parser.add_argument("--login-user", type=str, default=None, metavar="USER",
                        help="Login kullanıcı adı")
    parser.add_argument("--login-pass", type=str, default=None, metavar="PASS",
                        help="Login şifresi")
    parser.add_argument("--baseline", type=str, default=None, metavar="JSON",
                        help="Önceki tarama JSON dosyası — yeni/düzeltilmiş bulgu karşılaştırması")
    parser.add_argument("--version", action="version",
                        version=f"Maxima Recon Framework v{VERSION}")
    args = parser.parse_args()

    # --no-color: renkleri devre dışı bırak (pipe/dosya çıktısı için)
    if args.no_color:
        import re as _re
        _nc = type('NoColor', (), {'__getattr__': lambda s, n: ''})()
        import utils.compat as _uc
        _uc.Fore = _nc; _uc.Back = _nc; _uc.Style = _nc
        # Mevcut global'leri güncelle — BANNER zaten oluşmuş, ANSI sil
        global Fore, Style, BANNER
        Fore = Style = _nc
        BANNER = _re.sub(r'\x1b\[[0-9;]*m', '', BANNER)

    # --panel hedef gerektirmez
    if args.panel:
        print_panel()
        return

    print(BANNER)

    # Hedef al
    if not args.target:
        try:
            args.target = input(
                f"{Fore.CYAN}[?] Hedef URL/IP (ya da 'panel' yazın): {Style.RESET_ALL}"
            ).strip()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Çıkış.{Style.RESET_ALL}")
            return
        if args.target.lower() in ("--panel", "panel"):
            print_panel()
            return

    if not args.target:
        parser.print_help()
        return

    # Hedef doğrulama
    target = args.target.strip()
    if " " in target or len(target) > 500:
        print(f"{Fore.RED}[!] Geçersiz hedef: '{target[:60]}...'{Style.RESET_ALL}")
        return
    if not any(c.isalnum() for c in target):
        print(f"{Fore.RED}[!] Geçersiz hedef formatı.{Style.RESET_ALL}")
        return
    # Temel URL/IP format doğrulaması
    import re as _re_validate
    _clean = target.split("://", 1)[-1].split("/")[0].split(":")[0]  # host kısmını çıkar
    if not _re_validate.match(r'^[\w][\w.\-]{0,253}[\w]$|^\d{1,3}(\.\d{1,3}){3}$', _clean):
        print(f"{Fore.RED}[!] Geçersiz host formatı: '{_clean}'{Style.RESET_ALL}")
        return
    results_store = {}
    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name  = target.replace("://", "_").replace("/", "_").replace(":", "_")
    output_dir = f"maxima_reports/{safe_name}_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)

    # Dosya loglama aktifleştir (opsiyonel)
    log_file = getattr(args, "log_file", None)
    if log_file:
        from utils.base_module import BaseModule as _BM
        _BM.configure_logging(log_file=log_file)

    print(f"\n{Fore.GREEN}[+] Hedef    : {Fore.WHITE}{target}")
    print(f"{Fore.GREEN}[+] Timeout  : {Fore.WHITE}{args.timeout}s")
    if args.turbo:
        print(f"{Fore.GREEN}[+] Mod      : {Fore.WHITE}TURBO (paralel modül çalıştırma)")
    if args.quiet:
        print(f"{Fore.GREEN}[+] Mod      : {Fore.WHITE}Sessiz (yalnızca bulgular)")
    if args.proxy:
        print(f"{Fore.GREEN}[+] Proxy    : {Fore.WHITE}{args.proxy}")
    if args.delay:
        print(f"{Fore.GREEN}[+] Delay    : {Fore.WHITE}{args.delay}s")
    if args.ports:
        print(f"{Fore.GREEN}[+] Ports    : {Fore.WHITE}{args.ports}")
    if args.verify_ssl:
        print(f"{Fore.GREEN}[+] SSL Verify: {Fore.WHITE}Etkin")
    if log_file:
        print(f"{Fore.GREEN}[+] Log      : {Fore.WHITE}{log_file}")
    print(f"{Fore.GREEN}[+] Çıktı    : {Fore.WHITE}{output_dir}{Style.RESET_ALL}\n")

    # ── BaseModule class-level ayarlar ──
    from utils.base_module import BaseModule as _BM
    _BM.set_proxy(args.proxy)
    _BM.set_delay(args.delay)
    _BM.set_verify_ssl(args.verify_ssl)

    # ── Authenticated scanning ──
    if args.cookie:
        cookies = {}
        for part in args.cookie.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
        _BM.set_auth(cookies=cookies)
        print(f"{Fore.GREEN}[+] Auth     : {Fore.WHITE}{len(cookies)} cookie yüklendi{Style.RESET_ALL}")

    if args.auth_header:
        _BM.set_auth(headers={"Authorization": args.auth_header})
        print(f"{Fore.GREEN}[+] Auth     : {Fore.WHITE}Authorization header ayarlandı{Style.RESET_ALL}")

    if args.login_url and args.login_user and args.login_pass:
        print(f"{Fore.CYAN}[*] Login deneniyor: {args.login_url}{Style.RESET_ALL}")
        if _BM.login(args.login_url, args.login_user, args.login_pass):
            print(f"{Fore.GREEN}[+] Auth     : {Fore.WHITE}Login başarılı — session cookie alındı{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] Login başarısız — anonim tarama devam ediyor{Style.RESET_ALL}")

    # ── Çalıştırma modu ──
    if args.all:
        run_full_scan(target, results_store, args.timeout, args.quiet, args.wordlist, args.ports,
                      turbo=args.turbo)

    elif args.scan:
        run_scan_profile(args.scan, target, results_store, args.timeout, args.quiet, args.wordlist, args.ports,
                         turbo=args.turbo)

    elif args.modules:
        # Çoklu modül — virgülle ayrılmış
        raw_ids = [s.strip() for s in args.modules.split(",") if s.strip()]
        chosen = []
        for raw in raw_ids:
            try:
                mid = int(raw)
                if mid in MENU:
                    chosen.append(mid)
                else:
                    print(f"{Fore.YELLOW}[!] Geçersiz modül atlandı: {mid}{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.YELLOW}[!] Sayı değil, atlandı: '{raw}'{Style.RESET_ALL}")
        if chosen:
            print(f"{Fore.CYAN}[*] Özel modül listesi: {chosen}{Style.RESET_ALL}\n")
            for mid in chosen:
                run_module(mid, target, results_store, args.timeout, args.quiet, args.wordlist, args.ports)
        else:
            print(f"{Fore.RED}[!] Geçerli modül bulunamadı.{Style.RESET_ALL}")
            sys.exit(1)

    elif args.module is not None:
        if args.module not in MENU:
            print(f"{Fore.RED}[!] Geçersiz modül: {args.module} (1-{max(MENU.keys())}){Style.RESET_ALL}")
            sys.exit(1)
        run_module(args.module, target, results_store, args.timeout, args.quiet, args.wordlist, args.ports)

    else:
        # İnteraktif menü
        while True:
            print_menu()
            try:
                raw = input(
                    f"\n{Fore.CYAN}[?] Seçim (0=çıkış, 98=panel, 99=tümü): {Style.RESET_ALL}"
                ).strip()
                choice = int(raw)
            except ValueError:
                print(f"{Fore.RED}[!] Lütfen bir sayı girin.{Style.RESET_ALL}")
                continue
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[!] Çıkış...{Style.RESET_ALL}")
                break

            if choice == 0:
                break
            elif choice == 98:
                print_panel()
                continue
            elif choice == 99:
                run_full_scan(target, results_store, args.timeout, args.quiet, args.wordlist, args.ports)
            elif choice in MENU:
                run_module(choice, target, results_store, args.timeout, args.quiet, args.wordlist, args.ports)
            else:
                print(f"{Fore.RED}[!] Geçersiz seçim: {choice}{Style.RESET_ALL}")
                continue

            if results_store:
                try:
                    save = input(
                        f"\n{Fore.YELLOW}[?] Ara rapor oluşturulsun mu? (e/h): {Style.RESET_ALL}"
                    ).strip().lower()
                except KeyboardInterrupt:
                    save = "h"
                if save in ("e", "evet"):
                    _generate_reports(target, results_store, output_dir, args.output)

    # Nihai rapor + özet
    if results_store:
        _generate_reports(target, results_store, output_dir, args.output)
        _print_summary(results_store)
        # Baseline comparison
        if args.baseline:
            diff = compare_scans(results_store, args.baseline)
            _print_diff(diff)


def _print_summary(results_store: dict):
    """Tarama sonu özet tablosu."""
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    error_count = 0
    for result in results_store.values():
        if not isinstance(result, dict):
            continue
        if result.get("error"):
            error_count += 1
        for f in result.get("findings", []):
            sev = f.get("severity", "info")
            if sev in sev_counts:
                sev_counts[sev] += 1

    total = sum(sev_counts.values())
    W = 50
    print(f"\n{Fore.CYAN}{'═' * W}")
    print(f"{Fore.YELLOW}{'TARAMA ÖZETİ':^{W}}")
    print(f"{Fore.CYAN}{'═' * W}{Style.RESET_ALL}")
    print(f"  Çalıştırılan Modül  : {len(results_store)}")
    if error_count:
        print(f"  {Fore.RED}Hatalı Modül        : {error_count}{Style.RESET_ALL}")
    print(f"  Toplam Bulgu        : {total}")
    print(f"  {Fore.RED}Kritik  : {sev_counts['critical']:<4}{Style.RESET_ALL}"
          f"  {Fore.RED}Yüksek  : {sev_counts['high']}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Orta    : {sev_counts['medium']:<4}{Style.RESET_ALL}"
          f"  {Fore.CYAN}Düşük   : {sev_counts['low']}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Bilgi   : {sev_counts['info']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═' * W}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Ctrl+C — Tarama iptal edildi.{Style.RESET_ALL}")
        sys.exit(130)
    except Exception as exc:
        print(f"\n{Fore.RED}[✗] Beklenmeyen hata: {type(exc).__name__}: {exc}{Style.RESET_ALL}")
        sys.exit(1)

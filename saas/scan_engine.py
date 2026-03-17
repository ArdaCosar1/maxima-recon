"""
Maxima SaaS — Tarama Motoru
Mevcut cogs modüllerini SaaS API üzerinden çalıştırır.
"""
import sys
import os
import io
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

# Proje kökünü path'e ekle
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from utils.base_module import BaseModule
from saas.config import PLANS, REPORTS_DIR, SCAN_TIMEOUT_SECONDS

# ── Modül kayıt defteri (maxima.py'deki MENU ile aynı) ───────
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

MODULE_REGISTRY = {
    1:  ("Full Reconnaissance Scan",     FullReconScan),
    2:  ("Port Scanner",                  PortScanner),
    3:  ("Vulnerability Scanner",        VulnerabilityScanner),
    4:  ("SQL Injection Scanner",        SQLInjectionScanner),
    5:  ("XSS Scanner",                  XSSScanner),
    6:  ("LFI/RFI Scanner",             LFIRFIScanner),
    7:  ("Command Injection Scanner",    CommandInjectionScanner),
    8:  ("SSRF Scanner",                 SSRFScanner),
    9:  ("Subdomain Enumeration",        SubdomainEnumeration),
    10: ("Directory Enumeration",        DirectoryEnumeration),
    11: ("API Fuzzer",                    APIFuzzer),
    12: ("CORS Scanner",                 CORSScanner),
    13: ("SSL/TLS Analyzer",             SSLTLSAnalyzer),
    14: ("HTTP Header Analyzer",         HTTPHeaderAnalyzer),
    15: ("Technology Detector",          TechnologyDetector),
    16: ("JWT Analyzer",                 JWTAnalyzer),
    17: ("Clickjacking Tester",          ClickjackingTester),
    18: ("Open Redirect Scanner",        OpenRedirectScanner),
    19: ("Subdomain Takeover Check",     SubdomainTakeoverCheck),
    20: ("Rate Limit Tester",            RateLimitTester),
    21: ("WHOIS Lookup",                 WHOISLookup),
    22: ("IP Geolocation",               IPGeolocation),
    23: ("DNS Record Analysis",          DNSRecordAnalysis),
    24: ("Password Strength Checker",    PasswordStrengthChecker),
    25: ("Hash Identifier",              HashIdentifier),
    26: ("WAF Detector",                 WAFDetector),
    27: ("TLS Version Prober",           TLSVersionProber),
    28: ("Redirect Chain Analyzer",      RedirectChainAnalyzer),
    29: ("JS Crawler & Secret Scanner",  JSCrawlerSecretScanner),
    30: ("HTTP/2 Probe",                 HTTP2Probe),
    31: ("Payload Fuzzing Engine",       PayloadFuzzingEngine),
    32: ("Screenshot Capture",           ScreenshotCapture),
    33: ("CVE Template Engine",          CVETemplateEngine),
    34: ("Redirect-Aware Header Analysis", RedirectAwareHeaderAnalysis),
    35: ("Async Port Scanner",           AsyncPortScanner),
    36: ("CVE & Exploit Matcher",        CVEMatcher),
    37: ("Auth & Credential Tester",     AuthTester),
    38: ("OSINT Engine",                 OSINTEngine),
    39: ("Deep SQLi Scanner",            DeepSQLiScanner),
    40: ("SSTI+XXE+IDOR+GraphQL",        NewAttackVectors),
    41: ("Advanced Reporter",            AdvancedReporter),
}

# Tarama profilleri (maxima.py ile senkron)
PROFILE_MODULES = {
    "web":     [1, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 26, 27, 28, 29, 31, 32, 34],
    "osint":   [9, 15, 21, 22, 23, 24, 25, 38],
    "vuln":    [3, 4, 5, 6, 7, 8, 12, 16, 18, 19, 29, 31, 33, 36, 39, 40],
    "network": [2, 13, 22, 23, 26, 27, 30, 35],
    "full":    list(range(1, 35)),
    "full-v2": list(range(1, 42)),
}

# Modül 37 SaaS'ta otomatik çalıştırılmaz (yasal onay gerektirir)
RESTRICTED_MODULES = {37}


def get_module_list() -> List[Dict[str, Any]]:
    """Tüm modüllerin listesini döndür."""
    return [
        {
            "id": mid,
            "name": name,
            "restricted": mid in RESTRICTED_MODULES,
        }
        for mid, (name, _) in MODULE_REGISTRY.items()
    ]


def _run_single_module(
    module_id: int,
    target: str,
    timeout: int,
    results_store: dict,
) -> Optional[Dict]:
    """Tek bir modülü çalıştır."""
    if module_id not in MODULE_REGISTRY:
        return None
    if module_id in RESTRICTED_MODULES:
        return None

    name, ModuleClass = MODULE_REGISTRY[module_id]
    try:
        module = ModuleClass(target)
        module.timeout = timeout
        module._quiet = True  # SaaS'ta konsol çıktısı yok
        result = module.run()
        results_store[name] = result
        return result
    except Exception as e:
        results_store[name] = {"error": f"{type(e).__name__}: {e}", "module": name}
        return None


def execute_scan(
    target: str,
    module_ids: Optional[List[int]],
    profile: Optional[str],
    scan_type: str,
    turbo: bool,
    timeout: int,
    user_plan: str,
) -> Dict[str, Any]:
    """
    Taramayı senkron olarak çalıştır.
    Background thread'den çağrılır.

    Returns:
        {
            "results": {...},
            "total_findings": int,
            "severity_counts": {"critical": ..., "high": ..., ...},
            "risk_score": float,
        }
    """
    plan = PLANS.get(user_plan, PLANS["free"])
    results_store: Dict[str, Any] = {}

    # Çalıştırılacak modül listesini belirle
    if scan_type == "profile" and profile:
        ids_to_run = PROFILE_MODULES.get(profile, [])
    elif scan_type == "full":
        ids_to_run = list(range(1, 42))
    elif module_ids:
        ids_to_run = module_ids
    else:
        ids_to_run = [1]  # Varsayılan: Full Recon

    # Plan kontrolü: izin verilen modüller
    allowed = set(plan["allowed_module_ids"])
    ids_to_run = [mid for mid in ids_to_run if mid in allowed]

    # Modül sayı limiti
    max_mods = plan["max_modules_per_scan"]
    if max_mods > 0:
        ids_to_run = ids_to_run[:max_mods]

    # Restricted modülleri çıkar
    ids_to_run = [mid for mid in ids_to_run if mid not in RESTRICTED_MODULES]

    # Turbo: plan izin veriyorsa paralel çalıştır
    if turbo and plan["turbo"] and len(ids_to_run) > 2:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        max_w = min(len(ids_to_run), 6)
        # Modül 41 sıralı
        parallel = [c for c in ids_to_run if c != 41]
        sequential = [c for c in ids_to_run if c == 41]

        with ThreadPoolExecutor(max_workers=max_w) as pool:
            futures = {
                pool.submit(_run_single_module, mid, target, timeout, results_store): mid
                for mid in parallel
            }
            for f in as_completed(futures):
                pass

        for mid in sequential:
            _run_single_module(mid, target, timeout, results_store)
    else:
        for mid in ids_to_run:
            _run_single_module(mid, target, timeout, results_store)

    # Cache temizle (modüller arası paylaşım bitti)
    BaseModule.clear_cache()

    # Sonuç istatistiklerini hesapla
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total_findings = 0
    for result in results_store.values():
        if not isinstance(result, dict):
            continue
        for f in result.get("findings", []):
            sev = f.get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1
                total_findings += 1

    # Risk skoru
    if total_findings > 0:
        weighted = (severity_counts["critical"] * 10 + severity_counts["high"] * 7
                    + severity_counts["medium"] * 4 + severity_counts["low"] * 1)
        risk_score = round(min(10.0, weighted / max(total_findings, 1)), 1)
    else:
        risk_score = 0.0

    return {
        "results": results_store,
        "total_findings": total_findings,
        "severity_counts": severity_counts,
        "risk_score": risk_score,
    }


def generate_reports(
    target: str,
    results_store: dict,
    scan_id: str,
    user_plan: str,
) -> Dict[str, Optional[str]]:
    """HTML/PDF/JSON raporları oluştur."""
    plan = PLANS.get(user_plan, PLANS["free"])
    output_dir = str(REPORTS_DIR / scan_id)
    os.makedirs(output_dir, exist_ok=True)

    paths = {"html": None, "pdf": None, "json": None}

    try:
        from utils.report_generator import ReportGenerator
        gen = ReportGenerator(target, results_store, output_dir)

        if "html" in plan["report_formats"]:
            paths["html"] = gen.generate_html()
        if "json" in plan["report_formats"]:
            paths["json"] = gen.generate_json()
        if "pdf" in plan["report_formats"]:
            pdf = gen.generate_pdf()
            if pdf:
                paths["pdf"] = pdf
    except Exception:
        pass

    return paths

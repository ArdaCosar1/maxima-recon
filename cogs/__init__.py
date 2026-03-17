# cogs — Maxima tarama modülleri
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

__all__ = [
    "FullReconScan", "PortScanner", "VulnerabilityScanner", "SQLInjectionScanner",
    "XSSScanner", "LFIRFIScanner", "CommandInjectionScanner", "SSRFScanner",
    "SubdomainEnumeration", "DirectoryEnumeration", "APIFuzzer", "CORSScanner",
    "SSLTLSAnalyzer", "HTTPHeaderAnalyzer", "TechnologyDetector", "JWTAnalyzer",
    "ClickjackingTester", "OpenRedirectScanner", "SubdomainTakeoverCheck", "RateLimitTester",
    "WHOISLookup", "IPGeolocation", "DNSRecordAnalysis", "PasswordStrengthChecker",
    "HashIdentifier", "WAFDetector", "TLSVersionProber", "RedirectChainAnalyzer",
    "JSCrawlerSecretScanner", "HTTP2Probe", "PayloadFuzzingEngine", "ScreenshotCapture",
    "CVETemplateEngine", "RedirectAwareHeaderAnalysis", "AsyncPortScanner", "CVEMatcher",
    "AuthTester", "OSINTEngine", "DeepSQLiScanner", "NewAttackVectors", "AdvancedReporter",
    "load_plugins",
]


# ── Plugin / Extension sistemi ──────────────────────────────────
import importlib
import importlib.util
import inspect
import os
import logging

_plugin_logger = logging.getLogger("maxima.plugins")


def load_plugins(plugins_dir: str = None) -> dict:
    """Kullanıcı plugin'lerini otomatik keşfet ve yükle.

    plugins_dir altındaki her .py dosyasından BaseModule alt sınıflarını
    bulur ve {sınıf_adı: sınıf} sözlüğü döndürür.

    Varsayılan dizin: <proje_kökü>/plugins/

    Kullanım:
        from cogs import load_plugins
        user_modules = load_plugins()           # plugins/ dizini
        user_modules = load_plugins("/path/to") # özel dizin
    """
    from utils.base_module import BaseModule

    if plugins_dir is None:
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        plugins_dir = os.path.join(project_root, "plugins")

    discovered = {}

    if not os.path.isdir(plugins_dir):
        return discovered

    for fname in sorted(os.listdir(plugins_dir)):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        fpath = os.path.join(plugins_dir, fname)
        mod_name = f"plugins.{fname[:-3]}"
        try:
            spec = importlib.util.spec_from_file_location(mod_name, fpath)
            if spec is None or spec.loader is None:
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            for attr_name in dir(mod):
                attr = getattr(mod, attr_name)
                if (inspect.isclass(attr)
                        and issubclass(attr, BaseModule)
                        and attr is not BaseModule):
                    discovered[attr_name] = attr
                    _plugin_logger.info("Plugin yüklendi: %s (%s)", attr_name, fpath)
        except Exception as e:
            _plugin_logger.warning("Plugin yükleme hatası: %s — %s", fname, e)

    return discovered

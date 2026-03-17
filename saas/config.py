"""
Maxima SaaS — Konfigürasyon
"""
import os
from pathlib import Path

# ── Proje kök dizini ──────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{PROJECT_ROOT / 'maxima_saas.db'}")

# ── JWT ───────────────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "maxima-saas-dev-secret-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 saat

# ── Stripe Ödeme ──────────────────────────────────────────────
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")          # sk_test_... veya sk_live_...
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "") # pk_test_... veya pk_live_...
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")   # whsec_...

# Stripe Price ID'leri (Stripe Dashboard'dan alınır)
STRIPE_PRICE_IDS = {
    "pro":        os.getenv("STRIPE_PRICE_PRO", ""),        # price_...
    "enterprise": os.getenv("STRIPE_PRICE_ENTERPRISE", ""), # price_...
}

# ── Site Ayarları ─────────────────────────────────────────────
SITE_URL = os.getenv("SITE_URL", "http://localhost:8000")
SITE_NAME = "Maxima Recon"

# ── Abonelik Planları ─────────────────────────────────────────
PLANS = {
    "free": {
        "name": "Free",
        "price_monthly": 0,
        "scans_per_month": 5,
        "max_modules_per_scan": 5,
        "allowed_profiles": ["web"],
        "allowed_module_ids": list(range(1, 21)),  # İlk 20 modül
        "turbo": False,
        "api_access": False,
        "report_formats": ["html"],
    },
    "pro": {
        "name": "Pro",
        "price_monthly": 49,
        "scans_per_month": 100,
        "max_modules_per_scan": 41,
        "allowed_profiles": ["web", "osint", "vuln", "network", "full"],
        "allowed_module_ids": list(range(1, 42)),  # Tüm 41 modül
        "turbo": True,
        "api_access": True,
        "report_formats": ["html", "pdf", "json"],
    },
    "enterprise": {
        "name": "Enterprise",
        "price_monthly": 199,
        "scans_per_month": -1,  # Sınırsız
        "max_modules_per_scan": 41,
        "allowed_profiles": ["web", "osint", "vuln", "network", "full", "full-v2"],
        "allowed_module_ids": list(range(1, 42)),
        "turbo": True,
        "api_access": True,
        "report_formats": ["html", "pdf", "json"],
    },
}

# ── Scan limitleri ────────────────────────────────────────────
MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "3"))
SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", "600"))  # 10 dakika

# ── Rapor çıktı dizini ───────────────────────────────────────
REPORTS_DIR = PROJECT_ROOT / "saas_reports"
REPORTS_DIR.mkdir(exist_ok=True)

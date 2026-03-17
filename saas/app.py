"""
Maxima SaaS — FastAPI Ana Uygulama
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Web dashboard + REST API + Background scan engine

Calistirma:
    cd maxima_v11_final
    pip install -r requirements-saas.txt
    python -m saas.app
"""
import sys
import os
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, Query, Request
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

# Proje kökünü path'e ekle
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from saas.config import (
    PLANS, ACCESS_TOKEN_EXPIRE_MINUTES, MAX_CONCURRENT_SCANS,
    STRIPE_PUBLISHABLE_KEY, SITE_URL, SITE_NAME,
)
from saas.models import init_db, get_db, User, Scan, Payment
from saas.auth import (
    hash_password, verify_password, create_access_token,
    get_current_user, get_admin_user,
)
from saas.schemas import (
    RegisterRequest, LoginRequest, TokenResponse, UserResponse,
    UserUpdateRequest, PlanInfo,
    ScanCreateRequest, ScanResponse, ScanDetailResponse, ScanListResponse,
    DashboardStats,
)
from saas.scan_engine import (
    execute_scan, generate_reports, get_module_list,
    MODULE_REGISTRY, PROFILE_MODULES,
)

# Aktif scan thread sayacı
_active_scans = 0
_active_scans_lock = threading.Lock()


@asynccontextmanager
async def lifespan(app):
    init_db()
    yield


# ── FastAPI app ───────────────────────────────────────────────
app = FastAPI(
    title="Maxima Recon SaaS",
    description="Modular Reconnaissance Framework — SaaS API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ══════════════════════════════════════════════════════════════
#  AUTH ENDPOINTS
# ══════════════════════════════════════════════════════════════

@app.post("/api/auth/register", response_model=TokenResponse, tags=["Auth"])
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(400, "Bu e-posta zaten kayitli")
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(400, "Bu kullanici adi zaten alinmis")

    user = User(
        email=req.email,
        username=req.username,
        password_hash=hash_password(req.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token({"sub": user.id})
    return TokenResponse(
        access_token=token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user),
    )


@app.post("/api/auth/login", response_model=TokenResponse, tags=["Auth"])
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(401, "Gecersiz kullanici adi veya sifre")
    if not user.is_active:
        raise HTTPException(403, "Hesap devre disi")

    token = create_access_token({"sub": user.id})
    return TokenResponse(
        access_token=token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user),
    )


@app.get("/api/auth/me", response_model=UserResponse, tags=["Auth"])
def me(user: User = Depends(get_current_user)):
    return UserResponse.model_validate(user)


@app.put("/api/auth/me", response_model=UserResponse, tags=["Auth"])
def update_me(req: UserUpdateRequest, user: User = Depends(get_current_user),
              db: Session = Depends(get_db)):
    if req.email:
        existing = db.query(User).filter(User.email == req.email, User.id != user.id).first()
        if existing:
            raise HTTPException(400, "Bu e-posta baska bir hesapta kullaniliyor")
        user.email = req.email
    if req.password:
        user.password_hash = hash_password(req.password)
    db.commit()
    db.refresh(user)
    return UserResponse.model_validate(user)


@app.post("/api/auth/regenerate-api-key", response_model=UserResponse, tags=["Auth"])
def regenerate_api_key(user: User = Depends(get_current_user),
                       db: Session = Depends(get_db)):
    from saas.models import generate_api_key
    user.api_key = generate_api_key()
    db.commit()
    db.refresh(user)
    return UserResponse.model_validate(user)


# ══════════════════════════════════════════════════════════════
#  PLAN ENDPOINTS
# ══════════════════════════════════════════════════════════════

@app.get("/api/plans", tags=["Plans"])
def list_plans():
    return {key: PlanInfo(**{k: v for k, v in plan.items() if k != "allowed_module_ids"})
            for key, plan in PLANS.items()}


@app.get("/api/plans/current", response_model=PlanInfo, tags=["Plans"])
def current_plan(user: User = Depends(get_current_user)):
    plan = PLANS.get(user.plan, PLANS["free"])
    return PlanInfo(**{k: v for k, v in plan.items() if k != "allowed_module_ids"})


# ══════════════════════════════════════════════════════════════
#  MODULE ENDPOINTS
# ══════════════════════════════════════════════════════════════

@app.get("/api/modules", tags=["Modules"])
def list_modules(user: User = Depends(get_current_user)):
    plan = PLANS.get(user.plan, PLANS["free"])
    allowed = set(plan["allowed_module_ids"])
    modules = get_module_list()
    for m in modules:
        m["available"] = m["id"] in allowed
    return modules


@app.get("/api/profiles", tags=["Modules"])
def list_profiles(user: User = Depends(get_current_user)):
    plan = PLANS.get(user.plan, PLANS["free"])
    return {
        key: {
            "module_count": len(mods),
            "module_ids": mods,
            "available": key in plan["allowed_profiles"],
        }
        for key, mods in PROFILE_MODULES.items()
    }


# ══════════════════════════════════════════════════════════════
#  SCAN ENDPOINTS
# ══════════════════════════════════════════════════════════════

def _check_scan_quota(user: User, db: Session):
    """Aylık tarama kotasını kontrol et."""
    plan = PLANS.get(user.plan, PLANS["free"])
    limit = plan["scans_per_month"]
    if limit == -1:
        return  # Sınırsız

    # Ay başı reset kontrolü
    now = datetime.utcnow()
    if user.month_reset_date and user.month_reset_date.month != now.month:
        user.scans_this_month = 0
        user.month_reset_date = now
        db.commit()

    if user.scans_this_month >= limit:
        raise HTTPException(
            429,
            f"Aylik tarama kotaniz doldu ({limit}/{limit}). "
            f"Planınızı yükseltin: /api/plans"
        )


@app.post("/api/scans", response_model=ScanResponse, status_code=201, tags=["Scans"])
def create_scan(
    req: ScanCreateRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    plan = PLANS.get(user.plan, PLANS["free"])

    # Kota kontrolü
    _check_scan_quota(user, db)

    # Profil kontrolü
    if req.scan_type == "profile" and req.profile:
        if req.profile not in plan["allowed_profiles"]:
            raise HTTPException(
                403,
                f"'{req.profile}' profili planınızda yok. "
                f"Kullanılabilir: {plan['allowed_profiles']}"
            )

    # Turbo kontrolü
    if req.turbo and not plan["turbo"]:
        raise HTTPException(403, "Turbo mod planınızda yok. Pro veya Enterprise'a yükseltin.")

    # Eşzamanlı tarama kontrolü
    active = db.query(Scan).filter(
        Scan.user_id == user.id,
        Scan.status.in_(["pending", "running"]),
    ).count()
    if active >= MAX_CONCURRENT_SCANS:
        raise HTTPException(429, f"En fazla {MAX_CONCURRENT_SCANS} eşzamanlı tarama yapabilirsiniz")

    # Hedef doğrulama
    target = req.target.strip()
    if " " in target or len(target) > 500:
        raise HTTPException(400, "Gecersiz hedef URL")

    # Scan oluştur
    scan = Scan(
        user_id=user.id,
        target=target,
        scan_type=req.scan_type,
        profile=req.profile,
        module_ids=req.module_ids,
        turbo=req.turbo,
        timeout=req.timeout,
        status="pending",
    )
    db.add(scan)

    # Kota güncelle
    user.scans_this_month += 1
    db.commit()
    db.refresh(scan)

    # Background'da taramayı başlat
    _start_scan_background(scan.id, target, req, user.plan)

    return ScanResponse.model_validate(scan)


def _start_scan_background(scan_id: str, target: str, req: ScanCreateRequest, user_plan: str):
    """Taramayı ayrı bir thread'de başlat."""
    def _worker():
        global _active_scans
        from saas.models import SessionLocal
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return

            with _active_scans_lock:
                _active_scans += 1

            scan.status = "running"
            scan.started_at = datetime.utcnow()
            db.commit()

            # Taramayı çalıştır
            result = execute_scan(
                target=target,
                module_ids=req.module_ids,
                profile=req.profile,
                scan_type=req.scan_type,
                turbo=req.turbo,
                timeout=req.timeout,
                user_plan=user_plan,
            )

            # Sonuçları kaydet
            scan.results = result["results"]
            scan.total_findings = result["total_findings"]
            scan.critical_count = result["severity_counts"]["critical"]
            scan.high_count = result["severity_counts"]["high"]
            scan.medium_count = result["severity_counts"]["medium"]
            scan.low_count = result["severity_counts"]["low"]
            scan.info_count = result["severity_counts"]["info"]
            scan.risk_score = result["risk_score"]
            scan.status = "completed"
            scan.completed_at = datetime.utcnow()

            # Raporları oluştur
            paths = generate_reports(target, result["results"], scan_id, user_plan)
            scan.report_html_path = paths.get("html")
            scan.report_pdf_path = paths.get("pdf")
            scan.report_json_path = paths.get("json")

            db.commit()
        except Exception as e:
            try:
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                if scan:
                    scan.status = "failed"
                    scan.error_message = f"{type(e).__name__}: {e}"
                    scan.completed_at = datetime.utcnow()
                    db.commit()
            except Exception:
                pass
        finally:
            with _active_scans_lock:
                _active_scans -= 1
            db.close()

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()


@app.get("/api/scans", response_model=ScanListResponse, tags=["Scans"])
def list_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status_filter: Optional[str] = Query(None, alias="status"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(Scan).filter(Scan.user_id == user.id)
    if status_filter:
        q = q.filter(Scan.status == status_filter)
    total = q.count()
    scans = q.order_by(Scan.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    return ScanListResponse(
        total=total,
        scans=[ScanResponse.model_validate(s) for s in scans],
    )


@app.get("/api/scans/{scan_id}", response_model=ScanDetailResponse, tags=["Scans"])
def get_scan(scan_id: str, user: User = Depends(get_current_user),
             db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(404, "Tarama bulunamadi")
    return ScanDetailResponse.model_validate(scan)


@app.delete("/api/scans/{scan_id}", tags=["Scans"])
def cancel_scan(scan_id: str, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(404, "Tarama bulunamadi")
    if scan.status in ("pending", "running"):
        scan.status = "cancelled"
        scan.completed_at = datetime.utcnow()
        db.commit()
    return {"message": "Tarama iptal edildi"}


@app.get("/api/scans/{scan_id}/report/{format}", tags=["Scans"])
def download_report(scan_id: str, format: str,
                    user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(404, "Tarama bulunamadi")

    path_map = {
        "html": scan.report_html_path,
        "pdf": scan.report_pdf_path,
        "json": scan.report_json_path,
    }
    path = path_map.get(format)
    if not path or not os.path.exists(path):
        raise HTTPException(404, f"{format.upper()} rapor bulunamadi")

    media_types = {
        "html": "text/html",
        "pdf": "application/pdf",
        "json": "application/json",
    }
    return FileResponse(
        path,
        media_type=media_types.get(format, "application/octet-stream"),
        filename=f"maxima_report_{scan_id[:8]}.{format}",
    )


# ══════════════════════════════════════════════════════════════
#  DASHBOARD STATS
# ══════════════════════════════════════════════════════════════

@app.get("/api/dashboard", response_model=DashboardStats, tags=["Dashboard"])
def dashboard_stats(user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    plan = PLANS.get(user.plan, PLANS["free"])
    total_scans = db.query(Scan).filter(Scan.user_id == user.id).count()
    active_scans = db.query(Scan).filter(
        Scan.user_id == user.id,
        Scan.status.in_(["pending", "running"]),
    ).count()

    # Toplam bulgular
    completed_scans = db.query(Scan).filter(
        Scan.user_id == user.id,
        Scan.status == "completed",
    ).all()

    total_findings = sum(s.total_findings for s in completed_scans)
    critical_findings = sum(s.critical_count for s in completed_scans)
    high_findings = sum(s.high_count for s in completed_scans)

    scans_limit = plan["scans_per_month"]
    scans_remaining = -1 if scans_limit == -1 else max(0, scans_limit - user.scans_this_month)

    recent = db.query(Scan).filter(
        Scan.user_id == user.id,
    ).order_by(Scan.created_at.desc()).limit(10).all()

    return DashboardStats(
        total_scans=total_scans,
        scans_this_month=user.scans_this_month,
        scans_remaining=scans_remaining,
        total_findings=total_findings,
        critical_findings=critical_findings,
        high_findings=high_findings,
        active_scans=active_scans,
        plan=user.plan,
        plan_info=PlanInfo(**{k: v for k, v in plan.items() if k != "allowed_module_ids"}),
        recent_scans=[ScanResponse.model_validate(s) for s in recent],
    )


# ══════════════════════════════════════════════════════════════
#  ADMIN ENDPOINTS
# ══════════════════════════════════════════════════════════════

@app.get("/api/admin/users", tags=["Admin"])
def admin_list_users(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    admin: User = Depends(get_admin_user),
    db: Session = Depends(get_db),
):
    total = db.query(User).count()
    users = db.query(User).offset((page - 1) * per_page).limit(per_page).all()
    return {
        "total": total,
        "users": [UserResponse.model_validate(u) for u in users],
    }


@app.put("/api/admin/users/{user_id}/plan", tags=["Admin"])
def admin_update_plan(user_id: str, plan: str,
                      admin: User = Depends(get_admin_user),
                      db: Session = Depends(get_db)):
    if plan not in PLANS:
        raise HTTPException(400, f"Gecersiz plan: {plan}")
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(404, "Kullanici bulunamadi")
    target_user.plan = plan
    db.commit()
    return {"message": f"Plan guncellendi: {plan}"}


@app.get("/api/admin/stats", tags=["Admin"])
def admin_stats(admin: User = Depends(get_admin_user),
                db: Session = Depends(get_db)):
    total_users = db.query(User).count()
    total_scans = db.query(Scan).count()
    active_scans = db.query(Scan).filter(Scan.status.in_(["pending", "running"])).count()
    return {
        "total_users": total_users,
        "total_scans": total_scans,
        "active_scans": active_scans,
        "concurrent_limit": MAX_CONCURRENT_SCANS,
    }


# ══════════════════════════════════════════════════════════════
#  BILLING / STRIPE ENDPOINTS
# ══════════════════════════════════════════════════════════════

@app.post("/api/billing/checkout", tags=["Billing"])
def create_checkout(
    plan: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Stripe Checkout oturumu olustur — odeme sayfasina yonlendir."""
    if plan not in ("pro", "enterprise"):
        raise HTTPException(400, "Gecersiz plan. Secenekler: pro, enterprise")
    if user.plan == plan:
        raise HTTPException(400, f"Zaten {plan} planindsiniz")

    from saas.billing import create_checkout_session, is_stripe_configured
    if not is_stripe_configured():
        raise HTTPException(503, "Odeme sistemi henuz yapilandirilmamis. Lutfen yoneticiye basvurun.")

    try:
        result = create_checkout_session(user, plan, db)
        return result
    except Exception as e:
        raise HTTPException(500, f"Odeme oturumu olusturulamadi: {e}")


@app.post("/api/billing/portal", tags=["Billing"])
def billing_portal(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Stripe Customer Portal — abonelik yonetimi, fatura gecmisi."""
    from saas.billing import create_billing_portal_session, is_stripe_configured
    if not is_stripe_configured():
        raise HTTPException(503, "Odeme sistemi yapilandirilmamis")

    try:
        result = create_billing_portal_session(user, db)
        return result
    except Exception as e:
        raise HTTPException(500, f"Portal olusturulamadi: {e}")


@app.post("/api/billing/webhook", tags=["Billing"], include_in_schema=False)
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    """Stripe Webhook — odeme event'lerini isle."""
    from saas.billing import handle_webhook_event, is_stripe_configured
    if not is_stripe_configured():
        return JSONResponse({"status": "not configured"}, 200)

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        result = handle_webhook_event(payload, sig_header, db)
        return result
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/billing/history", tags=["Billing"])
def payment_history(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Odeme gecmisi."""
    payments = db.query(Payment).filter(
        Payment.user_id == user.id,
    ).order_by(Payment.created_at.desc()).limit(50).all()

    return [
        {
            "id": p.id,
            "amount": p.amount / 100,  # cent → dolar
            "currency": p.currency,
            "status": p.status,
            "plan": p.plan,
            "description": p.description,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        }
        for p in payments
    ]


# ══════════════════════════════════════════════════════════════
#  WEB PAGES (HTML)
# ══════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def landing_page():
    """Landing page — pazarlama sayfasi."""
    template_path = os.path.join(os.path.dirname(__file__), "templates", "landing.html")
    with open(template_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
@app.get("/register", response_class=HTMLResponse, include_in_schema=False)
@app.get("/scan/{scan_id}", response_class=HTMLResponse, include_in_schema=False)
@app.get("/new-scan", response_class=HTMLResponse, include_in_schema=False)
@app.get("/scans", response_class=HTMLResponse, include_in_schema=False)
@app.get("/settings", response_class=HTMLResponse, include_in_schema=False)
@app.get("/plans", response_class=HTMLResponse, include_in_schema=False)
@app.get("/billing/success", response_class=HTMLResponse, include_in_schema=False)
def serve_spa(request: Request, scan_id: str = None):
    """Tüm frontend route'ları aynı SPA HTML'i döndürür."""
    template_path = os.path.join(os.path.dirname(__file__), "templates", "dashboard.html")
    with open(template_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


# ══════════════════════════════════════════════════════════════
#  ENTRYPOINT
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    print(f"\n  Maxima SaaS baslatiliyor: http://localhost:{port}")
    print(f"  API Docs: http://localhost:{port}/api/docs")
    print(f"  Dashboard: http://localhost:{port}/\n")
    uvicorn.run("saas.app:app", host="0.0.0.0", port=port, reload=True)

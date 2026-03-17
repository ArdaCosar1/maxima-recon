"""
Maxima SaaS — Pydantic Semaları (Request/Response)
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, EmailStr, Field


# ── Auth ──────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=6, max_length=128)


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: "UserResponse"


class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    plan: str
    api_key: str
    is_active: bool
    scans_this_month: int
    created_at: datetime

    model_config = {"from_attributes": True}


class UserUpdateRequest(BaseModel):
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=6, max_length=128)


# ── Plan ──────────────────────────────────────────────────────
class PlanInfo(BaseModel):
    name: str
    price_monthly: int
    scans_per_month: int
    max_modules_per_scan: int
    allowed_profiles: List[str]
    turbo: bool
    api_access: bool
    report_formats: List[str]


# ── Scan ──────────────────────────────────────────────────────
class ScanCreateRequest(BaseModel):
    target: str = Field(min_length=3, max_length=500)
    scan_type: str = Field(default="single")  # single, profile, full
    profile: Optional[str] = None  # web, osint, vuln, network, full, full-v2
    module_ids: Optional[List[int]] = None  # [1, 5, 14]
    turbo: bool = False
    timeout: int = Field(default=8, ge=1, le=60)


class ScanResponse(BaseModel):
    id: str
    target: str
    status: str
    scan_type: str
    profile: Optional[str]
    module_ids: Optional[List[int]]
    turbo: bool
    timeout: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    risk_score: float
    error_message: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanDetailResponse(ScanResponse):
    results: Optional[Dict[str, Any]] = None
    report_html_path: Optional[str] = None
    report_pdf_path: Optional[str] = None
    report_json_path: Optional[str] = None


class ScanListResponse(BaseModel):
    total: int
    scans: List[ScanResponse]


# ── Dashboard ─────────────────────────────────────────────────
class DashboardStats(BaseModel):
    total_scans: int
    scans_this_month: int
    scans_remaining: int  # -1 = sınırsız
    total_findings: int
    critical_findings: int
    high_findings: int
    active_scans: int
    plan: str
    plan_info: PlanInfo
    recent_scans: List[ScanResponse]

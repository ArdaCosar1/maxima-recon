"""
Maxima SaaS — Veritabanı Modelleri (SQLAlchemy)
"""
import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float, DateTime, Text, Boolean,
    ForeignKey, JSON, create_engine, Index
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from saas.config import DATABASE_URL

Base = declarative_base()


def generate_uuid():
    return str(uuid.uuid4())


def generate_api_key():
    return f"mx_{uuid.uuid4().hex}"


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    plan = Column(String(20), nullable=False, default="free")
    api_key = Column(String(64), unique=True, default=generate_api_key, index=True)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    scans_this_month = Column(Integer, default=0)
    month_reset_date = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Stripe
    stripe_customer_id = Column(String(100), nullable=True, index=True)
    stripe_subscription_id = Column(String(100), nullable=True)
    subscription_status = Column(String(20), default="none")
    # none, active, past_due, cancelled, trialing

    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    payments = relationship("Payment", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User {self.username} plan={self.plan}>"


class Payment(Base):
    __tablename__ = "payments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    stripe_payment_intent_id = Column(String(100), nullable=True)
    stripe_invoice_id = Column(String(100), nullable=True)
    amount = Column(Integer, nullable=False)  # cent cinsinden
    currency = Column(String(3), default="usd")
    status = Column(String(20), default="pending")  # pending, succeeded, failed, refunded
    plan = Column(String(20), nullable=False)
    description = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="payments")

    def __repr__(self):
        return f"<Payment {self.id[:8]} ${self.amount/100:.2f} {self.status}>"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    target = Column(String(500), nullable=False)
    status = Column(String(20), nullable=False, default="pending")
    # pending -> running -> completed / failed / cancelled
    scan_type = Column(String(20), nullable=False, default="single")
    # single, profile, full
    profile = Column(String(20), nullable=True)  # web, osint, vuln, network, full, full-v2
    module_ids = Column(JSON, nullable=True)  # [1, 5, 14] veya null (profil/full ise)
    turbo = Column(Boolean, default=False)
    timeout = Column(Integer, default=8)

    # Sonuçlar
    results = Column(JSON, nullable=True)
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)

    report_html_path = Column(String(500), nullable=True)
    report_pdf_path = Column(String(500), nullable=True)
    report_json_path = Column(String(500), nullable=True)

    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="scans")

    __table_args__ = (
        Index("ix_scans_user_status", "user_id", "status"),
    )

    def __repr__(self):
        return f"<Scan {self.id[:8]} target={self.target} status={self.status}>"


# ── Engine & Session ──────────────────────────────────────────
engine = create_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

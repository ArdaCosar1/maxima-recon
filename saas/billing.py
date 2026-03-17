"""
Maxima SaaS — Stripe Odeme Entegrasyonu

Kurulum:
  1. https://dashboard.stripe.com adresinden hesap ac
  2. Products > Create product ile "Pro" ve "Enterprise" planlarini olustur
     - Her biri icin aylik recurring price ekle ($49 ve $199)
  3. .env dosyasina API anahtarlarini ekle:
     STRIPE_SECRET_KEY=sk_test_...
     STRIPE_PUBLISHABLE_KEY=pk_test_...
     STRIPE_WEBHOOK_SECRET=whsec_...
     STRIPE_PRICE_PRO=price_...
     STRIPE_PRICE_ENTERPRISE=price_...
"""
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from saas.config import (
    STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY,
    STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_IDS, SITE_URL,
)
from saas.models import User, Payment

logger = logging.getLogger("maxima.billing")

# Stripe SDK (opsiyonel import)
try:
    import stripe
    stripe.api_key = STRIPE_SECRET_KEY
    HAS_STRIPE = bool(STRIPE_SECRET_KEY)
except ImportError:
    HAS_STRIPE = False
    stripe = None


def is_stripe_configured() -> bool:
    return HAS_STRIPE and bool(STRIPE_SECRET_KEY)


def get_or_create_stripe_customer(user: User, db: Session) -> str:
    """Kullanici icin Stripe Customer olustur veya mevcut ID'yi don."""
    if not is_stripe_configured():
        raise RuntimeError("Stripe yapilandirilmamis")

    if user.stripe_customer_id:
        return user.stripe_customer_id

    customer = stripe.Customer.create(
        email=user.email,
        name=user.username,
        metadata={"user_id": user.id, "platform": "maxima"},
    )
    user.stripe_customer_id = customer.id
    db.commit()
    return customer.id


def create_checkout_session(user: User, plan: str, db: Session) -> dict:
    """
    Stripe Checkout Session olustur.
    Kullaniciyi Stripe odeme sayfasina yonlendir.

    Returns:
        {"checkout_url": "https://checkout.stripe.com/...", "session_id": "cs_..."}
    """
    if not is_stripe_configured():
        raise RuntimeError("Stripe yapilandirilmamis. .env dosyasini kontrol edin.")

    price_id = STRIPE_PRICE_IDS.get(plan)
    if not price_id:
        raise ValueError(f"'{plan}' plani icin Stripe Price ID tanimlanmamis")

    customer_id = get_or_create_stripe_customer(user, db)

    session = stripe.checkout.Session.create(
        customer=customer_id,
        payment_method_types=["card"],
        line_items=[{"price": price_id, "quantity": 1}],
        mode="subscription",
        success_url=f"{SITE_URL}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{SITE_URL}/plans",
        metadata={
            "user_id": user.id,
            "plan": plan,
        },
        subscription_data={
            "metadata": {"user_id": user.id, "plan": plan},
        },
    )

    return {
        "checkout_url": session.url,
        "session_id": session.id,
    }


def create_billing_portal_session(user: User, db: Session) -> dict:
    """
    Stripe Customer Portal — abonelik yonetimi, fatura gecmisi, iptal.
    """
    if not is_stripe_configured():
        raise RuntimeError("Stripe yapilandirilmamis")

    customer_id = get_or_create_stripe_customer(user, db)

    session = stripe.billing_portal.Session.create(
        customer=customer_id,
        return_url=f"{SITE_URL}/dashboard",
    )
    return {"portal_url": session.url}


def handle_webhook_event(payload: bytes, sig_header: str, db: Session) -> dict:
    """
    Stripe Webhook handler.
    Stripe'tan gelen event'leri isleme ve plan guncelleme.

    Desteklenen event'ler:
      - checkout.session.completed → plan yukseltme
      - customer.subscription.updated → plan degisikligi
      - customer.subscription.deleted → plan iptal
      - invoice.payment_succeeded → odeme basarili
      - invoice.payment_failed → odeme basarisiz
    """
    if not is_stripe_configured():
        return {"status": "stripe not configured"}

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except (ValueError, stripe.error.SignatureVerificationError) as e:
        logger.warning("Webhook dogrulama hatasi: %s", e)
        raise ValueError(f"Webhook dogrulama hatasi: {e}")

    event_type = event["type"]
    data = event["data"]["object"]

    logger.info("Stripe webhook: %s", event_type)

    if event_type == "checkout.session.completed":
        _handle_checkout_completed(data, db)

    elif event_type == "customer.subscription.updated":
        _handle_subscription_updated(data, db)

    elif event_type == "customer.subscription.deleted":
        _handle_subscription_deleted(data, db)

    elif event_type == "invoice.payment_succeeded":
        _handle_invoice_paid(data, db)

    elif event_type == "invoice.payment_failed":
        _handle_invoice_failed(data, db)

    return {"status": "ok", "event": event_type}


def _find_user_by_customer(customer_id: str, db: Session) -> Optional[User]:
    return db.query(User).filter(User.stripe_customer_id == customer_id).first()


def _handle_checkout_completed(data: dict, db: Session):
    """Checkout tamamlandi — plani yukselt."""
    user_id = data.get("metadata", {}).get("user_id")
    plan = data.get("metadata", {}).get("plan", "pro")
    subscription_id = data.get("subscription")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        user = _find_user_by_customer(data.get("customer"), db)
    if not user:
        logger.error("Checkout completed ama kullanici bulunamadi: %s", user_id)
        return

    user.plan = plan
    user.stripe_subscription_id = subscription_id
    user.subscription_status = "active"
    user.scans_this_month = 0  # Yeni plan ile reset

    # Odeme kaydı
    payment = Payment(
        user_id=user.id,
        stripe_payment_intent_id=data.get("payment_intent"),
        amount=data.get("amount_total", 0),
        currency=data.get("currency", "usd"),
        status="succeeded",
        plan=plan,
        description=f"Plan yukseltme: {plan}",
    )
    db.add(payment)
    db.commit()
    logger.info("Plan yukseltildi: user=%s plan=%s", user.username, plan)


def _handle_subscription_updated(data: dict, db: Session):
    """Abonelik guncellendi (plan degisikligi, odeme durumu)."""
    customer_id = data.get("customer")
    user = _find_user_by_customer(customer_id, db)
    if not user:
        return

    status = data.get("status")  # active, past_due, canceled, etc.
    user.subscription_status = status
    user.stripe_subscription_id = data.get("id")

    # Plan iptal edildiyse free'ye dusur
    if status in ("canceled", "unpaid"):
        user.plan = "free"
        logger.info("Abonelik iptal — free'ye dusuruldu: %s", user.username)

    # Plan degisikligi (metadata'dan)
    new_plan = data.get("metadata", {}).get("plan")
    if new_plan and status == "active":
        user.plan = new_plan

    db.commit()


def _handle_subscription_deleted(data: dict, db: Session):
    """Abonelik silindi — free plana dusur."""
    customer_id = data.get("customer")
    user = _find_user_by_customer(customer_id, db)
    if not user:
        return

    user.plan = "free"
    user.subscription_status = "cancelled"
    user.stripe_subscription_id = None
    db.commit()
    logger.info("Abonelik silindi — free: %s", user.username)


def _handle_invoice_paid(data: dict, db: Session):
    """Fatura odendi — odeme kaydi olustur."""
    customer_id = data.get("customer")
    user = _find_user_by_customer(customer_id, db)
    if not user:
        return

    payment = Payment(
        user_id=user.id,
        stripe_invoice_id=data.get("id"),
        stripe_payment_intent_id=data.get("payment_intent"),
        amount=data.get("amount_paid", 0),
        currency=data.get("currency", "usd"),
        status="succeeded",
        plan=user.plan,
        description=f"Aylik abonelik: {user.plan}",
    )
    db.add(payment)

    # Aylik kota reset
    user.scans_this_month = 0
    user.month_reset_date = datetime.utcnow()
    db.commit()


def _handle_invoice_failed(data: dict, db: Session):
    """Fatura odemesi basarisiz."""
    customer_id = data.get("customer")
    user = _find_user_by_customer(customer_id, db)
    if not user:
        return

    user.subscription_status = "past_due"

    payment = Payment(
        user_id=user.id,
        stripe_invoice_id=data.get("id"),
        amount=data.get("amount_due", 0),
        currency=data.get("currency", "usd"),
        status="failed",
        plan=user.plan,
        description=f"Odeme basarisiz: {user.plan}",
    )
    db.add(payment)
    db.commit()
    logger.warning("Odeme basarisiz: %s", user.username)

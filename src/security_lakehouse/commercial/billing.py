"""Stripe billing for commercial hosted tenants.

* **Plans ↔ prices.** Each self-serve tier maps to a Stripe Price through
  ``GRC_LAKE_STRIPE_PRICE_<TIER>`` (``STARTER``/``TEAM``/``BUSINESS``);
  Enterprise stays sales-led. Nothing is hardcoded to an account.
* **Hosted surfaces.** Plan purchase uses Stripe Checkout and changes use the
  Stripe customer portal, so card data never touches GRC Lake.
* **Webhooks.** ``Stripe-Signature`` is verified (HMAC-SHA256 over
  ``t.payload``, ``v1`` only, constant-time, 5-minute tolerance, several secrets
  for rotation). Event ids are recorded after successful processing, so
  redeliveries are applied once and failures are retried by Stripe. Stripe
  does not order events, so every handled event re-reads the customer's current
  subscription from the API instead of trusting the event snapshot.
* **Plan state.** The subscription's price sets ``tenants.plan_tier``, which the
  existing usage limits read.
* **Failure states.** ``past_due`` keeps full access for
  ``GRC_LAKE_BILLING_GRACE_DAYS`` (default 7), then the workspace becomes
  read-only; ``canceled``/``unpaid``/``incomplete_expired``/``paused`` are
  read-only immediately. Read-only keeps all data and reads; only writes are
  blocked, and admins can always reach billing to fix payment. Tenants that
  never subscribed (for example invoiced Enterprise contracts) are not locked.

Secrets follow the file-first pattern: ``GRC_LAKE_STRIPE_SECRET_KEY_FILE`` wins
over ``GRC_LAKE_STRIPE_SECRET_KEY``; webhook secrets likewise, comma-separated
while rolling. Stripe is called over HTTPS without the Stripe SDK.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.parse
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from security_lakehouse import netguard
from security_lakehouse.commercial.email import commercial_hosted_enabled
from security_lakehouse.db.models import StripeEvent, Tenant, TenantBilling
from security_lakehouse.runtime_environment import runtime_env

STRIPE_API = "https://api.stripe.com"
SELF_SERVE_TIERS = ("starter", "team", "business")
SIGNATURE_TOLERANCE_SECONDS = 300
DEFAULT_GRACE_DAYS = 7
GRANTING_STATUSES = {"active", "trialing", "past_due", "incomplete"}
READ_ONLY_STATUSES = {"canceled", "unpaid", "incomplete_expired", "paused"}
HANDLED_EVENTS = {
    "checkout.session.completed",
    "customer.subscription.created",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "customer.subscription.paused",
    "customer.subscription.resumed",
    "invoice.paid",
    "invoice.payment_failed",
}


class BillingError(Exception):
    """A billing request that cannot be served; ``status`` is the HTTP status."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


# --- configuration -----------------------------------------------------------


def _secret(name: str) -> str | None:
    file_path = runtime_env().get(f"{name}_FILE", "").strip()
    if file_path:
        try:
            value = Path(file_path).read_text(encoding="utf-8").strip()
        except OSError:
            return None
        return value or None
    return runtime_env().get(name, "").strip() or None


def stripe_secret_key() -> str | None:
    return _secret("GRC_LAKE_STRIPE_SECRET_KEY")


def webhook_secrets() -> list[str]:
    raw = _secret("GRC_LAKE_STRIPE_WEBHOOK_SECRET") or ""
    return [part.strip() for part in raw.split(",") if part.strip()]


def billing_enabled() -> bool:
    return (
        commercial_hosted_enabled()
        and runtime_env().get("GRC_LAKE_BILLING_ENABLED", "").lower() in {"1", "true", "yes"}
        and stripe_secret_key() is not None
    )


def price_for_tier(tier: str) -> str | None:
    tier = str(tier or "").strip().lower()
    if tier not in SELF_SERVE_TIERS:
        return None
    return runtime_env().get(f"GRC_LAKE_STRIPE_PRICE_{tier.upper()}", "").strip() or None


def tier_for_price(price_id: str | None) -> str | None:
    for tier in SELF_SERVE_TIERS:
        if price_id and price_for_tier(tier) == price_id:
            return tier
    return None


def grace_days() -> int:
    try:
        return max(0, int(runtime_env().get("GRC_LAKE_BILLING_GRACE_DAYS", DEFAULT_GRACE_DAYS)))
    except ValueError:
        return DEFAULT_GRACE_DAYS


# --- signature ---------------------------------------------------------------


def verify_stripe_signature(payload: bytes, header: str | None, secrets: list[str], *, now: int | None = None) -> bool:
    """Verify a ``Stripe-Signature`` header against the raw request body."""
    if not header or not secrets:
        return False
    timestamp: str | None = None
    signatures: list[str] = []
    for part in header.split(","):
        key, _, value = part.strip().partition("=")
        if key == "t":
            timestamp = value
        elif key == "v1":
            signatures.append(value)
    if timestamp is None or not timestamp.isdigit() or not signatures:
        return False
    current = int(time.time()) if now is None else now
    if abs(current - int(timestamp)) > SIGNATURE_TOLERANCE_SECONDS:
        return False
    signed = timestamp.encode() + b"." + payload
    for secret in secrets:
        expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
        if any(hmac.compare_digest(expected, candidate) for candidate in signatures):
            return True
    return False


# --- Stripe REST -------------------------------------------------------------


def _stripe_request(method: str, path: str, *, form: list[tuple[str, str]] | None = None) -> dict[str, Any]:
    key = stripe_secret_key()
    if not key:
        raise BillingError(501, "Stripe is not configured")
    headers = {
        "authorization": f"Bearer {key}",
        "accept": "application/json",
        "user-agent": "grc-lake",
    }
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["content-type"] = "application/x-www-form-urlencoded"
        headers["idempotency-key"] = str(uuid.uuid4())
    request = urllib.request.Request(f"{STRIPE_API}{path}", data=data, method=method, headers=headers)
    with netguard.open_public(request, timeout=30, label="stripe api") as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("Stripe returned non-object JSON")
    return payload


def _latest_subscription(customer_id: str) -> dict[str, Any] | None:
    query = urllib.parse.urlencode({"customer": customer_id, "status": "all", "limit": "1"})
    listing = _stripe_request("GET", f"/v1/subscriptions?{query}")
    data = listing.get("data") or []
    return data[0] if data and isinstance(data[0], dict) else None


# --- checkout + portal -------------------------------------------------------


def _public_url(path: str) -> str:
    base = runtime_env().get("GRC_LAKE_PUBLIC_URL", "").strip().rstrip("/")
    if not base.startswith("https://"):
        raise BillingError(500, "GRC_LAKE_PUBLIC_URL must be an https URL for Stripe redirects")
    return f"{base}{path}"


def create_checkout_session(session: Session, *, tenant_id: str, plan: str, email: str) -> str:
    price = price_for_tier(plan)
    if price is None:
        raise BillingError(400, "plan is not available for self-serve checkout")
    form: list[tuple[str, str]] = [
        ("mode", "subscription"),
        ("line_items[0][price]", price),
        ("line_items[0][quantity]", "1"),
        ("client_reference_id", tenant_id),
        ("metadata[tenant_id]", tenant_id),
        ("subscription_data[metadata][tenant_id]", tenant_id),
        ("success_url", _public_url("/console/auth/?billing=success")),
        ("cancel_url", _public_url("/console/auth/?billing=cancel")),
    ]
    billing = session.get(TenantBilling, tenant_id)
    form.append(("customer", billing.stripe_customer_id) if billing else ("customer_email", email))
    return str(_stripe_request("POST", "/v1/checkout/sessions", form=form)["url"])


def create_portal_session(session: Session, *, tenant_id: str) -> str:
    billing = session.get(TenantBilling, tenant_id)
    if billing is None:
        raise BillingError(409, "no Stripe customer is linked to this workspace yet; start a checkout first")
    form = [("customer", billing.stripe_customer_id), ("return_url", _public_url("/console/auth/"))]
    return str(_stripe_request("POST", "/v1/billing_portal/sessions", form=form)["url"])


# --- webhook processing ------------------------------------------------------


def handle_webhook(session: Session, payload: bytes, signature: str | None) -> str:
    """Verify and apply one Stripe event. Returns ``processed``/``duplicate``/``ignored``.

    Raises :class:`BillingError` (400) for an invalid signature or body; any other
    exception means processing failed and the caller should answer 5xx so Stripe
    retries.
    """
    if not verify_stripe_signature(payload, signature, webhook_secrets()):
        raise BillingError(400, "invalid Stripe signature")
    try:
        event = json.loads(payload)
    except ValueError as exc:
        raise BillingError(400, "invalid JSON body") from exc
    event_id, event_type = str(event.get("id") or ""), str(event.get("type") or "")
    if not event_id:
        raise BillingError(400, "event has no id")
    if session.get(StripeEvent, event_id) is not None:
        return "duplicate"
    outcome = "ignored"
    if event_type in HANDLED_EVENTS:
        obj = ((event.get("data") or {}).get("object")) or {}
        outcome = _apply_event(session, event_type, obj if isinstance(obj, dict) else {})
    session.add(StripeEvent(event_id=event_id, event_type=event_type[:128]))
    session.flush()
    return outcome


def _apply_event(session: Session, event_type: str, obj: dict[str, Any]) -> str:
    customer = str(obj.get("customer") or "")
    if event_type == "checkout.session.completed":
        tenant_id = str(obj.get("client_reference_id") or (obj.get("metadata") or {}).get("tenant_id") or "")
        if not customer or session.get(Tenant, tenant_id) is None:
            return "ignored"
        billing = session.get(TenantBilling, tenant_id)
        if billing is None:
            billing = TenantBilling(tenant_id=tenant_id, stripe_customer_id=customer)
            session.add(billing)
        billing.stripe_customer_id = customer
        session.flush()
    else:
        billing = session.scalars(
            select(TenantBilling).where(TenantBilling.stripe_customer_id == customer)
        ).one_or_none()
        if billing is None:
            return "ignored"
    _sync_subscription(session, billing)
    return "processed"


def _sync_subscription(session: Session, billing: TenantBilling) -> None:
    subscription = _latest_subscription(billing.stripe_customer_id)
    now = datetime.now(UTC)
    status = str(subscription.get("status")) if subscription else None
    items = ((subscription or {}).get("items") or {}).get("data") or []
    first = items[0] if items and isinstance(items[0], dict) else {}
    price_id = str((first.get("price") or {}).get("id") or "") or None
    period_end = first.get("current_period_end") or (subscription or {}).get("current_period_end")
    billing.stripe_subscription_id = str(subscription.get("id")) if subscription else None
    billing.subscription_status = status
    billing.price_id = price_id
    billing.current_period_end = datetime.fromtimestamp(int(period_end), UTC) if period_end else None
    billing.cancel_at_period_end = bool((subscription or {}).get("cancel_at_period_end"))
    if status == "past_due":
        billing.past_due_since = billing.past_due_since or now
    else:
        billing.past_due_since = None
    billing.updated_at = now
    tier = tier_for_price(price_id)
    tenant = session.get(Tenant, billing.tenant_id)
    if tenant is not None and tier and status in GRANTING_STATUSES:
        tenant.plan_tier = tier
    session.flush()


# --- access ------------------------------------------------------------------


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def billing_access(session: Session, *, tenant_id: str, now: datetime | None = None) -> str:
    """``active``, ``grace`` (past due, still writable), or ``read_only``."""
    if not billing_enabled():
        return "active"
    billing = session.get(TenantBilling, tenant_id)
    status = billing.subscription_status if billing else None
    if status is None or status in {"active", "trialing"}:
        return "active"
    if status in READ_ONLY_STATUSES:
        return "read_only"
    if status == "past_due" and billing is not None and billing.past_due_since is not None:
        deadline = _aware(billing.past_due_since) + timedelta(days=grace_days())
        return "grace" if (now or datetime.now(UTC)) < deadline else "read_only"
    return "grace"


def billing_view(session: Session, *, tenant_id: str) -> dict[str, Any]:
    billing = session.get(TenantBilling, tenant_id)
    tenant = session.get(Tenant, tenant_id)
    return {
        "plan_tier": tenant.plan_tier if tenant else None,
        "subscription_status": billing.subscription_status if billing else None,
        "access": billing_access(session, tenant_id=tenant_id),
        "customer_linked": billing is not None,
        "current_period_end": billing.current_period_end.isoformat()
        if billing and billing.current_period_end
        else None,
        "cancel_at_period_end": bool(billing.cancel_at_period_end) if billing else False,
        "past_due_since": billing.past_due_since.isoformat() if billing and billing.past_due_since else None,
        "grace_days": grace_days(),
        "self_serve_plans": [tier for tier in SELF_SERVE_TIERS if price_for_tier(tier)],
    }


__all__ = [
    "BillingError",
    "billing_access",
    "billing_enabled",
    "billing_view",
    "create_checkout_session",
    "create_portal_session",
    "handle_webhook",
    "price_for_tier",
    "stripe_secret_key",
    "tier_for_price",
    "verify_stripe_signature",
    "webhook_secrets",
]

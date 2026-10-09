"""Stripe billing for commercial hosted tenants (no live Stripe account needed).

Stripe is faked at the HTTP boundary (``netguard.open_public``) with payloads
shaped like the documented Checkout Session / Subscription / Event objects.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import time
import urllib.parse
from http import HTTPStatus
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")
pytest.importorskip("alembic")

from fastapi.testclient import TestClient  # noqa: E402

from security_lakehouse import netguard  # noqa: E402
from security_lakehouse.commercial.billing import verify_stripe_signature  # noqa: E402
from security_lakehouse.db.base import session_scope  # noqa: E402
from security_lakehouse.db.models import Tenant  # noqa: E402
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user  # noqa: E402
from security_lakehouse.server_app import create_app  # noqa: E402
from test_api_v1 import _seed_lake  # noqa: E402

WHSEC = "whsec_test_secret"
PRICES = {"starter": "price_starter", "team": "price_team", "business": "price_business"}


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _sign(body: bytes, *, secret: str = WHSEC, timestamp: int | None = None) -> str:
    ts = int(time.time()) if timestamp is None else timestamp
    digest = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={ts},v1={digest}"


class _FakeResponse(io.BytesIO):
    status = 200

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class FakeStripe:
    def __init__(self) -> None:
        self.requests: list[Any] = []
        self.subscriptions: dict[str, dict[str, Any]] = {}
        self.fail = False

    def subscription(self, customer: str, *, status: str, price: str, sub_id: str = "sub_1") -> None:
        self.subscriptions[customer] = {
            "id": sub_id,
            "object": "subscription",
            "customer": customer,
            "status": status,
            "cancel_at_period_end": False,
            "items": {"data": [{"price": {"id": price}, "current_period_end": 1893456000}]},
        }

    def __call__(self, request: Any, *, timeout: float, label: str) -> _FakeResponse:
        self.requests.append(request)
        parsed = urllib.parse.urlparse(request.full_url)
        assert parsed.hostname == "api.stripe.com"
        if self.fail:
            raise OSError("stripe unavailable")
        if parsed.path == "/v1/checkout/sessions":
            return _FakeResponse(
                json.dumps({"id": "cs_test_1", "url": "https://checkout.stripe.com/c/pay/cs_test_1"}).encode()
            )
        if parsed.path == "/v1/billing_portal/sessions":
            return _FakeResponse(
                json.dumps({"id": "bps_1", "url": "https://billing.stripe.com/p/session/test"}).encode()
            )
        if parsed.path == "/v1/subscriptions":
            customer = urllib.parse.parse_qs(parsed.query)["customer"][0]
            data = [self.subscriptions[customer]] if customer in self.subscriptions else []
            return _FakeResponse(json.dumps({"object": "list", "data": data, "has_more": False}).encode())
        raise AssertionError(f"unexpected Stripe call {request.get_method()} {request.full_url}")


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GRC_LAKE_COMMERCIAL_HOSTED", "1")
    monkeypatch.setenv("GRC_LAKE_BILLING_ENABLED", "1")
    monkeypatch.setenv("GRC_LAKE_STRIPE_SECRET_KEY", "sk_test_123")
    monkeypatch.setenv("GRC_LAKE_STRIPE_WEBHOOK_SECRET", WHSEC)
    monkeypatch.setenv("GRC_LAKE_PUBLIC_URL", "https://grc-lake.example.com")
    for tier, price in PRICES.items():
        monkeypatch.setenv(f"GRC_LAKE_STRIPE_PRICE_{tier.upper()}", price)
    fake = FakeStripe()
    monkeypatch.setattr(netguard, "open_public", fake)
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    keys: dict[str, str] = {}
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        keys["tenant_id"] = tenant.id
        for role in ("read_only", "contributor", "admin"):
            user = create_user(session, tenant_id=tenant.id, email=f"{role}@acme.test", role=role)
            _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
            keys[role] = token
    return client, keys, app, fake


def _event(event_id: str, event_type: str, obj: dict[str, Any]) -> bytes:
    return json.dumps({"id": event_id, "object": "event", "type": event_type, "data": {"object": obj}}).encode()


def _post_event(client: TestClient, body: bytes, **sign: Any) -> Any:
    return client.post(
        "/api/v1/billing/stripe/webhook",
        content=body,
        headers={"Stripe-Signature": _sign(body, **sign), "Content-Type": "application/json"},
    )


def _checkout_completed(client: TestClient, fake: FakeStripe, tenant_id: str, *, status: str = "active") -> None:
    fake.subscription("cus_1", status=status, price="price_team")
    body = _event(
        "evt_checkout",
        "checkout.session.completed",
        {
            "id": "cs_test_1",
            "object": "checkout.session",
            "client_reference_id": tenant_id,
            "customer": "cus_1",
            "subscription": "sub_1",
        },
    )
    resp = _post_event(client, body)
    assert resp.status_code == HTTPStatus.OK


# --- signature ---------------------------------------------------------------


def test_signature_verification_follows_stripe_rules() -> None:
    body = b'{"id":"evt_1"}'
    now = int(time.time())
    assert verify_stripe_signature(body, _sign(body, timestamp=now), [WHSEC], now=now)
    assert not verify_stripe_signature(body, _sign(body, secret="whsec_other", timestamp=now), [WHSEC], now=now)
    assert not verify_stripe_signature(body + b" ", _sign(body, timestamp=now), [WHSEC], now=now)
    assert not verify_stripe_signature(body, _sign(body, timestamp=now - 301), [WHSEC], now=now)
    rotated = _sign(body, secret="whsec_old", timestamp=now) + "," + _sign(body, timestamp=now).split(",")[1]
    assert verify_stripe_signature(body, rotated, [WHSEC], now=now)
    v0_only = _sign(body, timestamp=now).replace("v1=", "v0=")
    assert not verify_stripe_signature(body, v0_only, [WHSEC], now=now)
    assert not verify_stripe_signature(body, "garbage", [WHSEC], now=now)


# --- checkout + portal -------------------------------------------------------


def test_admin_checkout_creates_a_subscription_session(env) -> None:
    client, keys, _app, fake = env
    resp = client.post("/api/v1/billing/checkout", json={"plan": "team"}, headers=_bearer(keys["contributor"]))
    assert resp.status_code == HTTPStatus.FORBIDDEN
    resp = client.post("/api/v1/billing/checkout", json={"plan": "team"}, headers=_bearer(keys["admin"]))
    assert resp.status_code == HTTPStatus.OK, resp.text
    assert resp.json()["data"]["url"].startswith("https://checkout.stripe.com/")
    request = fake.requests[-1]
    form = urllib.parse.parse_qs(request.data.decode())
    assert form["mode"] == ["subscription"]
    assert form["line_items[0][price]"] == ["price_team"]
    assert form["line_items[0][quantity]"] == ["1"]
    assert form["client_reference_id"] == [keys["tenant_id"]]
    assert form["subscription_data[metadata][tenant_id]"] == [keys["tenant_id"]]
    assert form["success_url"][0].startswith("https://grc-lake.example.com/")
    assert request.get_header("Authorization") == "Bearer sk_test_123"
    assert request.get_header("Idempotency-key")


@pytest.mark.parametrize("plan", ["enterprise", "platinum", ""])
def test_checkout_rejects_plans_without_a_configured_price(env, plan: str) -> None:
    client, keys, _app, _fake = env
    resp = client.post("/api/v1/billing/checkout", json={"plan": plan}, headers=_bearer(keys["admin"]))
    assert resp.status_code == HTTPStatus.BAD_REQUEST


def test_portal_needs_a_linked_customer(env) -> None:
    client, keys, _app, fake = env
    resp = client.post("/api/v1/billing/portal", headers=_bearer(keys["admin"]))
    assert resp.status_code == HTTPStatus.CONFLICT
    _checkout_completed(client, fake, keys["tenant_id"])
    resp = client.post("/api/v1/billing/portal", headers=_bearer(keys["admin"]))
    assert resp.status_code == HTTPStatus.OK
    assert resp.json()["data"]["url"].startswith("https://billing.stripe.com/")
    form = urllib.parse.parse_qs(fake.requests[-1].data.decode())
    assert form["customer"] == ["cus_1"]


# --- webhook -----------------------------------------------------------------


def test_webhook_rejects_bad_signatures(env) -> None:
    client, _keys, _app, _fake = env
    body = _event("evt_x", "customer.subscription.updated", {"customer": "cus_1"})
    resp = client.post(
        "/api/v1/billing/stripe/webhook", content=body, headers={"Stripe-Signature": _sign(body, secret="whsec_wrong")}
    )
    assert resp.status_code == HTTPStatus.BAD_REQUEST


def test_checkout_completion_links_tenant_and_sets_plan_from_price(env) -> None:
    client, keys, app, fake = env
    _checkout_completed(client, fake, keys["tenant_id"])
    status = client.get("/api/v1/billing", headers=_bearer(keys["admin"])).json()["data"]
    assert (status["plan_tier"], status["subscription_status"], status["access"]) == ("team", "active", "active")
    with session_scope(app.state.sessionmaker) as session:
        assert session.get(Tenant, keys["tenant_id"]).plan_tier == "team"


def test_duplicate_events_are_processed_once(env) -> None:
    client, keys, _app, fake = env
    _checkout_completed(client, fake, keys["tenant_id"])
    calls = len(fake.requests)
    body = _event(
        "evt_checkout", "checkout.session.completed", {"client_reference_id": keys["tenant_id"], "customer": "cus_1"}
    )
    resp = _post_event(client, body)
    assert resp.status_code == HTTPStatus.OK
    assert len(fake.requests) == calls


def test_state_comes_from_stripe_not_the_possibly_stale_event_snapshot(env) -> None:
    client, keys, _app, fake = env
    _checkout_completed(client, fake, keys["tenant_id"])
    stale = _event(
        "evt_stale",
        "customer.subscription.updated",
        {"id": "sub_1", "object": "subscription", "customer": "cus_1", "status": "canceled"},
    )
    resp = _post_event(client, stale)
    assert resp.status_code == HTTPStatus.OK
    assert (
        client.get("/api/v1/billing", headers=_bearer(keys["admin"])).json()["data"]["subscription_status"] == "active"
    )


def test_failed_processing_returns_5xx_and_is_retried(env) -> None:
    client, keys, _app, fake = env
    fake.subscription("cus_1", status="active", price="price_team")
    body = _event(
        "evt_retry", "checkout.session.completed", {"client_reference_id": keys["tenant_id"], "customer": "cus_1"}
    )
    fake.fail = True
    resp = _post_event(client, body)
    assert resp.status_code >= 500
    fake.fail = False
    resp = _post_event(client, body)
    assert resp.status_code == HTTPStatus.OK
    assert (
        client.get("/api/v1/billing", headers=_bearer(keys["admin"])).json()["data"]["subscription_status"] == "active"
    )


def test_events_for_unknown_customers_are_acknowledged_and_ignored(env) -> None:
    client, keys, _app, _fake = env
    body = _event("evt_other", "invoice.payment_failed", {"object": "invoice", "customer": "cus_unknown"})
    resp = _post_event(client, body)
    assert resp.status_code == HTTPStatus.OK
    assert client.get("/api/v1/billing", headers=_bearer(keys["admin"])).json()["data"]["subscription_status"] is None


# --- access states -----------------------------------------------------------


def _set_status(client: TestClient, fake: FakeStripe, status: str, event_id: str) -> None:
    fake.subscription("cus_1", status=status, price="price_team")
    body = _event(event_id, "customer.subscription.updated", {"customer": "cus_1"})
    resp = _post_event(client, body)
    assert resp.status_code == HTTPStatus.OK


def test_past_due_is_writable_during_grace_then_read_only(env, monkeypatch: pytest.MonkeyPatch) -> None:
    client, keys, _app, fake = env
    _checkout_completed(client, fake, keys["tenant_id"])
    _set_status(client, fake, "past_due", "evt_pd")
    status = client.get("/api/v1/billing", headers=_bearer(keys["admin"])).json()["data"]
    assert status["access"] == "grace"
    resp = client.post("/api/v1/risks", json={"title": "during grace"}, headers=_bearer(keys["contributor"]))
    assert resp.status_code == HTTPStatus.CREATED

    monkeypatch.setenv("GRC_LAKE_BILLING_GRACE_DAYS", "0")
    assert client.get("/api/v1/billing", headers=_bearer(keys["admin"])).json()["data"]["access"] == "read_only"
    blocked = client.post("/api/v1/risks", json={"title": "blocked"}, headers=_bearer(keys["contributor"]))
    assert blocked.status_code == HTTPStatus.FORBIDDEN
    assert "billing" in blocked.json()["errors"][0]["detail"]
    assert client.get("/api/v1/risks", headers=_bearer(keys["read_only"])).status_code == HTTPStatus.OK
    # An admin can still reach billing to fix payment.
    resp = client.post("/api/v1/billing/portal", headers=_bearer(keys["admin"]))
    assert resp.status_code == HTTPStatus.OK

    _set_status(client, fake, "active", "evt_recovered")
    resp = client.post("/api/v1/risks", json={"title": "recovered"}, headers=_bearer(keys["contributor"]))
    assert resp.status_code == HTTPStatus.CREATED


@pytest.mark.parametrize("status", ["canceled", "unpaid", "incomplete_expired", "paused"])
def test_ended_subscriptions_are_read_only_with_data_kept(env, status: str) -> None:
    client, keys, _app, fake = env
    _checkout_completed(client, fake, keys["tenant_id"])
    _set_status(client, fake, status, f"evt_{status}")
    assert client.get("/api/v1/billing", headers=_bearer(keys["admin"])).json()["data"]["access"] == "read_only"
    resp = client.post("/api/v1/risks", json={"title": "x"}, headers=_bearer(keys["admin"]))
    assert resp.status_code == HTTPStatus.FORBIDDEN
    assert client.get("/api/v1/risks", headers=_bearer(keys["admin"])).status_code == HTTPStatus.OK


def test_tenants_without_a_subscription_are_not_locked(env) -> None:
    client, keys, _app, _fake = env
    assert client.get("/api/v1/billing", headers=_bearer(keys["admin"])).json()["data"]["access"] == "active"
    resp = client.post("/api/v1/risks", json={"title": "x"}, headers=_bearer(keys["contributor"]))
    assert resp.status_code == HTTPStatus.CREATED


def test_disabled_billing_returns_501_and_never_restricts(env, monkeypatch: pytest.MonkeyPatch) -> None:
    client, keys, _app, fake = env
    _checkout_completed(client, fake, keys["tenant_id"])
    _set_status(client, fake, "canceled", "evt_c")
    monkeypatch.setenv("GRC_LAKE_BILLING_ENABLED", "0")
    assert client.get("/api/v1/billing", headers=_bearer(keys["admin"])).status_code == HTTPStatus.NOT_IMPLEMENTED
    resp = client.post("/api/v1/risks", json={"title": "x"}, headers=_bearer(keys["contributor"]))
    assert resp.status_code == HTTPStatus.CREATED


def test_secret_key_prefers_the_file_variant(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from security_lakehouse.commercial.billing import stripe_secret_key

    key_file = tmp_path / "stripe_key"
    key_file.write_text("sk_test_from_file\n")
    monkeypatch.setenv("GRC_LAKE_STRIPE_SECRET_KEY", "sk_test_inline")
    monkeypatch.setenv("GRC_LAKE_STRIPE_SECRET_KEY_FILE", str(key_file))
    assert stripe_secret_key() == "sk_test_from_file"


def test_billing_migration_round_trips(tmp_path: Path) -> None:
    from alembic import command
    from sqlalchemy import inspect

    from security_lakehouse.db import migrate
    from security_lakehouse.db.base import create_engine_for, database_url

    migrate.upgrade(tmp_path)
    assert {"tenant_billing", "stripe_events"} <= set(inspect(create_engine_for(tmp_path)).get_table_names())
    command.downgrade(migrate._config(database_url(tmp_path)), "0017_scim")
    assert "tenant_billing" not in set(inspect(create_engine_for(tmp_path)).get_table_names())
    migrate.upgrade(tmp_path)

"""Commercial P5: pricing, signup, usage limits."""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")
pytest.importorskip("alembic")

from fastapi.testclient import TestClient

from security_lakehouse.commercial.pricing import get_tier, list_pricing_tiers
from security_lakehouse.db.base import session_scope
from security_lakehouse.db.models import Tenant
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
from security_lakehouse.server_app import create_app
from test_api_v1 import _seed_lake


def test_pricing_tiers_structure() -> None:
    tiers = list_pricing_tiers()
    assert len(tiers) == 4
    assert tiers[0]["id"] == "starter"
    assert get_tier("enterprise")["annual_usd"] is None


def test_platform_pricing_public(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    client = TestClient(create_app(tmp_path))
    resp = client.get("/api/v1/platform/pricing")
    assert resp.status_code == HTTPStatus.OK
    data = resp.json()["data"]
    assert data["currency"] == "USD"
    assert data["tiers"] == []


def test_platform_pricing_commercial_hosted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTOPS_COMMERCIAL_HOSTED", "1")
    _seed_lake(tmp_path)
    client = TestClient(create_app(tmp_path))
    resp = client.get("/api/v1/platform/pricing")
    assert resp.status_code == HTTPStatus.OK
    data = resp.json()["data"]
    assert data["currency"] == "USD"
    assert len(data["tiers"]) == 4


def test_signup_requires_flags(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TRUSTOPS_COMMERCIAL_HOSTED", raising=False)
    _seed_lake(tmp_path)
    client = TestClient(create_app(tmp_path))
    body = {
        "org_slug": "newco",
        "org_name": "New Co",
        "admin_email": "admin@newco.test",
        "plan_tier": "starter",
    }
    assert client.post("/api/v1/signup", json=body).status_code == HTTPStatus.NOT_IMPLEMENTED


def test_signup_creates_tenant(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTOPS_COMMERCIAL_HOSTED", "1")
    monkeypatch.setenv("TRUSTOPS_SELF_SERVE_SIGNUP", "1")
    monkeypatch.setenv("TRUSTOPS_ALLOW_OPEN_SIGNUP", "1")
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    body = {
        "org_slug": "newco",
        "org_name": "New Co",
        "admin_email": "admin@newco.test",
        "plan_tier": "team",
    }
    created = client.post("/api/v1/signup", json=body)
    assert created.status_code == HTTPStatus.CREATED
    assert created.json()["data"]["org_slug"] == "newco"
    assert created.json()["data"]["plan_tier"] == "team"
    with session_scope(app.state.sessionmaker) as session:
        tenant = session.query(Tenant).filter_by(slug="newco").one()
        assert tenant.plan_tier == "team"


def test_signup_secret_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTOPS_COMMERCIAL_HOSTED", "1")
    monkeypatch.setenv("TRUSTOPS_SELF_SERVE_SIGNUP", "1")
    monkeypatch.setenv("TRUSTOPS_SIGNUP_SECRET", "test-signup-secret")
    _seed_lake(tmp_path)
    client = TestClient(create_app(tmp_path))
    body = {"org_slug": "gated", "org_name": "Gated", "admin_email": "a@gated.test"}
    assert client.post("/api/v1/signup", json=body).status_code == HTTPStatus.FORBIDDEN
    ok = client.post(
        "/api/v1/signup",
        json=body,
        headers={"X-TrustOps-Signup-Secret": "test-signup-secret"},
    )
    assert ok.status_code == HTTPStatus.CREATED


def test_signup_without_secret_is_closed_unless_explicitly_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TRUSTOPS_COMMERCIAL_HOSTED", "1")
    monkeypatch.setenv("TRUSTOPS_SELF_SERVE_SIGNUP", "1")
    monkeypatch.delenv("TRUSTOPS_SIGNUP_SECRET", raising=False)
    monkeypatch.delenv("TRUSTOPS_ALLOW_OPEN_SIGNUP", raising=False)
    _seed_lake(tmp_path)
    client = TestClient(create_app(tmp_path))
    body = {"org_slug": "closed", "org_name": "Closed", "admin_email": "a@closed.test"}
    assert client.post("/api/v1/signup", json=body).status_code == HTTPStatus.FORBIDDEN
    assert (
        client.post("/api/v1/signup", json=body, headers={"X-TrustOps-Signup-Secret": ""}).status_code
        == HTTPStatus.FORBIDDEN
    )


def test_verify_signup_secret_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    from security_lakehouse.commercial import signup

    monkeypatch.delenv("TRUSTOPS_SIGNUP_SECRET", raising=False)
    monkeypatch.delenv("TRUSTOPS_ALLOW_OPEN_SIGNUP", raising=False)
    assert signup.verify_signup_secret(None) is False
    assert signup.verify_signup_secret("anything") is False
    monkeypatch.setenv("TRUSTOPS_ALLOW_OPEN_SIGNUP", "true")
    assert signup.verify_signup_secret(None) is True
    monkeypatch.setenv("TRUSTOPS_SIGNUP_SECRET", "s3cret")
    assert signup.verify_signup_secret(None) is False  # a configured secret always wins
    assert signup.verify_signup_secret("s3cret") is True
    assert signup.verify_signup_secret("s3cre") is False


def test_signup_disabled_is_501_even_without_a_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTOPS_COMMERCIAL_HOSTED", "1")
    monkeypatch.delenv("TRUSTOPS_SELF_SERVE_SIGNUP", raising=False)
    monkeypatch.delenv("TRUSTOPS_SIGNUP_SECRET", raising=False)
    _seed_lake(tmp_path)
    client = TestClient(create_app(tmp_path))
    body = {"org_slug": "off", "org_name": "Off", "admin_email": "a@off.test"}
    assert client.post("/api/v1/signup", json=body).status_code == HTTPStatus.NOT_IMPLEMENTED


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_usage_summary_for_admin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTOPS_COMMERCIAL_HOSTED", "1")
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="usageco", name="Usage Co")
        tenant.plan_tier = "starter"
        user = create_user(session, tenant_id=tenant.id, email="admin@usageco.test", role="admin")
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
    resp = client.get("/api/v1/platform/usage", headers=_bearer(token))
    assert resp.status_code == HTTPStatus.OK
    data = resp.json()["data"]
    assert data["plan_tier"] == "starter"
    assert data["usage"]["users"] == 1
    assert data["limits"]["max_users"] == 5


def test_usage_summary_is_501_without_commercial_hosting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TRUSTOPS_COMMERCIAL_HOSTED", raising=False)
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="ossco", name="OSS Co")
        user = create_user(session, tenant_id=tenant.id, email="admin@ossco.test", role="admin")
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
    resp = client.get("/api/v1/platform/usage", headers=_bearer(token))
    assert resp.status_code == HTTPStatus.NOT_IMPLEMENTED

"""Policy employee acknowledgment API."""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")
pytest.importorskip("alembic")

from fastapi.testclient import TestClient

from security_lakehouse.audit_readiness import build_audit_readiness
from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
from security_lakehouse.server_app import create_app
from test_agent_decision_authority import human
from test_api_v1 import _seed_lake


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("TRUSTOPS_COOKIE_SIGNING_KEY", "local-test-grc-signing-key")
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    tokens: dict[str, str] = {}
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        for role in ("read_only", "security_admin"):
            user = create_user(session, tenant_id=tenant.id, email=f"{role}@acme.test", role=role)
            _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
            tokens[role] = token
    return client, tokens


def _published_policy(client: TestClient, admin_headers: dict[str, str]) -> str:
    doc = client.post(
        "/api/v1/policies",
        json={
            "template_id": "access-control-policy",
            "variables": {"company_name": "Acme", "policy_owner": "CISO", "effective_date": "2026-01-01"},
        },
        headers=admin_headers,
    ).json()["data"]
    client.post(f"/api/v1/policies/{doc['id']}/publish", headers=admin_headers)
    return doc["id"]


def test_acknowledgment_requires_published_policy(env) -> None:
    client, tokens = env
    admin = _bearer(tokens["security_admin"])
    reader = human(client.app, tokens["read_only"])
    draft = client.post(
        "/api/v1/policies",
        json={
            "template_id": "access-control-policy",
            "variables": {"company_name": "Acme", "policy_owner": "CISO", "effective_date": "2026-01-01"},
        },
        headers=admin,
    ).json()["data"]
    resp = client.post(f"/api/v1/policies/{draft['id']}/acknowledgments", headers=reader, json={})
    assert resp.status_code == HTTPStatus.BAD_REQUEST


def test_record_and_list_acknowledgment(env) -> None:
    client, tokens = env
    admin = _bearer(tokens["security_admin"])
    reader = human(client.app, tokens["read_only"])
    document_id = _published_policy(client, admin)

    created = client.post(f"/api/v1/policies/{document_id}/acknowledgments", headers=reader, json={})
    assert created.status_code == HTTPStatus.CREATED
    assert created.json()["data"]["user_email"] == "read_only@acme.test"

    listed = client.get(f"/api/v1/policies/{document_id}/acknowledgments", headers=reader)
    assert listed.status_code == HTTPStatus.OK
    assert len(listed.json()["data"]) == 1

    summary = client.get("/api/v1/policies/attestation-summary", headers=reader)
    assert summary.json()["data"]["acknowledged"] == 1
    assert summary.json()["data"]["unattested"] == 0


def test_audit_readiness_policy_attestation_gap(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="policy-gap", name="Policy Gap")
        user = create_user(session, tenant_id=tenant.id, email="admin@policy-gap.test", role="security_admin")
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
        session.commit()
    document_id = _published_policy(client, _bearer(token))
    assert document_id
    with app.state.sessionmaker() as session:
        data = build_audit_readiness(lake=tmp_path, session=session, tenant_id=tenant.id)
    assert data["policy_attestation"]["unattested"] == 1
    assert any(gap["id"] == "policy_attestation" for gap in data["gaps"])

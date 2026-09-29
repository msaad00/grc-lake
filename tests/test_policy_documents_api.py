"""Policy document API over the v1 surface."""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")
pytest.importorskip("alembic")

from fastapi.testclient import TestClient  # noqa: E402

from security_lakehouse.db.base import session_scope  # noqa: E402
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user  # noqa: E402
from security_lakehouse.server_app import create_app  # noqa: E402
from test_api_v1 import _seed_lake  # noqa: E402


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def env(tmp_path: Path):
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


def test_list_templates_readable(env) -> None:
    client, tokens = env
    resp = client.get("/api/v1/policy-templates", headers=_bearer(tokens["read_only"]))
    assert resp.status_code == HTTPStatus.OK
    assert any(row["template_id"] == "information-security-policy" for row in resp.json()["data"])


def test_adopt_requires_control_manage(env) -> None:
    client, tokens = env
    body = {
        "template_id": "information-security-policy",
        "variables": {"company_name": "Acme", "policy_owner": "CISO", "effective_date": "2026-01-01"},
    }
    assert client.post("/api/v1/policies", json=body, headers=_bearer(tokens["read_only"])).status_code == (
        HTTPStatus.FORBIDDEN
    )
    created = client.post("/api/v1/policies", json=body, headers=_bearer(tokens["security_admin"]))
    assert created.status_code == HTTPStatus.CREATED
    assert created.json()["data"]["status"] == "draft"
    assert "Acme" in created.json()["data"]["content"]


def test_publish_and_coverage(env) -> None:
    client, tokens = env
    admin = _bearer(tokens["security_admin"])
    doc = client.post(
        "/api/v1/policies",
        json={
            "template_id": "access-control-policy",
            "variables": {"company_name": "Acme", "policy_owner": "CISO", "effective_date": "2026-01-01"},
        },
        headers=admin,
    ).json()["data"]
    published = client.post(f"/api/v1/policies/{doc['id']}/publish", headers=admin)
    assert published.status_code == HTTPStatus.OK
    assert published.json()["data"]["status"] == "published"
    coverage = client.get("/api/v1/policies/coverage", headers=admin).json()["data"]
    row = next(item for item in coverage if item["control_id"] == "SOC2-CC6.1")
    assert row["published"] is True


def test_list_filters_by_status(env) -> None:
    client, tokens = env
    admin = _bearer(tokens["security_admin"])
    variables = {"company_name": "Acme", "policy_owner": "CISO", "effective_date": "2026-01-01"}
    draft = client.post(
        "/api/v1/policies", json={"template_id": "information-security-policy", "variables": variables}, headers=admin
    ).json()["data"]
    published = client.post(
        "/api/v1/policies", json={"template_id": "access-control-policy", "variables": variables}, headers=admin
    ).json()["data"]
    client.post(f"/api/v1/policies/{published['id']}/publish", headers=admin)

    resp = client.get("/api/v1/policies?status=draft", headers=admin)
    assert resp.status_code == HTTPStatus.OK
    assert [row["id"] for row in resp.json()["data"]] == [draft["id"]]
    assert client.get("/api/v1/policies?status=published", headers=admin).json()["data"][0]["id"] == published["id"]

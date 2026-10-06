"""Access-review API: campaigns + items over the v1 surface (RBAC, lifecycle)."""

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
from test_agent_decision_authority import human  # noqa: E402
from test_api_v1 import _seed_lake  # noqa: E402


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
        # security_admin holds control_manage; read_only cannot manage.
        for role in ("read_only", "security_admin"):
            user = create_user(session, tenant_id=tenant.id, email=f"{role}@acme.test", role=role)
            _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
            tokens[role] = token
    return client, tokens


def test_requires_auth(env) -> None:
    client, _tokens = env
    assert client.get("/api/v1/access-reviews").status_code == HTTPStatus.UNAUTHORIZED


def test_create_requires_control_manage(env) -> None:
    client, tokens = env
    body = {"name": "Q3 review", "scope": "okta-identity"}
    # read_only cannot create a campaign.
    assert client.post("/api/v1/access-reviews", json=body, headers=_bearer(tokens["read_only"])).status_code == (
        HTTPStatus.FORBIDDEN
    )
    resp = client.post("/api/v1/access-reviews", json=body, headers=_bearer(tokens["security_admin"]))
    assert resp.status_code == HTTPStatus.CREATED
    assert resp.json()["data"]["status"] == "draft"


def test_full_campaign_lifecycle_over_api(env) -> None:
    client, tokens = env
    admin = human(client.app, tokens["security_admin"])

    campaign = client.post(
        "/api/v1/access-reviews", json={"name": "Q3 review", "scope": "okta-identity"}, headers=admin
    ).json()["data"]
    cid = campaign["id"]

    # Activate it.
    activated = client.patch(f"/api/v1/access-reviews/{cid}", json={"status": "active"}, headers=admin)
    assert activated.json()["data"]["status"] == "active"

    # Add an item.
    item = client.post(
        f"/api/v1/access-reviews/{cid}/items",
        json={"subject_id": "okta:user:1", "subject_name": "Dana", "source": "okta", "access_summary": "admin"},
        headers=admin,
    ).json()["data"]
    assert item["decision"] == "pending"

    # Decide it.
    decided = client.post(
        f"/api/v1/access-reviews/items/{item['id']}/decision",
        json={"decision": "revoked", "note": "left team"},
        headers=admin,
    ).json()["data"]
    assert decided["decision"] == "revoked"
    assert decided["reviewer"] == "security_admin@acme.test"

    # Campaign detail carries progress.
    detail = client.get(f"/api/v1/access-reviews/{cid}", headers=admin).json()["data"]
    assert detail["progress"]["revoked"] == 1
    assert detail["progress"]["total"] == 1

    # Items list is readable + paginated, filterable by decision.
    listed = client.get(f"/api/v1/access-reviews/{cid}/items?decision=revoked", headers=admin).json()
    assert len(listed["data"]) == 1
    assert listed["meta"]["limit"] >= 1


def test_invalid_decision_and_status_return_400(env) -> None:
    client, tokens = env
    admin = human(client.app, tokens["security_admin"])
    cid = client.post("/api/v1/access-reviews", json={"name": "r"}, headers=admin).json()["data"]["id"]
    assert client.patch(f"/api/v1/access-reviews/{cid}", json={"status": "bogus"}, headers=admin).status_code == (
        HTTPStatus.BAD_REQUEST
    )
    item_id = client.post(f"/api/v1/access-reviews/{cid}/items", json={"subject_id": "u1"}, headers=admin).json()[
        "data"
    ]["id"]
    bad = client.post(f"/api/v1/access-reviews/items/{item_id}/decision", json={"decision": "approve"}, headers=admin)
    assert bad.status_code == HTTPStatus.BAD_REQUEST


def test_unknown_campaign_returns_404(env) -> None:
    client, tokens = env
    admin = human(client.app, tokens["security_admin"])
    assert client.get("/api/v1/access-reviews/nope", headers=admin).status_code == HTTPStatus.NOT_FOUND
    assert client.get("/api/v1/access-reviews/nope/items", headers=admin).status_code == HTTPStatus.NOT_FOUND

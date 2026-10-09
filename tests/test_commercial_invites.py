"""Commercial hosted invite API."""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")
pytest.importorskip("alembic")

from fastapi.testclient import TestClient

from security_lakehouse.commercial import invites as invite_services
from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
from security_lakehouse.server_app import create_app
from test_api_v1 import _seed_lake


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("TRUSTOPS_COMMERCIAL_HOSTED", "1")
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    tokens: dict[str, str] = {}
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        for role in ("read_only", "admin"):
            user = create_user(session, tenant_id=tenant.id, email=f"{role}@acme.test", role=role)
            _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
            tokens[role] = token
        tokens["tenant_id"] = tenant.id
    return client, tokens


def test_create_invite_requires_admin(env) -> None:
    client, tokens = env
    body = {"email": "new-hire@acme.test", "role": "contributor"}
    assert client.post("/api/v1/invites", json=body, headers=_bearer(tokens["read_only"])).status_code == (
        HTTPStatus.FORBIDDEN
    )
    created = client.post("/api/v1/invites", json=body, headers=_bearer(tokens["admin"]))
    assert created.status_code == HTTPStatus.CREATED
    assert created.json()["data"]["email"] == "new-hire@acme.test"
    assert created.json()["data"]["status"] == "pending"


def test_list_and_accept_invite(env) -> None:
    client, tokens = env
    admin = _bearer(tokens["admin"])
    created = client.post(
        "/api/v1/invites",
        json={"email": "joiner@acme.test", "role": "read_only"},
        headers=admin,
    )
    assert created.status_code == HTTPStatus.CREATED
    listed = client.get("/api/v1/invites", headers=admin)
    assert listed.status_code == HTTPStatus.OK
    assert any(row["email"] == "joiner@acme.test" for row in listed.json()["data"])

    with session_scope(client.app.state.sessionmaker) as session:
        _row, plaintext = invite_services.create_invite(
            session,
            tenant_id=tokens["tenant_id"],
            email="accept-me@acme.test",
            role="contributor",
            invited_by="admin@acme.test",
        )
        session.commit()

    accepted = client.post("/api/v1/invites/accept", json={"token": plaintext, "display_name": "Accept Me"})
    assert accepted.status_code == HTTPStatus.OK
    assert accepted.json()["data"]["email"] == "accept-me@acme.test"


def test_commercial_disabled_returns_501(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TRUSTOPS_COMMERCIAL_HOSTED", raising=False)
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="solo", name="Solo")
        user = create_user(session, tenant_id=tenant.id, email="admin@solo.test", role="admin")
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
    resp = client.post(
        "/api/v1/invites",
        json={"email": "x@solo.test"},
        headers=_bearer(token),
    )
    assert resp.status_code == HTTPStatus.NOT_IMPLEMENTED


def test_scim_returns_501_when_disabled(env) -> None:
    client, tokens = env
    resp = client.get("/api/v1/scim/v2/Users", headers=_bearer(tokens["admin"]))
    assert resp.status_code == HTTPStatus.NOT_IMPLEMENTED


def test_scim_config_for_admin(env, monkeypatch: pytest.MonkeyPatch) -> None:
    client, tokens = env
    resp = client.get("/api/v1/platform/scim", headers=_bearer(tokens["admin"]))
    assert resp.status_code == HTTPStatus.OK
    assert resp.json()["data"]["enabled"] is False

    monkeypatch.setenv("TRUSTOPS_SCIM_ENABLED", "1")
    resp2 = client.get("/api/v1/platform/scim", headers=_bearer(tokens["admin"]))
    assert resp2.json()["data"]["enabled"] is True


def test_scim_users_when_enabled(env, monkeypatch: pytest.MonkeyPatch) -> None:
    client, tokens = env
    monkeypatch.setenv("TRUSTOPS_SCIM_ENABLED", "1")
    monkeypatch.setenv("TRUSTOPS_SCIM_BEARER_TOKEN", "scim-test-token")
    monkeypatch.setenv("TRUSTOPS_SCIM_TENANT_SLUG", "acme")
    scim_auth = {"Authorization": "Bearer scim-test-token"}

    listed = client.get("/api/v1/scim/v2/Users", headers=scim_auth)
    assert listed.status_code == HTTPStatus.OK
    assert listed.json()["totalResults"] >= 2

    created = client.post(
        "/api/v1/scim/v2/Users",
        headers=scim_auth,
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "scim-new@acme.test",
            "active": True,
            "trustopsRole": "contributor",
        },
    )
    assert created.status_code == HTTPStatus.CREATED
    assert created.json()["userName"] == "scim-new@acme.test"

    user_id = created.json()["id"]
    fetched = client.get(f"/api/v1/scim/v2/Users/{user_id}", headers=scim_auth)
    assert fetched.status_code == HTTPStatus.OK
    assert fetched.json()["userName"] == "scim-new@acme.test"
    assert fetched.json()["active"] is True

    patched = client.patch(
        f"/api/v1/scim/v2/Users/{user_id}",
        headers=scim_auth,
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
    )
    assert patched.status_code == HTTPStatus.OK
    assert patched.json()["active"] is False

    deleted = client.delete(f"/api/v1/scim/v2/Users/{user_id}", headers=scim_auth)
    assert deleted.status_code == HTTPStatus.NO_CONTENT

    # RFC 7644 3.6: a deleted resource is gone from SCIM (the row is kept, deactivated).
    after_delete = client.get(f"/api/v1/scim/v2/Users/{user_id}", headers=scim_auth)
    assert after_delete.status_code == HTTPStatus.NOT_FOUND

    missing = client.get("/api/v1/scim/v2/Users/does-not-exist", headers=scim_auth)
    assert missing.status_code == HTTPStatus.NOT_FOUND


def _pending_invite(client, tenant_id: str, email: str, role: str = "contributor") -> str:
    with session_scope(client.app.state.sessionmaker) as session:
        _row, plaintext = invite_services.create_invite(
            session, tenant_id=tenant_id, email=email, role=role, invited_by="admin@acme.test"
        )
    return plaintext


def test_accept_invite_returns_and_records_the_created_user_id(env) -> None:
    from sqlalchemy import select

    from security_lakehouse.db.models import TenantInvite, User

    client, tokens = env
    plaintext = _pending_invite(client, tokens["tenant_id"], "ids@acme.test")

    accepted = client.post("/api/v1/invites/accept", json={"token": plaintext})

    assert accepted.status_code == HTTPStatus.OK
    user_id = accepted.json()["data"]["user_id"]
    assert user_id
    with session_scope(client.app.state.sessionmaker) as session:
        user = session.scalars(select(User).where(User.email == "ids@acme.test")).one()
        invite = session.scalars(select(TenantInvite).where(TenantInvite.email == "ids@acme.test")).one()
        assert user.id == user_id
        assert invite.accepted_user_id == user_id
        assert invite.status == "accepted"


def test_accept_invite_for_existing_member_is_a_clean_conflict(env) -> None:
    client, tokens = env
    plaintext = _pending_invite(client, tokens["tenant_id"], "admin@acme.test")

    resp = client.post("/api/v1/invites/accept", json={"token": plaintext})

    assert resp.status_code == HTTPStatus.CONFLICT
    assert resp.json()["errors"][0]["code"] == "conflict"


def test_expired_invite_is_persisted_as_expired(env) -> None:
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import select

    from security_lakehouse.db.models import TenantInvite

    client, tokens = env
    plaintext = _pending_invite(client, tokens["tenant_id"], "late@acme.test")
    with session_scope(client.app.state.sessionmaker) as session:
        row = session.scalars(select(TenantInvite).where(TenantInvite.email == "late@acme.test")).one()
        row.expires_at = datetime.now(UTC) - timedelta(hours=1)

    resp = client.post("/api/v1/invites/accept", json={"token": plaintext})

    assert resp.status_code == HTTPStatus.BAD_REQUEST
    assert "expired" in resp.json()["errors"][0]["detail"]
    with session_scope(client.app.state.sessionmaker) as session:
        row = session.scalars(select(TenantInvite).where(TenantInvite.email == "late@acme.test")).one()
        assert row.status == "expired"


@pytest.mark.parametrize("role", ["owner", "superuser", "ADMIN", ""])
def test_create_invite_rejects_unknown_roles(env, role: str) -> None:
    client, tokens = env
    resp = client.post(
        "/api/v1/invites",
        json={"email": "role@acme.test", "role": role},
        headers=_bearer(tokens["admin"]),
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY
    listed = client.get("/api/v1/invites", headers=_bearer(tokens["admin"])).json()["data"]
    assert not any(row["email"] == "role@acme.test" for row in listed)


def test_create_invite_service_rejects_unknown_roles(env) -> None:
    client, tokens = env
    with session_scope(client.app.state.sessionmaker) as session, pytest.raises(ValueError, match="role"):
        invite_services.create_invite(
            session, tenant_id=tokens["tenant_id"], email="svc@acme.test", role="owner", invited_by="a@acme.test"
        )

"""Tenant user directory and API-key browser session tests."""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient

from security_lakehouse.auth.sessions import SESSION_COOKIE
from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
from security_lakehouse.server_app import create_app
from test_api_v1 import _seed_lake


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def env(tmp_path: Path):
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    tokens: dict[str, str] = {}
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme Inc")
        for role in ("admin", "read_only", "contributor"):
            user = create_user(session, tenant_id=tenant.id, email=f"{role}@acme.test", role=role)
            _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
            tokens[role] = token
        tokens["tenant_id"] = tenant.id
    return client, tokens


def test_list_users_requires_admin(env) -> None:
    client, tokens = env
    assert client.get("/api/v1/auth/users", headers=_bearer(tokens["read_only"])).status_code == HTTPStatus.FORBIDDEN
    listed = client.get("/api/v1/auth/users", headers=_bearer(tokens["admin"]))
    assert listed.status_code == HTTPStatus.OK
    emails = {row["email"] for row in listed.json()["data"]}
    assert "admin@acme.test" in emails
    assert "contributor@acme.test" in emails


def test_admin_can_promote_user(env) -> None:
    client, tokens = env
    listed = client.get("/api/v1/auth/users", headers=_bearer(tokens["admin"]))
    contributor = next(row for row in listed.json()["data"] if row["email"] == "contributor@acme.test")
    updated = client.patch(
        f"/api/v1/auth/users/{contributor['id']}",
        json={"role": "security_admin"},
        headers=_bearer(tokens["admin"]),
    )
    assert updated.status_code == HTTPStatus.OK
    assert updated.json()["data"]["role"] == "security_admin"


def test_cannot_demote_last_admin(env) -> None:
    client, tokens = env
    listed = client.get("/api/v1/auth/users", headers=_bearer(tokens["admin"]))
    admin = next(row for row in listed.json()["data"] if row["email"] == "admin@acme.test")
    resp = client.patch(
        f"/api/v1/auth/users/{admin['id']}",
        json={"role": "read_only"},
        headers=_bearer(tokens["admin"]),
    )
    assert resp.status_code == HTTPStatus.BAD_REQUEST


def test_session_from_key_sets_cookie(env) -> None:
    client, tokens = env
    resp = client.post("/api/v1/auth/session-from-key", json={"api_key": tokens["contributor"]})
    assert resp.status_code == HTTPStatus.OK
    assert resp.json()["data"]["email"] == "contributor@acme.test"
    cookie = resp.cookies.get(SESSION_COOKIE)
    assert cookie
    client.cookies.clear()
    client.cookies.set(SESSION_COOKIE, cookie)
    whoami = client.get("/api/v1/auth/whoami")
    assert whoami.status_code == HTTPStatus.OK
    assert whoami.json()["data"]["role"] == "contributor"


def test_session_from_key_rejects_invalid_key(env) -> None:
    client, _tokens = env
    resp = client.post("/api/v1/auth/session-from-key", json={"api_key": "tops_deadbeef"})
    assert resp.status_code == HTTPStatus.UNAUTHORIZED

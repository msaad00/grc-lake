"""Cookie-authenticated mutations require a JSON body and a same-origin Origin."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient

from security_lakehouse.auth.sessions import SESSION_COOKIE, encode_session_cookie
from security_lakehouse.db.repository import (
    create_api_key,
    create_tenant,
    create_user,
    create_user_session,
)
from security_lakehouse.server_app import create_app
from test_api_v1 import _seed_lake

EVIL = "https://evil.example"
BODY = json.dumps({"reason": "csrf"})


@pytest.fixture
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("TRUSTOPS_COOKIE_SIGNING_KEY", "x" * 48)
    monkeypatch.delenv("TRUSTOPS_PUBLIC_URL", raising=False)
    _seed_lake(tmp_path)

    def build():
        app = create_app(tmp_path)
        with app.state.sessionmaker() as session:
            tenant = create_tenant(session, slug="acme", name="Acme")
            user = create_user(session, tenant_id=tenant.id, email="admin@acme.test", role="admin")
            _row, session_token = create_user_session(session, tenant_id=tenant.id, user_id=user.id)
            _key, api_token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
            session.commit()
        client = TestClient(app, base_url="https://testserver")
        client.cookies.set(SESSION_COOKIE, encode_session_cookie(session_token))
        return client, api_token

    return build


def _post(client: TestClient, *, content_type: str = "application/json", origin: str | None = None, **extra):
    headers = {"Content-Type": content_type, **extra}
    if origin is not None:
        headers["Origin"] = origin
    return client.post("/api/v1/snapshots", content=BODY, headers=headers)


def test_cookie_mutation_with_text_plain_is_refused(server) -> None:
    client, _ = server()
    assert _post(client, content_type="text/plain;charset=UTF-8", origin=EVIL).status_code in {403, 415}
    assert _post(client, content_type="text/plain").status_code == 415
    assert client.get("/api/v1/snapshots").json()["data"] == []


def test_cookie_mutation_from_foreign_origin_is_refused(server) -> None:
    client, _ = server()
    for origin in (EVIL, "null", "https://testserver.evil.example"):
        resp = _post(client, origin=origin)
        assert resp.status_code == 403, origin
    assert client.get("/api/v1/snapshots").json()["data"] == []


def test_cookie_mutation_same_origin_json_is_allowed(server) -> None:
    client, _ = server()
    assert _post(client, origin="https://testserver").status_code == 201
    assert _post(client, content_type="application/json; charset=utf-8").status_code == 201


def test_configured_public_url_origin_is_allowed(server, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTOPS_PUBLIC_URL", "https://trust.example.com")
    client, _ = server()
    assert _post(client, origin="https://trust.example.com").status_code == 201
    assert _post(client, origin=EVIL).status_code == 403


def test_bearer_mutation_is_not_subject_to_cookie_checks(server) -> None:
    client, api_token = server()
    client.cookies.clear()
    resp = _post(client, origin=EVIL, Authorization=f"Bearer {api_token}")
    assert resp.status_code == 201


def test_session_from_key_login_csrf_is_refused(server) -> None:
    client, api_token = server()
    client.cookies.clear()
    body = json.dumps({"api_key": api_token})
    plain = client.post(
        "/api/v1/auth/session-from-key", content=body, headers={"Content-Type": "text/plain", "Origin": EVIL}
    )
    assert plain.status_code in {403, 415}
    foreign = client.post(
        "/api/v1/auth/session-from-key", content=body, headers={"Content-Type": "application/json", "Origin": EVIL}
    )
    assert foreign.status_code == 403
    same = client.post(
        "/api/v1/auth/session-from-key",
        content=body,
        headers={"Content-Type": "application/json", "Origin": "https://testserver"},
    )
    assert same.status_code == 200


def test_saml_acs_form_post_is_not_blocked_by_csrf_guard(server) -> None:
    client, _ = server()
    resp = client.post(
        "/api/v1/auth/saml/acs",
        content="SAMLResponse=abc",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://idp.example"},
    )
    assert resp.status_code not in {403, 415}

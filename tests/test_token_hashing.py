"""Token lookup digests are cheap to compute and legacy PBKDF2 rows keep working."""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from alembic import command  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402

from security_lakehouse.auth.sessions import SESSION_COOKIE, encode_session_cookie  # noqa: E402
from security_lakehouse.auth.tokens import hash_token  # noqa: E402
from security_lakehouse.db.migrate import _config  # noqa: E402
from security_lakehouse.db.models import ApiKey, UserSession  # noqa: E402
from security_lakehouse.db.repository import (  # noqa: E402
    create_api_key,
    create_tenant,
    create_user,
    create_user_session,
)
from security_lakehouse.server_app import create_app  # noqa: E402


def _legacy_api_digest(token: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", token.encode(), b"trustops-api-token-v2", 210_000).hex()


def _legacy_session_digest(token: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", token.encode(), b"trustops-session-token-v2", 210_000).hex()


@pytest.fixture
def pbkdf2_calls(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[bytes]]:
    calls: list[bytes] = []
    real = hashlib.pbkdf2_hmac

    def counting(name, password, salt, iterations, dklen=None):
        calls.append(salt)
        return real(name, password, salt, iterations, dklen)

    monkeypatch.setattr(hashlib, "pbkdf2_hmac", counting)
    yield calls


@pytest.fixture
def app_and_user(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("TRUSTOPS_COOKIE_SIGNING_KEY", "x" * 48)
    app = create_app(tmp_path)
    with app.state.sessionmaker() as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        user = create_user(session, tenant_id=tenant.id, email="admin@acme.test", role="admin")
        session.commit()
        ids = (tenant.id, user.id)
    return app, ids


def _token_digest_salts(calls: list[bytes]) -> list[bytes]:
    return [salt for salt in calls if salt.startswith(b"trustops-")]


@pytest.mark.parametrize(
    "bearer",
    ["tops_" + "0" * 48, "garbage", "tops_" + "z" * 48, "x" * 4096],
    ids=["unknown", "garbage", "non-hex", "oversized"],
)
def test_unknown_or_malformed_bearer_is_rejected_without_pbkdf2(app_and_user, pbkdf2_calls, bearer: str) -> None:
    app, _ids = app_and_user
    client = TestClient(app)
    resp = client.get("/api/v1/controls", headers={"Authorization": f"Bearer {bearer}"})
    assert resp.status_code == 401
    assert _token_digest_salts(pbkdf2_calls) == []


def test_new_api_key_authenticates_without_pbkdf2(app_and_user, pbkdf2_calls) -> None:
    app, (tenant_id, user_id) = app_and_user
    with app.state.sessionmaker() as session:
        _key, token = create_api_key(session, tenant_id=tenant_id, user_id=user_id)
        session.commit()
    resp = TestClient(app).get("/api/v1/controls", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert _token_digest_salts(pbkdf2_calls) == []


def test_legacy_api_key_still_authenticates_and_is_upgraded(app_and_user, pbkdf2_calls) -> None:
    app, (tenant_id, user_id) = app_and_user
    with app.state.sessionmaker() as session:
        key, token = create_api_key(session, tenant_id=tenant_id, user_id=user_id)
        key.key_hash = _legacy_api_digest(token)
        key.hash_version = 1
        session.commit()
        key_id = key.id
    pbkdf2_calls.clear()
    client = TestClient(app)
    assert client.get("/api/v1/controls", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    with app.state.sessionmaker() as session:
        row = session.get(ApiKey, key_id)
        assert row.key_hash == hash_token(token)
        assert row.hash_version == 2
    pbkdf2_calls.clear()
    assert client.get("/api/v1/controls", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert _token_digest_salts(pbkdf2_calls) == []


def test_wrong_token_sharing_a_legacy_prefix_does_not_authenticate(app_and_user) -> None:
    app, (tenant_id, user_id) = app_and_user
    with app.state.sessionmaker() as session:
        key, token = create_api_key(session, tenant_id=tenant_id, user_id=user_id)
        key.key_hash = _legacy_api_digest(token)
        key.hash_version = 1
        session.commit()
    forged = token[:12] + secrets.token_hex(24)[: len(token) - 12]
    resp = TestClient(app).get("/api/v1/controls", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401


def test_legacy_session_still_authenticates_and_is_upgraded(app_and_user, pbkdf2_calls) -> None:
    app, (tenant_id, user_id) = app_and_user
    with app.state.sessionmaker() as session:
        row, token = create_user_session(session, tenant_id=tenant_id, user_id=user_id)
        row.token_hash = _legacy_session_digest(token)
        session.commit()
        row_id = row.id
    client = TestClient(app)
    client.cookies.set(SESSION_COOKIE, encode_session_cookie(token))
    pbkdf2_calls.clear()
    assert client.get("/api/v1/controls").status_code == 200
    with app.state.sessionmaker() as session:
        assert session.get(UserSession, row_id).token_hash != _legacy_session_digest(token)
    pbkdf2_calls.clear()
    assert client.get("/api/v1/controls").status_code == 200
    assert _token_digest_salts(pbkdf2_calls) == []


def test_migration_marks_existing_api_keys_as_legacy(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'state.sqlite'}"
    cfg = _config(url)
    command.upgrade(cfg, "0026_authority_provenance")
    engine = create_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO tenants (id, slug, name) VALUES ('t', 'acme', 'Acme')"))
            conn.execute(text("INSERT INTO users (id, tenant_id, email) VALUES ('u', 't', 'u@acme.test')"))
            conn.execute(
                text(
                    "INSERT INTO api_keys (id, tenant_id, user_id, workspace_id, role, status, name, key_hash, prefix)"
                    " VALUES ('k', 't', 'u', 't', 'admin', 'active', '', :h, 'tops_abcdefg')"
                ),
                {"h": "0" * 64},
            )
        command.upgrade(cfg, "head")
        with engine.connect() as conn:
            assert conn.execute(text("SELECT hash_version FROM api_keys WHERE id = 'k'")).scalar_one() == 1
    finally:
        engine.dispose()

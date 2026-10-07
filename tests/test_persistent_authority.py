"""Persistent authority is checked equally at request, worker, and stream boundaries."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from security_lakehouse import api_v1, server_app
from security_lakehouse.auth.dependencies import get_identity
from security_lakehouse.auth.sessions import SESSION_COOKIE, encode_session_cookie
from security_lakehouse.db import repository
from security_lakehouse.db.models import ApiKey, OperationJob, User, UserSession


def _principal(tmp_path, method="oidc"):
    app = server_app.create_app(tmp_path)
    with app.state.sessionmaker.begin() as session:
        tenant = repository.create_tenant(session, slug="authority", name="Authority")
        other = repository.create_tenant(session, slug="other", name="Other")
        user = repository.create_user(session, tenant_id=tenant.id, email="reviewer@example.test", role="admin")
        key, token = repository.create_api_key(session, tenant_id=tenant.id, user_id=user.id)
        key_id, user_id, other_id = key.id, user.id, other.id
        if method == "bearer":
            headers = {"Authorization": f"Bearer {token}"}
            session_id = None
        else:
            login, token = repository.create_user_session(
                session,
                tenant_id=tenant.id,
                user_id=user.id,
                idp=method,
                source_api_key_id=key.id if method == "api_key" else None,
            )
            headers = {"Cookie": f"{SESSION_COOKIE}={encode_session_cookie(token)}"}
            session_id = login.id
    return app, headers, user_id, key_id, session_id, other_id


@pytest.mark.parametrize("method", ["bearer", "oidc", "saml", "api_key"])
def test_http_rejects_cross_tenant_credential_user_binding(tmp_path, method):
    app, headers, user_id, _, _, other_id = _principal(tmp_path, method)
    with app.state.sessionmaker.begin() as session:
        session.get(User, user_id).tenant_id = other_id
    response = TestClient(app).get("/api/v1/auth/whoami", headers=headers)
    assert response.status_code == 401


def test_worker_rejects_changed_source_key_binding(tmp_path, monkeypatch):
    app, headers, user_id, _, login_id, _ = _principal(tmp_path, "api_key")
    client = TestClient(app)
    response = client.post("/api/v1/ingestion/eval", headers={**headers, "Prefer": "respond-async"}, json={})
    assert response.status_code == 202
    with app.state.sessionmaker.begin() as session:
        user = session.get(User, user_id)
        replacement, _ = repository.create_api_key(session, tenant_id=user.tenant_id, user_id=user.id)
        session.get(UserSession, login_id).source_api_key_id = replacement.id
    calls = []
    monkeypatch.setattr(
        api_v1, "handle_post", lambda *a, **kw: (calls.append(1), (200, api_v1.envelope("eval", {})))[1]
    )
    assert app.state.operation_worker.run_once()
    assert calls == []
    with app.state.sessionmaker() as session:
        row = session.get(OperationJob, response.json()["data"]["id"])
        assert row.http_status == 403


@pytest.mark.parametrize("change", ["revoke_session", "expire_session", "disable_user", "role", "revoke_source_key"])
def test_live_stream_stops_when_persistent_authority_changes(tmp_path, monkeypatch, change):
    app, headers, user_id, key_id, login_id, _ = _principal(
        tmp_path, "api_key" if change == "revoke_source_key" else "oidc"
    )
    request = Request(
        {
            "type": "http",
            "app": app,
            "method": "GET",
            "path": "/api/v1/stream",
            "query_string": b"",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        }
    )
    with app.state.sessionmaker() as session:
        identity = get_identity(request, credentials=None, session=session)
    original_stream = server_app.platform_event_stream
    monkeypatch.setattr(server_app, "platform_event_stream", lambda *a, **kw: original_stream(*a, interval=0, **kw))
    count = 0

    def payloads(*args):
        nonlocal count
        count += 1
        return {"posture": {"sensitivity": "restricted", "owner": "private", "sequence": count}}

    monkeypatch.setattr(server_app, "_stream_payloads", payloads)
    endpoint = next(route.endpoint for route in app.routes if getattr(route, "path", None) == "/api/v1/stream")

    async def exercise():
        response = await endpoint(request, identity=identity)
        iterator = response.body_iterator
        assert '"owner": "private"' in await anext(iterator)
        with app.state.sessionmaker.begin() as session:
            if change == "revoke_session":
                session.get(UserSession, login_id).revoked_at = datetime.now(UTC)
            elif change == "expire_session":
                session.get(UserSession, login_id).expires_at = datetime.now(UTC) - timedelta(seconds=1)
            elif change == "disable_user":
                session.get(User, user_id).is_active = False
            elif change == "role":
                session.get(User, user_id).role = "auditor"
            else:
                session.get(ApiKey, key_id).revoked_at = datetime.now(UTC)
        with pytest.raises(StopAsyncIteration):
            await anext(iterator)

    async def connected():
        return False

    monkeypatch.setattr(request, "is_disconnected", connected)
    asyncio.run(exercise())


@pytest.mark.parametrize("method", ["bearer", "oidc", "saml", "api_key"])
def test_resolver_uses_current_grants_without_usage_writes(tmp_path, monkeypatch, method):
    from sqlalchemy import event

    from security_lakehouse.auth.authority import CredentialReference, resolve_authority
    from security_lakehouse.commercial import billing

    monkeypatch.setattr(billing, "billing_enabled", lambda: False)
    app, _, user_id, key_id, login_id, _ = _principal(tmp_path, method)
    with app.state.sessionmaker.begin() as session:
        user = session.get(User, user_id)
        user.role = "read_only"
        tenant_id = user.tenant_id
    reference = CredentialReference(
        user_id,
        tenant_id,
        "api_key" if method == "bearer" else f"session:{method}",
        key_id if method in {"bearer", "api_key"} else None,
        login_id,
    )
    with app.state.sessionmaker() as session:
        statements = []
        engine = session.get_bind()

        def record(connection, cursor, statement, parameters, context, executemany):
            statements.append(statement)

        event.listen(engine, "before_cursor_execute", record)
        try:
            identity = resolve_authority(session, reference)
        finally:
            event.remove(engine, "before_cursor_execute", record)
        assert identity.role == "read_only"
        assert identity.scopes == frozenset({"read"})
        assert identity.is_interactive_session == (method in {"oidc", "saml"})
        assert 2 <= len(statements) <= 3
        assert all(statement.lstrip().upper().startswith("SELECT") for statement in statements)


@pytest.mark.parametrize(
    "change", ["session_id", "user_id", "tenant_id", "idp", "source_key", "expired_key", "revoked_key"]
)
def test_resolver_rejects_changed_credential_provenance(tmp_path, change):
    from dataclasses import replace

    from security_lakehouse.auth.authority import AuthorityError, CredentialReference, resolve_authority

    app, _, user_id, key_id, login_id, other_id = _principal(tmp_path, "api_key")
    with app.state.sessionmaker() as session:
        tenant_id = session.get(User, user_id).tenant_id
    reference = CredentialReference(user_id, tenant_id, "session:api_key", key_id, login_id)
    if change in {"session_id", "user_id"}:
        reference = replace(reference, **{change: "missing"})
    elif change == "tenant_id":
        reference = replace(reference, tenant_id=other_id)
    elif change == "idp":
        reference = replace(reference, auth_method="session:oidc")
    elif change == "source_key":
        reference = replace(reference, api_key_id=None)
    else:
        with app.state.sessionmaker.begin() as session:
            key = session.get(ApiKey, key_id)
            if change == "expired_key":
                key.expires_at = datetime.now(UTC) - timedelta(seconds=1)
            else:
                key.revoked_at = datetime.now(UTC)
    with app.state.sessionmaker() as session, pytest.raises(AuthorityError):
        resolve_authority(session, reference)


def test_resolver_billing_and_auditor_narrowing_cannot_restore_authority(tmp_path, monkeypatch):
    from security_lakehouse.auth.authority import CredentialReference, resolve_authority
    from security_lakehouse.commercial import billing

    app, _, user_id, _, login_id, _ = _principal(tmp_path)
    monkeypatch.setattr(billing, "billing_enabled", lambda: True)
    monkeypatch.setattr(billing, "billing_access", lambda *args, **kwargs: "read_only")
    with app.state.sessionmaker() as session:
        user = session.get(User, user_id)
        reference = CredentialReference(user.id, user.tenant_id, "session:oidc", session_id=login_id)
        identity = resolve_authority(session, reference, auditor_view=True)
        assert identity.role == "auditor"
        assert identity.scopes == frozenset({"read"})
        assert identity.billing_read_only


def test_insecure_reference_requires_validated_mode_and_exact_identity(tmp_path):
    from dataclasses import replace

    from security_lakehouse.auth.authority import (
        INSECURE_IDENTITY,
        AuthorityError,
        CredentialReference,
        resolve_authority,
    )

    app = server_app.create_app(tmp_path, require_auth=False)
    reference = CredentialReference.from_identity(INSECURE_IDENTITY)
    with app.state.sessionmaker() as session:
        with pytest.raises(AuthorityError):
            resolve_authority(session, reference)
        with pytest.raises(AuthorityError):
            resolve_authority(session, replace(reference, tenant_id="someone-else"), allow_insecure=True)
        identity = resolve_authority(session, reference, allow_insecure=True, auditor_view=True)
        assert not identity.is_interactive_session
        assert identity.scopes == frozenset({"read"})


@pytest.mark.parametrize("auditor_transport", ["header", "query"])
def test_stream_refresh_preserves_requested_auditor_view(tmp_path, monkeypatch, auditor_transport):
    app, headers, _, _, _, _ = _principal(tmp_path)
    if auditor_transport == "header":
        headers["X-Trust-Role"] = "auditor"
    request = Request(
        {
            "type": "http",
            "app": app,
            "method": "GET",
            "path": "/api/v1/stream",
            "query_string": b"role=auditor" if auditor_transport == "query" else b"",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        }
    )
    with app.state.sessionmaker() as session:
        identity = get_identity(request, credentials=None, session=session)
    original_stream = server_app.platform_event_stream
    monkeypatch.setattr(server_app, "platform_event_stream", lambda *a, **kw: original_stream(*a, interval=0, **kw))
    count = 0

    def payloads(*args):
        nonlocal count
        count += 1
        return {"posture": {"owner": "private", "sequence": count}}

    monkeypatch.setattr(server_app, "_stream_payloads", payloads)

    async def connected():
        return False

    monkeypatch.setattr(request, "is_disconnected", connected)
    endpoint = next(route.endpoint for route in app.routes if getattr(route, "path", None) == "/api/v1/stream")

    async def exercise():
        response = await endpoint(request, identity=identity)
        iterator = response.body_iterator
        for _ in range(2):
            frame = await anext(iterator)
            assert '"owner": "[redacted]"' in frame
            assert "private" not in frame
        await iterator.aclose()

    asyncio.run(exercise())


def test_stream_checks_authority_after_payload_collection(tmp_path, monkeypatch):
    app, headers, _, _, login_id, _ = _principal(tmp_path)
    request = Request(
        {
            "type": "http",
            "app": app,
            "method": "GET",
            "path": "/api/v1/stream",
            "query_string": b"",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        }
    )
    with app.state.sessionmaker() as session:
        identity = get_identity(request, credentials=None, session=session)

    def payloads(*args):
        with app.state.sessionmaker.begin() as session:
            session.get(UserSession, login_id).revoked_at = datetime.now(UTC)
        return {"posture": {"owner": "must not escape"}}

    monkeypatch.setattr(server_app, "_stream_payloads", payloads)

    async def connected():
        return False

    monkeypatch.setattr(request, "is_disconnected", connected)
    endpoint = next(route.endpoint for route in app.routes if getattr(route, "path", None) == "/api/v1/stream")

    async def exercise():
        response = await endpoint(request, identity=identity)
        with pytest.raises(StopAsyncIteration):
            await anext(response.body_iterator)

    asyncio.run(exercise())


@pytest.mark.parametrize("change", ["revoke", "role"])
def test_stream_revocation_stops_remaining_frames_in_collected_batch(tmp_path, monkeypatch, change):
    app, headers, user_id, _, login_id, _ = _principal(tmp_path)
    request = Request(
        {
            "type": "http",
            "app": app,
            "method": "GET",
            "path": "/api/v1/stream",
            "query_string": b"",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        }
    )
    with app.state.sessionmaker() as session:
        identity = get_identity(request, credentials=None, session=session)
    monkeypatch.setattr(
        server_app,
        "_stream_payloads",
        lambda *args: {
            "posture": {"owner": "first owner"},
            "ai-governance": {"sensitivity": "restricted", "owner": "must not escape"},
        },
    )

    async def connected():
        return False

    monkeypatch.setattr(request, "is_disconnected", connected)
    endpoint = next(route.endpoint for route in app.routes if getattr(route, "path", None) == "/api/v1/stream")

    async def exercise():
        response = await endpoint(request, identity=identity)
        iterator = response.body_iterator
        assert "event: posture" in await anext(iterator)
        with app.state.sessionmaker.begin() as session:
            if change == "revoke":
                session.get(UserSession, login_id).revoked_at = datetime.now(UTC)
            else:
                session.get(User, user_id).role = "auditor"
        with pytest.raises(StopAsyncIteration):
            await anext(iterator)

    asyncio.run(exercise())

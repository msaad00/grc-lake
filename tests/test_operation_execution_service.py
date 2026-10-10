"""Spawned operations use domain services without rebuilding the HTTP app."""

import pytest
from fastapi.testclient import TestClient

from security_lakehouse import api_v1, server_app
from security_lakehouse.db import migrate, repository
from security_lakehouse.services import webhooks as webhook_services


def test_spawned_executor_does_not_bootstrap_http_or_migrate(tmp_path, monkeypatch):
    app = server_app.create_app(tmp_path, require_auth=False)
    response = TestClient(app).post("/api/v1/ingestion/eval", json={}, headers={"Prefer": "respond-async"})
    assert response.status_code == 202
    row = app.state.operation_queue.claim()
    assert row is not None

    def unexpected(*args, **kwargs):
        raise AssertionError("queued execution must not bootstrap HTTP or run migrations")

    monkeypatch.setattr(server_app, "create_app", unexpected)
    monkeypatch.setattr(migrate, "upgrade", unexpected)
    calls = []
    monkeypatch.setattr(
        api_v1, "handle_post", lambda *args, **kwargs: (calls.append(args), (200, api_v1.envelope("eval", {})))[1]
    )
    code, _ = app.state.operation_worker.subprocess_execute(tmp_path, row)
    assert code == 200
    assert len(calls) == 1
    assert calls[0][2] == tmp_path / "tenants" / "insecure"


def test_spawned_executor_retains_tenant_binding_and_snapshot_hook(tmp_path, monkeypatch):
    app = server_app.create_app(tmp_path)
    with app.state.sessionmaker.begin() as session:
        tenant = repository.create_tenant(session, slug="first", name="First")
        user = repository.create_user(session, tenant_id=tenant.id, email="one@example.test", role="admin")
        _, token = repository.create_api_key(session, tenant_id=tenant.id, user_id=user.id)
        repository.create_tenant(session, slug="second", name="Second")
        tenant_id = tenant.id
    response = TestClient(app).post(
        "/api/v1/snapshots", json={}, headers={"Authorization": "Bearer " + token, "Prefer": "respond-async"}
    )
    assert response.status_code == 202
    row = app.state.operation_queue.claim()
    assert row is not None
    calls = []

    def dispatch(session, tenant_id, **kwargs):
        calls.append((tenant_id, kwargs["snapshot_path"]))
        repository.create_user(session, tenant_id=tenant_id, email="hook@example.test", role="read_only")

    def handle(path, payload, lake, *, on_snapshot_written):
        assert lake == tmp_path / "tenants" / tenant_id
        on_snapshot_written(lake / "snapshot.json", {}, [], [])
        return 201, api_v1.envelope("snapshot", {})

    monkeypatch.setattr(webhook_services, "dispatch_snapshot_events", dispatch)
    monkeypatch.setattr(api_v1, "handle_post", handle)
    code, _ = app.state.operation_worker.subprocess_execute(tmp_path, row)
    assert code == 201
    assert calls == [(tenant_id, tmp_path / "tenants" / tenant_id / "snapshot.json")]
    from sqlalchemy import select

    from security_lakehouse.db.models import User

    with app.state.sessionmaker() as session:
        assert session.scalar(select(User).where(User.email == "hook@example.test")) is not None


@pytest.mark.parametrize("environment", ["production", "prod", "staging"])
def test_spawned_executor_preserves_production_no_auth_guard(tmp_path, monkeypatch, environment):
    from security_lakehouse.db.models import OperationJob
    from security_lakehouse.operation_execution import execute_stored_operation

    monkeypatch.setenv("GRC_LAKE_ENV", environment)
    with pytest.raises(RuntimeError, match="Unauthenticated server mode is forbidden"):
        execute_stored_operation(tmp_path, OperationJob(), require_auth=False)


def test_spawned_executor_rechecks_revoked_credentials(tmp_path, monkeypatch):
    from datetime import UTC, datetime

    from security_lakehouse.db.models import ApiKey

    app = server_app.create_app(tmp_path)
    with app.state.sessionmaker.begin() as session:
        tenant = repository.create_tenant(session, slug="first", name="First")
        user = repository.create_user(session, tenant_id=tenant.id, email="one@example.test", role="admin")
        key, token = repository.create_api_key(session, tenant_id=tenant.id, user_id=user.id)
        key_id = key.id
    response = TestClient(app).post(
        "/api/v1/ingestion/eval", json={}, headers={"Authorization": "Bearer " + token, "Prefer": "respond-async"}
    )
    assert response.status_code == 202
    row = app.state.operation_queue.claim()
    with app.state.sessionmaker.begin() as session:
        session.get(ApiKey, key_id).revoked_at = datetime.now(UTC)

    def unexpected(*args, **kwargs):
        raise AssertionError("revoked queued work must not execute")

    monkeypatch.setattr(api_v1, "handle_post", unexpected)
    code, _ = app.state.operation_worker.subprocess_execute(tmp_path, row)
    assert code == 403

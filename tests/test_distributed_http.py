"""Distributed API replicas keep auth, tenant isolation, and publication atomic."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from security_lakehouse.server_app import create_app


def test_two_api_replicas_share_evidence_and_keep_tenants_separate(replicas):
    apps, credentials = replicas
    tenant, headers = credentials[0]
    with apps[0].state.distributed_runtime.write(tenant) as lake:
        (lake / "gold").mkdir()
        (lake / "gold/metrics.json").write_text('{"event_count":7}')
    clients = [TestClient(app) for app in apps]
    for client in clients:
        assert client.get("/api/v1/operations", headers=headers).status_code == 200
        assert client.get("/api/v1/operations").status_code == 401
    assert (
        apps[1].state.distributed_runtime.read_path(tenant).joinpath("gold/metrics.json").read_text()
        == '{"event_count":7}'
    )
    other, _ = credentials[1]
    assert not apps[1].state.distributed_runtime.read_path(other).joinpath("gold/metrics.json").exists()


def test_async_acceptance_is_visible_across_api_replicas(replicas):
    apps, credentials = replicas
    _, headers = credentials[0]
    headers = {**headers, "Prefer": "respond-async", "Idempotency-Key": "distributed-job"}
    first, second = [TestClient(app) for app in apps]
    response = first.post("/api/v1/ingestion/eval", headers=headers, json={})
    assert response.status_code == 202, response.text
    job = response.json()["data"]
    assert second.get(job["status_url"], headers=headers).json()["data"]["id"] == job["id"]
    again = second.post("/api/v1/ingestion/eval", headers=headers, json={})
    assert again.status_code == 202, again.text
    assert again.json()["data"]["id"] == job["id"]


@pytest.mark.parametrize("failure", ["http", "object"])
def test_failed_mutations_rollback_sql_and_files_but_preserve_denial_audit(replicas, monkeypatch, failure):
    import json

    from sqlalchemy import select
    from starlette.responses import JSONResponse

    from security_lakehouse.db.models import DistributedRequestAudit, Tenant
    from security_lakehouse.distributed.context import binding

    apps, credentials = replicas
    app = apps[0]
    tenant, headers = credentials[0]
    original = None
    with app.state.sessionmaker() as session:
        original = session.get(Tenant, tenant).name

    @app.post("/api/v1/ingestion/eval")
    def mutate():
        (binding.get().path / "proof").write_text("must not become visible")
        with app.state.sessionmaker.begin() as session:
            session.get(Tenant, tenant).name = "must roll back"
        return JSONResponse({"ok": True}, status_code=422 if failure == "http" else 200)

    app.router.routes.insert(0, app.router.routes.pop())
    if failure == "object":

        def unavailable(*args, **kwargs):
            raise OSError("test object store outage")

        monkeypatch.setattr(app.state.distributed_runtime.objects, "put", unavailable)
    response = TestClient(app).post("/api/v1/ingestion/eval", headers=headers)
    expected = 422 if failure == "http" else 503
    assert response.status_code == expected
    assert app.state.distributed_runtime.catalog.head(tenant).version == 0
    with app.state.sessionmaker() as session:
        assert session.get(Tenant, tenant).name == original
        events = [
            json.loads(raw)
            for raw in session.scalars(
                select(DistributedRequestAudit.event_json).where(DistributedRequestAudit.tenant_id == tenant)
            )
        ]
    assert len(events) == 1
    assert events[0]["status_code"] == expected and events[0]["decision"] == "deny"
    result = TestClient(apps[1]).get("/api/v1/audit-log?category=request", headers=headers)
    assert result.status_code == 200, result.text
    assert result.json()["data"][0]["payload"]["status_code"] == expected


def test_scheduler_attempt_survives_worker_failure_without_publishing_partial_lake(replicas):
    from datetime import UTC, datetime

    from security_lakehouse.scheduler import _read_state, _write_state

    apps, credentials = replicas
    runtime = apps[0].state.distributed_runtime
    tenant, _ = credentials[0]
    now = datetime.now(UTC)

    def failed_worker():
        with runtime.write(tenant) as lake:
            _write_state(lake, target_kind="workflow", target_id="example", fired_at=now, result="started")
            raise RuntimeError("lost worker")

    with pytest.raises(RuntimeError, match="lost worker"):
        failed_worker()
    assert runtime.catalog.head(tenant).version == 0
    with apps[1].state.distributed_runtime.read(tenant) as lake:
        assert _read_state(lake)["workflow:example"] == now


def test_job_polling_and_cancellation_do_not_download_or_lock_writer_lake(replicas, monkeypatch):
    apps, credentials = replicas
    tenant, headers = credentials[0]
    first, second = [TestClient(app) for app in apps]
    runtime = apps[0].state.distributed_runtime
    with runtime.write(tenant) as lake:
        (lake / "proof").write_text("large evidence stand-in")
    version = runtime.catalog.head(tenant).version

    def no_restore(*args, **kwargs):
        pytest.fail("job metadata must not hydrate evidence")

    for app in apps:
        monkeypatch.setattr(app.state.distributed_runtime.objects, "restore", no_restore)
    response = first.post(
        "/api/v1/ingestion/eval",
        headers={**headers, "Prefer": "respond-async", "Idempotency-Key": "no-hydration"},
        json={},
    )
    assert response.status_code == 202, response.text
    job = response.json()["data"]
    lease = runtime.catalog.acquire(tenant, owner="active-writer")
    try:
        assert second.get(job["status_url"], headers=headers).status_code == 200
        assert second.post(job["status_url"] + "/cancel", headers=headers).status_code == 200
    finally:
        runtime.catalog.release(lease)
    assert runtime.catalog.head(tenant).version == version


def test_reader_replica_rejects_authenticated_and_anonymous_mutations(replicas, tmp_path, monkeypatch):
    apps, credentials = replicas
    _, headers = credentials[0]
    monkeypatch.setenv("GRC_LAKE_REPLICA_ROLE", "reader")
    reader = create_app(tmp_path / "reader")
    try:
        client = TestClient(reader)
        assert client.get("/api/v1/operations", headers=headers).status_code == 200
        assert client.post("/api/v1/ingestion/eval", headers=headers, json={}).status_code == 405
        assert client.post("/api/v1/signup", json={}).status_code == 405
    finally:
        reader.state.sessionmaker.kw["bind"].dispose()


def test_public_share_routing_and_revocation_follow_shared_publication(replicas):
    from security_lakehouse.trust_share import create_share, revoke_share
    from test_api_v1 import _seed_lake

    apps, credentials = replicas
    tenant, _ = credentials[0]
    with apps[0].state.distributed_runtime.write(tenant) as lake:
        _seed_lake(lake)
        share = create_share(lake, role="auditor")
    client = TestClient(apps[1])
    path = "/api/public/trust/" + share["token"]
    response = client.get(path)
    assert response.status_code == 200, response.text
    with apps[0].state.distributed_runtime.write(tenant) as lake:
        revoke_share(lake, share["share_id"])
    assert client.get(path).status_code == 404
    assert client.get("/api/public/trust/not-a-share").status_code == 404


def test_rate_limit_sheds_requests_before_distributed_database_lookup(replicas, monkeypatch):
    from security_lakehouse.distributed.http import DistributedMiddleware

    apps, _ = replicas

    class Deny:
        enabled = True

        def check(self, key):
            return False, 1

    apps[0].state.rate_limiter = Deny()

    def forbidden(*args):
        pytest.fail("rate-limited requests must not reach distributed authentication")

    monkeypatch.setattr(DistributedMiddleware, "_tenant", forbidden)
    assert TestClient(apps[0]).get("/api/v1/operations").status_code == 429


def test_shared_audit_uses_database_time_even_when_a_replica_clock_is_wrong(replicas, monkeypatch):
    import json
    from datetime import datetime

    from sqlalchemy import select

    from security_lakehouse.auth import request_audit
    from security_lakehouse.db.models import DistributedRequestAudit

    apps, credentials = replicas
    tenant, headers = credentials[0]
    monkeypatch.setattr(request_audit, "_now", lambda: "1900-01-01T00:00:00+00:00")
    assert TestClient(apps[0]).get("/api/v1/operations", headers=headers).status_code == 200
    with apps[0].state.sessionmaker() as session:
        row = session.scalar(select(DistributedRequestAudit).where(DistributedRequestAudit.tenant_id == tenant))
        event = json.loads(row.event_json)
        assert not event["occurred_at"].startswith("1900")
        assert datetime.fromisoformat(event["occurred_at"]) == row.occurred_at


def test_cancelled_mutation_rolls_back_and_propagates_cancellation(replicas):
    import asyncio

    from security_lakehouse.db.models import Tenant
    from security_lakehouse.distributed.context import binding
    from security_lakehouse.distributed.http import DistributedMiddleware

    apps, credentials = replicas
    app = apps[0]
    tenant, _ = credentials[0]
    runtime = app.state.distributed_runtime
    with app.state.sessionmaker() as session:
        original = session.get(Tenant, tenant).name

    async def cancelled(scope, receive, send):
        (binding.get().path / "unpublished").write_text("cancelled request")
        with app.state.sessionmaker() as session:
            session.get(Tenant, tenant).name = "must roll back"
            session.commit()
        raise asyncio.CancelledError()

    async def unexpected_message(*args):
        pytest.fail("cancelled mutation must not send an HTTP response")

    middleware = DistributedMiddleware(cancelled, runtime=runtime, factory=app.state.sessionmaker)
    scope = {"type": "http", "method": "POST", "path": "/api/v1/ingestion/eval", "headers": []}
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(middleware._dispatch(tenant, scope, unexpected_message, unexpected_message))
    assert runtime.catalog.head(tenant).version == 0
    with app.state.sessionmaker() as session:
        assert session.get(Tenant, tenant).name == original
    with runtime.write(tenant) as lake:
        assert not (lake / "unpublished").exists()
    assert binding.get() is None


def test_cluster_scheduler_dispatches_each_registered_tenant(replicas, tmp_path):
    from datetime import UTC, datetime

    from security_lakehouse.scheduler import tick

    apps, credentials = replicas
    rows = tick(tmp_path / "scheduler-node", now=datetime(2026, 10, 9, tzinfo=UTC), all_tenants=True)
    assert not any(row.get("result") == "error" for row in rows), rows
    for tenant, _ in credentials:
        assert apps[0].state.distributed_runtime.catalog.head(tenant).version == 1

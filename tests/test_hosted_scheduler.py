"""Hosted root ticks are tenant-scoped operator actions."""

from pathlib import Path

import pytest

from security_lakehouse import scheduler
from security_lakehouse.connector_state import append_config_event
from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_tenant
from security_lakehouse.execution_mode import server_execution, server_tenant_id
from security_lakehouse.server_app import create_app


@pytest.fixture
def hosted(tmp_path, monkeypatch):
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        ids = [create_tenant(session, slug=name, name=name).id for name in ("a", "b", "disabled")]
    for index, tenant in enumerate(ids):
        append_config_event(
            tmp_path / "tenants" / tenant,
            connector_id="github-security",
            state="enabled" if index < 2 else "disabled",
            actor="test",
            options={"sync_schedule": "every 23h"},
        )
    append_config_event(
        tmp_path / "tenants" / "unregistered",
        connector_id="github-security",
        state="enabled",
        actor="test",
        options={"sync_schedule": "every 23h"},
    )
    monkeypatch.setenv("TRUSTOPS_COMMERCIAL_HOSTED", "1")
    monkeypatch.setattr(scheduler, "_scheduled_lake_eval", lambda lake: None)
    return ids


def test_hosted_root_fires_registered_enabled_tenant_sources(tmp_path, hosted):
    calls = []

    def collect(lake, **kwargs):
        calls.append((Path(lake), server_tenant_id()))
        return {"result": "ok", "evidence_count": 1}

    rows = scheduler.tick(tmp_path, connector_runner=collect)
    assert calls == [(tmp_path / "tenants" / tenant, tenant) for tenant in hosted[:2]]
    assert {row["tenant_id"] for row in rows} == set(hosted[:2])
    assert scheduler.tick(tmp_path, connector_runner=collect) == []
    assert not (tmp_path / "gold" / scheduler.STATE_FILE).exists()
    assert server_tenant_id() is None


def test_one_tenant_lock_does_not_block_the_other(tmp_path, hosted):
    import fcntl

    lake = tmp_path / "tenants" / hosted[0]
    path = scheduler._lock_path(lake)
    with path.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        rows = scheduler.tick(tmp_path, connector_runner=lambda *a, **kw: {"result": "ok"})
    by_tenant = {row["tenant_id"]: row for row in rows}
    assert by_tenant[hosted[0]]["skipped_locked"] is True
    assert by_tenant[hosted[1]]["result"] == "ok"


def test_authenticated_tenant_tick_never_enumerates_siblings(tmp_path, hosted):
    tenant = hosted[0]
    calls = []
    with server_execution(tenant):
        scheduler.tick(
            tmp_path / "tenants" / tenant,
            connector_runner=lambda lake, **kw: calls.append(server_tenant_id()) or {"result": "ok"},
        )
    assert calls == [tenant]
    assert not (tmp_path / "tenants" / hosted[1] / "gold" / scheduler.STATE_FILE).exists()


def test_tenant_symlink_cannot_schedule_another_tenants_lake(tmp_path, hosted):
    lake = tmp_path / "tenants" / hosted[0]
    lake.rename(lake.with_name(hosted[0] + "-saved"))
    lake.symlink_to(tmp_path / "tenants" / hosted[1], target_is_directory=True)
    calls = []
    rows = scheduler.tick(
        tmp_path, connector_runner=lambda lake, **kw: calls.append(server_tenant_id()) or {"result": "ok"}
    )
    assert calls == [hosted[1]]
    rejected = next(row for row in rows if row["tenant_id"] == hosted[0])
    assert rejected["result"] == "error"
    assert rejected["error"] == "internal error"


def test_scheduled_snapshots_bind_webhook_identity_and_commit(tmp_path, hosted, monkeypatch):
    from sqlalchemy import select

    from security_lakehouse.db.base import create_engine_for, session_factory
    from security_lakehouse.db.models import User
    from security_lakehouse.db.repository import create_user
    from security_lakehouse.services import webhooks
    from security_lakehouse.workflows import save_workflow
    from test_api_v1 import _seed_lake

    calls = []

    def dispatch(session, tenant_id, **kwargs):
        assert server_tenant_id() == tenant_id
        assert kwargs["snapshot_path"].is_relative_to(tmp_path / "tenants" / tenant_id)
        calls.append(tenant_id)
        create_user(session, tenant_id=tenant_id, email="hook@example.test")

    monkeypatch.setattr(webhooks, "dispatch_snapshot_events", dispatch)
    for tenant in hosted[:2]:
        lake = tmp_path / "tenants" / tenant
        _seed_lake(lake)
        save_workflow(
            lake,
            workflow_id="scheduled",
            name="scheduled",
            description="",
            nodes=[
                {"id": "cron", "node_type": "trigger.cron", "params": {"schedule": "every 23h"}},
                {"id": "snapshot", "node_type": "action.snapshot", "params": {}},
            ],
            edges=[{"source": "cron", "target": "snapshot"}],
        )
    rows = scheduler.tick(tmp_path, connector_runner=lambda *a, **kw: {"result": "ok"})
    assert [row["result"] for row in rows if row["target_kind"] == "workflow"] == ["ok", "ok"]
    assert calls == hosted[:2]
    engine = create_engine_for(tmp_path)
    try:
        with session_factory(engine)() as session:
            assert set(session.scalars(select(User.tenant_id))) == set(hosted[:2])
    finally:
        engine.dispose()


def test_single_registered_tenant_keeps_flat_lake_binding(tmp_path, monkeypatch):
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="flat", name="flat").id
    (tmp_path / "silver").mkdir()
    append_config_event(
        tmp_path, connector_id="github-security", state="enabled", actor="test", options={"sync_schedule": "every 23h"}
    )
    monkeypatch.setenv("TRUSTOPS_COMMERCIAL_HOSTED", "1")
    monkeypatch.setattr(scheduler, "_scheduled_lake_eval", lambda lake: None)
    calls = []
    rows = scheduler.tick(
        tmp_path, connector_runner=lambda lake, **kw: calls.append((lake, server_tenant_id())) or {"result": "ok"}
    )
    assert calls == [(tmp_path, tenant)]
    assert rows[0]["tenant_id"] == tenant


def test_local_root_tick_does_not_enumerate_hosted_tenants(tmp_path, hosted, monkeypatch):
    monkeypatch.delenv("TRUSTOPS_COMMERCIAL_HOSTED")
    assert scheduler.tick(tmp_path, connector_runner=lambda *a, **kw: pytest.fail("local mode crossed tenants")) == []


def test_cli_all_tenants_is_explicit_without_hosted_environment(tmp_path, hosted, monkeypatch, capsys):
    import json

    from security_lakehouse.cli import main

    monkeypatch.delenv("TRUSTOPS_COMMERCIAL_HOSTED")
    calls = []
    monkeypatch.setattr(
        scheduler, "run_connector_sync", lambda lake, **kw: calls.append(server_tenant_id()) or {"result": "ok"}
    )
    assert main(["scheduler", "tick", "--lake", str(tmp_path), "--all-tenants"]) == 0
    assert calls == hosted[:2]
    assert {row["tenant_id"] for row in json.loads(capsys.readouterr().out)["results"]} == set(hosted[:2])


def test_scoped_context_cannot_request_all_tenants(tmp_path, hosted):
    with server_execution(hosted[0]), pytest.raises(ValueError, match="unbound lake root"):
        scheduler.tick(tmp_path, all_tenants=True)


def test_http_tick_ignores_cross_tenant_body_override(tmp_path, hosted, monkeypatch):
    from fastapi.testclient import TestClient

    from security_lakehouse.db.repository import create_api_key, create_user

    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        user = create_user(session, tenant_id=hosted[0], email="admin@example.test", role="security_admin")
        _, token = create_api_key(session, tenant_id=hosted[0], user_id=user.id)
    calls = []
    monkeypatch.setattr(
        scheduler, "run_connector_sync", lambda lake, **kw: calls.append(server_tenant_id()) or {"result": "ok"}
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scheduler/tick", json={"all_tenants": True}, headers={"Authorization": f"Bearer {token}"}
        )
    assert response.status_code == 201
    assert calls == [hosted[0]]
    assert not (tmp_path / "tenants" / hosted[1] / "gold" / scheduler.STATE_FILE).exists()


def test_tenant_failure_does_not_abort_other_tenants(tmp_path, hosted, monkeypatch):
    original = scheduler._tick_locked

    def fail_first(lake, **kwargs):
        if server_tenant_id() == hosted[0]:
            raise RuntimeError("private tenant error")
        return original(lake, **kwargs)

    monkeypatch.setattr(scheduler, "_tick_locked", fail_first)
    rows = scheduler.tick(tmp_path, connector_runner=lambda *a, **kw: {"result": "ok"})
    by_tenant = {row["tenant_id"]: row for row in rows}
    assert by_tenant[hosted[0]]["error"] == "internal error"
    assert by_tenant[hosted[1]]["result"] == "ok"

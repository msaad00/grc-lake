"""Metrics & insights tests: data model, derived aggregates, and API RBAC."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient

from security_lakehouse.db import metrics as metrics_db
from security_lakehouse.db import remediation
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
        tenant = create_tenant(session, slug="acme", name="Acme")
        for role in ("read_only", "contributor", "security_admin"):
            user = create_user(session, tenant_id=tenant.id, email=f"{role}@acme.test", role=role)
            _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
            tokens[role] = token
    return app, client, tokens


# ---------------------------------------------------------------------------
# Data-model layer
# ---------------------------------------------------------------------------


def test_capture_and_list(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        point = metrics_db.capture_metric_point(session, tenant_id=tenant.id, lake_dir=tmp_path)
        session.commit()

        rows = metrics_db.list_metric_points(session, tenant_id=tenant.id)
        assert len(rows) == 1
        assert rows[0].id == point.id
        assert isinstance(rows[0].posture_score, float)
        assert 0.0 <= rows[0].control_pass_rate <= 1.0
        assert rows[0].open_violations >= 0


def test_list_ordering_ascending(tmp_path: Path) -> None:
    """list_metric_points returns rows oldest-first for chart rendering."""
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        t1 = datetime(2026, 1, 1, tzinfo=UTC)
        t2 = datetime(2026, 1, 2, tzinfo=UTC)
        metrics_db.capture_metric_point(session, tenant_id=tenant.id, lake_dir=tmp_path, now=t1)
        metrics_db.capture_metric_point(session, tenant_id=tenant.id, lake_dir=tmp_path, now=t2)
        session.commit()

        rows = metrics_db.list_metric_points(session, tenant_id=tenant.id)
        assert len(rows) == 2
        assert rows[0].captured_at <= rows[1].captured_at


def test_list_limit(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        for i in range(5):
            t = datetime(2026, 1, i + 1, tzinfo=UTC)
            metrics_db.capture_metric_point(session, tenant_id=tenant.id, lake_dir=tmp_path, now=t)
        session.commit()

        rows = metrics_db.list_metric_points(session, tenant_id=tenant.id, limit=3)
        assert len(rows) == 3


def test_metric_point_to_dict_shape(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        point = metrics_db.capture_metric_point(session, tenant_id=tenant.id, lake_dir=tmp_path)
        d = metrics_db.metric_point_to_dict(point)
    expected_keys = {
        "id",
        "tenant_id",
        "captured_at",
        "posture_score",
        "control_pass_rate",
        "open_violations",
        "critical_violations",
        "stale_controls",
        "evidence_fresh_pct",
        "remediation_open",
        "remediation_overdue",
    }
    assert expected_keys == set(d.keys())


# ---------------------------------------------------------------------------
# Remediation insights math
# ---------------------------------------------------------------------------


def test_remediation_insights_empty(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        ins = metrics_db.remediation_insights(session, tenant_id=tenant.id)
    assert ins["open"] == 0
    assert ins["overdue"] == 0
    assert ins["mttr_hours"] is None
    assert ins["sla_attainment_pct"] is None


def test_remediation_insights_mttr(tmp_path: Path) -> None:
    """MTTR is the average time from created_at to resolved_at in hours."""
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    now = datetime.now(UTC)
    created = now - timedelta(hours=4)
    resolved = now - timedelta(hours=2)  # 2 h resolution time

    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        task = remediation.create_task(session, tenant_id=tenant.id, title="fix-me", created_by="test")
        # Manually set timestamps to get deterministic MTTR
        task.created_at = created
        task.resolved_at = resolved
        task.status = "resolved"
        session.flush()
        session.commit()

        ins = metrics_db.remediation_insights(session, tenant_id=tenant.id, now=now)

    assert ins["resolved_count"] == 1
    assert ins["open"] == 0
    assert ins["mttr_hours"] is not None
    assert abs(ins["mttr_hours"] - 2.0) < 0.1


def test_remediation_insights_sla_attainment(tmp_path: Path) -> None:
    """SLA attainment: tasks resolved on/before due_at count as on-time."""
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    base = datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)

    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")

        # on-time: resolved before due_at
        t1 = remediation.create_task(session, tenant_id=tenant.id, title="t1")
        t1.created_at = base
        t1.due_at = base + timedelta(hours=8)
        t1.resolved_at = base + timedelta(hours=6)
        t1.status = "resolved"

        # late: resolved after due_at
        t2 = remediation.create_task(session, tenant_id=tenant.id, title="t2")
        t2.created_at = base
        t2.due_at = base + timedelta(hours=8)
        t2.resolved_at = base + timedelta(hours=10)
        t2.status = "resolved"

        session.flush()
        session.commit()

        ins = metrics_db.remediation_insights(session, tenant_id=tenant.id)

    assert ins["sla_eligible_count"] == 2
    # 1 of 2 on time = 50 %
    assert ins["sla_attainment_pct"] == 50.0


def test_remediation_insights_overdue(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    past = datetime.now(UTC) - timedelta(days=1)
    future = datetime.now(UTC) + timedelta(days=1)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        remediation.create_task(session, tenant_id=tenant.id, title="late", due_at=past)
        remediation.create_task(session, tenant_id=tenant.id, title="soon", due_at=future)
        session.commit()

        ins = metrics_db.remediation_insights(session, tenant_id=tenant.id)

    assert ins["open"] == 2
    assert ins["overdue"] == 1


def test_framework_readiness_trends_from_current(tmp_path: Path) -> None:
    """Without snapshots, trends include at least the live posture baseline."""
    _seed_lake(tmp_path)
    data = metrics_db.framework_readiness_trends(tmp_path)
    assert isinstance(data["frameworks"], list)
    assert len(data["frameworks"]) >= 1
    assert len(data["points"]) >= 1
    last = data["points"][-1]
    assert last["source"] in {"current", "snapshot"}
    assert isinstance(last["frameworks"], dict)
    for fw in data["frameworks"]:
        assert fw in last["frameworks"]


def test_sla_heatmap_buckets(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    base = datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)
    now = base + timedelta(days=2)

    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")

        remediation.create_task(
            session,
            tenant_id=tenant.id,
            title="late",
            priority="high",
            owner="platform",
            due_at=base,
        )
        remediation.create_task(
            session,
            tenant_id=tenant.id,
            title="ok",
            priority="critical",
            owner="security",
            due_at=base + timedelta(days=7),
        )
        resolved_on_time = remediation.create_task(session, tenant_id=tenant.id, title="done")
        resolved_on_time.priority = "medium"
        resolved_on_time.created_at = base
        resolved_on_time.due_at = base + timedelta(hours=8)
        resolved_on_time.resolved_at = base + timedelta(hours=4)
        resolved_on_time.status = "resolved"

        session.flush()
        session.commit()

        heat = metrics_db.sla_heatmap(session, tenant_id=tenant.id, now=now)

    assert heat["columns"] == [
        "open_on_track",
        "open_overdue",
        "open_no_sla",
        "resolved_on_time",
        "resolved_late",
    ]
    high = next(row for row in heat["rows"] if row["priority"] == "high")
    critical = next(row for row in heat["rows"] if row["priority"] == "critical")
    medium = next(row for row in heat["rows"] if row["priority"] == "medium")
    assert high["open_overdue"] == 1
    assert critical["open_on_track"] == 1
    assert medium["resolved_on_time"] == 1
    assert heat["owner_rows"] == [
        {
            "owner": "platform",
            "open_on_track": 0,
            "open_overdue": 1,
            "open_no_sla": 0,
            "resolved_on_time": 0,
            "resolved_late": 0,
        },
        {
            "owner": "security",
            "open_on_track": 1,
            "open_overdue": 0,
            "open_no_sla": 0,
            "resolved_on_time": 0,
            "resolved_late": 0,
        },
        {
            "owner": "Unassigned",
            "open_on_track": 0,
            "open_overdue": 0,
            "open_no_sla": 0,
            "resolved_on_time": 1,
            "resolved_late": 0,
        },
    ]


# ---------------------------------------------------------------------------
# API layer — RBAC
# ---------------------------------------------------------------------------


def test_timeseries_requires_auth(env) -> None:
    _app, client, _tokens = env
    res = client.get("/api/v1/insights/timeseries")
    assert res.status_code == HTTPStatus.UNAUTHORIZED


def test_timeseries_read_ok(env) -> None:
    _app, client, tokens = env
    res = client.get("/api/v1/insights/timeseries", headers=_bearer(tokens["read_only"]))
    assert res.status_code == HTTPStatus.OK
    body = res.json()
    assert "data" in body
    assert isinstance(body["data"], list)


def test_timeseries_limit_param(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme2", name="Acme2")
        _key, token = create_api_key(
            session,
            tenant_id=tenant.id,
            user_id=create_user(session, tenant_id=tenant.id, email="r@x.test", role="read_only").id,
        )
        for i in range(5):
            t = datetime(2026, 1, i + 1, tzinfo=UTC)
            metrics_db.capture_metric_point(session, tenant_id=tenant.id, lake_dir=tmp_path, now=t)
        session.commit()

    res = client.get("/api/v1/insights/timeseries?limit=2", headers=_bearer(token))
    assert res.status_code == HTTPStatus.OK


def test_remediation_insights_api_read_ok(env) -> None:
    _app, client, tokens = env
    res = client.get("/api/v1/insights/remediation", headers=_bearer(tokens["read_only"]))
    assert res.status_code == HTTPStatus.OK
    body = res.json()
    data = body["data"]
    assert "open" in data
    assert "overdue" in data
    assert "mttr_hours" in data
    assert "sla_attainment_pct" in data


def test_remediation_insights_requires_auth(env) -> None:
    _app, client, _tokens = env
    res = client.get("/api/v1/insights/remediation")
    assert res.status_code == HTTPStatus.UNAUTHORIZED


def test_capture_requires_write(env) -> None:
    _app, client, tokens = env
    # read_only cannot capture
    res = client.post("/api/v1/insights/capture", headers=_bearer(tokens["read_only"]))
    assert res.status_code == HTTPStatus.FORBIDDEN


def test_capture_requires_auth(env) -> None:
    _app, client, _tokens = env
    res = client.post("/api/v1/insights/capture")
    assert res.status_code == HTTPStatus.UNAUTHORIZED


def test_capture_contributor_ok(env) -> None:
    _app, client, tokens = env
    res = client.post("/api/v1/insights/capture", headers=_bearer(tokens["contributor"]))
    assert res.status_code == HTTPStatus.CREATED
    body = res.json()
    data = body["data"]
    assert "id" in data
    assert "posture_score" in data
    assert "captured_at" in data


def test_framework_trends_api_read_ok(env) -> None:
    _app, client, tokens = env
    res = client.get("/api/v1/insights/framework-trends", headers=_bearer(tokens["read_only"]))
    assert res.status_code == HTTPStatus.OK
    body = res.json()
    data = body["data"]
    assert "frameworks" in data
    assert "points" in data
    assert isinstance(data["points"], list)


def test_framework_trends_requires_auth(env) -> None:
    _app, client, _tokens = env
    res = client.get("/api/v1/insights/framework-trends")
    assert res.status_code == HTTPStatus.UNAUTHORIZED


def test_sla_heatmap_api_read_ok(env) -> None:
    _app, client, tokens = env
    res = client.get("/api/v1/insights/sla-heatmap", headers=_bearer(tokens["read_only"]))
    assert res.status_code == HTTPStatus.OK
    body = res.json()
    data = body["data"]
    assert "rows" in data
    assert "columns" in data
    assert len(data["rows"]) == 4


def test_sla_heatmap_requires_auth(env) -> None:
    _app, client, _tokens = env
    res = client.get("/api/v1/insights/sla-heatmap")
    assert res.status_code == HTTPStatus.UNAUTHORIZED

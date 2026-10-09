"""Unified platform jobs feed tests."""

from __future__ import annotations

import json
from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient

from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
from security_lakehouse.platform_jobs import build_platform_jobs
from security_lakehouse.server_app import create_app


def _seed_jobs_lake(lake: Path) -> None:
    (lake / "gold").mkdir(parents=True, exist_ok=True)
    (lake / "gold" / "connector_runs.jsonl").write_text(
        json.dumps(
            {
                "run_id": "c1",
                "connector_id": "github-security",
                "result": "ok",
                "occurred_at": "2026-07-10T10:00:00Z",
                "actor": "scheduler",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (lake / "gold" / "eval_runs.jsonl").write_text(
        json.dumps(
            {
                "kind": "eval",
                "actor": "scheduler",
                "result": "ok",
                "mode": "local_incremental",
                "occurred_at": "2026-07-10T09:00:00Z",
                "pass_rate": 0.91,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (lake / "gold" / "workflow_runs.jsonl").write_text(
        json.dumps(
            {
                "run_id": "w1",
                "workflow_id": "stale-evidence-escalation",
                "status": "completed",
                "started_at": "2026-07-10T08:00:00Z",
                "finished_at": "2026-07-10T08:01:00Z",
                "actor": "cron",
            }
        )
        + "\n",
        encoding="utf-8",
    )


def test_build_platform_jobs_merges_lake_sources(tmp_path: Path) -> None:
    _seed_jobs_lake(tmp_path)
    payload = build_platform_jobs(
        str(tmp_path),
        agent_runs=[
            {
                "id": "run-1",
                "harness": "posture_review",
                "status": "completed",
                "created_at": "2026-07-10T11:00:00Z",
                "completed_at": "2026-07-10T11:05:00Z",
                "created_by": "agent@test",
                "objective": "Review posture",
            }
        ],
        limit=20,
    )
    kinds = {row["kind"] for row in payload["jobs"]}
    assert {"connector_sync", "lake_eval", "workflow", "agent_run"}.issubset(kinds)
    assert payload["jobs"][0]["kind"] == "agent_run"
    assert payload["count"] == 4


def test_build_platform_jobs_filters_by_kind(tmp_path: Path) -> None:
    _seed_jobs_lake(tmp_path)
    payload = build_platform_jobs(str(tmp_path), limit=10, kind="lake_eval")
    assert payload["count"] == 1
    assert payload["jobs"][0]["kind"] == "lake_eval"


@pytest.fixture
def api_env(tmp_path: Path):
    app = create_app(tmp_path)
    client = TestClient(app)
    tenant_id = ""
    with app.state.sessionmaker() as session:
        tenant = create_tenant(session, slug="jobs", name="Jobs Co")
        tenant_id = tenant.id
        user = create_user(session, tenant_id=tenant.id, email="reader@jobs.test", role="read_only")
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
        session.commit()
    _seed_jobs_lake(tmp_path / "tenants" / tenant_id)
    return client, token


def test_platform_jobs_api(api_env) -> None:
    client, token = api_env
    resp = client.get(
        "/api/v1/platform/jobs?limit=10",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == HTTPStatus.OK
    body = resp.json()
    assert body["meta"]["resource"] == "platform.jobs"
    assert body["data"]["count"] >= 3

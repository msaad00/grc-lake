"""Persisted agent harness run tests: DB, API, RBAC, and idempotency."""

from __future__ import annotations

import importlib.util
import json
from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")
pytest.importorskip("alembic")

from fastapi.testclient import TestClient
from sqlalchemy import inspect

from security_lakehouse.auth.sessions import SESSION_COOKIE, encode_session_cookie
from security_lakehouse.db import agent_runs, migrate
from security_lakehouse.db.base import create_engine_for, session_scope
from security_lakehouse.db.models import AgentRun
from security_lakehouse.db.repository import (
    create_api_key,
    create_tenant,
    create_user,
    create_user_session,
    resolve_api_key,
)
from security_lakehouse.server_app import create_app
from test_api_v1 import _seed_lake


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _human(app, token):
    with session_scope(app.state.sessionmaker) as session:
        key = resolve_api_key(session, token)
        _, value = create_user_session(session, tenant_id=key.tenant_id, user_id=key.user_id, idp="oidc")
    return {"Cookie": f"{SESSION_COOKIE}={encode_session_cookie(value)}", "Content-Type": "application/json"}


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n", encoding="utf-8")


def _seed_gap(lake: Path) -> None:
    _seed_lake(lake)
    _write_jsonl(
        lake / "gold" / "control_tests.jsonl",
        [
            {
                "test_id": "test-soc2",
                "control_id": "SOC2-CC6.1",
                "framework": "SOC 2",
                "owner": "security-platform",
                "status": "needs_evidence",
                "missing_evidence_types": ["identity.access_review"],
                "stale_evidence_types": [],
                "expired_evidence_types": ["mfa.status"],
                "freshness_status": "expired",
            }
        ],
    )


def _provision(app, slug: str, roles: tuple[str, ...] = ("read_only", "contributor")) -> dict[str, str]:
    tokens: dict[str, str] = {}
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug=slug, name=slug.title())
        for role in roles:
            user = create_user(session, tenant_id=tenant.id, email=f"{role}@{slug}.test", role=role)
            _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
            tokens[role] = token
    return tokens


@pytest.fixture
def env(tmp_path: Path):
    _seed_gap(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    tokens = _provision(app, "acme", roles=("read_only", "contributor", "security_admin"))
    return app, client, tokens


def test_migration_creates_agent_runs_table(tmp_path: Path) -> None:
    migrate.upgrade(tmp_path)
    engine = create_engine_for(tmp_path)
    inspector = inspect(engine)
    assert "agent_runs" in inspector.get_table_names()
    columns = {col["name"] for col in inspector.get_columns("agent_runs")}
    assert {"id", "tenant_id", "harness", "mode", "status", "input_hash", "evaluation_json"} <= columns
    indexes = {ix["name"] for ix in inspector.get_indexes("agent_runs")}
    assert "ix_agent_runs_tenant_harness_created" in indexes


def test_agent_run_repository_round_trip(tmp_path: Path) -> None:
    _seed_gap(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        row, created = agent_runs.run_and_persist_agent(
            session,
            tenant_id=tenant.id,
            lake_dir=tmp_path,
            harness="posture_review",
            objective="review gaps",
            role="read_only",
            created_by="agent@acme.test",
            idempotency_key="agent-run-1",
        )
        assert created is True
        again, created_again = agent_runs.run_and_persist_agent(
            session,
            tenant_id=tenant.id,
            lake_dir=tmp_path,
            harness="posture_review",
            objective="review gaps",
            role="read_only",
            created_by="agent@acme.test",
            idempotency_key="agent-run-1",
        )
        assert created_again is False
        assert again.id == row.id
        data = agent_runs.agent_run_to_dict(row, include_state=True)
        assert data["harness"] == "posture_review"
        assert data["evaluation"]["ok"] is True
        assert data["state"]["data_readiness"]["status"] == "lake_ready"
        assert data["decisions"][0]["requires_approval"] is True
        assert "lake_dir" not in data["state"]


def test_agent_runs_require_auth(env) -> None:
    _app, client, _tokens = env
    assert client.get("/api/v1/agent-runs").status_code == HTTPStatus.UNAUTHORIZED


def test_agent_run_api_create_list_get_and_idempotency(env) -> None:
    _app, client, tokens = env
    denied = client.post(
        "/api/v1/agent-runs",
        json={"harness": "posture_review"},
        headers=_bearer(tokens["read_only"]),
    )
    assert denied.status_code == HTTPStatus.FORBIDDEN

    body = {"harness": "posture_review", "objective": "review gaps", "idempotency_key": "retry-safe-1"}
    created = client.post("/api/v1/agent-runs", json=body, headers=_bearer(tokens["contributor"]))
    assert created.status_code == HTTPStatus.CREATED
    run = created.json()["data"]
    assert created.json()["meta"]["created"] is True
    assert run["mode"] == "rules_only"
    assert run["status"] == "completed"
    assert run["state"]["data_readiness"]["status"] == "lake_ready"
    assert run["state"]["data_readiness"]["next_action"] == "use_existing_security_data_lake"
    assert run["evaluation"]["confidence"] == "high"
    assert run["decisions"][0]["status"] == "proposed"
    assert run["decisions"][0]["requires_approval"] is True
    assert "lake_dir" not in run["state"]

    retry = client.post("/api/v1/agent-runs", json=body, headers=_bearer(tokens["contributor"]))
    assert retry.status_code == HTTPStatus.OK
    assert retry.json()["meta"]["created"] is False
    assert retry.json()["data"]["id"] == run["id"]

    listed = client.get("/api/v1/agent-runs?harness=posture_review", headers=_bearer(tokens["contributor"]))
    assert listed.status_code == HTTPStatus.OK
    assert [row["id"] for row in listed.json()["data"]] == [run["id"]]

    fetched = client.get(f"/api/v1/agent-runs/{run['id']}", headers=_bearer(tokens["contributor"]))
    assert fetched.status_code == HTTPStatus.OK
    assert fetched.json()["data"]["id"] == run["id"]


def test_agent_run_api_langgraph_orchestrator_requires_extra(env) -> None:
    if importlib.util.find_spec("langgraph") is not None:
        pytest.skip("LangGraph-installed API path is covered by the harness execution tests")
    _app, client, tokens = env

    created = client.post(
        "/api/v1/agent-runs",
        json={"harness": "posture_review", "orchestrator": "langgraph"},
        headers=_bearer(tokens["contributor"]),
    )

    assert created.status_code == HTTPStatus.BAD_REQUEST
    assert created.json()["errors"][0] == {
        "code": "bad_request",
        "detail": "langgraph orchestrator requires grc-lake[agents]",
    }


def test_agent_run_api_accepts_langgraph_for_soc_triage_when_installed(env) -> None:
    if importlib.util.find_spec("langgraph") is None:
        pytest.skip("LangGraph optional extra not installed")
    _app, client, tokens = env

    created = client.post(
        "/api/v1/agent-runs",
        json={"harness": "soc_triage", "orchestrator": "langgraph"},
        headers=_bearer(tokens["contributor"]),
    )

    assert created.status_code == HTTPStatus.CREATED
    assert created.json()["data"]["harness"] == "soc_triage"


def test_agent_run_approval_executes_evidence_request_once(env) -> None:
    app, client, tokens = env
    created = client.post(
        "/api/v1/agent-runs",
        json={"harness": "posture_review", "objective": "review gaps"},
        headers=_bearer(tokens["contributor"]),
    )
    assert created.status_code == HTTPStatus.CREATED
    run_id = created.json()["data"]["id"]

    denied = client.post(f"/api/v1/agent-runs/{run_id}/decisions/0/approve", headers=_bearer(tokens["read_only"]))
    assert denied.status_code == HTTPStatus.FORBIDDEN

    approved = client.post(
        f"/api/v1/agent-runs/{run_id}/decisions/0/approve",
        json={"note": "Need this before customer review."},
        headers=_human(app, tokens["security_admin"]),
    )
    assert approved.status_code == HTTPStatus.OK
    body = approved.json()
    assert body["meta"]["resource"] == "agent-runs.decisions"
    assert body["meta"]["executed"] is True
    decision = body["data"]["decisions"][0]
    assert decision["status"] == "executed"
    assert decision["approved_by"] == "security_admin@acme.test"
    assert decision["execution_result"]["type"] == "evidence_request"

    requests = client.get("/api/v1/remediation/evidence-requests", headers=_human(app, tokens["security_admin"]))
    assert requests.status_code == HTTPStatus.OK
    rows = requests.json()["data"]
    assert len(rows) == 1
    assert rows[0]["control_id"] == "SOC2-CC6.1"
    assert "Approval note" in rows[0]["note"]

    retry = client.post(
        f"/api/v1/agent-runs/{run_id}/decisions/0/approve", headers=_human(app, tokens["security_admin"])
    )
    assert retry.status_code == HTTPStatus.OK
    assert retry.json()["meta"]["executed"] is False
    again = client.get("/api/v1/remediation/evidence-requests", headers=_human(app, tokens["security_admin"]))
    assert len(again.json()["data"]) == 1


def test_agent_run_approval_keeps_tenant_boundary(tmp_path: Path) -> None:
    _seed_gap(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    tokens_a = _provision(app, "acme")
    tokens_b = _provision(app, "globex")

    created = client.post(
        "/api/v1/agent-runs",
        json={"harness": "posture_review"},
        headers=_bearer(tokens_a["contributor"]),
    )
    assert created.status_code == HTTPStatus.CREATED
    run_id = created.json()["data"]["id"]

    b_approve = client.post(
        f"/api/v1/agent-runs/{run_id}/decisions/0/approve",
        headers=_bearer(tokens_b["contributor"]),
    )
    assert b_approve.status_code == HTTPStatus.NOT_FOUND


def test_agent_run_snapshot_approval_requires_snapshot_scope(env) -> None:
    app, client, tokens = env
    created = client.post(
        "/api/v1/agent-runs",
        json={"harness": "posture_review"},
        headers=_bearer(tokens["contributor"]),
    )
    assert created.status_code == HTTPStatus.CREATED
    run_id = created.json()["data"]["id"]
    decision = [
        {
            "action": "freeze_snapshot",
            "reason": "Freeze current posture for audit.",
            "payload": {},
            "requires_approval": True,
            "status": "proposed",
        }
    ]
    with session_scope(app.state.sessionmaker) as session:
        row = session.get(AgentRun, run_id)
        assert row is not None
        row.decisions_json = json.dumps(decision, sort_keys=True)
        state = json.loads(row.state_json)
        state["decisions"] = decision
        row.state_json = json.dumps(state, sort_keys=True)

    denied = client.post(f"/api/v1/agent-runs/{run_id}/decisions/0/approve", headers=_bearer(tokens["contributor"]))
    assert denied.status_code == HTTPStatus.FORBIDDEN

    approved = client.post(
        f"/api/v1/agent-runs/{run_id}/decisions/0/approve",
        headers=_human(app, tokens["security_admin"]),
    )
    assert approved.status_code == HTTPStatus.OK
    result = approved.json()["meta"]["execution_result"]
    assert result["type"] == "snapshot"
    assert Path(result["snapshot_path"]).is_file()


def test_agent_run_rejects_role_escalation(env) -> None:
    _app, client, tokens = env
    response = client.post(
        "/api/v1/agent-runs",
        json={"harness": "posture_review", "role": "security_admin"},
        headers=_bearer(tokens["contributor"]),
    )
    assert response.status_code == HTTPStatus.FORBIDDEN


def test_agent_run_provider_metadata_does_not_expose_key_env(env, monkeypatch: pytest.MonkeyPatch) -> None:
    _app, client, tokens = env
    monkeypatch.setenv("GRC_LAKE_AGENT_PROVIDER", "openai")
    monkeypatch.setenv("GRC_LAKE_AGENT_MODEL", "gpt-test")
    monkeypatch.setenv("GRC_LAKE_AGENT_API_KEY_ENV", "GRC_LAKE_TEST_OPENAI_KEY")
    monkeypatch.setenv("GRC_LAKE_TEST_OPENAI_KEY", "secret-test-value")

    created = client.post(
        "/api/v1/agent-runs",
        json={"harness": "posture_review", "use_model": False},
        headers=_bearer(tokens["contributor"]),
    )

    assert created.status_code == HTTPStatus.CREATED
    text = json.dumps(created.json(), sort_keys=True)
    assert "GRC_LAKE_TEST_OPENAI_KEY" not in text
    assert "secret-test-value" not in text
    assert created.json()["data"]["provider"]["configured"] is True


def test_agent_run_tenant_isolation(tmp_path: Path) -> None:
    _seed_gap(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    tokens_a = _provision(app, "acme")
    tokens_b = _provision(app, "globex")

    created = client.post(
        "/api/v1/agent-runs",
        json={"harness": "posture_review"},
        headers=_bearer(tokens_a["contributor"]),
    )
    assert created.status_code == HTTPStatus.CREATED
    run_id = created.json()["data"]["id"]

    b_list = client.get("/api/v1/agent-runs", headers=_bearer(tokens_b["contributor"])).json()["data"]
    assert b_list == []
    b_get = client.get(f"/api/v1/agent-runs/{run_id}", headers=_bearer(tokens_b["contributor"]))
    assert b_get.status_code == HTTPStatus.NOT_FOUND


def test_agent_run_resource_is_discoverable(env) -> None:
    _app, client, tokens = env
    catalog = client.get("/api/v1", headers=_bearer(tokens["read_only"])).json()["data"]["resources"]
    paths = {row["path"] for row in catalog}
    assert "/api/v1/agent-runs" in paths
    assert "/api/v1/agent-runs/{run_id}" in paths


def test_agent_run_persists_needs_ingestion_when_lake_is_empty(tmp_path: Path) -> None:
    app = create_app(tmp_path)
    client = TestClient(app)
    tokens = _provision(app, "acme")

    created = client.post(
        "/api/v1/agent-runs",
        json={"harness": "soc_triage"},
        headers=_bearer(tokens["contributor"]),
    )

    assert created.status_code == HTTPStatus.CREATED
    readiness = created.json()["data"]["state"]["data_readiness"]
    assert readiness["status"] == "needs_ingestion"
    assert readiness["ready_for_harness"] is False
    assert readiness["required_artifacts"] == ["silver.normalized_events"]
    assert readiness["missing_required_artifacts"] == ["silver.normalized_events"]
    assert readiness["artifact_status"][0] == {
        "artifact": "silver.normalized_events",
        "relative_path": "silver/normalized_events.jsonl",
        "rows": 0,
        "required": True,
        "present": False,
    }
    assert readiness["recommended_next_steps"][0]["action"] == "inspect_connectors"
    assert str(tmp_path) not in json.dumps(readiness, sort_keys=True)


def _posture_run(client: TestClient, token: str) -> str:
    created = client.post(
        "/api/v1/agent-runs",
        json={"harness": "posture_review", "objective": "review gaps"},
        headers=_bearer(token),
    )
    assert created.status_code == HTTPStatus.CREATED
    return str(created.json()["data"]["id"])


def test_agent_decision_can_be_rejected_with_a_reason_and_is_never_executed(env) -> None:
    app, client, tokens = env
    run_id = _posture_run(client, tokens["contributor"])
    url = f"/api/v1/agent-runs/{run_id}/decisions/0/reject"

    assert client.post(url, json={"reason": "no"}, headers=_bearer(tokens["read_only"])).status_code == 403
    assert client.post(url, json={"reason": "  "}, headers=_human(app, tokens["security_admin"])).status_code == 400

    rejected = client.post(
        url, json={"reason": "Already covered by vendor SOC report."}, headers=_human(app, tokens["security_admin"])
    )
    assert rejected.status_code == HTTPStatus.OK
    decision = rejected.json()["data"]["decisions"][0]
    assert decision["status"] == "rejected"
    assert decision["rejected_by"] == "security_admin@acme.test"
    assert decision["rejection_reason"] == "Already covered by vendor SOC report."
    assert "execution_result" not in decision

    again = client.post(url, json={"reason": "second"}, headers=_human(app, tokens["security_admin"]))
    assert again.status_code == HTTPStatus.OK
    assert again.json()["data"]["decisions"][0]["rejection_reason"] == "Already covered by vendor SOC report."

    approve = client.post(
        f"/api/v1/agent-runs/{run_id}/decisions/0/approve", headers=_human(app, tokens["security_admin"])
    )
    assert approve.status_code == HTTPStatus.CONFLICT
    requests = client.get("/api/v1/remediation/evidence-requests", headers=_human(app, tokens["security_admin"]))
    assert requests.json()["data"] == []


def test_executed_agent_decision_cannot_be_rejected(env) -> None:
    app, client, tokens = env
    run_id = _posture_run(client, tokens["contributor"])
    base = f"/api/v1/agent-runs/{run_id}/decisions/0"
    assert client.post(f"{base}/approve", headers=_human(app, tokens["security_admin"])).status_code == HTTPStatus.OK

    rejected = client.post(f"{base}/reject", json={"reason": "too late"}, headers=_human(app, tokens["security_admin"]))

    assert rejected.status_code == HTTPStatus.CONFLICT

"""Approval credentials and durable workflow decisions cannot be replayed."""

from __future__ import annotations

import multiprocessing
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from security_lakehouse import workflows
from security_lakehouse.db.base import session_scope
from security_lakehouse.db.models import ApiKey, UserSession
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user, revoke_api_key
from security_lakehouse.server_app import create_app
from test_api_v1 import _seed_lake
from test_mapping_review_api import _decision_body
from test_workflows import _bootstrap_silver


@pytest.fixture
def credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("TRUSTOPS_COOKIE_SIGNING_KEY", "local-test-approval-signing-key")
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="audit", name="Audit")
        user = create_user(session, tenant_id=tenant.id, email="admin@example.test", role="admin")
        key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
        other = create_user(session, tenant_id=tenant.id, email="reviewer@example.test", role="compliance_reviewer")
    return app, token, key.id, tenant.id, other.email


def test_api_key_browser_session_cannot_decide_mapping(credentials):
    app, token, *_ = credentials
    client = TestClient(app, base_url="https://testserver")
    assert client.post("/api/v1/auth/session-from-key", json={"api_key": token}).status_code == 200
    assert client.get("/api/v1/auth/whoami").status_code == 200
    assert client.post("/api/v1/mapping-reviews/decisions", json=_decision_body()).status_code == 403


def test_key_revocation_invalidates_derived_browser_session(credentials):
    app, token, key_id, tenant_id, _ = credentials
    client = TestClient(app, base_url="https://testserver")
    assert client.post("/api/v1/auth/session-from-key", json={"api_key": token}).status_code == 200
    with session_scope(app.state.sessionmaker) as session:
        revoke_api_key(session, tenant_id=tenant_id, key_id=key_id, now=datetime.now(UTC))
    assert client.get("/api/v1/auth/whoami").status_code == 401


def test_admin_cannot_mint_another_reviewers_key(credentials):
    app, token, _, _, email = credentials
    response = TestClient(app).post(
        "/api/v1/auth/keys", json={"user_email": email}, headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403


def paused_workflow(lake):
    _bootstrap_silver(lake)
    nodes = [
        {"id": "t", "node_type": "trigger.cron", "params": {"schedule": "@hourly"}},
        {"id": "g", "node_type": "gate.approval", "params": {"title": "Review"}},
        {"id": "c", "node_type": "check.evidence_exists", "params": {"control_id": "SOC2-CC6.1", "minimum": 1}},
    ]
    edges = [
        {"source": "t", "target": "g", "condition": "always"},
        {"source": "g", "target": "c", "condition": "always"},
    ]
    workflows.save_workflow(lake, workflow_id="wf", name="Workflow", description="", nodes=nodes, edges=edges)
    return workflows.run_workflow(lake, workflow_id="wf"), nodes, edges


def test_rejected_and_approved_workflow_cannot_be_approved_again(tmp_path):
    paused, _, _ = paused_workflow(tmp_path)
    workflows.reject_workflow_run(tmp_path, run_id=paused["run_id"])
    with pytest.raises(ValueError):
        workflows.approve_workflow_run(tmp_path, run_id=paused["run_id"])
    paused = workflows.run_workflow(tmp_path, workflow_id="wf")
    workflows.approve_workflow_run(tmp_path, run_id=paused["run_id"])
    with pytest.raises(ValueError):
        workflows.approve_workflow_run(tmp_path, run_id=paused["run_id"])


def test_changed_workflow_requires_a_new_review(tmp_path):
    paused, nodes, edges = paused_workflow(tmp_path)
    nodes[-1]["params"]["minimum"] = 999
    workflows.save_workflow(tmp_path, workflow_id="wf", name="Changed", description="", nodes=nodes, edges=edges)
    with pytest.raises(ValueError, match="version"):
        workflows.approve_workflow_run(tmp_path, run_id=paused["run_id"])


def _approve_in_process(args):
    lake, run_id = args
    try:
        workflows.approve_workflow_run(lake, run_id=run_id)
        return "executed"
    except ValueError:
        return "conflict"


def test_concurrent_workflow_approval_executes_once(tmp_path):
    paused, _, _ = paused_workflow(tmp_path)
    with multiprocessing.get_context("spawn").Pool(4) as pool:
        results = pool.map(_approve_in_process, [(str(tmp_path), paused["run_id"])] * 8)
    assert results.count("executed") == 1


def test_interrupted_execution_stays_claimed(tmp_path, monkeypatch):
    paused, _, _ = paused_workflow(tmp_path)

    def crash(*args, **kwargs):
        raise RuntimeError("simulated crash after claim")

    monkeypatch.setattr(workflows, "_execute_workflow_nodes", crash)
    with pytest.raises(RuntimeError):
        workflows.approve_workflow_run(tmp_path, run_id=paused["run_id"])
    with pytest.raises(ValueError):
        workflows.approve_workflow_run(tmp_path, run_id=paused["run_id"])


def test_interrupted_execution_cannot_be_retried(tmp_path, monkeypatch):
    paused, _, _ = paused_workflow(tmp_path)

    def crash(*args, **kwargs):
        raise RuntimeError("simulated crash after claim")

    monkeypatch.setattr(workflows, "_execute_workflow_nodes", crash)
    with pytest.raises(RuntimeError):
        workflows.approve_workflow_run(tmp_path, run_id=paused["run_id"])
    with pytest.raises(workflows.ApprovalConflict):
        workflows.retry_workflow_run(tmp_path, run_id=paused["run_id"])


@pytest.mark.parametrize("change", ["expire", "delete", "legacy"])
def test_derived_sessions_require_active_origin(credentials, change):
    app, token, key_id, *_ = credentials
    client = TestClient(app, base_url="https://testserver")
    assert client.post("/api/v1/auth/session-from-key", json={"api_key": token}).status_code == 200
    with session_scope(app.state.sessionmaker) as session:
        if change == "expire":
            session.get(ApiKey, key_id).expires_at = datetime.now(UTC) - timedelta(seconds=1)
        elif change == "delete":
            session.delete(session.get(ApiKey, key_id))
        else:
            from sqlalchemy import select

            derived = session.scalars(select(UserSession).where(UserSession.source_api_key_id == key_id)).one()
            derived.source_api_key_id = None
    assert client.get("/api/v1/auth/whoami").status_code == 401

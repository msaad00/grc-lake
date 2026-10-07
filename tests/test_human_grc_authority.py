"""Machine credentials cannot supply human review or employee attestations."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from security_lakehouse.cli import _refuse_exposed_local_mode
from security_lakehouse.db import remediation
from security_lakehouse.db.base import session_scope
from security_lakehouse.remediation_verification import verify_task
from test_agent_decision_authority import human
from test_approval_authority import credentials as credentials_fixture
from test_policy_acknowledgments import _published_policy

credentials = credentials_fixture


@pytest.mark.parametrize("derived", [False, True])
@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("remediation/exceptions/missing/approve", {}),
        ("remediation/tasks/missing/verify", {}),
        ("access-reviews/items/missing/decision", {"decision": "certified"}),
        ("policies/missing/acknowledgments", {}),
        ("workflows/runs/missing/approve", {}),
        ("workflows/runs/missing/reject", {}),
        ("workflows/runs/missing/reconcile", {"note": "review"}),
    ],
)
def test_machine_credentials_cannot_attest(credentials, derived, path, body):
    app, token, *_ = credentials
    client = TestClient(app, base_url="https://testserver")
    headers = {"Authorization": f"Bearer {token}"}
    if derived:
        assert client.post("/api/v1/auth/session-from-key", json={"api_key": token}).status_code == 200
        headers = {}
    response = client.post("/api/v1/" + path, json=body, headers=headers)
    assert response.status_code == 403, response.text


def test_even_human_admin_cannot_attest_for_another_employee(credentials):
    app, token, *_ = credentials
    client = TestClient(app)
    headers = human(app, token)
    document = _published_policy(client, headers)
    response = client.post(
        f"/api/v1/policies/{document}/acknowledgments",
        headers=headers,
        json={"user_email": "someone-else@example.test"},
    )
    assert response.status_code == 403
    assert client.get(f"/api/v1/policies/{document}/acknowledgments", headers=headers).json()["data"] == []
    assert client.post(f"/api/v1/policies/{document}/acknowledgments", headers=headers, json={}).status_code == 201


@pytest.mark.parametrize("field", ["created_by", "owner"])
def test_remediator_cannot_verify_their_own_task(credentials, tmp_path, field):
    app, _, _, tenant_id, _ = credentials
    with session_scope(app.state.sessionmaker) as session:
        task = remediation.create_task(
            session, tenant_id=tenant_id, title="Fix", control_id="SOC2-CC6.1", **{field: "reviewer@example.test"}
        )
        with pytest.raises(ValueError, match="independent"):
            verify_task(
                session,
                tmp_path,
                tenant_id=tenant_id,
                task_id=task.id,
                reviewer_id="reviewer",
                reviewer="reviewer@example.test",
                now=datetime.now(UTC),
            )


def test_linked_task_cannot_be_dismissed_without_retest(credentials):
    app, _, _, tenant_id, _ = credentials
    with session_scope(app.state.sessionmaker) as session:
        task = remediation.create_task(session, tenant_id=tenant_id, title="Fix", control_id="SOC2-CC6.1")
        with pytest.raises(ValueError, match="retest"):
            remediation.update_task(session, tenant_id=tenant_id, task_id=task.id, changes={"status": "dismissed"})
        assert task.status == "open"


@pytest.mark.parametrize("env", ["production", "prod", "staging"])
def test_local_insecure_flag_cannot_override_production_guard(monkeypatch, env):
    monkeypatch.setenv("TRUSTOPS_ALLOW_INSECURE_NO_AUTH", "true")
    monkeypatch.setenv("TRUSTOPS_ENV", env)
    with pytest.raises(SystemExit, match="production|staging"):
        _refuse_exposed_local_mode("0.0.0.0")


def test_hosted_workflow_initiator_cannot_approve_own_run(tmp_path):
    from security_lakehouse import workflows
    from security_lakehouse.execution_mode import server_execution
    from test_approval_authority import paused_workflow

    paused_workflow(tmp_path)
    with server_execution("test"):
        run = workflows.run_workflow(tmp_path, workflow_id="wf", actor="initiator@example.test")
        assert run["actor"] == "initiator@example.test"
        with pytest.raises(workflows.ApprovalConflict, match="independent"):
            workflows.approve_workflow_run(tmp_path, run_id=run["run_id"], actor="initiator@example.test")
        assert workflows.get_workflow_run(tmp_path, run["run_id"])["status"] == "awaiting_approval"
        assert (
            workflows.approve_workflow_run(tmp_path, run_id=run["run_id"], actor="reviewer@example.test")["result"]
            == "ok"
        )


def test_human_cannot_certify_their_own_access(credentials):
    app, token, *_ = credentials
    client = TestClient(app)
    headers = human(app, token)
    campaign = client.post("/api/v1/access-reviews", json={"name": "review"}, headers=headers).json()["data"]
    item = client.post(
        f"/api/v1/access-reviews/{campaign['id']}/items", json={"subject_id": "admin@example.test"}, headers=headers
    ).json()["data"]
    response = client.post(
        f"/api/v1/access-reviews/items/{item['id']}/decision", json={"decision": "certified"}, headers=headers
    )
    assert response.status_code == 400


def test_exception_approval_requires_a_different_human(credentials):
    from datetime import timedelta

    from security_lakehouse.db.repository import create_api_key, create_user

    app, token, _, tenant_id, _ = credentials
    client = TestClient(app)
    with session_scope(app.state.sessionmaker) as session:
        other = create_user(session, tenant_id=tenant_id, email="independent@example.test", role="security_admin")
        _, other_token = create_api_key(session, tenant_id=tenant_id, user_id=other.id)
    row = client.post(
        "/api/v1/remediation/exceptions",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "control_id": "SOC2-CC6.1",
            "reason": "Review required",
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        },
    ).json()["data"]
    path = f"/api/v1/remediation/exceptions/{row['id']}/approve"
    assert client.post(path, headers={"Authorization": f"Bearer {other_token}"}).status_code == 403
    assert client.post(path, headers=human(app, token)).status_code == 400
    response = client.post(path, headers=human(app, other_token))
    assert response.status_code == 200
    assert response.json()["data"]["approved_by"] == "independent@example.test"

"""A failed action is terminal without wedging unrelated proposals or replaying writes."""

import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from security_lakehouse import server_app
from security_lakehouse.db import agent_runs
from security_lakehouse.db.base import session_scope
from security_lakehouse.db.models import AgentRun
from test_agent_decision_authority import human
from test_agent_runs_api import _bearer, _posture_run, _provision
from test_agent_runs_api import env as _agent_env

env = _agent_env


def proposals(app, run_id, *, invalid=False, executing=False):
    with session_scope(app.state.sessionmaker) as session:
        row = session.get(AgentRun, run_id)
        decision = agent_runs.agent_run_decisions(row)[0]
        second = {**decision, "payload": dict(decision["payload"])}
        if invalid:
            decision["payload"] = {"control_id": ""}
        decisions = [decision, second]
        row.decisions_json = json.dumps(decisions)
        state = json.loads(row.state_json)
        state["decisions"] = decisions
        row.state_json = json.dumps(state)
        session.commit()
        if executing:
            agent_runs.claim_decision(session, row, decision_index=0, actor="prior-reviewer")


def test_invalid_action_becomes_failed_and_other_proposal_can_execute(env):
    app, client, tokens = env
    run_id = _posture_run(client, tokens["contributor"])
    proposals(app, run_id, invalid=True)
    headers = human(app, tokens["security_admin"])
    base = f"/api/v1/agent-runs/{run_id}"
    failed = client.post(base + "/decisions/0/approve", headers=headers)
    assert failed.status_code == 400
    fetched = client.get(base, headers=headers).json()["data"]
    assert fetched["decisions"][0]["status"] == "failed"
    assert fetched["decisions"] == fetched["state"]["decisions"]
    assert fetched["decisions"][0]["failure_code"] == "execution_failed"
    repeated = client.post(base + "/decisions/0/approve", headers=headers)
    assert repeated.status_code == 409
    next_decision = client.post(base + "/decisions/1/approve", headers=headers)
    assert next_decision.status_code == 200
    requests = client.get("/api/v1/remediation/evidence-requests", headers=headers)
    assert len(requests.json()["data"]) == 1


def test_unexpected_failure_rolls_back_db_writes_and_does_not_store_exception(env, monkeypatch):
    app, client, tokens = env
    run_id = _posture_run(client, tokens["contributor"])
    proposals(app, run_id)
    headers = human(app, tokens["security_admin"])
    execute = server_app._execute_agent_decision

    def fail_after_write(*args, **kwargs):
        execute(*args, **kwargs)
        raise RuntimeError("sensitive-provider-token")

    monkeypatch.setattr(server_app, "_execute_agent_decision", fail_after_write)
    with TestClient(app, raise_server_exceptions=False) as failing_client:
        failed = failing_client.post(f"/api/v1/agent-runs/{run_id}/decisions/0/approve", headers=headers)
    assert failed.status_code == 500
    fetched = client.get(f"/api/v1/agent-runs/{run_id}", headers=headers)
    assert "sensitive-provider-token" not in fetched.text
    assert fetched.json()["data"]["decisions"][0]["status"] == "failed"
    requests = client.get("/api/v1/remediation/evidence-requests", headers=headers)
    assert requests.json()["data"] == []


def test_reconcile_abandoned_claim_is_terminal_and_does_not_execute(env, monkeypatch):
    app, client, tokens = env
    run_id = _posture_run(client, tokens["contributor"])
    proposals(app, run_id, executing=True)
    headers = human(app, tokens["security_admin"])
    base = f"/api/v1/agent-runs/{run_id}/decisions/0"
    monkeypatch.setattr(server_app, "_execute_agent_decision", lambda *a, **k: pytest.fail("recovery executed action"))
    result = client.post(base + "/reconcile", headers=headers, json={"reason": "Worker stopped; reviewed records"})
    assert result.status_code == 200, result.text
    data = result.json()["data"]
    decision = data["decisions"][0]
    assert decision["status"] == "failed"
    assert decision["failure_code"] == "outcome_unknown"
    assert decision["reconciled_by"] == "security_admin@acme.test"
    assert decision["approved_by"] == "prior-reviewer"
    assert data["decisions"] == data["state"]["decisions"]
    replay = client.post(base + "/approve", headers=headers)
    assert replay.status_code == 409
    repeated = client.post(base + "/reconcile", headers=headers, json={"reason": "again"})
    assert repeated.status_code == 409
    monkeypatch.undo()
    next_result = client.post(f"/api/v1/agent-runs/{run_id}/decisions/1/approve", headers=headers)
    assert next_result.status_code == 200


def test_reconcile_refuses_active_execution(env, monkeypatch):
    app, client, tokens = env
    run_id = _posture_run(client, tokens["contributor"])
    headers = human(app, tokens["security_admin"])
    entered, release = threading.Event(), threading.Event()
    execute = server_app._execute_agent_decision

    def slow(*args, **kwargs):
        entered.set()
        released = release.wait(10)
        assert released
        return execute(*args, **kwargs)

    monkeypatch.setattr(server_app, "_execute_agent_decision", slow)
    base = f"/api/v1/agent-runs/{run_id}/decisions/0"
    with ThreadPoolExecutor(max_workers=1) as pool:
        running = pool.submit(client.post, base + "/approve", headers=headers)
        try:
            started = entered.wait(10)
            assert started
            result = client.post(base + "/reconcile", headers=headers, json={"reason": "must not interrupt"})
            assert result.status_code == 409
        finally:
            release.set()
        completed = running.result()
        assert completed.status_code == 200
    fetched = client.get(f"/api/v1/agent-runs/{run_id}", headers=headers)
    assert fetched.json()["data"]["decisions"][0]["status"] == "executed"


def test_reconcile_requires_independent_human_and_tenant_and_reason(env):
    app, client, tokens = env
    run_id = _posture_run(client, tokens["contributor"])
    proposals(app, run_id, executing=True)
    url = f"/api/v1/agent-runs/{run_id}/decisions/0/reconcile"
    for headers in (
        _bearer(tokens["security_admin"]),
        human(app, tokens["contributor"]),
        human(app, tokens["read_only"]),
    ):
        denied = client.post(url, headers=headers, json={"reason": "reviewed"})
        assert denied.status_code == 403
    other = _provision(app, "other", roles=("security_admin",))
    hidden = client.post(url, headers=human(app, other["security_admin"]), json={"reason": "reviewed"})
    assert hidden.status_code == 404
    blank = client.post(url, headers=human(app, tokens["security_admin"]), json={"reason": " "})
    assert blank.status_code == 400

"""Interrupted workflow claims can be closed without replay or racing a worker."""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from security_lakehouse import workflows


def paused(lake):
    nodes = [
        {"id": "trigger", "node_type": "trigger.cron", "params": {"schedule": "@hourly"}},
        {"id": "gate", "node_type": "gate.approval", "params": {"title": "Review"}},
    ]
    workflows.save_workflow(
        lake,
        workflow_id="review",
        name="Review",
        description="",
        nodes=nodes,
        edges=[{"source": "trigger", "target": "gate", "condition": "always"}],
    )
    from security_lakehouse.execution_mode import server_execution

    with server_execution("fixture"):
        return workflows.run_workflow(lake, workflow_id="review", actor="initiator@example.test")


def test_reconcile_closes_claim_without_execution_or_replay(tmp_path, monkeypatch):
    prior = paused(tmp_path)
    workflows._claim_workflow_decision(tmp_path, prior["run_id"], "approver@example.test", "approval")
    monkeypatch.setattr(workflows, "_execute_workflow_nodes", lambda *a, **k: pytest.fail("recovery replayed actions"))
    result = workflows.reconcile_workflow_run(
        tmp_path,
        run_id=prior["run_id"],
        actor="reviewer@example.test",
        note="Worker stopped; provider outcome inspected",
    )
    assert result["status"] == "interrupted"
    assert result["failure_code"] == "outcome_unknown"
    assert result["decision_actor"] == "approver@example.test"
    assert result["reconciled_by"] == "reviewer@example.test"
    assert workflows.get_workflow_run(tmp_path, prior["run_id"])["status"] == "interrupted"
    for action in (workflows.approve_workflow_run, workflows.retry_workflow_run, workflows.reconcile_workflow_run):
        with pytest.raises(workflows.ApprovalConflict):
            action(tmp_path, run_id=prior["run_id"], actor="reviewer@example.test")


def test_reconcile_requires_independent_named_actor_and_reason(tmp_path):
    prior = paused(tmp_path)
    workflows._claim_workflow_decision(tmp_path, prior["run_id"], "approver@example.test", "approval")
    for actor, note in [
        ("", "reason"),
        ("reviewer@example.test", ""),
        ("APPROVER@example.test", "reason"),
        ("initiator@example.test", "reason"),
    ]:
        with pytest.raises(ValueError):
            workflows.reconcile_workflow_run(tmp_path, run_id=prior["run_id"], actor=actor, note=note)
    assert workflows.get_workflow_run(tmp_path, prior["run_id"])["status"] == "approval_claimed"


def test_reconcile_refuses_live_execution(tmp_path, monkeypatch):
    prior = paused(tmp_path)
    entered, release = threading.Event(), threading.Event()
    execute = workflows._execute_workflow_nodes

    def slow(*args, **kwargs):
        entered.set()
        assert release.wait(10)
        return execute(*args, **kwargs)

    monkeypatch.setattr(workflows, "_execute_workflow_nodes", slow)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            workflows.approve_workflow_run, tmp_path, run_id=prior["run_id"], actor="approver@example.test"
        )
        try:
            assert entered.wait(10)
            with pytest.raises(workflows.ApprovalConflict):
                workflows.reconcile_workflow_run(
                    tmp_path, run_id=prior["run_id"], actor="reviewer@example.test", note="Must not race"
                )
        finally:
            release.set()
        assert future.result()["status"] == "ok"


def test_reconciliation_api_contract_and_scope(tmp_path):
    from security_lakehouse import api_v1

    prior = paused(tmp_path)
    workflows._claim_workflow_decision(tmp_path, prior["run_id"], "approver@example.test", "approval")
    path = f"/api/v1/workflows/runs/{prior['run_id']}/reconcile"
    assert api_v1.required_post_scope(path) == "workflow_manage"
    status, body = api_v1.handle_post(
        path, {"actor": "reviewer@example.test", "note": "Reviewed provider receipts"}, tmp_path
    )
    assert status == 200
    assert body["data"]["status"] == "interrupted"

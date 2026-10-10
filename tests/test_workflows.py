"""Workflow DAG, trust shares, and audit log tests."""

from __future__ import annotations

import json
import re
import threading
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from security_lakehouse.audit_log import build_audit_log
from security_lakehouse.connector_state import append_config_event
from security_lakehouse.server import _Handler
from security_lakehouse.tracking import append_event as append_triage
from security_lakehouse.trust_share import create_share, list_shares, revoke_share
from security_lakehouse.workflows import (
    action_catalog,
    approve_workflow_run,
    get_workflow,
    get_workflow_run,
    list_runs,
    list_workflows,
    reject_workflow_run,
    retry_workflow_run,
    run_action,
    run_workflow,
    save_workflow,
)

# --- workflow action library ----------------------------------------------------


def _bootstrap_silver(lake: Path) -> None:
    (lake / "silver").mkdir(parents=True, exist_ok=True)
    (lake / "silver" / "normalized_events.jsonl").write_text(
        "\n".join(
            json.dumps(
                {
                    "event_id": f"evt-{i}",
                    "control_ids": ["SOC2-CC6.1"],
                    "asset_id": "x",
                    "asset_owner": "platform",
                    "environment": "test",
                    "source": "test",
                    "event_type": "test.evidence",
                    "event_time": "2026-05-20T00:00:00Z",
                    "evidence_collected_at": "2026-05-20T00:00:00Z",
                    "evidence_ref": f"test://evt-{i}",
                    "raw_sha256": "0" * 64,
                    "severity": "info",
                    "severity_score": 0,
                    "status": "passed",
                }
            )
            for i in range(3)
        )
        + "\n",
        encoding="utf-8",
    )
    (lake / "gold").mkdir(parents=True, exist_ok=True)
    # action.snapshot routes through build_current_posture which expects the
    # full gold layer; populate the minimum files so workflow tests can
    # exercise that path without running the entire ingest pipeline.
    (lake / "gold" / "control_posture.jsonl").write_text(
        json.dumps(
            {
                "control_id": "SOC2-CC6.1",
                "framework": "SOC 2",
                "framework_id": "soc2",
                "status": "pass",
                "control_count": 1,
                "evidence_count": 3,
                "event_count": 3,
                "risk_score": 10,
                "owner": "security-platform",
                "title": "Logical access",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (lake / "gold" / "asset_risk.jsonl").write_text(
        json.dumps(
            {
                "asset_id": "x",
                "asset_owner": "platform",
                "asset_type": "test",
                "environment": "test",
                "risk_score": 0,
                "critical_open": 0,
                "high_open": 0,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (lake / "gold" / "control_tests.jsonl").write_text(
        json.dumps(
            {
                "control_id": "SOC2-CC6.1",
                "result": "pass",
                "evaluated_at": "2026-05-20T00:00:00Z",
                "confidence_score": 88,
            }
        )
        + "\n",
        encoding="utf-8",
    )


def test_action_catalog_includes_all_nodes() -> None:
    catalog = action_catalog()
    node_types = {a["node_type"] for a in catalog}
    assert node_types == {
        "trigger.evidence_changed",
        "trigger.cron",
        "check.evidence_exists",
        "check.control_pass",
        "gate.approval",
        "action.snapshot",
        "action.assign_owner",
        "action.connector_sync",
        "action.webhook",
        "action.slack",
        "action.jira",
    }
    for action in catalog:
        assert action["kind"] in {"trigger", "check", "gate", "action"}
        assert action["input_schema"]
        assert action["output_schema"]


def test_action_catalog_descriptions_use_plain_language() -> None:
    """Node descriptions render in the workflow builder; keep internals out."""
    internal = re.compile(r"GRC_LAKE_|gold/|silver|bronze|\bPOST /|/rest/api/")
    for action in action_catalog():
        assert not internal.search(action["description"]), (action["node_type"], action["description"])


def test_run_action_check_evidence_exists(tmp_path: Path) -> None:
    _bootstrap_silver(tmp_path)
    out = run_action(
        tmp_path,
        node_type="check.evidence_exists",
        params={"control_id": "SOC2-CC6.1", "minimum": 2},
    )
    assert out == {"matched_count": 3, "passed": True, "minimum": 2}


def test_run_action_check_control_pass(tmp_path: Path) -> None:
    _bootstrap_silver(tmp_path)
    out = run_action(tmp_path, node_type="check.control_pass", params={"control_id": "SOC2-CC6.1"})
    assert out["passed"] is True
    assert out["result"] == "pass"


def test_run_action_unknown_node_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        run_action(tmp_path, node_type="action.does_not_exist", params={})


def test_run_action_connector_sync_dry_run(tmp_path: Path) -> None:
    out = run_action(
        tmp_path,
        node_type="action.connector_sync",
        params={"connector_id": "aws-posture"},
        dry_run=True,
    )
    assert out["dry_run"] is True
    assert out["connector_id"] == "aws-posture"
    assert "sync connector" in out["would"]


def test_run_action_connector_sync_reports_successful_sync(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from security_lakehouse import connector_runner

    def fake_sync(lake_dir: object, *, connector_id: str, actor: str) -> connector_runner.ConnectorSyncResult:
        return connector_runner.ConnectorSyncResult(
            connector_id=connector_id,
            result="ok",
            raw_path=str(tmp_path / "raw.jsonl"),
            evidence_count=3,
            materialized=True,
            run={"result": "ok"},
            watermark_cursor="2026-09-28T00:00:00Z",
        )

    monkeypatch.setattr(connector_runner, "run_connector_sync", fake_sync)
    out = run_action(tmp_path, node_type="action.connector_sync", params={"connector_id": "aws-posture"})

    assert out == {
        "connector_id": "aws-posture",
        "result": "ok",
        "evidence_count": 3,
        "error": None,
        "watermark_cursor": "2026-09-28T00:00:00Z",
    }


# --- workflow persistence + run -------------------------------------------------


def _trivial_dag() -> tuple[list[dict], list[dict]]:
    nodes = [
        {"id": "n1", "node_type": "trigger.evidence_changed", "params": {}},
        {
            "id": "n2",
            "node_type": "check.evidence_exists",
            "params": {"control_id": "SOC2-CC6.1", "minimum": 1},
        },
        {"id": "n3", "node_type": "action.snapshot", "params": {"reason": "test"}},
    ]
    edges = [
        {"source": "n1", "target": "n2"},
        {"source": "n2", "target": "n3"},
    ]
    return nodes, edges


def test_save_workflow_versions_and_lists(tmp_path: Path) -> None:
    nodes, edges = _trivial_dag()
    a = save_workflow(
        tmp_path,
        workflow_id=None,
        name="Snapshot when SOC2 evidence drops",
        description="",
        nodes=nodes,
        edges=edges,
    )
    b = save_workflow(
        tmp_path,
        workflow_id=a["workflow_id"],
        name="Snapshot when SOC2 evidence drops",
        description="updated",
        nodes=nodes,
        edges=edges,
    )
    assert a["version"] == 1
    assert b["version"] == 2
    listed = list_workflows(tmp_path)
    assert len(listed) == 1  # latest only
    assert listed[0]["version"] == 2


def test_save_workflow_rejects_empty_name(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        save_workflow(tmp_path, workflow_id=None, name="", description="", nodes=[], edges=[])


def test_run_workflow_topological_order(tmp_path: Path) -> None:
    _bootstrap_silver(tmp_path)
    nodes, edges = _trivial_dag()
    saved = save_workflow(
        tmp_path,
        workflow_id=None,
        name="Snapshot",
        description="",
        nodes=nodes,
        edges=edges,
    )
    run = run_workflow(tmp_path, workflow_id=saved["workflow_id"])
    assert run["result"] == "ok"
    assert [r["node_id"] for r in run["node_results"]] == ["n1", "n2", "n3"]
    assert run["node_results"][2]["output"]["snapshot_path"].endswith(".json")

    runs = list_runs(tmp_path, saved["workflow_id"])
    assert len(runs) == 1
    assert runs[0]["result"] == "ok"


def test_run_workflow_substitutes_variable_references(tmp_path: Path) -> None:
    """{{nodeId.output.field}} in downstream params resolves from upstream output."""
    _bootstrap_silver(tmp_path)
    nodes = [
        {
            "id": "n1",
            "node_type": "check.evidence_exists",
            "params": {"control_id": "SOC2-CC6.1", "minimum": 1},
        },
        {
            "id": "n2",
            "node_type": "action.snapshot",
            "params": {"reason": "evidence_count_was_{{n1.output.matched_count}}"},
        },
    ]
    edges = [{"source": "n1", "target": "n2"}]
    saved = save_workflow(tmp_path, workflow_id=None, name="vars", description="", nodes=nodes, edges=edges)
    run = run_workflow(tmp_path, workflow_id=saved["workflow_id"])
    assert run["result"] == "ok"
    snapshot_node = next(r for r in run["node_results"] if r["node_id"] == "n2")
    # n1 saw 3 evidence rows in _bootstrap_silver; substitution should embed "3".
    assert snapshot_node["params"]["reason"] == "evidence_count_was_3"


def test_run_workflow_respects_conditional_edges(tmp_path: Path) -> None:
    """Edges with condition='failed' only fire when the parent check returns passed=false."""
    _bootstrap_silver(tmp_path)
    nodes = [
        {
            "id": "n1",
            "node_type": "check.evidence_exists",
            "params": {"control_id": "SOC2-CC6.1", "minimum": 99},  # forces passed=false
        },
        {"id": "ok", "node_type": "action.snapshot", "params": {"reason": "passed_branch"}},
        {"id": "fail", "node_type": "action.snapshot", "params": {"reason": "failed_branch"}},
    ]
    edges = [
        {"source": "n1", "target": "ok", "condition": "passed"},
        {"source": "n1", "target": "fail", "condition": "failed"},
    ]
    saved = save_workflow(tmp_path, workflow_id=None, name="cond", description="", nodes=nodes, edges=edges)
    run = run_workflow(tmp_path, workflow_id=saved["workflow_id"])
    by_id = {r["node_id"]: r for r in run["node_results"]}
    assert by_id["n1"]["result"] == "ok"
    assert by_id["ok"]["result"] == "skipped"  # passed branch declined
    assert by_id["fail"]["result"] == "ok"  # failed branch fired


def test_run_workflow_unknown_id_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        run_workflow(tmp_path, workflow_id="not-a-workflow")


def test_get_workflow_returns_latest(tmp_path: Path) -> None:
    nodes, edges = _trivial_dag()
    a = save_workflow(tmp_path, workflow_id=None, name="x", description="", nodes=nodes, edges=edges)
    save_workflow(
        tmp_path,
        workflow_id=a["workflow_id"],
        name="x",
        description="newer",
        nodes=nodes,
        edges=edges,
    )
    found = get_workflow(tmp_path, a["workflow_id"])
    assert found is not None
    assert found["version"] == 2
    assert found["description"] == "newer"


# --- trust share ----------------------------------------------------------------


def test_trust_share_round_trip(tmp_path: Path) -> None:
    share = create_share(tmp_path, role="auditor", scope="posture_full", expires_in_hours=12)
    assert share["token"].startswith("trust_")
    assert share["token_sha256"]
    # listing does not return the raw token
    listed = list_shares(tmp_path)
    assert len(listed) == 1
    assert "token" not in listed[0]
    assert listed[0]["share_id"] == share["share_id"]
    assert listed[0]["expired"] is False


def test_trust_share_rejects_bad_role(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        create_share(tmp_path, role="admin", scope="posture_full")


def test_trust_share_rejects_bad_expiry(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        create_share(tmp_path, role="auditor", scope="posture_full", expires_in_hours=0)
    with pytest.raises(ValueError):
        create_share(tmp_path, role="auditor", scope="posture_full", expires_in_hours=10_000)


def test_revoke_share(tmp_path: Path) -> None:
    share = create_share(tmp_path, role="auditor", scope="posture_full")
    revoked = revoke_share(tmp_path, share["share_id"])
    assert revoked is not None
    assert revoked["revoked_at"]
    assert list_shares(tmp_path) == []  # excluded by default
    assert len(list_shares(tmp_path, include_revoked=True)) == 1


# --- audit log aggregator -------------------------------------------------------


def test_audit_log_aggregates_every_category(tmp_path: Path) -> None:
    append_triage(tmp_path, violation_id="v1", actor="alice", state="triaged")
    append_config_event(tmp_path, connector_id="github-security", state="enabled", actor="alice")
    create_share(tmp_path, role="auditor", scope="posture_full", created_by="alice")
    entries = build_audit_log(tmp_path, limit=10)
    cats = {e["category"] for e in entries}
    assert {"triage", "connector", "trust_share"}.issubset(cats)
    # ordering newest-first
    for prev, current in zip(entries, entries[1:], strict=False):
        assert prev["occurred_at"] >= current["occurred_at"]


def test_audit_log_filters_by_category(tmp_path: Path) -> None:
    append_triage(tmp_path, violation_id="v1", actor="alice", state="triaged")
    append_config_event(tmp_path, connector_id="github-security", state="enabled", actor="alice")
    only = build_audit_log(tmp_path, category="triage")
    assert all(e["category"] == "triage" for e in only)


# --- HTTP integration -----------------------------------------------------------


def _spin_handler(lake: Path) -> ThreadingHTTPServer:
    (lake / "gold").mkdir(parents=True, exist_ok=True)
    (lake / "silver").mkdir(parents=True, exist_ok=True)
    (lake / "console.html").write_bytes(b"<!doctype html>")

    class Handler(_Handler):
        lake_dir = lake
        dashboard_path = lake / "console.html"
        web_dist = None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _request(
    server: ThreadingHTTPServer,
    method: str,
    path: str,
    *,
    body: dict | None = None,
    role: str | None = None,
) -> tuple[int, dict]:
    host, port = server.server_address
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(  # noqa: S310 (local test url)
        f"http://{host}:{port}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    if role:
        req.add_header("X-Trust-Role", role)
    try:
        with urllib.request.urlopen(req) as resp:
            return int(resp.status), json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return int(exc.code), json.loads(exc.read().decode("utf-8"))


def test_workflow_endpoints_round_trip(tmp_path: Path) -> None:
    _bootstrap_silver(tmp_path)
    server = _spin_handler(tmp_path)
    try:
        status, body = _request(server, "GET", "/api/workflows/actions")
        assert status == HTTPStatus.OK
        assert len(body["actions"]) == 11

        nodes, edges = _trivial_dag()
        status, body = _request(
            server,
            "POST",
            "/api/workflows",
            body={"name": "snap soc2", "description": "", "nodes": nodes, "edges": edges},
        )
        assert status == HTTPStatus.CREATED
        workflow_id = body["workflow"]["workflow_id"]

        status, body = _request(server, "GET", f"/api/workflows/{workflow_id}")
        assert status == HTTPStatus.OK
        assert body["workflow_id"] == workflow_id

        status, body = _request(server, "POST", f"/api/workflows/{workflow_id}/run", body={})
        assert status == HTTPStatus.CREATED
        assert body["run"]["result"] == "ok"

        status, body = _request(
            server,
            "POST",
            "/api/workflows/actions/run",
            body={
                "node_type": "check.evidence_exists",
                "params": {"control_id": "SOC2-CC6.1", "minimum": 1},
            },
        )
        assert status == HTTPStatus.CREATED
        assert body["output"]["passed"] is True

        status, body = _request(server, "GET", f"/api/workflows/{workflow_id}/runs")
        assert status == HTTPStatus.OK
        assert len(body["runs"]) == 1
    finally:
        server.shutdown()


def test_trust_share_endpoints(tmp_path: Path) -> None:
    server = _spin_handler(tmp_path)
    try:
        status, body = _request(server, "POST", "/api/trust-shares", body={"role": "auditor", "expires_in_hours": 1})
        assert status == HTTPStatus.CREATED
        share_id = body["share"]["share_id"]
        assert body["share"]["token"].startswith("trust_")

        status, body = _request(server, "GET", "/api/trust-shares")
        assert status == HTTPStatus.OK
        assert body["count"] == 1

        status, body = _request(server, "POST", f"/api/trust-shares/{share_id}/revoke", body={})
        assert status == HTTPStatus.OK
        assert body["share"]["revoked_at"]
    finally:
        server.shutdown()


def test_audit_log_endpoint(tmp_path: Path) -> None:
    append_triage(tmp_path, violation_id="v1", actor="alice", state="triaged")
    server = _spin_handler(tmp_path)
    try:
        status, body = _request(server, "GET", "/api/audit-log?limit=5")
        assert status == HTTPStatus.OK
        assert body["count"] >= 1
        assert body["entries"][0]["category"] == "triage"
    finally:
        server.shutdown()


def test_auditor_role_blocks_workflow_post(tmp_path: Path) -> None:
    server = _spin_handler(tmp_path)
    try:
        status, body = _request(
            server,
            "POST",
            "/api/workflows",
            body={"name": "x", "nodes": [{"id": "n", "node_type": "trigger.cron"}], "edges": []},
            role="auditor",
        )
        assert status == HTTPStatus.FORBIDDEN
        assert body["error"] == "forbidden"
    finally:
        server.shutdown()


def test_workflow_run_has_run_id_and_dry_run_flag(tmp_path: Path) -> None:
    _bootstrap_silver(tmp_path)
    nodes, edges = _trivial_dag()
    saved = save_workflow(tmp_path, workflow_id="dry-run", name="dry", description="", nodes=nodes, edges=edges)
    preview = run_workflow(tmp_path, workflow_id=saved["workflow_id"], dry_run=True)
    assert preview["run_id"]
    assert preview["dry_run"] is True
    live = run_workflow(tmp_path, workflow_id=saved["workflow_id"], dry_run=False)
    assert live["run_id"]
    assert live["dry_run"] is False
    fetched = get_workflow_run(tmp_path, live["run_id"])
    assert fetched is not None
    assert fetched["workflow_id"] == saved["workflow_id"]


def test_workflow_approval_gate_pause_and_resume(tmp_path: Path) -> None:
    _bootstrap_silver(tmp_path)
    nodes = [
        {"id": "t1", "node_type": "trigger.cron", "params": {"schedule": "@hourly"}},
        {"id": "g1", "node_type": "gate.approval", "params": {"title": "Ship it"}},
        {"id": "c1", "node_type": "check.evidence_exists", "params": {"control_id": "SOC2-CC6.1", "minimum": 1}},
    ]
    edges = [
        {"source": "t1", "target": "g1", "condition": "always"},
        {"source": "g1", "target": "c1", "condition": "always"},
    ]
    saved = save_workflow(
        tmp_path, workflow_id="approval-flow", name="approval", description="", nodes=nodes, edges=edges
    )
    paused = run_workflow(tmp_path, workflow_id=saved["workflow_id"])
    assert paused["result"] == "awaiting_approval"
    assert paused["pending_node_id"] == "g1"
    check = next(row for row in paused["node_results"] if row["node_id"] == "c1")
    assert check["result"] == "skipped"
    resumed = approve_workflow_run(tmp_path, run_id=paused["run_id"], actor="console", note="ok")
    assert resumed["result"] == "ok"
    check_after = next(row for row in resumed["node_results"] if row["node_id"] == "c1")
    assert check_after["result"] == "ok"


def test_workflow_approval_gate_reject(tmp_path: Path) -> None:
    _bootstrap_silver(tmp_path)
    nodes = [
        {"id": "t1", "node_type": "trigger.cron", "params": {"schedule": "@hourly"}},
        {"id": "g1", "node_type": "gate.approval", "params": {"title": "Ship it"}},
        {"id": "c1", "node_type": "check.evidence_exists", "params": {"control_id": "SOC2-CC6.1", "minimum": 1}},
    ]
    edges = [
        {"source": "t1", "target": "g1", "condition": "always"},
        {"source": "g1", "target": "c1", "condition": "always"},
    ]
    saved = save_workflow(tmp_path, workflow_id="reject-flow", name="reject", description="", nodes=nodes, edges=edges)
    paused = run_workflow(tmp_path, workflow_id=saved["workflow_id"])
    assert paused["result"] == "awaiting_approval"
    rejected = reject_workflow_run(tmp_path, run_id=paused["run_id"], actor="console", note="no")
    assert rejected["result"] == "rejected"
    check = next(row for row in rejected["node_results"] if row["node_id"] == "c1")
    assert check["result"] == "skipped"


def test_workflow_retry_and_http_inspector(tmp_path: Path) -> None:
    _bootstrap_silver(tmp_path)
    nodes, edges = _trivial_dag()
    saved = save_workflow(tmp_path, workflow_id="retry-me", name="retry", description="", nodes=nodes, edges=edges)
    first = run_workflow(tmp_path, workflow_id=saved["workflow_id"])
    retried = retry_workflow_run(tmp_path, run_id=first["run_id"])
    assert retried["workflow_id"] == saved["workflow_id"]
    assert retried["run_id"] != first["run_id"]

    server = _spin_handler(tmp_path)
    try:
        status, body = _request(server, "GET", f"/api/workflows/runs/{first['run_id']}")
        assert status == HTTPStatus.OK
        assert body["run"]["run_id"] == first["run_id"]

        status, body = _request(
            server,
            "POST",
            f"/api/workflows/{saved['workflow_id']}/run",
            body={"dry_run": True},
        )
        assert status == HTTPStatus.CREATED
        assert body["run"]["dry_run"] is True

        status, body = _request(server, "POST", f"/api/workflows/runs/{first['run_id']}/retry", body={})
        assert status == HTTPStatus.CREATED
        assert body["run"]["workflow_id"] == saved["workflow_id"]
    finally:
        server.shutdown()

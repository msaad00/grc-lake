"""Whole-DAG dry-run preview + expression-based edge routing.

Two capabilities are exercised here:

* ``wf.run_workflow(..., dry_run=True)`` must preview the DAG without performing any
  side effect — no snapshot file written, no triage event appended, no egress.
  Read-only checks still run so branching stays realistic, and the persisted run
  record is marked ``dry_run: true``. With ``dry_run=False`` the same workflow
  behaves exactly as before.
* ``_edge_allows`` accepts safe comparison expressions over the parent node's
  output (``==``, ``!=``, ``>``, ``>=``, ``<``, ``<=``, ``in``) in addition to the
  legacy ``passed``/``failed``/``always`` literals.
"""

from __future__ import annotations

import json
from pathlib import Path

import security_lakehouse.workflows as wf
from security_lakehouse.tracking import list_events

ALLOWLIST_ENV = "GRC_LAKE_WORKFLOW_EGRESS_ALLOWLIST"


def _bootstrap(lake: Path) -> None:
    """Minimal silver+gold layer so checks and snapshot have data to read."""
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
    gold = lake / "gold"
    gold.mkdir(parents=True, exist_ok=True)
    (gold / "control_posture.jsonl").write_text(
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
    (gold / "asset_risk.jsonl").write_text(
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


def _side_effect_dag() -> tuple[list[dict], list[dict]]:
    """A check feeding three side-effecting actions (snapshot/assign_owner/webhook)."""
    nodes = [
        {
            "id": "chk",
            "node_type": "check.evidence_exists",
            "params": {"control_id": "SOC2-CC6.1", "minimum": 1},
        },
        {"id": "snap", "node_type": "action.snapshot", "params": {"reason": "dryrun_test"}},
        {
            "id": "own",
            "node_type": "action.assign_owner",
            "params": {"violation_id": "v-1", "assignee": "alice", "state": "triaged"},
        },
        {
            "id": "hook",
            "node_type": "action.webhook",
            "params": {"url": "https://hooks.example.com/x", "body": "hi"},
        },
    ]
    edges = [
        {"source": "chk", "target": "snap"},
        {"source": "chk", "target": "own"},
        {"source": "chk", "target": "hook"},
    ]
    return nodes, edges


# --- (a) dry-run suppresses every side effect -----------------------------------


def test_dry_run_suppresses_side_effects(monkeypatch, tmp_path: Path) -> None:
    _bootstrap(tmp_path)
    # Egress is allowlisted so a real run *would* try to POST — assert it does not.
    monkeypatch.setenv(ALLOWLIST_ENV, "hooks.example.com")
    egress_calls: list[object] = []
    monkeypatch.setattr(wf, "_http_post", lambda *a, **k: egress_calls.append((a, k)) or {})

    nodes, edges = _side_effect_dag()
    saved = wf.save_workflow(tmp_path, workflow_id=None, name="dry", description="", nodes=nodes, edges=edges)

    run = wf.run_workflow(tmp_path, workflow_id=saved["workflow_id"], dry_run=True)

    assert run["dry_run"] is True
    assert run["result"] == "ok"
    by_id = {r["node_id"]: r for r in run["node_results"]}

    # Read-only check ran for real (branching stays realistic).
    assert by_id["chk"]["result"] == "ok"
    assert by_id["chk"]["output"]["matched_count"] == 3

    # No snapshot file written, and the preview carries dry_run markers.
    assert not (tmp_path / "gold" / "snapshots").exists()
    assert by_id["snap"]["output"]["dry_run"] is True
    assert "would" in by_id["snap"]["output"]
    assert by_id["snap"]["output"]["snapshot_path"] is None

    # No triage event appended.
    assert list_events(tmp_path) == []
    assert by_id["own"]["output"]["dry_run"] is True
    assert by_id["own"]["output"]["tracking_id"] is None

    # No egress.
    assert egress_calls == []
    assert by_id["hook"]["output"]["dry_run"] is True

    # The persisted run is marked dry_run too.
    persisted = [json.loads(line) for line in (tmp_path / "gold" / wf.RUNS_FILE).read_text().splitlines() if line]
    assert persisted[-1]["dry_run"] is True


def test_real_run_still_performs_side_effects(monkeypatch, tmp_path: Path) -> None:
    _bootstrap(tmp_path)
    monkeypatch.setenv(ALLOWLIST_ENV, "hooks.example.com")
    egress_calls: list[object] = []
    monkeypatch.setattr(
        wf,
        "_http_post",
        lambda *a, **k: egress_calls.append((a, k)) or {"status_code": 200, "ok": True},
    )

    nodes, edges = _side_effect_dag()
    saved = wf.save_workflow(tmp_path, workflow_id=None, name="real", description="", nodes=nodes, edges=edges)

    run = wf.run_workflow(tmp_path, workflow_id=saved["workflow_id"])  # default dry_run=False

    assert run["dry_run"] is False
    by_id = {r["node_id"]: r for r in run["node_results"]}

    # Snapshot file written, triage appended, egress called — same as before.
    assert by_id["snap"]["output"]["snapshot_path"].endswith(".json")
    assert "dry_run" not in by_id["snap"]["output"]
    assert len(list_events(tmp_path)) == 1
    assert by_id["own"]["output"]["tracking_id"]
    assert len(egress_calls) == 1


# --- (b) expression-based edge routing ------------------------------------------


def _result(output: dict) -> dict:
    return {"result": "ok", "output": output}


def test_expression_numeric_routes_true_and_false() -> None:
    edge = {"source": "a", "target": "b", "condition": "output.matched_count > 0"}
    assert wf._edge_allows(edge, _result({"matched_count": 3})) is True
    assert wf._edge_allows(edge, _result({"matched_count": 0})) is False


def test_expression_equality_against_status() -> None:
    edge = {"source": "a", "target": "b", "condition": "output.status == 403"}
    assert wf._edge_allows(edge, _result({"status": 403})) is True
    assert wf._edge_allows(edge, _result({"status": 200})) is False
    # The producer may have emitted the status as a string — still matches.
    assert wf._edge_allows(edge, _result({"status": "403"})) is True


def test_expression_boolean_and_inequality() -> None:
    ok_edge = {"condition": "output.ok != true"}
    assert wf._edge_allows(ok_edge, _result({"ok": False})) is True
    assert wf._edge_allows(ok_edge, _result({"ok": True})) is False

    ge_edge = {"condition": "output.matched_count >= 2"}
    assert wf._edge_allows(ge_edge, _result({"matched_count": 2})) is True
    assert wf._edge_allows(ge_edge, _result({"matched_count": 1})) is False


def test_expression_membership_in() -> None:
    edge = {"condition": 'output.result in ["pass", "warn"]'}
    assert wf._edge_allows(edge, _result({"result": "pass"})) is True
    assert wf._edge_allows(edge, _result({"result": "fail"})) is False
    # Comma-list form is also accepted.
    edge2 = {"condition": "output.result in pass, warn"}
    assert wf._edge_allows(edge2, _result({"result": "warn"})) is True


def test_expression_object_form() -> None:
    edge = {"condition": {"expression": "output.matched_count < 5"}}
    assert wf._edge_allows(edge, _result({"matched_count": 3})) is True
    assert wf._edge_allows(edge, _result({"matched_count": 9})) is False


def test_expression_unknown_field_declines_without_crash() -> None:
    edge = {"condition": "output.nope == 1"}
    # Field absent from output -> edge declines, no exception.
    assert wf._edge_allows(edge, _result({"matched_count": 3})) is False
    # Malformed expression -> declines too.
    assert wf._edge_allows({"condition": "output.x ?? 1"}, _result({"x": 1})) is False
    # Parent never completed -> declines.
    assert wf._edge_allows({"condition": "output.matched_count > 0"}, {"result": "error"}) is False


def test_legacy_conditions_unchanged() -> None:
    assert wf._edge_allows({"condition": "always"}, None) is True
    assert wf._edge_allows({}, None) is True  # default is always
    passed_parent = _result({"passed": True})
    failed_parent = _result({"passed": False})
    assert wf._edge_allows({"condition": "passed"}, passed_parent) is True
    assert wf._edge_allows({"condition": "passed"}, failed_parent) is False
    assert wf._edge_allows({"condition": "failed"}, failed_parent) is True
    assert wf._edge_allows({"condition": "failed"}, passed_parent) is False
    # passed/failed still require the parent to have completed ok.
    assert wf._edge_allows({"condition": "passed"}, None) is False


def test_expression_routing_end_to_end(tmp_path: Path) -> None:
    """A real DAG where an expression edge gates a downstream node."""
    _bootstrap(tmp_path)
    nodes = [
        {
            "id": "chk",
            "node_type": "check.evidence_exists",
            "params": {"control_id": "SOC2-CC6.1", "minimum": 1},
        },
        {"id": "fire", "node_type": "action.snapshot", "params": {"reason": "matched"}},
        {"id": "skip", "node_type": "action.snapshot", "params": {"reason": "none"}},
    ]
    edges = [
        {"source": "chk", "target": "fire", "condition": "output.matched_count > 0"},
        {"source": "chk", "target": "skip", "condition": "output.matched_count > 100"},
    ]
    saved = wf.save_workflow(tmp_path, workflow_id=None, name="expr", description="", nodes=nodes, edges=edges)
    run = wf.run_workflow(tmp_path, workflow_id=saved["workflow_id"], dry_run=True)
    by_id = {r["node_id"]: r for r in run["node_results"]}
    assert by_id["fire"]["result"] == "ok"  # matched_count=3 > 0
    assert by_id["skip"]["result"] == "skipped"  # 3 > 100 is false

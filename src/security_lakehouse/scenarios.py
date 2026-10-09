"""Repeatable product scenarios over the GRC Lake lake.

Scenarios are thin orchestration around shipped primitives. They are meant to
prove end-to-end claims against fixtures, cloud shells, or live cloud accounts
without creating a second execution path.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any

from security_lakehouse.assessment import build_current_posture, verify_snapshot_chain, write_assessment_snapshot
from security_lakehouse.connector_runner import ConnectorSyncError, run_connector_sync
from security_lakehouse.connector_state import append_config_event
from security_lakehouse.evidence_provenance import contains_synthetic_evidence
from security_lakehouse.io import read_jsonl, write_json
from security_lakehouse.verification import verify_lake_integrity
from security_lakehouse.workflows import run_workflow, save_workflow

LIVE_CLOUD_SCENARIO = "live-cloud-posture"
DEFAULT_LIVE_CONNECTORS = ("azure-posture", "aws-posture", "snowflake-evidence-lake")
SCENARIO_REPORT = ("gold", "scenario_reports", "live-cloud-posture.json")
SCENARIO_PROOF_PACK = ("gold", "scenario_reports", "live-cloud-posture.md")
SCENARIO_WORKFLOW_ID = "live-cloud-posture-freeze"
SYNTHETIC_NOTICE = "Contains synthetic demonstration evidence; synthetic rows are not production proof."
UNVERIFIED_NOTICE = (
    "No synthetic marker found; provider origin and tenant authorization require independent verification."
)


def parse_fixture_specs(values: list[str] | None) -> dict[str, str]:
    """Parse ``connector_id=path`` fixture specs from the CLI."""
    fixtures: dict[str, str] = {}
    for raw in values or []:
        if "=" not in raw:
            raise ValueError(f"fixture spec must be connector_id=path, got {raw!r}")
        connector_id, path = raw.split("=", 1)
        connector_id = connector_id.strip()
        path = path.strip()
        if not connector_id or not path:
            raise ValueError(f"fixture spec must be connector_id=path, got {raw!r}")
        fixtures[connector_id] = path
    return fixtures


def run_live_cloud_posture_scenario(
    lake_dir: str | Path,
    *,
    connectors: list[str] | tuple[str, ...] | None = None,
    fixture_dirs: dict[str, str] | None = None,
    actor: str = "scenario",
    continue_on_error: bool = False,
) -> dict[str, Any]:
    """Run a live-cloud posture scenario and return a durable report.

    The scenario:

    1. enables selected connectors,
    2. syncs them into the managed raw lake,
    3. verifies evidence integrity/idempotency,
    4. freezes a snapshot and verifies the snapshot chain,
    5. saves and runs a workflow DAG that freezes another snapshot when
       SOC2-CC6.1 evidence exists.
    """
    lake = Path(lake_dir)
    connector_ids = list(connectors or DEFAULT_LIVE_CONNECTORS)
    fixtures = fixture_dirs or {}
    syncs: list[dict[str, Any]] = []

    for connector_id in connector_ids:
        append_config_event(lake, connector_id=connector_id, state="enabled", actor=actor)
        try:
            result = run_connector_sync(
                lake,
                connector_id=connector_id,
                actor=actor,
                fixture_dir=fixtures.get(connector_id),
                materialize=True,
            )
            syncs.append({"connector_id": connector_id, "ok": True, **asdict(result)})
        except ConnectorSyncError as exc:
            entry = {
                "connector_id": connector_id,
                "ok": False,
                "error": str(exc),
                "run": exc.run,
            }
            syncs.append(entry)
            if not continue_on_error:
                report = _scenario_report(
                    lake,
                    actor=actor,
                    connectors=connector_ids,
                    syncs=syncs,
                    integrity=None,
                    snapshot=None,
                    snapshot_chain=None,
                    workflow=None,
                )
                _write_report(lake, report)
                raise

    integrity = verify_lake_integrity(lake)
    snapshot_path = write_assessment_snapshot(lake, reason=f"scenario:{LIVE_CLOUD_SCENARIO}")
    workflow = _run_scenario_workflow(lake, actor=actor)
    snapshot_chain = verify_snapshot_chain(lake)
    report = _scenario_report(
        lake,
        actor=actor,
        connectors=connector_ids,
        syncs=syncs,
        integrity=integrity,
        snapshot=str(snapshot_path),
        snapshot_chain=snapshot_chain,
        workflow=workflow,
    )
    _write_report(lake, report)
    return report


def format_live_cloud_posture_summary(report: dict[str, Any]) -> str:
    """Render the scenario report as a concise operator-facing summary."""
    summary = report.get("summary") or {}
    integrity = report.get("integrity") or {}
    snapshot_chain = report.get("snapshot_chain") or {}
    workflow_run = (report.get("workflow") or {}).get("run") or {}
    source_counts = summary.get("evidence_by_source") or {}
    connector_results = summary.get("connector_results") or []

    lines = [
        f"GRC Lake scenario: {report.get('scenario', LIVE_CLOUD_SCENARIO)}",
        f"Status: {'ok' if summary.get('ok') else 'needs attention'}",
        SYNTHETIC_NOTICE if summary.get("synthetic_fixture") else UNVERIFIED_NOTICE,
        (f"Evidence: {summary.get('evidence_count', 0)} normalized rows from {_format_counts(source_counts)}"),
        (
            "Posture: "
            f"{summary.get('posture_state', 'unknown')} "
            f"score={summary.get('posture_score', 'unknown')} "
            f"open_violations={summary.get('open_violations', 'unknown')} "
            f"frameworks={summary.get('frameworks', 'unknown')}"
        ),
        "Connectors:",
    ]
    for result in connector_results:
        status = "ok" if result.get("ok") else "failed"
        evidence_count = result.get("evidence_count", 0)
        materialized = "materialized" if result.get("materialized") else "raw-only"
        line = f"- {result.get('connector_id')}: {status}, evidence={evidence_count}, {materialized}"
        if not result.get("ok") and result.get("error"):
            line = f"{line}, error={result['error']}"
        lines.append(line)

    lines.extend(
        [
            f"Integrity: {'ok' if integrity.get('ok') else 'not verified'}",
            (
                "Snapshot chain: "
                f"{'ok' if snapshot_chain.get('ok') else 'not verified'} "
                f"length={snapshot_chain.get('length', 0)}"
            ),
            f"Workflow: {workflow_run.get('result', 'not run')}",
            f"Proof pack: {(report.get('artifacts') or {}).get('proof_pack', '')}",
            f"Report: {(report.get('artifacts') or {}).get('report', '')}",
        ]
    )
    return "\n".join(lines)


def _run_scenario_workflow(lake: Path, *, actor: str) -> dict[str, Any]:
    workflow = save_workflow(
        lake,
        workflow_id=SCENARIO_WORKFLOW_ID,
        name="Live cloud posture freeze",
        description="Freeze a snapshot when live cloud evidence for SOC2-CC6.1 exists.",
        actor=actor,
        nodes=[
            {
                "id": "evidence_changed",
                "node_type": "trigger.evidence_changed",
                "params": {},
            },
            {
                "id": "soc2_evidence",
                "node_type": "check.evidence_exists",
                "params": {"control_id": "SOC2-CC6.1", "minimum": 1},
            },
            {
                "id": "freeze_snapshot",
                "node_type": "action.snapshot",
                "params": {"reason": f"workflow:{LIVE_CLOUD_SCENARIO}"},
            },
        ],
        edges=[
            {"source": "evidence_changed", "target": "soc2_evidence"},
            {"source": "soc2_evidence", "target": "freeze_snapshot", "condition": "passed"},
        ],
    )
    run = run_workflow(lake, workflow_id=workflow["workflow_id"], actor="scheduler")
    return {"workflow": workflow, "run": run}


def _scenario_report(
    lake: Path,
    *,
    actor: str,
    connectors: list[str],
    syncs: list[dict[str, Any]],
    integrity: dict[str, Any] | None,
    snapshot: str | None,
    snapshot_chain: dict[str, Any] | None,
    workflow: dict[str, Any] | None,
) -> dict[str, Any]:
    posture = build_current_posture(lake)
    silver_rows = read_jsonl(lake / "silver" / "normalized_events.jsonl", missing_ok=True)
    evidence_by_source = Counter(str(row.get("source") or "") for row in silver_rows if row.get("source"))
    source_breakdown = _source_breakdown(silver_rows)
    workflow_ok = workflow is not None and (workflow.get("run") or {}).get("result") == "ok"
    chain_ok = snapshot_chain is not None and snapshot_chain.get("ok") is True
    connector_results = [_connector_result_summary(sync) for sync in syncs]
    summary = {
        "synthetic_fixture": contains_synthetic_evidence(lake, silver_rows),
        "ok": all(row.get("ok") for row in syncs)
        and bool(integrity and integrity.get("ok"))
        and chain_ok
        and workflow_ok,
        "proof_state": _proof_state(posture),
        "connector_count": len(connector_results),
        "successful_connectors": sum(1 for row in connector_results if row.get("ok")),
        "failed_connectors": sum(1 for row in connector_results if not row.get("ok")),
        "connector_results": connector_results,
        "evidence_count": len(silver_rows),
        "evidence_by_source": dict(sorted(evidence_by_source.items())),
        "sources": sorted({str(row.get("source") or "") for row in silver_rows if row.get("source")}),
        "source_breakdown": source_breakdown,
        "event_type_count": len({str(row.get("event_type") or "") for row in silver_rows if row.get("event_type")}),
        "asset_count": len({str(row.get("asset_id") or "") for row in silver_rows if row.get("asset_id")}),
        "controls_referenced": len(_controls_referenced(silver_rows)),
        "posture_score": posture.get("posture", {}).get("score"),
        "posture_state": posture.get("posture", {}).get("state"),
        "open_violations": posture.get("posture", {}).get("open_violation_count"),
        "critical_violations": posture.get("posture", {}).get("critical_violation_count"),
        "high_violations": posture.get("posture", {}).get("high_violation_count"),
        "frameworks": posture.get("posture", {}).get("framework_count"),
    }
    summary["recommended_actions"] = _recommended_actions(
        summary=summary,
        syncs=syncs,
        integrity=integrity,
        snapshot_chain=snapshot_chain,
        workflow=workflow,
        posture=posture,
    )
    return {
        "schema_version": "trustops.scenario_report.v1",
        "scenario": LIVE_CLOUD_SCENARIO,
        "actor": actor,
        "lake": str(lake),
        "connectors": connectors,
        "syncs": syncs,
        "summary": summary,
        "integrity": integrity,
        "snapshot": snapshot,
        "snapshot_chain": snapshot_chain,
        "workflow": workflow,
        "artifacts": {
            "raw": str(lake / "raw" / "connector_events.jsonl"),
            "bronze": str(lake / "bronze" / "raw_events.jsonl"),
            "silver": str(lake / "silver" / "normalized_events.jsonl"),
            "posture": str(lake / "gold" / "current_posture.json"),
            "integrity": str(lake / "gold" / "evidence_integrity.json"),
            "report": str(lake.joinpath(*SCENARIO_REPORT)),
            "proof_pack": str(lake.joinpath(*SCENARIO_PROOF_PACK)),
        },
    }


def _write_report(lake: Path, report: dict[str, Any]) -> Path:
    path = lake.joinpath(*SCENARIO_REPORT)
    write_json(path, report)
    _write_proof_pack(lake, report)
    return path


def _write_proof_pack(lake: Path, report: dict[str, Any]) -> Path:
    path = lake.joinpath(*SCENARIO_PROOF_PACK)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_format_proof_pack(report), encoding="utf-8")
    return path


def _connector_result_summary(sync: dict[str, Any]) -> dict[str, Any]:
    return {
        "connector_id": sync.get("connector_id"),
        "ok": bool(sync.get("ok")),
        "evidence_count": int(sync.get("evidence_count") or 0),
        "materialized": bool(sync.get("materialized")),
        "error": str(sync.get("error") or "")[:240] if not sync.get("ok") else "",
    }


def _format_counts(counts: dict[str, Any]) -> str:
    if not counts:
        return "no sources"
    return ", ".join(f"{source}={count}" for source, count in sorted(counts.items()))


def _source_breakdown(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_source: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        source = str(row.get("source") or "unknown")
        by_source.setdefault(source, []).append(row)
    breakdown = []
    for source, source_rows in sorted(by_source.items()):
        event_types = Counter(str(row.get("event_type") or "unknown") for row in source_rows)
        severities = Counter(str(row.get("severity") or "unknown") for row in source_rows)
        breakdown.append(
            {
                "source": source,
                "evidence_count": len(source_rows),
                "asset_count": len({str(row.get("asset_id") or "") for row in source_rows if row.get("asset_id")}),
                "control_count": len(_controls_referenced(source_rows)),
                "open_items": sum(1 for row in source_rows if str(row.get("status") or "").lower() == "open"),
                "high_or_critical": sum(
                    1 for row in source_rows if str(row.get("severity") or "").lower() in {"high", "critical"}
                ),
                "top_event_types": [
                    {"event_type": event_type, "count": count} for event_type, count in event_types.most_common(5)
                ],
                "severity_counts": dict(sorted(severities.items())),
            }
        )
    return breakdown


def _controls_referenced(rows: list[dict[str, Any]]) -> set[str]:
    controls: set[str] = set()
    for row in rows:
        raw = row.get("control_ids")
        if isinstance(raw, list):
            controls.update(str(item) for item in raw if str(item).strip())
        elif raw:
            controls.add(str(raw))
    return controls


def _proof_state(posture: dict[str, Any]) -> str:
    current = posture.get("posture") or {}
    if current.get("critical_violation_count", 0):
        return "action_required"
    score = float(current.get("score") or 0)
    if score >= 80:
        return "review_ready"
    if score >= 50:
        return "needs_review"
    return "action_required"


def _recommended_actions(
    *,
    summary: dict[str, Any],
    syncs: list[dict[str, Any]],
    integrity: dict[str, Any] | None,
    snapshot_chain: dict[str, Any] | None,
    workflow: dict[str, Any] | None,
    posture: dict[str, Any],
) -> list[dict[str, str]]:
    actions: list[dict[str, str]] = []
    failed = [row for row in syncs if not row.get("ok")]
    if failed:
        actions.append(
            {
                "priority": "p0",
                "action": "restore_failed_connectors",
                "reason": f"{len(failed)} connector(s) failed; posture is incomplete until every selected source syncs.",
            }
        )
    if not (integrity and integrity.get("ok")):
        actions.append(
            {
                "priority": "p0",
                "action": "repair_evidence_integrity",
                "reason": "Evidence hash/idempotency checks did not pass.",
            }
        )
    if not (snapshot_chain and snapshot_chain.get("ok")):
        actions.append(
            {
                "priority": "p0",
                "action": "repair_snapshot_chain",
                "reason": "Snapshot ledger verification failed or did not run.",
            }
        )
    if not (workflow and (workflow.get("run") or {}).get("result") == "ok"):
        actions.append(
            {
                "priority": "p1",
                "action": "inspect_workflow_run",
                "reason": "The scenario workflow did not complete successfully.",
            }
        )
    if int(summary.get("critical_violations") or 0):
        actions.append(
            {
                "priority": "p0",
                "action": "assign_critical_findings",
                "reason": f"{summary.get('critical_violations')} critical violation(s) are open.",
            }
        )
    elif int(summary.get("open_violations") or 0):
        actions.append(
            {
                "priority": "p1",
                "action": "triage_open_findings",
                "reason": f"{summary.get('open_violations')} open violation(s) need owners or exceptions.",
            }
        )
    if (posture.get("evidence_freshness") or {}).get("stale_count", 0):
        actions.append(
            {
                "priority": "p1",
                "action": "refresh_stale_evidence",
                "reason": f"{(posture.get('evidence_freshness') or {}).get('stale_count')} evidence item(s) are stale.",
            }
        )
    if not actions:
        actions.append(
            {
                "priority": "p2",
                "action": "share_review_pack",
                "reason": "Connectors, integrity, snapshots, and workflow checks are ready for reviewer validation.",
            }
        )
    return actions[:5]


def _format_proof_pack(report: dict[str, Any]) -> str:
    summary = report.get("summary") or {}
    integrity = report.get("integrity") or {}
    snapshot_chain = report.get("snapshot_chain") or {}
    workflow_run = (report.get("workflow") or {}).get("run") or {}
    artifacts = report.get("artifacts") or {}
    lines = [
        "# GRC Lake Live Cloud Proof Pack",
        "",
        f"- Scenario: `{report.get('scenario', LIVE_CLOUD_SCENARIO)}`",
        f"- Status: `{'ok' if summary.get('ok') else 'needs_attention'}`",
        f"- Evidence provenance: {SYNTHETIC_NOTICE if summary.get('synthetic_fixture') else UNVERIFIED_NOTICE}",
        f"- Proof state: `{summary.get('proof_state', 'unknown')}`",
        f"- Evidence: `{summary.get('evidence_count', 0)}` normalized rows across `{len(summary.get('sources') or [])}` source(s)",
        f"- Posture: `{summary.get('posture_state', 'unknown')}` score `{summary.get('posture_score', 'unknown')}`",
        f"- Open violations: `{summary.get('open_violations', 'unknown')}`",
        f"- Snapshot chain: `{'ok' if snapshot_chain.get('ok') else 'not_verified'}` length `{snapshot_chain.get('length', 0)}`",
        f"- Integrity: `{'ok' if integrity.get('ok') else 'not_verified'}`",
        f"- Workflow: `{workflow_run.get('result', 'not_run')}`",
        "",
        "## Connector Results",
        "",
        "| Connector | Status | Evidence | Materialized |",
        "| --- | --- | ---: | --- |",
    ]
    for row in summary.get("connector_results") or []:
        lines.append(
            "| "
            f"`{row.get('connector_id')}` | "
            f"{'ok' if row.get('ok') else 'failed'} | "
            f"{row.get('evidence_count', 0)} | "
            f"{'yes' if row.get('materialized') else 'no'} |"
        )
    lines.extend(
        [
            "",
            "## Source Breakdown",
            "",
            "| Source | Evidence | Assets | Controls | Open | High/Critical |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in summary.get("source_breakdown") or []:
        lines.append(
            "| "
            f"`{row.get('source')}` | "
            f"{row.get('evidence_count', 0)} | "
            f"{row.get('asset_count', 0)} | "
            f"{row.get('control_count', 0)} | "
            f"{row.get('open_items', 0)} | "
            f"{row.get('high_or_critical', 0)} |"
        )
    lines.extend(["", "## Recommended Actions", ""])
    for action in summary.get("recommended_actions") or []:
        lines.append(f"- `{action.get('priority')}` `{action.get('action')}`: {action.get('reason')}")
    lines.extend(
        [
            "",
            "## Durable Artifacts",
            "",
            f"- JSON report: `{artifacts.get('report', '')}`",
            f"- Current posture: `{artifacts.get('posture', '')}`",
            f"- Integrity: `{artifacts.get('integrity', '')}`",
            f"- Silver evidence: `{artifacts.get('silver', '')}`",
            f"- Raw connector events: `{artifacts.get('raw', '')}`",
        ]
    )
    return "\n".join(lines) + "\n"

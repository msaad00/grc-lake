"""Live ingestion status for UI, API, agents, and operators."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from security_lakehouse.connector_health import build_connector_health
from security_lakehouse.connector_state import build_catalog_view, connector_state_reader, list_runs
from security_lakehouse.generations import generation_reader
from security_lakehouse.ingestion_metrics import build_catalog_coverage, build_eval_accuracy
from security_lakehouse.io import count_jsonl, jsonl_field_counts, read_json, read_jsonl
from security_lakehouse.jsontypes import JsonObject
from security_lakehouse.lake_scale import (
    DEFAULT_EVAL_SCHEDULE,
    DEFAULT_SYNC_SCHEDULE,
    WAREHOUSE_ROW_THRESHOLD,
    lake_eval_schedule,
    resolve_materialize_strategy,
)
from security_lakehouse.scheduler import eval_schedule_status


@generation_reader
@connector_state_reader
def build_ingestion_status(lake_dir: str | Path) -> JsonObject:
    """Return one compact status object for the continuous ingestion loop."""
    lake = Path(lake_dir)
    connectors = [_connector_summary(row) for row in build_catalog_view(lake)]
    enabled = [row for row in connectors if row["state"] == "enabled"]
    latest_runs = list_runs(lake, limit=25)
    evidence_count = _silver_evidence_count(lake)
    source_counts = _silver_source_counts(lake)
    stale_count = _stale_evidence_count(lake)
    current_posture = _read_optional_json(lake / "gold" / "current_posture.json", lake)
    integrity = _read_optional_json(lake / "gold" / "evidence_integrity.json", lake)
    proof = _latest_live_cloud_proof(lake)
    failed_connectors = [
        row for row in connectors if row.get("latest_sync", {}).get("result") == "error" or row.get("last_error")
    ]
    never_synced = [row for row in enabled if row.get("latest_sync", {}).get("result") is None]
    health = build_connector_health(lake)
    silent_count = int(health["summary"]["silent"]) + int(health["summary"]["never_succeeded"])
    raw_path = lake / "raw" / "connector_events.jsonl"
    scale = resolve_materialize_strategy(lake, raw_path)
    eval_status = eval_schedule_status(lake)
    scale_with_eval = {**scale, **eval_status}
    state = _overall_state(
        enabled=enabled,
        evidence_count=evidence_count,
        failed_connectors=failed_connectors,
        never_synced=never_synced,
        stale_count=stale_count,
        integrity=integrity,
    )
    eval_accuracy = build_eval_accuracy(lake)
    catalog_coverage = build_catalog_coverage(connectors=connectors)
    return {
        "state": state,
        "summary": {
            "connector_count": len(connectors),
            "enabled_connectors": len(enabled),
            "failed_connectors": len(failed_connectors),
            "never_synced_connectors": len(never_synced),
            "evidence_count": evidence_count,
            "source_count": len(source_counts),
            "stale_evidence": stale_count,
            "silent_connectors": silent_count,
            "posture_score": (current_posture.get("posture") or {}).get("score"),
            "posture_state": (current_posture.get("posture") or {}).get("state"),
            "open_violations": (current_posture.get("posture") or {}).get("open_violation_count"),
        },
        "sources": [{"source": source, "evidence_count": count} for source, count in sorted(source_counts.items())],
        "connectors": connectors,
        "health": health,
        "latest_runs": [_run_summary(row) for row in latest_runs],
        "pipeline": _pipeline_artifacts(lake),
        "integrity": _integrity_summary(integrity),
        "proof": proof,
        "recommended_actions": _recommended_actions(
            state=state,
            enabled=enabled,
            failed_connectors=failed_connectors,
            never_synced=never_synced,
            stale_count=stale_count,
            silent_count=silent_count,
            proof=proof,
            current_posture=current_posture,
            scale=scale_with_eval,
            eval_accuracy=eval_accuracy,
        ),
        "eval_accuracy": eval_accuracy,
        "catalog_coverage": catalog_coverage,
        "scale": {
            **scale,
            "eval_schedule": lake_eval_schedule(lake),
            "default_sync_schedule": DEFAULT_SYNC_SCHEDULE,
            "default_eval_schedule": DEFAULT_EVAL_SCHEDULE,
            "warehouse_row_threshold": WAREHOUSE_ROW_THRESHOLD,
            "latest_eval": _latest_eval_run(lake),
            **eval_schedule_status(lake),
            "manifest": _manifest_summary(lake),
        },
    }


def _latest_eval_run(lake: Path) -> JsonObject:
    from security_lakehouse.lake_eval import list_eval_runs

    rows = list_eval_runs(lake, limit=1)
    return rows[0] if rows else {}


def _manifest_summary(lake: Path) -> JsonObject:
    manifest = _read_optional_json(lake / "manifest.json", lake)
    if not manifest:
        return {}
    return {
        "materialize_mode": manifest.get("materialize_mode"),
        "delta_count": manifest.get("delta_count"),
        "removed_count": manifest.get("removed_count"),
        "row_counts": manifest.get("row_counts") or {},
    }


def _read_optional_json(path: Path, lake: Path) -> JsonObject:
    if not path.is_file():
        return {}
    try:
        payload = read_json(path, base_dir=lake)
    except (OSError, json.JSONDecodeError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _connector_summary(row: JsonObject) -> JsonObject:
    latest_sync = _run_summary(row.get("last_sync") or {})
    latest_probe = _run_summary(row.get("last_probe") or {})
    return {
        "connector_id": row.get("connector_id"),
        "name": row.get("name"),
        "category": row.get("category"),
        "state": row.get("state", "disabled"),
        "production_status": row.get("production_status"),
        "collection_mode": row.get("collection_mode"),
        "access_boundary": row.get("access_boundary"),
        "freshness_slo_minutes": row.get("freshness_slo_minutes"),
        "freshness_state": row.get("freshness_state"),
        "last_sync_at": row.get("last_sync_at"),
        "next_run_at": row.get("next_run_at"),
        "latest_sync": latest_sync,
        "latest_probe": latest_probe,
        "last_successful_sync": _run_summary(row.get("last_successful_sync") or {}),
        "last_error": latest_sync.get("error"),
    }


def _run_summary(row: JsonObject) -> JsonObject:
    if not row:
        return {"result": None}
    return {
        "connector_id": row.get("connector_id"),
        "kind": row.get("kind"),
        "result": row.get("result"),
        "occurred_at": row.get("occurred_at"),
        "duration_ms": row.get("duration_ms"),
        "evidence_count": row.get("evidence_count"),
        "error": row.get("error"),
    }


def _manifest_row_counts(lake: Path) -> dict[str, int]:
    manifest = _read_optional_json(lake / "manifest.json", lake)
    row_counts = manifest.get("row_counts")
    if isinstance(row_counts, dict):
        return {str(key): int(value) for key, value in row_counts.items() if isinstance(value, (int, float))}
    return {}


def _silver_evidence_count(lake: Path) -> int:
    counts = _manifest_row_counts(lake)
    if "silver" in counts:
        return counts["silver"]
    return count_jsonl(lake / "silver" / "normalized_events.jsonl", missing_ok=True, base_dir=lake)


def _silver_source_counts(lake: Path) -> Counter[str]:
    return jsonl_field_counts(
        lake / "silver" / "normalized_events.jsonl",
        "source",
        missing_ok=True,
        base_dir=lake,
    )


def _stale_evidence_count(lake: Path) -> int:
    return sum(
        1
        for row in read_jsonl(lake / "gold" / "evidence_freshness.jsonl", missing_ok=True, base_dir=lake)
        if str(row.get("status") or "") in {"stale", "expired", "missing"}
    )


def _pipeline_artifacts(lake: Path) -> list[JsonObject]:
    manifest_counts = _manifest_row_counts(lake)
    artifacts = [
        ("raw_events", lake / "raw" / "connector_events.jsonl"),
        ("bronze_events", lake / "bronze" / "raw_events.jsonl"),
        ("normalized_events", lake / "silver" / "normalized_events.jsonl"),
        ("control_posture", lake / "gold" / "control_posture.jsonl"),
        ("control_tests", lake / "gold" / "control_tests.jsonl"),
        ("asset_risk", lake / "gold" / "asset_risk.jsonl"),
        ("evidence_freshness", lake / "gold" / "evidence_freshness.jsonl"),
        ("workflow_runs", lake / "gold" / "workflow_runs.jsonl"),
    ]
    manifest_keys = {
        "raw_events": "raw",
        "bronze_events": "bronze",
        "normalized_events": "silver",
        "control_posture": "gold_control_posture",
        "control_tests": "gold_control_tests",
        "asset_risk": "gold_asset_risk",
        "evidence_freshness": "gold_evidence_freshness",
    }
    out = []
    for name, path in artifacts:
        count = None
        if path.suffix == ".jsonl":
            manifest_key = manifest_keys.get(name)
            if manifest_key and manifest_key in manifest_counts:
                count = manifest_counts[manifest_key]
            else:
                count = count_jsonl(path, missing_ok=True, base_dir=lake)
        out.append({"name": name, "path": str(path), "exists": path.is_file(), "row_count": count})
    return out


def _integrity_summary(payload: JsonObject) -> JsonObject:
    if not payload:
        return {"ok": None}
    return {
        "ok": payload.get("ok"),
        "evidence_count": payload.get("evidence_count"),
        "unique_event_ids": payload.get("unique_event_ids"),
        "duplicate_event_ids": payload.get("duplicate_event_ids"),
        "raw_sha256": payload.get("raw_sha256"),
    }


def _latest_live_cloud_proof(lake: Path) -> JsonObject:
    report_path = lake / "gold" / "scenario_reports" / "live-cloud-posture.json"
    proof_path = lake / "gold" / "scenario_reports" / "live-cloud-posture.md"
    report = _read_optional_json(report_path, lake)
    summary = report.get("summary")
    if not isinstance(summary, dict):
        summary = {}
    return {
        "report_path": str(report_path),
        "report_exists": report_path.is_file(),
        "proof_pack_path": str(proof_path),
        "proof_pack_exists": proof_path.is_file(),
        "scenario": report.get("scenario"),
        "status": "ok" if summary.get("ok") else ("needs_attention" if report else "not_run"),
        "proof_state": summary.get("proof_state"),
        "evidence_count": summary.get("evidence_count"),
        "sources": summary.get("sources") or [],
        "open_violations": summary.get("open_violations"),
        "recommended_actions": summary.get("recommended_actions") or [],
    }


def _overall_state(
    *,
    enabled: list[JsonObject],
    evidence_count: int,
    failed_connectors: list[JsonObject],
    never_synced: list[JsonObject],
    stale_count: int,
    integrity: JsonObject,
) -> str:
    if not enabled and evidence_count == 0:
        return "needs_configuration"
    if failed_connectors or integrity.get("ok") is False:
        return "error"
    if never_synced or stale_count:
        return "attention_required"
    if evidence_count:
        return "active"
    return "needs_data"


def _recommended_actions(
    *,
    state: str,
    enabled: list[JsonObject],
    failed_connectors: list[JsonObject],
    never_synced: list[JsonObject],
    stale_count: int,
    silent_count: int,
    proof: JsonObject,
    current_posture: JsonObject,
    scale: JsonObject,
    eval_accuracy: JsonObject | None = None,
) -> list[JsonObject]:
    actions: list[JsonObject] = []
    if scale.get("eval_overdue"):
        actions.append(
            {
                "priority": "p1",
                "action": "run_lake_eval",
                "reason": "Lake evaluation is overdue — posture and control tests may be stale.",
            }
        )
    if eval_accuracy and int(eval_accuracy.get("failing") or 0) > 0:
        actions.append(
            {
                "priority": "p1",
                "action": "triage_failing_control_tests",
                "reason": f"{int(eval_accuracy['failing'])} control test(s) failing after the latest eval.",
            }
        )
    if scale.get("mode") == "warehouse_required":
        actions.append(
            {
                "priority": "p0",
                "action": "configure_warehouse_sink",
                "reason": str(scale.get("recommendation") or "Warehouse sink required above 100k events."),
            }
        )
    if silent_count:
        actions.append(
            {
                "priority": "p0",
                "action": "investigate_silent_connectors",
                "reason": (
                    f"{silent_count} enabled connector(s) have no successful sync within their freshness SLO "
                    "(silent failure) — evidence is going stale without anyone being told."
                ),
            }
        )
    if state == "needs_configuration":
        actions.append(
            {
                "priority": "p0",
                "action": "configure_read_only_source",
                "reason": "No enabled connector or normalized evidence exists.",
            }
        )
    if failed_connectors:
        actions.append(
            {
                "priority": "p0",
                "action": "restore_failed_connectors",
                "reason": f"{len(failed_connectors)} connector sync(s) failed.",
            }
        )
    if never_synced:
        actions.append(
            {
                "priority": "p1",
                "action": "run_initial_sync",
                "reason": f"{len(never_synced)} enabled connector(s) have not synced yet.",
            }
        )
    if stale_count:
        actions.append(
            {
                "priority": "p1",
                "action": "refresh_stale_evidence",
                "reason": f"{stale_count} evidence item(s) are stale, expired, or missing.",
            }
        )
    posture = current_posture.get("posture") or {}
    open_violations = int(posture.get("open_violation_count") or 0)
    if open_violations:
        actions.append(
            {
                "priority": "p1",
                "action": "triage_open_findings",
                "reason": f"{open_violations} open violation(s) need owners or exceptions.",
            }
        )
    if enabled and not proof.get("proof_pack_exists"):
        actions.append(
            {
                "priority": "p2",
                "action": "run_live_cloud_proof",
                "reason": "No live-cloud proof pack is available for reviewer handoff.",
            }
        )
    if not actions:
        actions.append(
            {
                "priority": "p2",
                "action": "share_latest_proof_pack",
                "reason": "Ingestion, integrity, and proof artifacts are ready for review.",
            }
        )
    return actions[:5]

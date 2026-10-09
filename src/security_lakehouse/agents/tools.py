"""Typed GRC Lake tools exposed to the optional agent harness."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from security_lakehouse.assessment import build_current_posture
from security_lakehouse.data_policy import redact_payload
from security_lakehouse.io import read_jsonl

ARTIFACT_RELATIVE_PATHS = {
    "silver.normalized_events": "silver/normalized_events.jsonl",
    "gold.control_tests": "gold/control_tests.jsonl",
    "gold.control_posture": "gold/control_posture.jsonl",
    "gold.evidence_freshness": "gold/evidence_freshness.jsonl",
}

REQUIRED_ARTIFACTS_BY_HARNESS = {
    "soc_triage": ("silver.normalized_events",),
    "posture_review": ("gold.control_tests", "silver.normalized_events"),
}


def _agent_cli_name(harness: str) -> str:
    return harness.replace("_", "-")


def _readiness_next_steps(*, status: str, missing: list[str], harness: str) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    if status == "lake_ready":
        return [
            {
                "action": "run_harness",
                "label": "Run the selected harness against the existing tenant lake.",
                "command": f"grc-lake agents {_agent_cli_name(harness)} --lake <lake> --role read_only",
            }
        ]

    if "silver.normalized_events" in missing:
        steps.extend(
            [
                {
                    "action": "inspect_connectors",
                    "label": "List read-only connectors that can land normalized evidence.",
                    "command": "grc-lake connectors list --lake <lake>",
                },
                {
                    "action": "enable_connector",
                    "label": "Enable a configured read-only connector for this lake.",
                    "command": (
                        "grc-lake connectors configure --lake <lake> --connector-id <connector_id> --state enabled"
                    ),
                },
                {
                    "action": "sync_connector",
                    "label": "Sync the selected connector into bronze, silver, and gold artifacts.",
                    "command": "grc-lake connectors sync --lake <lake> --connector-id <connector_id>",
                },
            ]
        )

    if any(name.startswith("gold.") for name in missing):
        steps.append(
            {
                "action": "materialize_control_evidence",
                "label": "Run the deterministic pipeline to materialize control artifacts from raw evidence.",
                "command": "grc-lake pipeline run --raw <raw_events.jsonl> --out <lake>",
            }
        )

    if status == "needs_ingestion":
        steps.append(
            {
                "action": "load_demo_lake",
                "label": "Load fixture data for demos only; do not use this as production evidence.",
                "command": "grc-lake fixtures load --company fintech --out <lake>",
                "demo_only": True,
            }
        )

    return steps


def assess_data_readiness(lake_dir: str | Path, *, role: str, harness: str) -> dict[str, Any]:
    """Decide whether the tenant/account lake already has enough facts.

    The harness should not blindly call a model or propose work when the lake is
    empty. This deterministic preflight tells humans and headless callers
    whether to use existing normalized data or run ingestion/connectors first.
    """
    lake = Path(lake_dir)
    artifacts = {name: lake / relative for name, relative in ARTIFACT_RELATIVE_PATHS.items()}
    counts = {name: len(read_jsonl(path, missing_ok=True)) for name, path in artifacts.items()}
    required = REQUIRED_ARTIFACTS_BY_HARNESS.get(harness, REQUIRED_ARTIFACTS_BY_HARNESS["posture_review"])
    missing = [name for name in required if counts.get(name, 0) == 0]
    if not missing:
        status = "lake_ready"
        next_action = "use_existing_security_data_lake"
    elif any(counts.values()):
        status = "partial_lake"
        next_action = "run_targeted_ingestion_or_control_evaluation"
    else:
        status = "needs_ingestion"
        next_action = "configure_read_only_connectors_or_load_existing_lake_exports"
    artifact_status = [
        {
            "artifact": name,
            "relative_path": ARTIFACT_RELATIVE_PATHS[name],
            "rows": counts[name],
            "required": name in required,
            "present": counts[name] > 0,
        }
        for name in ARTIFACT_RELATIVE_PATHS
    ]
    payload = {
        "account_scope": "tenant_lake",
        "data_source_mode": "existing_lake",
        "harness": harness,
        "status": status,
        "ready_for_harness": status == "lake_ready",
        "required_artifacts": list(required),
        "artifact_status": artifact_status,
        "artifact_counts": counts,
        "missing_required_artifacts": missing,
        "next_action": next_action,
        "recommended_next_steps": _readiness_next_steps(status=status, missing=missing, harness=harness),
    }
    redacted = redact_payload(payload, role=role)
    return redacted if isinstance(redacted, dict) else payload


def load_redacted_posture(lake_dir: str | Path, *, role: str) -> dict[str, Any]:
    """Read current posture through the same role redaction used by the API."""
    posture = build_current_posture(Path(lake_dir))
    redacted = redact_payload(posture, role=role)
    return redacted if isinstance(redacted, dict) else {}


def load_evidence_gaps(lake_dir: str | Path, *, role: str) -> list[dict[str, Any]]:
    """Return controls with missing, stale, or expired evidence."""
    rows = read_jsonl(Path(lake_dir) / "gold" / "control_tests.jsonl", missing_ok=True)
    gaps: list[dict[str, Any]] = []
    for row in rows:
        missing = row.get("missing_evidence_types") or []
        stale = row.get("stale_evidence_types") or []
        expired = row.get("expired_evidence_types") or []
        if not (missing or stale or expired):
            continue
        gap = {
            "control_id": row.get("control_id"),
            "framework": row.get("framework"),
            "status": row.get("status"),
            "owner": row.get("owner"),
            "missing_evidence_types": missing,
            "stale_evidence_types": stale,
            "expired_evidence_types": expired,
            "freshness_status": row.get("freshness_status"),
        }
        redacted = redact_payload(gap, role=role)
        if isinstance(redacted, dict):
            gaps.append(redacted)
    return gaps


def propose_evidence_gap_actions(gaps: list[dict[str, Any]], *, limit: int = 10) -> list[dict[str, Any]]:
    """Build deterministic, approval-required action proposals."""
    proposals: list[dict[str, Any]] = []
    for gap in gaps[:limit]:
        control_id = str(gap.get("control_id") or "")
        missing = gap.get("missing_evidence_types") or []
        stale = gap.get("stale_evidence_types") or []
        expired = gap.get("expired_evidence_types") or []
        reason_parts = []
        if missing:
            reason_parts.append(f"missing {', '.join(str(item) for item in missing)}")
        if stale:
            reason_parts.append(f"stale {', '.join(str(item) for item in stale)}")
        if expired:
            reason_parts.append(f"expired {', '.join(str(item) for item in expired)}")
        proposals.append(
            {
                "action": "create_evidence_request",
                "control_id": control_id,
                "reason": "; ".join(reason_parts) or "evidence gap",
                "requires_approval": True,
                "status": "proposed",
            }
        )
    return proposals

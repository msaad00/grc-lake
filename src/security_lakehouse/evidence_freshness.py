"""Evidence freshness evaluation.

Continuous posture is only useful when the evidence feeding it is current.
This module turns normalized evidence rows into explicit freshness records
using source-specific connector SLOs where available.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from security_lakehouse.connectors import load_connector_catalog
from security_lakehouse.models import parse_event_time, utc_iso

STALE_STATUSES = {"stale", "expired", "missing"}
STATUS_SCORES = {"fresh": 100, "stale": 30, "expired": 0, "missing": 0}

SOURCE_CONNECTOR_ALIASES = {
    "audit-log": "snowflake-evidence-lake",
    "aws": "aws-posture",
    "azure": "azure-posture",
    "cloud-cspm": "object-storage-evidence",
    "compliance-export": "snowflake-evidence-lake",
    "gcp": "gcp-posture",
    "github": "github-security",
    "github-public-repo": "github-security",
    "github-repo-governance": "github-security",
    "gitlab": "gitlab-security",
    "gitlab-repo-governance": "gitlab-security",
    "google_workspace": "google-workspace-identity",
    "google-workspace": "google-workspace-identity",
    "identity-provider": "identity-provider",
    "model-registry": "object-storage-evidence",
    "okta": "okta-identity",
    "runtime-gateway": "runtime-gateway",
    "scanner": "object-storage-evidence",
    "siem": "siem-alerts",
    "ticketing": "ticketing",
}


def build_evidence_freshness(
    rows: list[dict[str, Any]],
    *,
    now: datetime | None = None,
    default_slo_minutes: int = 60 * 24 * 7,
    connectors: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return one freshness record per normalized evidence row."""
    evaluated_at = (now or datetime.now(UTC)).astimezone(UTC)
    connectors = load_connector_catalog() if connectors is None else connectors
    records = [
        _freshness_record(
            row,
            connectors=connectors,
            evaluated_at=evaluated_at,
            default_slo_minutes=default_slo_minutes,
        )
        for row in rows
    ]
    return sorted(records, key=lambda item: (item["status"], item["source"], item["event_id"]))


def summarize_source_freshness(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate freshness health by source for posture and UI filters."""
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[str(record["source"])].append(record)

    out: list[dict[str, Any]] = []
    for source, items in grouped.items():
        statuses = Counter(str(item["status"]) for item in items)
        latest = max(str(item.get("evidence_collected_at") or "") for item in items)
        stale_count = sum(statuses[status] for status in STALE_STATUSES)
        status = _source_status(statuses)
        out.append(
            {
                "source": source,
                "connector_id": str(items[0].get("connector_id") or "unknown"),
                "fresh_count": statuses["fresh"],
                "stale_count": statuses["stale"],
                "expired_count": statuses["expired"],
                "missing_count": statuses["missing"],
                "evidence_count": len(items),
                "latest_evidence_at": latest or None,
                "freshness_slo_minutes": int(items[0].get("freshness_slo_minutes") or 0),
                "state": "current" if stale_count == 0 else "action_required",
                "status": status,
                "next_action": _next_action(status, source),
            }
        )
    return sorted(out, key=lambda item: (-int(item["stale_count"]), item["source"]))


def summarize_control_freshness(
    events: list[dict[str, Any]],
    *,
    required_evidence_types: list[str],
    now: datetime | None = None,
    default_slo_minutes: int = 60 * 24 * 7,
    connectors: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Evaluate required evidence types for a control test."""
    evaluated_at = (now or datetime.now(UTC)).astimezone(UTC)
    freshness_rows = build_evidence_freshness(
        events,
        now=evaluated_at,
        default_slo_minutes=default_slo_minutes,
        connectors=connectors,
    )
    latest_by_type: dict[str, dict[str, Any]] = {}
    for row in freshness_rows:
        for event_type in _record_evidence_types(row):
            current = latest_by_type.get(event_type)
            if current is None or str(row.get("evidence_collected_at") or "") > str(
                current.get("evidence_collected_at") or ""
            ):
                latest_by_type[event_type] = row

    required = [str(item) for item in required_evidence_types]
    if not required:
        return _untyped_control_freshness(freshness_rows, default_slo_minutes)
    missing = [event_type for event_type in required if event_type not in latest_by_type]
    stale = [
        event_type
        for event_type in required
        if event_type in latest_by_type and latest_by_type[event_type]["status"] == "stale"
    ]
    expired = [
        event_type
        for event_type in required
        if event_type in latest_by_type and latest_by_type[event_type]["status"] == "expired"
    ]
    if missing and len(missing) == len(required):
        status = "missing"
    elif expired:
        status = "expired"
    elif stale or missing:
        status = "stale"
    else:
        status = "fresh"

    scores = [STATUS_SCORES[str(latest_by_type[item]["status"])] for item in required if item in latest_by_type]
    scores.extend(0 for _ in missing)
    latest_values = [str(row.get("evidence_collected_at") or "") for row in latest_by_type.values()]
    return {
        "status": status,
        "score": int(round(sum(scores) / len(scores))) if scores else 0,
        "latest_evidence_at": max(latest_values) if latest_values else None,
        "freshness_slo_minutes": default_slo_minutes,
        "missing_evidence_types": sorted(missing),
        "stale_evidence_types": sorted(stale),
        "expired_evidence_types": sorted(expired),
    }


def _untyped_control_freshness(freshness_rows: list[dict[str, Any]], default_slo_minutes: int) -> dict[str, Any]:
    # With no configured evidence types, the control is only as fresh as its newest evidence row.
    dated = [row for row in freshness_rows if row["status"] != "missing"]
    if not dated:
        return {
            "status": "missing",
            "score": STATUS_SCORES["missing"],
            "latest_evidence_at": None,
            "freshness_slo_minutes": default_slo_minutes,
            "missing_evidence_types": [],
            "stale_evidence_types": [],
            "expired_evidence_types": [],
        }
    latest = max(dated, key=lambda row: str(row.get("evidence_collected_at") or ""))
    status = str(latest["status"])
    latest_types = sorted(set(_record_evidence_types(latest)))
    return {
        "status": status,
        "score": STATUS_SCORES[status],
        "latest_evidence_at": str(latest.get("evidence_collected_at") or "") or None,
        "freshness_slo_minutes": default_slo_minutes,
        "missing_evidence_types": [],
        "stale_evidence_types": latest_types if status == "stale" else [],
        "expired_evidence_types": latest_types if status == "expired" else [],
    }


def stale_control_ids(records: list[dict[str, Any]]) -> set[str]:
    """Return controls touched by stale, expired, or missing evidence rows."""
    controls: set[str] = set()
    for record in records:
        if record["status"] not in STALE_STATUSES:
            continue
        controls.update(str(item) for item in record.get("control_ids", []))
    return controls


def _freshness_record(
    row: dict[str, Any],
    *,
    connectors: dict[str, dict[str, Any]],
    evaluated_at: datetime,
    default_slo_minutes: int,
) -> dict[str, Any]:
    source = str(row.get("source") or "unknown")
    connector_id = _connector_id_for_source(source, connectors)
    connector = connectors.get(connector_id, {})
    slo_minutes = int(connector.get("freshness_slo_minutes") or default_slo_minutes)
    collected_at_raw = str(row.get("evidence_collected_at") or row.get("event_time") or "")
    has_evidence = bool(str(row.get("evidence_ref") or ""))

    if not collected_at_raw or not has_evidence:
        return {
            **_base_record(row, connector_id, evaluated_at, slo_minutes),
            "status": "missing",
            "score": STATUS_SCORES["missing"],
            "age_minutes": None,
            "expires_at": None,
            "reason": "evidence_ref or evidence_collected_at is missing",
            "next_action": _next_action("missing", source),
        }

    collected_at = parse_event_time(collected_at_raw).astimezone(UTC)
    age_minutes = max(0, int((evaluated_at - collected_at).total_seconds() // 60))
    expires_at = collected_at + timedelta(minutes=slo_minutes)
    if age_minutes <= slo_minutes:
        status = "fresh"
    elif age_minutes <= slo_minutes * 2:
        status = "stale"
    else:
        status = "expired"
    return {
        **_base_record(row, connector_id, evaluated_at, slo_minutes),
        "status": status,
        "score": STATUS_SCORES[status],
        "age_minutes": age_minutes,
        "expires_at": utc_iso(expires_at),
        "reason": _reason(status, source, slo_minutes),
        "next_action": _next_action(status, source),
    }


def _base_record(
    row: dict[str, Any],
    connector_id: str,
    evaluated_at: datetime,
    freshness_slo_minutes: int,
) -> dict[str, Any]:
    return {
        "event_id": str(row.get("event_id") or ""),
        "evidence_id": str(row.get("evidence_id") or row.get("event_id") or ""),
        "evidence_ref": str(row.get("evidence_ref") or ""),
        "source": str(row.get("source") or "unknown"),
        "connector_id": connector_id,
        "event_type": str(row.get("event_type") or ""),
        "evidence_types": _record_evidence_types(row),
        "asset_id": str(row.get("asset_id") or ""),
        "control_ids": [str(item) for item in row.get("control_ids", [])],
        "evidence_collected_at": str(row.get("evidence_collected_at") or ""),
        "evaluated_at": utc_iso(evaluated_at),
        "freshness_slo_minutes": freshness_slo_minutes,
    }


def _record_evidence_types(row: dict[str, Any]) -> list[str]:
    evidence_types = row.get("evidence_types")
    if isinstance(evidence_types, list):
        return [str(item) for item in evidence_types if str(item)]
    event_type = str(row.get("event_type") or "")
    return [event_type] if event_type else []


def _connector_id_for_source(source: str, connectors: dict[str, dict[str, Any]]) -> str:
    if source in connectors:
        return source
    if source in SOURCE_CONNECTOR_ALIASES:
        return SOURCE_CONNECTOR_ALIASES[source]
    normalized = source.replace("_", "-")
    if normalized in connectors:
        return normalized
    return "managed-local-evidence"


def _reason(status: str, source: str, slo_minutes: int) -> str:
    if status == "fresh":
        return f"{source} evidence is within the {slo_minutes} minute freshness SLO"
    if status == "stale":
        return f"{source} evidence exceeded the {slo_minutes} minute freshness SLO"
    return f"{source} evidence exceeded twice the {slo_minutes} minute freshness SLO"


def _source_status(statuses: Counter[str]) -> str:
    if statuses["expired"]:
        return "expired"
    if statuses["missing"]:
        return "missing"
    if statuses["stale"]:
        return "stale"
    return "fresh"


def _next_action(status: str, source: str) -> str:
    if status == "fresh":
        return "keep monitoring evidence freshness and source health"
    if status == "missing":
        return f"request missing {source} evidence and confirm collection metadata"
    if status == "expired":
        return f"recollect expired {source} evidence and rerun affected control tests"
    return f"refresh stale {source} evidence and rerun affected control tests"


def build_freshness_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate SLA breach counts for audit room and headless automation."""
    statuses = Counter(str(row.get("status") or "unknown") for row in records)
    stale_rows = [row for row in records if str(row.get("status") or "") in STALE_STATUSES]
    total = len(records)
    fresh_count = int(statuses.get("fresh", 0))
    stale_count = int(statuses.get("stale", 0))
    expired_count = int(statuses.get("expired", 0))
    missing_count = int(statuses.get("missing", 0))
    breach_count = len(stale_rows)
    fresh_rate = round(100 * fresh_count / total, 1) if total else 100.0
    sources = summarize_source_freshness(records)
    action_sources = [row for row in sources if row.get("state") == "action_required"]
    return {
        "total": total,
        "fresh_count": fresh_count,
        "stale_count": stale_count,
        "expired_count": expired_count,
        "missing_count": missing_count,
        "sla_breach_count": breach_count,
        "fresh_rate_pct": fresh_rate,
        "state": "healthy" if breach_count == 0 else "action_required",
        "sources": sources,
        "sources_needing_action": len(action_sources),
        "top_breaches": [
            {
                "event_id": row.get("event_id"),
                "source": row.get("source"),
                "status": row.get("status"),
                "age_minutes": row.get("age_minutes"),
                "reason": row.get("reason"),
                "next_action": row.get("next_action"),
                "control_ids": row.get("control_ids") or [],
            }
            for row in stale_rows[:25]
        ],
    }


__all__ = [
    "STALE_STATUSES",
    "build_evidence_freshness",
    "build_freshness_summary",
    "stale_control_ids",
    "summarize_control_freshness",
    "summarize_source_freshness",
]

"""Unified workbench activity stream.

Aggregates posture-changing events from every append-only log in
``gold/`` into a single, sortable, filterable stream the UI renders at
``/audit-log``. Categories:

    triage         violation triage events (gold/violation_tracking.jsonl)
    connector      connector config / probe / sync events
                       (gold/connector_config.jsonl + connector_runs.jsonl)
    snapshot       point-in-time snapshot freezes (gold/snapshots/)
    workflow       workflow runs (gold/workflow_runs.jsonl)
    trust_share    trust portal share create / revoke (gold/trust_shares.jsonl)
    mapping_review operator actions on the mapping-review decision log, such as
                   re-signing its tip after a key rotation
                   (gold/mapping_review_audit.jsonl)

Request authorization decisions are also available with ``category="request"``
for security debugging, but are excluded from the default activity stream so
routine page loads do not drown out trust-center events.

Every entry has the same shape so the UI table is a single render path.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from security_lakehouse.auth.request_audit import REQUEST_AUDIT_FILE
from security_lakehouse.connector_state import CONFIG_FILE as CONNECTOR_CONFIG_FILE
from security_lakehouse.connector_state import RUNS_FILE as CONNECTOR_RUNS_FILE
from security_lakehouse.io import iter_jsonl
from security_lakehouse.models import instant_sort_key
from security_lakehouse.trust_share import SHARES_FILE as TRUST_SHARES_FILE
from security_lakehouse.workflows import RUNS_FILE as WORKFLOW_RUNS_FILE

TRIAGE_FILE = "violation_tracking.jsonl"
MAPPING_REVIEW_AUDIT_FILE = "mapping_review_audit.jsonl"
SNAPSHOTS_DIR = "snapshots"


def _gold(lake_dir: str | Path) -> Path:
    return Path(lake_dir) / "gold"


def _read_log(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return list(iter_jsonl(path, missing_ok=True))


def _stable_event_id(
    *,
    category: str,
    subject: str,
    occurred_at: str,
    payload: dict[str, Any],
) -> str:
    for key in ("event_id", "tracking_id", "share_id", "correlation_id", "run_id", "idempotency_key"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    digest = hashlib.sha256(
        json.dumps(
            {"category": category, "subject": subject, "occurred_at": occurred_at},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return digest[:32]


def _entry(
    *,
    category: str,
    actor: str,
    occurred_at: str,
    summary: str,
    subject: str,
    result: str | None = None,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = payload or {}
    return {
        "event_id": _stable_event_id(
            category=category,
            subject=subject,
            occurred_at=occurred_at,
            payload=body,
        ),
        "category": category,
        "actor": actor or "system",
        "occurred_at": occurred_at,
        "summary": summary,
        "subject": subject,
        "result": result,
        "payload": body,
    }


def _triage_entries(lake: Path) -> list[dict[str, Any]]:
    rows = _read_log(_gold(lake) / TRIAGE_FILE)
    out: list[dict[str, Any]] = []
    for row in rows:
        out.append(
            _entry(
                category="triage",
                actor=str(row.get("actor") or "anonymous"),
                occurred_at=str(row.get("occurred_at") or ""),
                summary=(
                    f"violation {row.get('violation_id')} → {row.get('state')}"
                    + (f" (assignee {row['assignee']})" if row.get("assignee") else "")
                ),
                subject=str(row.get("violation_id") or ""),
                result=str(row.get("state") or ""),
                payload=row,
            )
        )
    return out


def _connector_entries(lake: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in _read_log(_gold(lake) / CONNECTOR_CONFIG_FILE):
        out.append(
            _entry(
                category="connector",
                actor=str(row.get("actor") or "console"),
                occurred_at=str(row.get("occurred_at") or ""),
                summary=f"{row.get('connector_id')} {row.get('state')}",
                subject=str(row.get("connector_id") or ""),
                result=str(row.get("state") or ""),
                payload=row,
            )
        )
    for row in _read_log(_gold(lake) / CONNECTOR_RUNS_FILE):
        out.append(
            _entry(
                category="connector",
                actor=str(row.get("actor") or "system"),
                occurred_at=str(row.get("occurred_at") or ""),
                summary=(
                    f"{row.get('connector_id')} {row.get('kind')} {row.get('result')}"
                    + (f" — {row['error']}" if row.get("error") else "")
                ),
                subject=str(row.get("connector_id") or ""),
                result=str(row.get("result") or ""),
                payload=row,
            )
        )
    return out


def _snapshot_entries(lake: Path) -> list[dict[str, Any]]:
    snapshots_dir = _gold(lake) / SNAPSHOTS_DIR
    if not snapshots_dir.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for path in snapshots_dir.glob("assessment-*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        out.append(
            _entry(
                category="snapshot",
                actor="console",
                occurred_at=str(payload.get("evaluated_at") or ""),
                summary=f"snapshot frozen ({payload.get('snapshot_reason') or 'manual'})",
                subject=str(path.name),
                result=str(payload.get("posture", {}).get("state") or ""),
                payload={
                    "snapshot_path": str(path),
                    "assessment_hash": payload.get("assessment_hash"),
                    "posture_score": payload.get("posture", {}).get("score"),
                },
            )
        )
    return out


def _workflow_entries(lake: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in _read_log(_gold(lake) / WORKFLOW_RUNS_FILE):
        out.append(
            _entry(
                category="workflow",
                actor=str(row.get("actor") or "console"),
                occurred_at=str(row.get("started_at") or ""),
                summary=f"workflow {row.get('workflow_id')} v{row.get('workflow_version')} {row.get('result')}",
                subject=str(row.get("workflow_id") or ""),
                result=str(row.get("result") or ""),
                payload=row,
            )
        )
    return out


def _trust_share_entries(lake: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in _read_log(_gold(lake) / TRUST_SHARES_FILE):
        is_revoke = bool(row.get("revoked_at"))
        out.append(
            _entry(
                category="trust_share",
                actor=str(row.get("revoked_by") if is_revoke else row.get("created_by") or "console"),
                occurred_at=str(row.get("revoked_at") if is_revoke else row.get("created_at") or ""),
                summary=(
                    f"share {row.get('share_id')} revoked"
                    if is_revoke
                    else f"share {row.get('share_id')} created ({row.get('role')}, scope {row.get('scope')})"
                ),
                subject=str(row.get("share_id") or ""),
                result="revoked" if is_revoke else "created",
                payload=row,
            )
        )
    return out


def _mapping_review_entries(lake: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in _read_log(_gold(lake) / MAPPING_REVIEW_AUDIT_FILE):
        if row.get("event") != "tip_resigned":
            continue
        out.append(
            _entry(
                category="mapping_review",
                actor=str(row.get("actor") or "operator"),
                occurred_at=str(row.get("occurred_at") or ""),
                summary=f"decision log tip re-signed with the current key ({row.get('log_length')} decisions)",
                subject=str(row.get("tip_hash") or ""),
                result="resigned",
                payload=row,
            )
        )
    return out


def _request_entries(lake: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in _read_log(_gold(lake) / REQUEST_AUDIT_FILE):
        out.append(
            _entry(
                category="request",
                actor=str(row.get("actor") or "anonymous"),
                occurred_at=str(row.get("occurred_at") or ""),
                summary=(f"{row.get('method')} {row.get('route')} {row.get('decision')} ({row.get('status_code')})"),
                subject=str(row.get("event_id") or row.get("correlation_id") or ""),
                result=str(row.get("decision") or ""),
                payload=row,
            )
        )
    return out


def build_audit_log(
    lake_dir: str | Path,
    *,
    category: str | None = None,
    actor: str | None = None,
    limit: int = 200,
    include_requests: bool = False,
) -> list[dict[str, Any]]:
    lake = Path(lake_dir)
    entries = (
        _triage_entries(lake)
        + _connector_entries(lake)
        + _snapshot_entries(lake)
        + _workflow_entries(lake)
        + _trust_share_entries(lake)
        + _mapping_review_entries(lake)
    )
    if include_requests or category == "request":
        entries += _request_entries(lake)
    if category:
        entries = [e for e in entries if e["category"] == category]
    if actor:
        entries = [e for e in entries if e["actor"] == actor]
    entries.sort(key=lambda e: instant_sort_key(e.get("occurred_at")), reverse=True)
    return entries[:limit]

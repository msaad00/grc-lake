"""Data-access + serialization for posture metrics and remediation insights.

``PostureMetricPoint`` rows are append-only time-series captures. Derived
aggregates (MTTR, SLA attainment, overdue counts) are computed at read time
from ``remediation_tasks`` so they are always accurate without extra columns.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from security_lakehouse.db.models import PostureMetricPoint, RemediationTask


def _now(now: datetime | None) -> datetime:
    return now or datetime.now(UTC)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _as_aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------


def capture_metric_point(
    session: Session,
    *,
    tenant_id: str,
    lake_dir: str | Path,
    now: datetime | None = None,
) -> PostureMetricPoint:
    """Read current posture + remediation state and insert a snapshot row."""
    from security_lakehouse.assessment import build_current_posture

    moment = _now(now)
    posture = build_current_posture(lake_dir, now=moment)
    p = posture.get("posture", {})

    posture_score: float = float(p.get("score", 0.0))
    open_violations: int = int(p.get("open_violation_count", 0))
    critical_violations: int = int(p.get("critical_violation_count", 0))
    stale_controls: int = int(p.get("stale_control_count", 0))

    # Only explicit current passes count; unknown and stale controls are not passes.
    total_controls = int(p.get("control_count", 0))
    passing_controls = sum(int(f.get("passing_control_count", 0)) for f in posture.get("frameworks", []))
    control_pass_rate = passing_controls / total_controls if total_controls else 0.0

    # evidence freshness percentage
    ef = posture.get("evidence_freshness", {})
    ef_count: int = int(ef.get("count", 0))
    ef_stale: int = int(ef.get("stale_count", 0))
    evidence_fresh_pct: float = (ef_count - ef_stale) / ef_count if ef_count > 0 else 1.0

    # remediation open / overdue counts from the DB
    stmt = select(RemediationTask).where(RemediationTask.tenant_id == tenant_id)
    tasks = list(session.scalars(stmt))
    remediation_open: int = sum(1 for t in tasks if t.is_open)
    remediation_overdue: int = sum(1 for t in tasks if t.is_overdue(now=moment))

    point = PostureMetricPoint(
        tenant_id=tenant_id,
        captured_at=moment,
        posture_score=posture_score,
        control_pass_rate=control_pass_rate,
        open_violations=open_violations,
        critical_violations=critical_violations,
        stale_controls=stale_controls,
        evidence_fresh_pct=evidence_fresh_pct,
        remediation_open=remediation_open,
        remediation_overdue=remediation_overdue,
    )
    session.add(point)
    session.flush()
    return point


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------


def list_metric_points(
    session: Session,
    *,
    tenant_id: str,
    limit: int = 90,
) -> list[PostureMetricPoint]:
    stmt = (
        select(PostureMetricPoint)
        .where(PostureMetricPoint.tenant_id == tenant_id)
        .order_by(PostureMetricPoint.captured_at.desc())
        .limit(limit)
    )
    rows = list(session.scalars(stmt))
    # Return in ascending chronological order for chart rendering
    rows.reverse()
    return rows


# ---------------------------------------------------------------------------
# Derived insights (MTTR, SLA attainment)
# ---------------------------------------------------------------------------


def remediation_insights(
    session: Session,
    *,
    tenant_id: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Derive MTTR, SLA attainment, open and overdue counts from remediation tasks."""
    moment = _now(now)
    stmt = select(RemediationTask).where(RemediationTask.tenant_id == tenant_id)
    tasks = list(session.scalars(stmt))

    open_count = 0
    overdue_count = 0
    resolved_durations: list[float] = []  # seconds
    sla_total = 0
    sla_on_time = 0

    for task in tasks:
        if task.is_open:
            open_count += 1
            if task.is_overdue(now=moment):
                overdue_count += 1
        if task.status == "resolved" and task.resolved_at is not None and task.created_at is not None:
            resolved_at = _as_aware(task.resolved_at)
            created_at = _as_aware(task.created_at)
            duration_s = (resolved_at - created_at).total_seconds()
            if duration_s >= 0:
                resolved_durations.append(duration_s)
            if task.due_at is not None:
                sla_total += 1
                if resolved_at <= _as_aware(task.due_at):
                    sla_on_time += 1

    mttr_hours: float | None = (
        sum(resolved_durations) / len(resolved_durations) / 3600.0 if resolved_durations else None
    )
    sla_attainment_pct: float | None = sla_on_time / sla_total * 100.0 if sla_total > 0 else None

    return {
        "open": open_count,
        "overdue": overdue_count,
        "mttr_hours": round(mttr_hours, 2) if mttr_hours is not None else None,
        "sla_attainment_pct": round(sla_attainment_pct, 1) if sla_attainment_pct is not None else None,
        "resolved_count": len(resolved_durations),
        "sla_eligible_count": sla_total,
    }


# ---------------------------------------------------------------------------
# Visual analytics (#18): framework trends + SLA heatmap
# ---------------------------------------------------------------------------

_SLA_PRIORITIES = ("critical", "high", "medium", "low")
_SLA_COLUMNS = (
    "open_on_track",
    "open_overdue",
    "open_no_sla",
    "resolved_on_time",
    "resolved_late",
)


def framework_readiness_trends(
    lake_dir: str | Path,
    *,
    limit: int = 90,
    include_current: bool = True,
) -> dict[str, Any]:
    """Per-framework readiness scores over time from gold snapshots + current posture."""
    from security_lakehouse.assessment import _iter_snapshots, build_current_posture

    snapshots = _iter_snapshots(lake_dir, limit=limit)

    points: list[dict[str, Any]] = []
    framework_names: set[str] = set()

    for evaluated_at, payload, path in snapshots:
        fw_scores: dict[str, float] = {}
        for row in payload.get("frameworks") or []:
            name = row.get("framework")
            if not isinstance(name, str) or not name:
                continue
            framework_names.add(name)
            fw_scores[name] = round(float(row.get("score") or 0.0), 1)
        points.append(
            {
                "at": _iso(evaluated_at),
                "source": "snapshot",
                "snapshot_id": path.stem,
                "frameworks": fw_scores,
            }
        )

    if include_current:
        current = build_current_posture(lake_dir)
        fw_scores = {}
        for row in current.get("frameworks") or []:
            name = row.get("framework")
            if not isinstance(name, str) or not name:
                continue
            framework_names.add(name)
            fw_scores[name] = round(float(row.get("score") or 0.0), 1)
        at = current.get("evaluated_at")
        if isinstance(at, str) and (not points or points[-1]["at"] != at):
            points.append(
                {
                    "at": at,
                    "source": "current",
                    "snapshot_id": None,
                    "frameworks": fw_scores,
                }
            )

    return {
        "frameworks": sorted(framework_names),
        "points": points,
    }


def sla_heatmap(
    session: Session,
    *,
    tenant_id: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Remediation SLA grids by owner and priority with live resolution timing."""
    moment = _now(now)
    stmt = select(RemediationTask).where(RemediationTask.tenant_id == tenant_id)
    tasks = list(session.scalars(stmt))

    cells: dict[str, dict[str, int]] = {
        priority: {column: 0 for column in _SLA_COLUMNS} for priority in _SLA_PRIORITIES
    }
    owner_cells: dict[str, dict[str, int]] = {}

    for task in tasks:
        priority = task.priority if task.priority in _SLA_PRIORITIES else "medium"
        owner = task.owner.strip() or "Unassigned"
        buckets = (
            cells[priority],
            owner_cells.setdefault(owner, {column: 0 for column in _SLA_COLUMNS}),
        )

        if task.is_open:
            if task.due_at is None:
                column = "open_no_sla"
            elif task.is_overdue(now=moment):
                column = "open_overdue"
            else:
                column = "open_on_track"
            for bucket in buckets:
                bucket[column] += 1
            continue

        if task.status != "resolved" or task.resolved_at is None or task.due_at is None:
            continue

        resolved_at = _as_aware(task.resolved_at)
        due_at = _as_aware(task.due_at)
        column = "resolved_on_time" if resolved_at <= due_at else "resolved_late"
        for bucket in buckets:
            bucket[column] += 1

    rows = [{"priority": priority, **cells[priority]} for priority in _SLA_PRIORITIES]
    owner_rows = [
        {"owner": owner, **counts}
        for owner, counts in sorted(
            owner_cells.items(),
            key=lambda item: (-item[1]["open_overdue"], item[0].lower()),
        )
    ]
    return {"columns": list(_SLA_COLUMNS), "rows": rows, "owner_rows": owner_rows}


# ---------------------------------------------------------------------------
# Serializers
# ---------------------------------------------------------------------------


def metric_point_to_dict(point: PostureMetricPoint) -> dict[str, Any]:
    return {
        "id": point.id,
        "tenant_id": point.tenant_id,
        "captured_at": _iso(point.captured_at),
        "posture_score": point.posture_score,
        "control_pass_rate": point.control_pass_rate,
        "open_violations": point.open_violations,
        "critical_violations": point.critical_violations,
        "stale_controls": point.stale_controls,
        "evidence_fresh_pct": point.evidence_fresh_pct,
        "remediation_open": point.remediation_open,
        "remediation_overdue": point.remediation_overdue,
    }


__all__ = [
    "capture_metric_point",
    "framework_readiness_trends",
    "list_metric_points",
    "metric_point_to_dict",
    "remediation_insights",
    "sla_heatmap",
]

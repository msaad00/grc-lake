"""Unified mid-run job list for connectors, lake eval, workflows, and agents."""

from __future__ import annotations

from typing import Any

from security_lakehouse.connector_state import list_runs as list_connector_runs
from security_lakehouse.lake_eval import list_eval_runs
from security_lakehouse.models import instant_sort_key
from security_lakehouse.workflows import list_runs as list_workflow_runs

JobRow = dict[str, Any]


def build_platform_jobs(
    lake_dir: str,
    *,
    agent_runs: list[dict[str, Any]] | None = None,
    operations: list[dict[str, Any]] | None = None,
    limit: int = 50,
    kind: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Return a single sorted job feed across lake + tenant-scoped agent runs."""
    per_source = max(1, min(limit, 200))
    jobs: list[JobRow] = list(operations or [])

    for row in list_connector_runs(lake_dir, limit=per_source):
        jobs.append(_connector_job(row))

    for row in list_eval_runs(lake_dir, limit=per_source):
        jobs.append(_eval_job(row))

    for row in list_workflow_runs(lake_dir, limit=per_source):
        jobs.append(_workflow_job(row))

    for row in agent_runs or []:
        jobs.append(_agent_job(row))

    if kind:
        jobs = [row for row in jobs if row["kind"] == kind]
    if status:
        jobs = [row for row in jobs if row["status"] == status]

    jobs.sort(key=lambda row: instant_sort_key(row.get("started_at")), reverse=True)
    capped = jobs[: max(1, min(limit, 500))]
    counts: dict[str, int] = {}
    for row in capped:
        key = str(row["kind"])
        counts[key] = counts.get(key, 0) + 1
    running = sum(1 for row in capped if row.get("status") in {"running", "in_progress", "pending", "queued"})
    return {
        "jobs": capped,
        "count": len(capped),
        "running_count": running,
        "counts_by_kind": counts,
    }


def _connector_job(row: dict[str, Any]) -> JobRow:
    result = str(row.get("result") or "unknown")
    status = "failed" if result == "error" else "completed" if result == "ok" else result
    return {
        "id": f"connector:{row.get('run_id') or row.get('connector_id')}",
        "kind": "connector_sync",
        "status": status,
        "label": str(row.get("connector_id") or "connector"),
        "started_at": row.get("occurred_at"),
        "finished_at": row.get("occurred_at"),
        "actor": row.get("actor"),
        "detail": row.get("detail") or row.get("message"),
        "connector_id": row.get("connector_id"),
        "events_added": row.get("events_added"),
        "result": result,
    }


def _eval_job(row: dict[str, Any]) -> JobRow:
    result = str(row.get("result") or "unknown")
    status = "failed" if result == "error" else "completed"
    started = row.get("occurred_at") or row.get("evaluated_at")
    return {
        "id": f"lake_eval:{started or row.get('actor')}",
        "kind": "lake_eval",
        "status": status,
        "label": "Lake evaluation",
        "started_at": started,
        "finished_at": started,
        "actor": row.get("actor"),
        "detail": row.get("error") or row.get("mode"),
        "mode": row.get("mode"),
        "pass_rate": row.get("pass_rate"),
        "duration_ms": row.get("duration_ms"),
        "result": result,
    }


def _workflow_job(row: dict[str, Any]) -> JobRow:
    status = str(row.get("status") or "unknown")
    normalized = {
        "completed": "completed",
        "failed": "failed",
        "running": "running",
        "pending": "pending",
    }.get(status, status)
    return {
        "id": f"workflow:{row.get('run_id') or row.get('workflow_id')}",
        "kind": "workflow",
        "status": normalized,
        "label": str(row.get("workflow_id") or "workflow"),
        "started_at": row.get("started_at"),
        "finished_at": row.get("finished_at"),
        "actor": row.get("actor"),
        "detail": row.get("error") or row.get("summary"),
        "workflow_id": row.get("workflow_id"),
        "run_id": row.get("run_id"),
    }


def _agent_job(row: dict[str, Any]) -> JobRow:
    status = str(row.get("status") or "unknown")
    return {
        "id": f"agent:{row.get('id')}",
        "kind": "agent_run",
        "status": status,
        "label": str(row.get("harness") or "agent run"),
        "started_at": row.get("created_at"),
        "finished_at": row.get("completed_at"),
        "actor": row.get("created_by"),
        "detail": row.get("objective"),
        "run_id": row.get("id"),
        "harness": row.get("harness"),
    }


__all__ = ["build_platform_jobs"]

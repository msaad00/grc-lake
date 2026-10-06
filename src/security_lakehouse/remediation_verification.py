"""Verify control-linked remediation using freshly collected, sealed evidence.

A receipt proves a point-in-time retest of the observed population, not complete
inventory coverage or sustained operating effectiveness. Risk exceptions are
never consulted when deciding whether a control passes.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import update
from sqlalchemy.orm import Session

from security_lakehouse.assessment import build_current_posture
from security_lakehouse.db import remediation
from security_lakehouse.db.models import RemediationTask, _as_aware
from security_lakehouse.generations import generation_identity, generation_reader
from security_lakehouse.io import read_json, read_jsonl
from security_lakehouse.verification import verify_lake_integrity


@generation_reader
def verify_task(
    session: Session,
    lake: Path,
    *,
    tenant_id: str,
    task_id: str,
    reviewer_id: str,
    reviewer: str,
    now: datetime | None = None,
) -> RemediationTask:
    task = remediation.get_task(session, tenant_id=tenant_id, task_id=task_id)
    if task is None or not task.control_id:
        raise ValueError("verification requires a task with a control in this tenant")
    if not reviewer_id or not reviewer:
        raise ValueError("verification requires an authenticated reviewer")
    actors = {reviewer.strip().casefold(), reviewer_id.strip().casefold()}
    if any(value and value.strip().casefold() in actors for value in (task.created_by, task.owner)):
        raise ValueError("verification requires an independent reviewer, not the creator or owner")
    moment = now or datetime.now(UTC)
    identity = generation_identity(lake)
    if not identity:
        raise ValueError("verification requires a sealed evidence generation")
    manifest = read_json(lake / "manifest.json")
    if not identity or manifest.get("tenant_id") != tenant_id or not verify_lake_integrity(lake)["ok"]:
        raise ValueError("verification requires an intact generation owned by this tenant")
    history = json.loads(task.verification_history or "[]")
    if history and any(receipt.get("generation") == identity for receipt in history):
        raise ValueError("retest requires a new evidence generation after the previous verification")
    threshold = max(_as_aware(task.created_at), _as_aware(task.updated_at)) if history else _as_aware(task.created_at)
    tests = [row for row in read_jsonl(lake / "gold/control_tests.jsonl") if row["control_id"] == task.control_id]
    posture = build_current_posture(lake, now=moment)
    if not tests or any(row.get("result") != "pass" for row in tests) or task.control_id in posture["stale_controls"]:
        raise ValueError("control must pass all tests with fresh, complete required evidence")
    evidence = [
        row
        for row in read_jsonl(lake / "silver/normalized_events.jsonl")
        if task.control_id in row.get("control_ids", [])
    ]
    if not evidence:
        raise ValueError("control has no evidence to verify")
    sources = {row.get("source") for row in evidence}
    from security_lakehouse.connector_errors import collection_gaps

    raw_rows = [
        row["raw"]
        for row in read_jsonl(lake / "bronze/raw_events.jsonl")
        if row.get("raw", {}).get("source") in sources
    ]
    if collection_gaps(raw_rows):
        raise ValueError("partial collection cannot verify a remediation retest")
    from security_lakehouse.connector_state import latest_run

    for connector in {row.get("connector_id") for row in evidence} - {None, ""}:
        run = latest_run(lake, str(connector), kind="sync")
        if not run or run.get("result") != "ok" or (run.get("metadata") or {}).get("partial"):
            raise ValueError("partial or unsuccessful collection cannot verify a remediation retest")
    for row in evidence:
        observed = datetime.fromisoformat(row["event_time"].replace("Z", "+00:00"))
        collected = datetime.fromisoformat(row["evidence_collected_at"].replace("Z", "+00:00"))
        if observed.tzinfo is None or collected.tzinfo is None or not (threshold < observed <= collected <= moment):
            raise ValueError(
                "retest evidence must be observed and collected after the task was created, and not in the future"
            )
    receipt = {
        "verified_at": moment.isoformat(),
        "verified_by": reviewer,
        "reviewer_id": reviewer_id,
        "tenant_id": tenant_id,
        "control_id": task.control_id,
        "generation": identity,
        "scope": "observed_assets",
        "assessment_hash": posture["assessment_hash"],
        "evidence": [{"event_id": row["event_id"], "raw_sha256": row["raw_sha256"]} for row in evidence],
    }
    previous_history = task.verification_history
    history = json.loads(previous_history or "[]")
    history.append(receipt)
    result = session.execute(
        update(RemediationTask)
        .where(
            RemediationTask.id == task.id,
            RemediationTask.tenant_id == tenant_id,
            RemediationTask.verification_history == previous_history,
            RemediationTask.updated_at == task.updated_at,
        )
        .values(
            verification_history=json.dumps(history, sort_keys=True),
            status="resolved",
            resolved_at=moment,
            updated_at=moment,
        )
        .returning(RemediationTask.id)
    )
    if result.scalar_one_or_none() is None:
        raise ValueError("task changed during verification; reload it before retrying")
    session.refresh(task)
    return task


def reconcile_published_tasks(lake: Path, *, tenant_id: str) -> int:
    """Reopen verified tasks after a newly published failing control result.

    Called after publication only when an application database already exists,
    or in hosted mode with an explicitly configured external database.
    """
    import os

    from sqlalchemy import select

    from security_lakehouse.db.base import create_engine_for, session_factory, session_scope
    from security_lakehouse.execution_mode import in_server_mode

    root = lake.parent.parent if lake.parent.name == "tenants" else lake
    if not (root / "server/app.db").is_file() and not (in_server_mode() and os.environ.get("TRUSTOPS_DATABASE_URL")):
        return 0
    failures = {r["control_id"] for r in read_jsonl(lake / "gold/control_posture.jsonl") if r.get("status") == "fail"}
    if not failures:
        return 0
    engine = create_engine_for(root)
    try:
        with session_scope(session_factory(engine)) as session:
            tasks = session.scalars(
                select(RemediationTask).where(
                    RemediationTask.tenant_id == tenant_id,
                    RemediationTask.status == "resolved",
                    RemediationTask.control_id.in_(failures),
                )
            ).all()
            for task in tasks:
                task.status = "open"
                task.resolved_at = None
                task.updated_at = datetime.now(UTC)
                task.resolution_note = "Reopened: a newly published assessment reports a control regression. Prior verification receipts are retained."
            return len(tasks)
    finally:
        engine.dispose()

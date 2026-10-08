"""POA&M workflow service — sync from lake posture and manage milestones."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from security_lakehouse.db import poam as poam_db
from security_lakehouse.io import read_jsonl
from security_lakehouse.jsontypes import JsonObject
from security_lakehouse.services import NotFound, ValidationError
from security_lakehouse.sprs import CMMC_FRAMEWORK_ID, evaluate_cmmc_posture, requirement_id_from_control


def list_poam_items(
    session: Session,
    tenant_id: str,
    *,
    framework_id: str | None = None,
    status: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> list[JsonObject]:
    rows = poam_db.list_items(
        session,
        tenant_id=tenant_id,
        framework_id=framework_id,
        status=status,
        limit=limit,
        offset=offset,
    )
    return [poam_db.item_to_dict(row) for row in rows]


def create_poam_item(
    session: Session,
    tenant_id: str,
    *,
    requirement_id: str,
    control_id: str,
    title: str,
    weakness: str = "",
    framework_id: str = CMMC_FRAMEWORK_ID,
    owner: str = "",
    milestone: str = "",
    sprs_points: int = 1,
    poam_eligible: bool = True,
    due_at: datetime | None = None,
    remediation_task_id: str | None = None,
    created_by: str = "",
) -> JsonObject:
    try:
        item = poam_db.create_item(
            session,
            tenant_id=tenant_id,
            requirement_id=requirement_id,
            control_id=control_id,
            title=title,
            weakness=weakness,
            framework_id=framework_id,
            owner=owner,
            milestone=milestone,
            sprs_points=sprs_points,
            poam_eligible=poam_eligible,
            due_at=due_at,
            remediation_task_id=remediation_task_id,
            created_by=created_by,
        )
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    session.commit()
    return poam_db.item_to_dict(item)


def update_poam_item(
    session: Session,
    tenant_id: str,
    item_id: str,
    *,
    changes: dict[str, Any],
) -> JsonObject:
    try:
        item = poam_db.update_item(session, tenant_id=tenant_id, item_id=item_id, changes=changes)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    if item is None:
        raise NotFound("POA&M item not found")
    session.commit()
    return poam_db.item_to_dict(item)


def sync_poam_from_posture(
    session: Session,
    tenant_id: str,
    lake_dir: str | Path,
    *,
    framework_id: str = CMMC_FRAMEWORK_ID,
    created_by: str = "",
) -> JsonObject:
    """Upsert open POA&M rows for failing CMMC control tests; close resolved ones."""
    lake = Path(lake_dir)
    sprs_report, outcomes = evaluate_cmmc_posture(lake)
    deductions = {row["requirement_id"]: row for row in sprs_report.get("deductions", [])}

    created = 0
    updated = 0
    for requirement_id, meta in deductions.items():
        control_id = f"CMMC-{requirement_id}"
        existing = poam_db.get_by_requirement(
            session, tenant_id=tenant_id, framework_id=framework_id, requirement_id=requirement_id
        )
        weakness = f"Control test failing for NIST SP 800-171 Rev 2 {requirement_id}"
        if existing is None:
            poam_db.create_item(
                session,
                tenant_id=tenant_id,
                requirement_id=requirement_id,
                control_id=control_id,
                title=str(meta["title"]),
                weakness=weakness,
                framework_id=framework_id,
                sprs_points=int(meta["sprs_points"]),
                poam_eligible=bool(meta["poam_eligible"]),
                created_by=created_by,
            )
            created += 1
            continue
        if existing.status == "risk_accepted":
            continue
        reopened = existing.status == "completed"
        if reopened:
            poam_db.update_item(session, tenant_id=tenant_id, item_id=existing.id, changes={"status": "open"})
        if reopened or existing.weakness != weakness or existing.sprs_points != int(meta["sprs_points"]):
            existing.weakness = weakness
            existing.sprs_points = int(meta["sprs_points"])
            updated += 1

    closed = 0
    open_items = poam_db.list_items(session, tenant_id=tenant_id, framework_id=framework_id, status="open")
    open_items.extend(poam_db.list_items(session, tenant_id=tenant_id, framework_id=framework_id, status="in_progress"))
    for item in open_items:
        if outcomes.get(item.requirement_id) == "pass":
            poam_db.update_item(session, tenant_id=tenant_id, item_id=item.id, changes={"status": "completed"})
            closed += 1

    session.commit()
    return {
        "framework_id": framework_id,
        "sprs": sprs_report,
        "created": created,
        "updated": updated,
        "closed": closed,
        "open_poam_count": len(
            poam_db.list_items(session, tenant_id=tenant_id, framework_id=framework_id, status="open")
        ),
    }


def failing_cmmc_requirements(lake_dir: str | Path) -> set[str]:
    lake = Path(lake_dir)
    failing: set[str] = set()
    for row in read_jsonl(lake / "gold" / "control_tests.jsonl", missing_ok=True, base_dir=lake):
        if str(row.get("framework_id", "")) != CMMC_FRAMEWORK_ID:
            continue
        if str(row.get("result", "")).lower() not in {"fail", "failing", "open"}:
            continue
        requirement_id = requirement_id_from_control(str(row.get("control_id", "")))
        if requirement_id:
            failing.add(requirement_id)
    return failing


__all__ = [
    "create_poam_item",
    "failing_cmmc_requirements",
    "list_poam_items",
    "sync_poam_from_posture",
    "update_poam_item",
]

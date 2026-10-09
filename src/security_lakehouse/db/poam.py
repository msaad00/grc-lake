"""Plan of Action & Milestones (POA&M) persistence for gov/defense programs."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from security_lakehouse.db.base import apply_pagination
from security_lakehouse.db.models import POAM_STATUSES, PoamItem
from security_lakehouse.timeutil import iso_offset, utc_now


def create_item(
    session: Session,
    *,
    tenant_id: str,
    requirement_id: str,
    control_id: str,
    title: str,
    weakness: str = "",
    framework_id: str = "cmmc-2-level2",
    owner: str = "",
    milestone: str = "",
    sprs_points: int = 1,
    poam_eligible: bool = True,
    due_at: datetime | None = None,
    remediation_task_id: str | None = None,
    created_by: str = "",
) -> PoamItem:
    if not requirement_id.strip():
        raise ValueError("POA&M item requires requirement_id")
    if not control_id.strip():
        raise ValueError("POA&M item requires control_id")
    if not title.strip():
        raise ValueError("POA&M item requires title")
    item = PoamItem(
        tenant_id=tenant_id,
        framework_id=framework_id,
        requirement_id=requirement_id,
        control_id=control_id,
        title=title,
        weakness=weakness,
        owner=owner,
        milestone=milestone,
        sprs_points=sprs_points,
        poam_eligible=poam_eligible,
        due_at=due_at,
        remediation_task_id=remediation_task_id,
        created_by=created_by,
    )
    session.add(item)
    session.flush()
    return item


def get_item(session: Session, *, tenant_id: str, item_id: str) -> PoamItem | None:
    row = session.get(PoamItem, item_id)
    return row if row is not None and row.tenant_id == tenant_id else None


def get_by_requirement(session: Session, *, tenant_id: str, framework_id: str, requirement_id: str) -> PoamItem | None:
    stmt = (
        select(PoamItem)
        .where(
            PoamItem.tenant_id == tenant_id,
            PoamItem.framework_id == framework_id,
            PoamItem.requirement_id == requirement_id,
        )
        .order_by(PoamItem.created_at.desc())
        .limit(1)
    )
    return session.scalars(stmt).first()


def list_items(
    session: Session,
    *,
    tenant_id: str,
    framework_id: str | None = None,
    status: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> list[PoamItem]:
    stmt = select(PoamItem).where(PoamItem.tenant_id == tenant_id)
    if framework_id:
        stmt = stmt.where(PoamItem.framework_id == framework_id)
    if status:
        stmt = stmt.where(PoamItem.status == status)
    stmt = apply_pagination(stmt.order_by(PoamItem.created_at.desc()), limit=limit, offset=offset)
    return list(session.scalars(stmt))


def update_item(
    session: Session,
    *,
    tenant_id: str,
    item_id: str,
    changes: dict[str, Any],
    now: datetime | None = None,
) -> PoamItem | None:
    item = get_item(session, tenant_id=tenant_id, item_id=item_id)
    if item is None:
        return None
    moment = utc_now(now)
    if "status" in changes:
        status = str(changes["status"])
        if status not in POAM_STATUSES:
            raise ValueError(f"status must be one of {list(POAM_STATUSES)}, got {status!r}")
        item.status = status
        item.completed_at = moment if status in {"completed", "risk_accepted"} else None
    for field in ("title", "weakness", "owner", "milestone", "remediation_task_id"):
        if field in changes and changes[field] is not None:
            setattr(item, field, str(changes[field]))
    if "due_at" in changes:
        item.due_at = changes["due_at"]
    item.updated_at = moment
    session.flush()
    return item


def item_to_dict(item: PoamItem) -> dict[str, Any]:
    return {
        "id": item.id,
        "framework_id": item.framework_id,
        "requirement_id": item.requirement_id,
        "control_id": item.control_id,
        "title": item.title,
        "weakness": item.weakness,
        "status": item.status,
        "owner": item.owner,
        "milestone": item.milestone,
        "sprs_points": item.sprs_points,
        "poam_eligible": item.poam_eligible,
        "due_at": iso_offset(item.due_at),
        "remediation_task_id": item.remediation_task_id,
        "created_by": item.created_by,
        "created_at": iso_offset(item.created_at),
        "updated_at": iso_offset(item.updated_at),
        "completed_at": iso_offset(item.completed_at),
    }


__all__ = [
    "POAM_STATUSES",
    "create_item",
    "get_by_requirement",
    "get_item",
    "item_to_dict",
    "list_items",
    "update_item",
]

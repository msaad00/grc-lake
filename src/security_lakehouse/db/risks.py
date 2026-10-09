"""Data-access + serialization for the GRC risk register.

Risks live in the application-state database (server mode). Every query is
tenant-scoped so one workspace can never read or mutate another's register.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from security_lakehouse.db.base import apply_pagination
from security_lakehouse.db.models import RISK_LEVELS, RISK_STATUSES, Risk
from security_lakehouse.timeutil import iso_offset, utc_now


def _validate_level(field: str, value: str) -> None:
    if value not in RISK_LEVELS:
        raise ValueError(f"{field} must be one of {list(RISK_LEVELS)}, got {value!r}")


def create_risk(
    session: Session,
    *,
    tenant_id: str,
    title: str,
    description: str = "",
    category: str = "",
    severity: str = "medium",
    likelihood: str = "medium",
    impact: str = "medium",
    status: str = "open",
    treatment: str = "",
    owner: str = "",
    control_id: str | None = None,
    asset_id: str | None = None,
    due_at: datetime | None = None,
) -> Risk:
    if not title.strip():
        raise ValueError("risk requires a title")
    _validate_level("severity", severity)
    _validate_level("likelihood", likelihood)
    _validate_level("impact", impact)
    if status not in RISK_STATUSES:
        raise ValueError(f"status must be one of {list(RISK_STATUSES)}, got {status!r}")
    risk = Risk(
        tenant_id=tenant_id,
        title=title,
        description=description,
        category=category,
        severity=severity,
        likelihood=likelihood,
        impact=impact,
        status=status,
        treatment=treatment,
        owner=owner,
        control_id=control_id,
        asset_id=asset_id,
        due_at=due_at,
    )
    session.add(risk)
    session.flush()
    return risk


def get_risk(session: Session, *, tenant_id: str, risk_id: str) -> Risk | None:
    risk = session.get(Risk, risk_id)
    return risk if risk is not None and risk.tenant_id == tenant_id else None


def list_risks(
    session: Session,
    *,
    tenant_id: str,
    status: str | None = None,
    severity: str | None = None,
    owner: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> list[Risk]:
    stmt = select(Risk).where(Risk.tenant_id == tenant_id)
    if status:
        stmt = stmt.where(Risk.status == status)
    if severity:
        stmt = stmt.where(Risk.severity == severity)
    if owner:
        stmt = stmt.where(Risk.owner == owner)
    stmt = apply_pagination(stmt.order_by(Risk.created_at.desc()), limit=limit, offset=offset)
    return list(session.scalars(stmt))


def update_risk(
    session: Session,
    *,
    tenant_id: str,
    risk_id: str,
    changes: dict[str, Any],
    now: datetime | None = None,
) -> Risk | None:
    risk = get_risk(session, tenant_id=tenant_id, risk_id=risk_id)
    if risk is None:
        return None
    for field in ("severity", "likelihood", "impact"):
        if field in changes and changes[field] is not None:
            value = str(changes[field])
            _validate_level(field, value)
            setattr(risk, field, value)
    if "status" in changes and changes["status"] is not None:
        status = str(changes["status"])
        if status not in RISK_STATUSES:
            raise ValueError(f"status must be one of {list(RISK_STATUSES)}, got {status!r}")
        risk.status = status
    for field in ("title", "description", "category", "treatment", "owner"):
        if field in changes and changes[field] is not None:
            setattr(risk, field, str(changes[field]))
    for field in ("control_id", "asset_id"):
        if field in changes:
            setattr(risk, field, changes[field])
    if "due_at" in changes:
        risk.due_at = changes["due_at"]
    risk.updated_at = utc_now(now)
    session.flush()
    return risk


def delete_risk(session: Session, *, tenant_id: str, risk_id: str) -> bool:
    risk = get_risk(session, tenant_id=tenant_id, risk_id=risk_id)
    if risk is None:
        return False
    session.delete(risk)
    session.flush()
    return True


def risk_to_dict(risk: Risk) -> dict[str, Any]:
    return {
        "id": risk.id,
        "title": risk.title,
        "description": risk.description,
        "category": risk.category,
        "severity": risk.severity,
        "likelihood": risk.likelihood,
        "impact": risk.impact,
        "status": risk.status,
        "treatment": risk.treatment,
        "owner": risk.owner,
        "control_id": risk.control_id,
        "asset_id": risk.asset_id,
        "due_at": iso_offset(risk.due_at),
        "created_at": iso_offset(risk.created_at),
        "updated_at": iso_offset(risk.updated_at),
    }


__all__ = [
    "RISK_LEVELS",
    "RISK_STATUSES",
    "create_risk",
    "delete_risk",
    "get_risk",
    "list_risks",
    "risk_to_dict",
    "update_risk",
]

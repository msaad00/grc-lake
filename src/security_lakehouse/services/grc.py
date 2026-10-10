"""Shared GRC service functions (risks + remediation tasks).

Pure, transport-agnostic functions that wrap the ``db`` repositories plus
serialization. They take a SQLAlchemy session, a ``tenant_id``, and already
parsed plain params (datetimes, not ISO strings), and return plain dicts ready
to drop into any response envelope.

Write functions own their commit so any caller — FastAPI routes, the MCP
server, the SDK, or the CLI — gets durable DB-backed writes without repeating
the commit dance. Repository validation (``ValueError``) is surfaced as
:class:`~security_lakehouse.services.ValidationError`; missing rows surface as
:class:`~security_lakehouse.services.NotFound`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from security_lakehouse.db import remediation
from security_lakehouse.db import risks as risks_db
from security_lakehouse.services import NotFound, ValidationError

# --- risks -------------------------------------------------------------------


def list_risks(
    session: Session,
    tenant_id: str,
    *,
    status: str | None = None,
    severity: str | None = None,
    owner: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> list[dict[str, Any]]:
    rows = risks_db.list_risks(
        session,
        tenant_id=tenant_id,
        status=status,
        severity=severity,
        owner=owner,
        limit=limit,
        offset=offset,
    )
    return [risks_db.risk_to_dict(row) for row in rows]


def count_risks(
    session: Session,
    tenant_id: str,
    *,
    status: str | None = None,
    severity: str | None = None,
    owner: str | None = None,
) -> int:
    return risks_db.count_risks(session, tenant_id=tenant_id, status=status, severity=severity, owner=owner)


def create_risk(
    session: Session,
    tenant_id: str,
    *,
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
) -> dict[str, Any]:
    try:
        risk = risks_db.create_risk(
            session,
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
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    session.commit()
    return risks_db.risk_to_dict(risk)


def get_risk(session: Session, tenant_id: str, risk_id: str) -> dict[str, Any]:
    risk = risks_db.get_risk(session, tenant_id=tenant_id, risk_id=risk_id)
    if risk is None:
        raise NotFound("risk not found")
    return risks_db.risk_to_dict(risk)


def update_risk(
    session: Session,
    tenant_id: str,
    risk_id: str,
    *,
    changes: dict[str, Any],
) -> dict[str, Any]:
    try:
        risk = risks_db.update_risk(session, tenant_id=tenant_id, risk_id=risk_id, changes=changes)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    if risk is None:
        raise NotFound("risk not found")
    session.commit()
    return risks_db.risk_to_dict(risk)


def delete_risk(session: Session, tenant_id: str, risk_id: str) -> dict[str, Any]:
    deleted = risks_db.delete_risk(session, tenant_id=tenant_id, risk_id=risk_id)
    if not deleted:
        raise NotFound("risk not found")
    session.commit()
    return {"id": risk_id, "deleted": True}


# --- remediation tasks -------------------------------------------------------


def list_tasks(
    session: Session,
    tenant_id: str,
    *,
    status: str | None = None,
    owner: str | None = None,
    control_id: str | None = None,
    overdue: bool | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> list[dict[str, Any]]:
    tasks = remediation.list_tasks(
        session,
        tenant_id=tenant_id,
        status=status,
        owner=owner,
        control_id=control_id,
        overdue=overdue,
        limit=limit,
        offset=offset,
    )
    return [remediation.task_to_dict(task) for task in tasks]


def count_tasks(
    session: Session,
    tenant_id: str,
    *,
    status: str | None = None,
    owner: str | None = None,
    control_id: str | None = None,
    overdue: bool | None = None,
) -> int:
    return remediation.count_tasks(
        session, tenant_id=tenant_id, status=status, owner=owner, control_id=control_id, overdue=overdue
    )


def create_task(
    session: Session,
    tenant_id: str,
    *,
    title: str,
    description: str = "",
    control_id: str | None = None,
    violation_id: str | None = None,
    owner: str = "",
    priority: str = "medium",
    due_at: datetime | None = None,
    created_by: str = "",
) -> dict[str, Any]:
    try:
        task = remediation.create_task(
            session,
            tenant_id=tenant_id,
            title=title,
            description=description,
            control_id=control_id,
            violation_id=violation_id,
            owner=owner,
            priority=priority,
            due_at=due_at,
            created_by=created_by,
        )
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    session.commit()
    return remediation.task_to_dict(task)


def update_task(
    session: Session,
    tenant_id: str,
    task_id: str,
    *,
    changes: dict[str, Any],
) -> dict[str, Any]:
    try:
        task = remediation.update_task(session, tenant_id=tenant_id, task_id=task_id, changes=changes)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    if task is None:
        raise NotFound("task not found")
    session.commit()
    return remediation.task_to_dict(task)


def list_evidence_requests(
    session: Session,
    tenant_id: str,
    *,
    status: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> list[dict[str, Any]]:
    rows = remediation.list_evidence_requests(
        session,
        tenant_id=tenant_id,
        status=status,
        limit=limit,
        offset=offset,
    )
    return [remediation.evidence_request_to_dict(row) for row in rows]


def create_evidence_request(
    session: Session,
    tenant_id: str,
    *,
    control_id: str,
    requested_from: str = "",
    note: str = "",
    due_at: datetime | None = None,
    created_by: str = "",
) -> dict[str, Any]:
    try:
        request = remediation.create_evidence_request(
            session,
            tenant_id=tenant_id,
            control_id=control_id,
            requested_from=requested_from,
            note=note,
            due_at=due_at,
            created_by=created_by,
        )
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    session.commit()
    return remediation.evidence_request_to_dict(request)


__all__ = [
    "create_evidence_request",
    "create_risk",
    "create_task",
    "delete_risk",
    "get_risk",
    "list_evidence_requests",
    "list_risks",
    "list_tasks",
    "update_risk",
    "update_task",
]

"""Data-access + serialization for the remediation workflow.

Remediation tasks, evidence requests, and control exceptions live in the
application-state database (server mode). SLA state (``overdue``) is derived at
read time from ``due_at`` rather than stored, so it is always correct.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from security_lakehouse.db.base import apply_pagination
from security_lakehouse.db.models import (
    EVIDENCE_REQUEST_STATUSES,
    EXCEPTION_STATUSES,
    REMEDIATION_CLOSED,
    REMEDIATION_PRIORITIES,
    REMEDIATION_STATUSES,
    ControlException,
    EvidenceRequest,
    RemediationTask,
    _as_aware,
)

RESOLUTION_NOTE_MAX = 4000


def _now(now: datetime | None) -> datetime:
    return now or datetime.now(UTC)


def _iso(value: datetime | None) -> str | None:
    return _as_aware(value).isoformat() if value else None


# --- remediation tasks -------------------------------------------------------


def create_task(
    session: Session,
    *,
    tenant_id: str,
    title: str,
    description: str = "",
    control_id: str | None = None,
    violation_id: str | None = None,
    owner: str = "",
    priority: str = "medium",
    due_at: datetime | None = None,
    created_by: str = "",
) -> RemediationTask:
    if not title.strip():
        raise ValueError("remediation task requires a title")
    if priority not in REMEDIATION_PRIORITIES:
        raise ValueError(f"priority must be one of {list(REMEDIATION_PRIORITIES)}, got {priority!r}")
    task = RemediationTask(
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
    session.add(task)
    session.flush()
    return task


def get_task(session: Session, *, tenant_id: str, task_id: str) -> RemediationTask | None:
    task = session.get(RemediationTask, task_id)
    return task if task is not None and task.tenant_id == tenant_id else None


def list_tasks(
    session: Session,
    *,
    tenant_id: str,
    status: str | None = None,
    owner: str | None = None,
    control_id: str | None = None,
    overdue: bool | None = None,
    now: datetime | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> list[RemediationTask]:
    stmt = select(RemediationTask).where(RemediationTask.tenant_id == tenant_id)
    if status:
        stmt = stmt.where(RemediationTask.status == status)
    if owner:
        stmt = stmt.where(RemediationTask.owner == owner)
    if control_id:
        stmt = stmt.where(RemediationTask.control_id == control_id)
    if overdue is not None:
        # Push the overdue predicate into SQL so pagination is stable.
        # overdue = due_at IS NOT NULL AND due_at < now AND status is open.
        moment = _now(now)
        closed = list(REMEDIATION_CLOSED)
        if overdue:
            stmt = stmt.where(
                RemediationTask.due_at.is_not(None),
                RemediationTask.due_at < moment,
                RemediationTask.status.not_in(closed),
            )
        else:
            stmt = stmt.where(
                (RemediationTask.due_at.is_(None))
                | (RemediationTask.due_at >= moment)
                | (RemediationTask.status.in_(closed))
            )
    stmt = apply_pagination(stmt.order_by(RemediationTask.created_at.desc()), limit=limit, offset=offset)
    return list(session.scalars(stmt))


def update_task(
    session: Session,
    *,
    tenant_id: str,
    task_id: str,
    changes: dict[str, Any],
    now: datetime | None = None,
) -> RemediationTask | None:
    task = get_task(session, tenant_id=tenant_id, task_id=task_id)
    if task is None:
        return None
    moment = _now(now)
    if "status" in changes:
        status = str(changes["status"])
        if status not in REMEDIATION_STATUSES:
            raise ValueError(f"status must be one of {list(REMEDIATION_STATUSES)}, got {status!r}")
        if status in {"resolved", "dismissed"} and (task.control_id or task.violation_id):
            raise ValueError("linked remediation requires an evidence retest via the verify endpoint")
        task.status = status
        task.resolved_at = moment if status == "resolved" else None
    if "priority" in changes:
        priority = str(changes["priority"])
        if priority not in REMEDIATION_PRIORITIES:
            raise ValueError(f"priority must be one of {list(REMEDIATION_PRIORITIES)}, got {priority!r}")
        task.priority = priority
    for field in ("title", "description", "owner"):
        if field in changes and changes[field] is not None:
            setattr(task, field, str(changes[field]))
    if "due_at" in changes:
        task.due_at = changes["due_at"]
    if changes.get("resolution_note") is not None:
        note = str(changes["resolution_note"]).strip()
        if len(note) > RESOLUTION_NOTE_MAX:
            raise ValueError(f"resolution_note must be at most {RESOLUTION_NOTE_MAX} characters")
        task.resolution_note = note
    task.updated_at = moment
    session.flush()
    return task


def task_to_dict(task: RemediationTask, *, now: datetime | None = None) -> dict[str, Any]:
    return {
        "id": task.id,
        "title": task.title,
        "description": task.description,
        "control_id": task.control_id,
        "violation_id": task.violation_id,
        "owner": task.owner,
        "status": task.status,
        "priority": task.priority,
        "due_at": _iso(task.due_at),
        "overdue": task.is_overdue(now=now),
        "created_by": task.created_by,
        "created_at": _iso(task.created_at),
        "updated_at": _iso(task.updated_at),
        "resolved_at": _iso(task.resolved_at),
        "resolution_note": task.resolution_note or "",
        "verification_history": json.loads(task.verification_history or "[]"),
    }


# --- evidence requests -------------------------------------------------------


def create_evidence_request(
    session: Session,
    *,
    tenant_id: str,
    control_id: str,
    requested_from: str = "",
    note: str = "",
    due_at: datetime | None = None,
    created_by: str = "",
) -> EvidenceRequest:
    if not control_id.strip():
        raise ValueError("evidence request requires a control_id")
    request = EvidenceRequest(
        tenant_id=tenant_id,
        control_id=control_id,
        requested_from=requested_from,
        note=note,
        due_at=due_at,
        created_by=created_by,
    )
    session.add(request)
    session.flush()
    return request


def list_evidence_requests(
    session: Session,
    *,
    tenant_id: str,
    status: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> list[EvidenceRequest]:
    stmt = select(EvidenceRequest).where(EvidenceRequest.tenant_id == tenant_id)
    if status:
        stmt = stmt.where(EvidenceRequest.status == status)
    stmt = apply_pagination(stmt.order_by(EvidenceRequest.created_at.desc()), limit=limit, offset=offset)
    return list(session.scalars(stmt))


def set_evidence_request_status(
    session: Session, *, tenant_id: str, request_id: str, status: str, now: datetime | None = None
) -> EvidenceRequest | None:
    if status not in EVIDENCE_REQUEST_STATUSES:
        raise ValueError(f"status must be one of {list(EVIDENCE_REQUEST_STATUSES)}, got {status!r}")
    request = session.get(EvidenceRequest, request_id)
    if request is None or request.tenant_id != tenant_id:
        return None
    request.status = status
    request.fulfilled_at = _now(now) if status == "fulfilled" else None
    session.flush()
    return request


def evidence_request_to_dict(request: EvidenceRequest) -> dict[str, Any]:
    return {
        "id": request.id,
        "control_id": request.control_id,
        "requested_from": request.requested_from,
        "status": request.status,
        "note": request.note,
        "due_at": _iso(request.due_at),
        "created_by": request.created_by,
        "created_at": _iso(request.created_at),
        "fulfilled_at": _iso(request.fulfilled_at),
    }


# --- control exceptions ------------------------------------------------------


def create_exception(
    session: Session,
    *,
    tenant_id: str,
    control_id: str,
    reason: str = "",
    requested_by_id: str,
    expires_at: datetime | None = None,
    created_by: str = "",
) -> ControlException:
    if not control_id.strip():
        raise ValueError("control exception requires a control_id")
    if not reason.strip() or not created_by.strip() or not requested_by_id.strip():
        raise ValueError("exception requires a reason and an authenticated requester")
    if expires_at is None or expires_at.tzinfo is None or expires_at <= _now(None):
        raise ValueError("exception requires a future timezone-aware expiry")
    exception = ControlException(
        tenant_id=tenant_id,
        control_id=control_id,
        reason=reason,
        requested_by_id=requested_by_id,
        approved_by="",
        status="pending",
        expires_at=expires_at.astimezone(UTC),
        created_by=created_by,
    )
    session.add(exception)
    session.flush()
    return exception


def list_exceptions(
    session: Session,
    *,
    tenant_id: str,
    active_only: bool = False,
    now: datetime | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> list[ControlException]:
    stmt = select(ControlException).where(ControlException.tenant_id == tenant_id)
    if active_only:
        stmt = stmt.where(
            ControlException.status == "active",
            ControlException.revoked_at.is_(None),
            ControlException.expires_at > _now(now),
            ControlException.approved_at.is_not(None),
            ControlException.requested_by_id.is_not(None),
            ControlException.approved_by_id.is_not(None),
            ControlException.requested_by_id != ControlException.approved_by_id,
        )
    stmt = apply_pagination(
        stmt.order_by(ControlException.created_at.desc(), ControlException.id), limit=limit, offset=offset
    )
    return list(session.scalars(stmt))


def approve_exception(
    session: Session, *, tenant_id: str, exception_id: str, reviewer_id: str, reviewer: str, now: datetime | None = None
) -> ControlException:
    moment = _now(now)
    if not reviewer_id or not reviewer:
        raise ValueError("approval requires an authenticated reviewer")
    result = session.execute(
        update(ControlException)
        .where(
            ControlException.id == exception_id,
            ControlException.tenant_id == tenant_id,
            ControlException.status == "pending",
            ControlException.revoked_at.is_(None),
            ControlException.requested_by_id.is_not(None),
            ControlException.requested_by_id != reviewer_id,
            ControlException.expires_at > moment,
        )
        .values(status="active", approved_by=reviewer, approved_by_id=reviewer_id, approved_at=moment)
        .execution_options(synchronize_session="fetch")
        .returning(ControlException.id)
    )
    if result.scalar_one_or_none() is None:
        raise ValueError("exception must be pending, unexpired, and requested by a different user")
    session.flush()
    row = session.get(ControlException, exception_id)
    assert row is not None
    session.refresh(row)
    return row


def revoke_exception(
    session: Session, *, tenant_id: str, exception_id: str, now: datetime | None = None
) -> ControlException | None:
    exception = session.get(ControlException, exception_id)
    if exception is None or exception.tenant_id != tenant_id or exception.status not in {"pending", "active"}:
        return None
    exception.status = "revoked"
    exception.revoked_at = _now(now)
    session.flush()
    return exception


def exception_to_dict(exception: ControlException, *, now: datetime | None = None) -> dict[str, Any]:
    moment = _now(now)
    effective_status = exception.status
    if effective_status in {"pending", "active"} and exception.expires_at and _as_aware(exception.expires_at) <= moment:
        effective_status = "expired"
    return {
        "id": exception.id,
        "control_id": exception.control_id,
        "reason": exception.reason,
        "approved_by": exception.approved_by,
        "approved_at": _iso(exception.approved_at),
        "requested_by_id": exception.requested_by_id,
        "approved_by_id": exception.approved_by_id,
        "acceptance_effect": "risk_accepted_not_control_pass",
        "status": effective_status,
        "active": exception.is_active(now=moment),
        "expires_at": _iso(exception.expires_at),
        "created_by": exception.created_by,
        "created_at": _iso(exception.created_at),
        "revoked_at": _iso(exception.revoked_at),
    }


__all__ = [
    "EVIDENCE_REQUEST_STATUSES",
    "EXCEPTION_STATUSES",
    "REMEDIATION_PRIORITIES",
    "REMEDIATION_STATUSES",
    "create_evidence_request",
    "create_exception",
    "create_task",
    "evidence_request_to_dict",
    "exception_to_dict",
    "get_task",
    "list_evidence_requests",
    "list_exceptions",
    "list_tasks",
    "revoke_exception",
    "set_evidence_request_status",
    "task_to_dict",
    "update_task",
]

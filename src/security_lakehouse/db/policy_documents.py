"""Data-access + serialization for tenant policy documents."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from security_lakehouse.db.base import apply_pagination
from security_lakehouse.db.models import POLICY_DOCUMENT_STATUSES, PolicyDocument
from security_lakehouse.timeutil import iso_offset, utc_now


def _parse_json(raw: str, *, default: Any) -> Any:
    try:
        payload = json.loads(raw or "")
    except json.JSONDecodeError:
        return default
    return payload


def document_to_dict(row: PolicyDocument) -> dict[str, Any]:
    return {
        "id": row.id,
        "template_id": row.template_id,
        "title": row.title,
        "status": row.status,
        "content": row.content,
        "variables": _parse_json(row.variables_json, default={}),
        "related_control_ids": _parse_json(row.related_control_ids_json, default=[]),
        "owner": row.owner,
        "created_by": row.created_by,
        "created_at": iso_offset(row.created_at),
        "updated_at": iso_offset(row.updated_at),
        "published_at": iso_offset(row.published_at),
        "review_due_at": iso_offset(row.review_due_at),
    }


def create_document(
    session: Session,
    *,
    tenant_id: str,
    template_id: str,
    title: str,
    content: str,
    variables: dict[str, Any] | None = None,
    related_control_ids: list[str] | None = None,
    owner: str = "",
    created_by: str = "",
    review_due_at: datetime | None = None,
) -> PolicyDocument:
    if not template_id.strip():
        raise ValueError("policy document requires a template_id")
    if not title.strip():
        raise ValueError("policy document requires a title")
    row = PolicyDocument(
        tenant_id=tenant_id,
        template_id=template_id.strip(),
        title=title.strip(),
        content=content,
        variables_json=json.dumps(variables or {}, sort_keys=True),
        related_control_ids_json=json.dumps(related_control_ids or [], sort_keys=True),
        owner=owner,
        created_by=created_by,
        review_due_at=review_due_at,
    )
    session.add(row)
    session.flush()
    return row


def get_document(session: Session, *, tenant_id: str, document_id: str) -> PolicyDocument | None:
    row = session.get(PolicyDocument, document_id)
    return row if row is not None and row.tenant_id == tenant_id else None


def list_documents(
    session: Session,
    *,
    tenant_id: str,
    status: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> list[PolicyDocument]:
    stmt = select(PolicyDocument).where(PolicyDocument.tenant_id == tenant_id)
    if status:
        stmt = stmt.where(PolicyDocument.status == status)
    stmt = apply_pagination(stmt.order_by(PolicyDocument.updated_at.desc()), limit=limit, offset=offset)
    return list(session.scalars(stmt))


def update_document(
    session: Session,
    *,
    tenant_id: str,
    document_id: str,
    changes: dict[str, Any],
    now: datetime | None = None,
) -> PolicyDocument | None:
    row = get_document(session, tenant_id=tenant_id, document_id=document_id)
    if row is None:
        return None
    moment = utc_now(now)
    if "title" in changes and str(changes["title"]).strip():
        row.title = str(changes["title"]).strip()
    if "content" in changes:
        row.content = str(changes.get("content") or "")
    if "owner" in changes:
        row.owner = str(changes.get("owner") or "")
    if "variables" in changes and isinstance(changes["variables"], dict):
        row.variables_json = json.dumps(changes["variables"], sort_keys=True)
    if "related_control_ids" in changes and isinstance(changes["related_control_ids"], list):
        row.related_control_ids_json = json.dumps(changes["related_control_ids"], sort_keys=True)
    if "review_due_at" in changes:
        row.review_due_at = changes.get("review_due_at")
    if "status" in changes:
        status = str(changes["status"])
        if status not in POLICY_DOCUMENT_STATUSES:
            raise ValueError(f"status must be one of {sorted(POLICY_DOCUMENT_STATUSES)}")
        row.status = status
        if status == "published":
            row.published_at = moment
    row.updated_at = moment
    session.flush()
    return row


def _is_current(review_due_at: datetime | None) -> bool:
    if review_due_at is None:
        return True
    due = review_due_at if review_due_at.tzinfo else review_due_at.replace(tzinfo=UTC)
    return due > utc_now()


def published_control_ids(session: Session, *, tenant_id: str) -> dict[str, dict[str, Any]]:
    """Map control_id -> latest published policy metadata for coverage."""
    rows = list(
        session.scalars(
            select(PolicyDocument).where(
                PolicyDocument.tenant_id == tenant_id,
                PolicyDocument.status == "published",
            )
        )
    )
    coverage: dict[str, dict[str, Any]] = {}
    for row in rows:
        for control_id in _parse_json(row.related_control_ids_json, default=[]):
            cid = str(control_id)
            existing = coverage.get(cid)
            published_at = row.published_at or row.updated_at
            if existing is None or str(existing.get("published_at") or "") < published_at.isoformat():
                coverage[cid] = {
                    "control_id": cid,
                    "document_id": row.id,
                    "title": row.title,
                    "published_at": published_at.isoformat(),
                    "review_due_at": iso_offset(row.review_due_at),
                    "current": _is_current(row.review_due_at),
                }
    return coverage


def default_review_due_at(template: dict[str, Any], *, now: datetime | None = None) -> datetime | None:
    days = int(template.get("review_cadence_days") or 0)
    if days <= 0:
        return None
    return utc_now(now) + timedelta(days=days)

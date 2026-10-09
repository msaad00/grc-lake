"""Data-access + serialization for vendor-risk assessments."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from security_lakehouse.db.base import apply_pagination
from security_lakehouse.db.models import VENDOR_ASSESSMENT_STATUSES, VendorAssessment
from security_lakehouse.timeutil import iso_offset, utc_now


def _parse_responses(raw: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def assessment_to_dict(row: VendorAssessment, *, template: dict[str, Any] | None = None) -> dict[str, Any]:
    data = {
        "id": row.id,
        "vendor_name": row.vendor_name,
        "template_id": row.template_id,
        "status": row.status,
        "control_id": row.control_id,
        "owner": row.owner,
        "responses": _parse_responses(row.responses_json),
        "score": row.score,
        "risk_level": row.risk_level,
        "due_at": iso_offset(row.due_at),
        "created_by": row.created_by,
        "created_at": iso_offset(row.created_at),
        "updated_at": iso_offset(row.updated_at),
        "completed_at": iso_offset(row.completed_at),
    }
    if template is not None:
        data["template"] = template
    return data


def create_assessment(
    session: Session,
    *,
    tenant_id: str,
    vendor_name: str,
    template_id: str,
    owner: str = "",
    control_id: str | None = None,
    due_at: datetime | None = None,
    created_by: str = "",
) -> VendorAssessment:
    if not vendor_name.strip():
        raise ValueError("vendor assessment requires a vendor_name")
    if not template_id.strip():
        raise ValueError("vendor assessment requires a template_id")
    row = VendorAssessment(
        tenant_id=tenant_id,
        vendor_name=vendor_name.strip(),
        template_id=template_id.strip(),
        owner=owner,
        control_id=control_id,
        due_at=due_at,
        created_by=created_by,
    )
    session.add(row)
    session.flush()
    return row


def get_assessment(session: Session, *, tenant_id: str, assessment_id: str) -> VendorAssessment | None:
    row = session.get(VendorAssessment, assessment_id)
    return row if row is not None and row.tenant_id == tenant_id else None


def list_assessments(
    session: Session,
    *,
    tenant_id: str,
    status: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> list[VendorAssessment]:
    stmt = select(VendorAssessment).where(VendorAssessment.tenant_id == tenant_id)
    if status:
        stmt = stmt.where(VendorAssessment.status == status)
    stmt = apply_pagination(stmt.order_by(VendorAssessment.created_at.desc()), limit=limit, offset=offset)
    return list(session.scalars(stmt))


def update_assessment(
    session: Session,
    *,
    tenant_id: str,
    assessment_id: str,
    changes: dict[str, Any],
    now: datetime | None = None,
) -> VendorAssessment | None:
    row = get_assessment(session, tenant_id=tenant_id, assessment_id=assessment_id)
    if row is None:
        return None
    moment = utc_now(now)
    if "vendor_name" in changes and str(changes["vendor_name"]).strip():
        row.vendor_name = str(changes["vendor_name"]).strip()
    if "owner" in changes:
        row.owner = str(changes.get("owner") or "")
    if "control_id" in changes:
        row.control_id = changes.get("control_id")
    if "due_at" in changes:
        row.due_at = changes.get("due_at")
    if "responses" in changes and isinstance(changes["responses"], dict):
        row.responses_json = json.dumps(changes["responses"], sort_keys=True)
    if "status" in changes:
        status = str(changes["status"])
        if status not in VENDOR_ASSESSMENT_STATUSES:
            raise ValueError(f"status must be one of {sorted(VENDOR_ASSESSMENT_STATUSES)}")
        row.status = status
        if status == "completed":
            row.completed_at = moment
    if "score" in changes:
        row.score = changes.get("score")
    if "risk_level" in changes:
        row.risk_level = changes.get("risk_level")
    row.updated_at = moment
    session.flush()
    return row

"""Data-access + serialization for policy employee acknowledgments."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from security_lakehouse.db.models import PolicyAcknowledgment, PolicyDocument
from security_lakehouse.timeutil import iso_offset, utc_now


def acknowledgment_to_dict(row: PolicyAcknowledgment) -> dict[str, Any]:
    return {
        "id": row.id,
        "policy_document_id": row.policy_document_id,
        "user_email": row.user_email,
        "display_name": row.display_name,
        "acknowledged_at": iso_offset(row.acknowledged_at),
    }


def list_acknowledgments(
    session: Session,
    *,
    tenant_id: str,
    policy_document_id: str,
) -> list[PolicyAcknowledgment]:
    return list(
        session.scalars(
            select(PolicyAcknowledgment)
            .where(
                PolicyAcknowledgment.tenant_id == tenant_id,
                PolicyAcknowledgment.policy_document_id == policy_document_id,
            )
            .order_by(PolicyAcknowledgment.acknowledged_at.desc())
        )
    )


def record_acknowledgment(
    session: Session,
    *,
    tenant_id: str,
    policy_document_id: str,
    user_email: str,
    display_name: str = "",
    now: datetime | None = None,
) -> PolicyAcknowledgment:
    normalized = user_email.strip().lower()
    if not normalized or "@" not in normalized:
        raise ValueError("acknowledgment requires a valid user_email")
    document = session.get(PolicyDocument, policy_document_id)
    if document is None or document.tenant_id != tenant_id:
        raise ValueError("policy document not found")
    if document.status != "published":
        raise ValueError("only published policies accept employee acknowledgments")
    existing = session.scalars(
        select(PolicyAcknowledgment).where(
            PolicyAcknowledgment.tenant_id == tenant_id,
            PolicyAcknowledgment.policy_document_id == policy_document_id,
            PolicyAcknowledgment.user_email == normalized,
        )
    ).one_or_none()
    if existing is not None:
        return existing
    row = PolicyAcknowledgment(
        tenant_id=tenant_id,
        policy_document_id=policy_document_id,
        user_email=normalized,
        display_name=display_name.strip(),
        acknowledged_at=utc_now(now),
    )
    session.add(row)
    session.flush()
    return row


def count_acknowledgments_by_policy(session: Session, *, tenant_id: str) -> dict[str, int]:
    rows = session.execute(
        select(PolicyAcknowledgment.policy_document_id, func.count())
        .where(PolicyAcknowledgment.tenant_id == tenant_id)
        .group_by(PolicyAcknowledgment.policy_document_id)
    )
    return {str(policy_id): int(count) for policy_id, count in rows}


def attestation_summary(session: Session, *, tenant_id: str) -> dict[str, int]:
    published = list(
        session.scalars(
            select(PolicyDocument).where(
                PolicyDocument.tenant_id == tenant_id,
                PolicyDocument.status == "published",
            )
        )
    )
    ack_counts = count_acknowledgments_by_policy(session, tenant_id=tenant_id)
    with_acks = sum(1 for row in published if ack_counts.get(row.id, 0) > 0)
    return {
        "published": len(published),
        "acknowledged": with_acks,
        "unattested": max(len(published) - with_acks, 0),
        "total_acknowledgments": sum(ack_counts.values()),
    }

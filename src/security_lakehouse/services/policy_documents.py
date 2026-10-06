"""Policy template catalog + tenant policy document service."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.db import policy_acknowledgments as pa
from security_lakehouse.db import policy_documents as pd
from security_lakehouse.policy_templates import (
    get_policy_template,
    list_policy_templates,
    render_policy_template,
    validate_policy_template_catalog,
)
from security_lakehouse.services import NotFound, ValidationError


def list_templates() -> list[dict[str, Any]]:
    return [
        {
            "template_id": row["template_id"],
            "title": row.get("title"),
            "category": row.get("category"),
            "framework_ids": row.get("framework_ids") or [],
            "related_control_ids": row.get("related_control_ids") or [],
            "owner_role": row.get("owner_role"),
            "review_cadence_days": row.get("review_cadence_days"),
            "summary": row.get("summary"),
            "variables": row.get("variables") or [],
        }
        for row in list_policy_templates()
    ]


def get_template(template_id: str) -> dict[str, Any]:
    template = get_policy_template(template_id)
    if template is None:
        raise NotFound("policy template not found")
    return template


def validate_catalog() -> list[str]:
    return validate_policy_template_catalog()


def list_documents(
    session: Session,
    tenant_id: str,
    *,
    status: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> list[dict[str, Any]]:
    rows = pd.list_documents(session, tenant_id=tenant_id, status=status, limit=limit, offset=offset)
    return [pd.document_to_dict(row) for row in rows]


def adopt_template(
    session: Session,
    tenant_id: str,
    *,
    template_id: str,
    variables: dict[str, Any] | None = None,
    owner: str = "",
    created_by: str = "",
) -> dict[str, Any]:
    template = get_policy_template(template_id)
    if template is None:
        raise ValidationError(f"unknown policy template: {template_id}")
    rendered = render_policy_template(template, variables)
    try:
        row = pd.create_document(
            session,
            tenant_id=tenant_id,
            template_id=template_id,
            title=str(template.get("title") or template_id),
            content=rendered,
            variables=variables,
            related_control_ids=list(template.get("related_control_ids") or []),
            owner=owner,
            created_by=created_by,
            review_due_at=pd.default_review_due_at(template),
        )
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    session.commit()
    return pd.document_to_dict(row)


def get_document(session: Session, tenant_id: str, document_id: str) -> dict[str, Any]:
    row = pd.get_document(session, tenant_id=tenant_id, document_id=document_id)
    if row is None:
        raise NotFound("policy document not found")
    return pd.document_to_dict(row)


def update_document(
    session: Session,
    tenant_id: str,
    document_id: str,
    *,
    changes: dict[str, Any],
) -> dict[str, Any]:
    try:
        updated = pd.update_document(session, tenant_id=tenant_id, document_id=document_id, changes=changes)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    if updated is None:
        raise NotFound("policy document not found")
    session.commit()
    return pd.document_to_dict(updated)


def publish_document(session: Session, tenant_id: str, document_id: str) -> dict[str, Any]:
    return update_document(session, tenant_id, document_id, changes={"status": "published"})


def list_acknowledgments(session: Session, tenant_id: str, document_id: str) -> list[dict[str, Any]]:
    row = pd.get_document(session, tenant_id=tenant_id, document_id=document_id)
    if row is None:
        raise NotFound("policy document not found")
    rows = pa.list_acknowledgments(session, tenant_id=tenant_id, policy_document_id=document_id)
    return [pa.acknowledgment_to_dict(item) for item in rows]


def record_acknowledgment(
    session: Session,
    tenant_id: str,
    document_id: str,
    *,
    user_email: str,
    display_name: str = "",
) -> dict[str, Any]:
    try:
        row = pa.record_acknowledgment(
            session,
            tenant_id=tenant_id,
            policy_document_id=document_id,
            user_email=user_email,
            display_name=display_name,
        )
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    session.commit()
    return pa.acknowledgment_to_dict(row)


def attestation_summary(session: Session, tenant_id: str) -> dict[str, int]:
    return pa.attestation_summary(session, tenant_id=tenant_id)


def control_coverage(session: Session, tenant_id: str) -> list[dict[str, Any]]:
    controls = load_control_catalog()
    published = pd.published_control_ids(session, tenant_id=tenant_id)
    rows: list[dict[str, Any]] = []
    templates = list_policy_templates()
    for control_id, control in controls.items():
        related = [
            template["template_id"]
            for template in templates
            if control_id in (template.get("related_control_ids") or [])
        ]
        if not related:
            continue
        row = published.get(control_id)
        rows.append(
            {
                "control_id": control_id,
                "framework": control.get("framework_id"),
                "title": control.get("title"),
                "template_ids": related,
                "published": row is not None,
                "current": bool(row and row.get("current")),
                "document_id": row.get("document_id") if row else None,
                "document_title": row.get("title") if row else None,
                "published_at": row.get("published_at") if row else None,
                "review_due_at": row.get("review_due_at") if row else None,
            }
        )
    rows.sort(key=lambda item: str(item["control_id"]))
    return rows

"""Authenticated creation and independent review of immutable audit workpapers."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from security_lakehouse import api_v1
from security_lakehouse.audit_workpapers import build_workpaper, render_workpaper
from security_lakehouse.auth.dependencies import get_session, require_scope
from security_lakehouse.auth.rbac import Identity
from security_lakehouse.db import remediation
from security_lakehouse.db.models import AuditWorkpaper, RemediationTask
from security_lakehouse.io import canonical_sha256
from security_lakehouse.server_routes.schemas.base import StrictModel

_require_read = require_scope("read")
_require_create = require_scope("control_manage")
_require_review = require_scope("workpaper_review")


class CreateWorkpaper(StrictModel):
    plan: dict[str, Any]
    baseline: dict[str, Any]
    narrative: str = Field(default="", max_length=10000)
    citations: list[str] = Field(default_factory=list, max_length=500)


class ReviewWorkpaper(StrictModel):
    decision: Literal["approve", "reject"]
    rationale: str = Field(min_length=1, max_length=4000)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def _content(row: AuditWorkpaper) -> dict[str, Any]:
    content = json.loads(row.content_json)
    if canonical_sha256(content) != row.content_sha256:
        raise HTTPException(409, "workpaper integrity check failed")
    return content


def _serialize(row: AuditWorkpaper, *, include_content: bool = True) -> dict[str, Any]:
    result = {
        key: getattr(row, key)
        for key in ("id", "tenant_id", "content_sha256", "status", "created_by", "reviewed_by", "review_rationale")
    }
    result.update(
        created_at=row.created_at.isoformat(),
        reviewed_at=row.reviewed_at.isoformat() if row.reviewed_at else None,
        review_scope="workpaper_review_only",
    )
    if include_content:
        result["content"] = _content(row)
    return result


def _get(session: Session, tenant_id: str, workpaper_id: str) -> AuditWorkpaper:
    row = session.scalar(
        select(AuditWorkpaper).where(AuditWorkpaper.id == workpaper_id, AuditWorkpaper.tenant_id == tenant_id)
    )
    if row is None:
        raise HTTPException(404, "workpaper not found")
    return row


def build_audit_workpapers_router(*, lake_for: Callable[[Identity], Path]) -> APIRouter:
    router = APIRouter(prefix="/api/v1/audit-workpapers", tags=["audit-workpapers"])

    @router.post("", status_code=201)
    def create(
        body: CreateWorkpaper, identity: Identity = Depends(_require_create), session: Session = Depends(get_session)
    ) -> dict:
        if body.plan.get("tenant_id") != identity.tenant_id or body.baseline.get("tenant_id") != identity.tenant_id:
            raise HTTPException(400, "workpaper scope must match the authenticated tenant")
        try:
            content = build_workpaper(lake_for(identity), **body.model_dump())
        except (ValueError, OSError) as exc:
            raise HTTPException(400, "workpaper inputs or evidence generation are invalid") from exc
        control_ids = {
            member["control_id"]
            for control in content["assurance"]["controls"]
            for member in control["requirement_mappings"]
        }
        tasks = list(
            session.scalars(
                select(RemediationTask)
                .where(RemediationTask.tenant_id == identity.tenant_id, RemediationTask.control_id.in_(control_ids))
                .order_by(RemediationTask.created_at, RemediationTask.id)
                .limit(501)
            )
        )
        if len(tasks) > 500:
            raise HTTPException(400, "more than 500 linked tasks; split the workpaper scope")
        content["remediation"] = {
            "source": "application_state_snapshot",
            "tasks": [remediation.task_to_dict(task) for task in tasks],
        }
        if len(json.dumps(content).encode()) > 2 * 1024 * 1024:
            raise HTTPException(400, "workpaper exceeds 2 MiB; split scope")
        row = AuditWorkpaper(
            tenant_id=identity.tenant_id,
            content_json=json.dumps(content, sort_keys=True),
            content_sha256=canonical_sha256(content),
            created_by_id=identity.user_id,
            created_by=identity.email,
        )
        session.add(row)
        session.commit()
        return api_v1.envelope("audit-workpapers", _serialize(row))

    @router.get("")
    def list_workpapers(
        limit: int = Query(25, ge=1, le=100),
        offset: int = Query(0, ge=0),
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> dict:
        rows = session.scalars(
            select(AuditWorkpaper)
            .where(AuditWorkpaper.tenant_id == identity.tenant_id)
            .order_by(AuditWorkpaper.created_at.desc(), AuditWorkpaper.id)
            .limit(limit + 1)
            .offset(offset)
        ).all()
        return api_v1.envelope(
            "audit-workpapers",
            [_serialize(row, include_content=False) for row in rows[:limit]],
            meta={"has_more": len(rows) > limit},
        )

    @router.get("/{workpaper_id}")
    def get(
        workpaper_id: str, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> dict:
        return api_v1.envelope("audit-workpapers", _serialize(_get(session, identity.tenant_id, workpaper_id)))

    @router.get("/{workpaper_id}/html", response_class=HTMLResponse)
    def export_html(
        workpaper_id: str, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> HTMLResponse:
        row = _get(session, identity.tenant_id, workpaper_id)
        return HTMLResponse(
            render_workpaper(_content(row), review=_serialize(row, include_content=False)),
            headers={
                "Cache-Control": "no-store",
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
            },
        )

    @router.post("/{workpaper_id}/review")
    def review(
        workpaper_id: str,
        body: ReviewWorkpaper,
        identity: Identity = Depends(_require_review),
        session: Session = Depends(get_session),
    ) -> dict:
        row = _get(session, identity.tenant_id, workpaper_id)
        _content(row)
        if (
            row.created_by_id == identity.user_id
            or not identity.is_interactive_session
            or identity.auth_method == "insecure"
        ):
            raise HTTPException(403, "independent authenticated reviewer required")
        if not body.rationale.strip():
            raise HTTPException(400, "review rationale is required")
        result = session.execute(
            update(AuditWorkpaper)
            .where(
                AuditWorkpaper.id == row.id,
                AuditWorkpaper.tenant_id == identity.tenant_id,
                AuditWorkpaper.status == "draft",
                AuditWorkpaper.content_sha256 == body.content_sha256,
            )
            .values(
                status="approved" if body.decision == "approve" else "rejected",
                reviewed_by_id=identity.user_id,
                reviewed_by=identity.email,
                reviewed_at=datetime.now(UTC),
                review_rationale=body.rationale.strip(),
            )
            .returning(AuditWorkpaper.id)
        )
        if result.scalar_one_or_none() is None:
            raise HTTPException(409, "workpaper was already reviewed or content digest changed")
        session.commit()
        session.refresh(row)
        return api_v1.envelope("audit-workpapers", _serialize(row))

    return router

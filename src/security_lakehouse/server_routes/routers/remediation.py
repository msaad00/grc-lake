"""Remediation routes, registered before generic dispatch."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from security_lakehouse import api_v1
from security_lakehouse.auth.dependencies import get_session, require_human, require_scope
from security_lakehouse.auth.rbac import Identity
from security_lakehouse.db import remediation
from security_lakehouse.db.base import MAX_PAGE_LIMIT
from security_lakehouse.server_routes.deps import parse_dt as _parse_dt
from security_lakehouse.server_routes.payloads import (
    _applied_filters,
    _page_meta,
    _page_window,
    _pagination,
    _params,
    _redact_payload,
)
from security_lakehouse.server_routes.schemas.workflows import (
    CreateEvidenceRequestRequest,
    CreateExceptionRequest,
    CreateTaskRequest,
    EvidenceRequestStatusRequest,
    UpdateTaskRequest,
    VerifyTaskRequest,
)
from security_lakehouse.services import NotFound, ValidationError
from security_lakehouse.services import grc as grc_services

_require_control_manage = require_scope("control_manage")
_require_evidence_request = require_scope("evidence_request")
_require_read = require_scope("read")
_require_write = require_scope("write")


def build_remediation_router(*, lake_for: Callable[[Identity], Path]) -> APIRouter:
    """Bind this workflow to the current request tenant lake."""
    router = APIRouter()

    @router.get("/api/v1/remediation/tasks")
    def list_tasks(
        request: Request, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        params = _params(request)
        limit, offset = _page_window(params, maximum=MAX_PAGE_LIMIT)
        overdue_raw = api_v1.first_param(params, "overdue")
        overdue = None if overdue_raw is None else overdue_raw.lower() in {"1", "true", "yes"}
        filters = {
            "status": api_v1.first_param(params, "status"),
            "owner": api_v1.first_param(params, "owner"),
            "control_id": next(iter(params.get("control_id") or []), None),
        }
        rows = grc_services.list_tasks(
            session, identity.tenant_id, **filters, overdue=overdue, limit=limit, offset=offset
        )
        total = grc_services.count_tasks(session, identity.tenant_id, **filters, overdue=overdue)
        return JSONResponse(
            api_v1.collection_page_response(
                "remediation.tasks",
                _redact_payload(rows, identity),  # type: ignore[arg-type]
                count=total,
                limit=limit,
                offset=offset,
                sort=None,
                filters=_applied_filters(**filters, overdue=overdue_raw),
            )
        )

    @router.post("/api/v1/remediation/tasks", status_code=status.HTTP_201_CREATED)
    def create_task(
        body: CreateTaskRequest, identity: Identity = Depends(_require_write), session: Session = Depends(get_session)
    ) -> JSONResponse:
        try:
            task = grc_services.create_task(
                session,
                identity.tenant_id,
                title=body.title,
                description=body.description,
                control_id=body.control_id,
                violation_id=body.violation_id,
                owner=body.owner,
                priority=body.priority,
                due_at=_parse_dt(body.due_at),
                created_by=identity.email,
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("remediation.tasks", task), status_code=status.HTTP_201_CREATED)

    @router.get("/api/v1/remediation/tasks/{task_id}")
    def get_task(
        task_id: str, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        task = remediation.get_task(session, tenant_id=identity.tenant_id, task_id=task_id)
        if task is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="task not found")
        return JSONResponse(
            api_v1.envelope("remediation.tasks", _redact_payload(remediation.task_to_dict(task), identity))
        )

    @router.patch("/api/v1/remediation/tasks/{task_id}")
    def update_task(
        task_id: str,
        body: UpdateTaskRequest,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        changes = body.model_dump(exclude_unset=True)
        if "due_at" in changes:
            changes["due_at"] = _parse_dt(changes["due_at"])
        try:
            task = grc_services.update_task(session, identity.tenant_id, task_id, changes=changes)
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("remediation.tasks", task))

    @router.post("/api/v1/remediation/tasks/{task_id}/verify")
    def verify_remediation_task(
        task_id: str,
        body: VerifyTaskRequest,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        require_human(identity)
        from security_lakehouse.remediation_verification import verify_task

        try:
            remediation.update_task(
                session,
                tenant_id=identity.tenant_id,
                task_id=task_id,
                changes={"resolution_note": body.resolution_note},
            )
            task = verify_task(
                session,
                lake_for(identity),
                tenant_id=identity.tenant_id,
                task_id=task_id,
                reviewer_id=identity.user_id,
                reviewer=identity.email,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        session.commit()
        return JSONResponse(api_v1.envelope("remediation.tasks", remediation.task_to_dict(task)))

    @router.get("/api/v1/remediation/evidence-requests")
    def list_evidence_requests(
        request: Request, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        params = _params(request)
        limit, offset = _pagination(params)
        rows = remediation.list_evidence_requests(
            session,
            tenant_id=identity.tenant_id,
            status=api_v1.first_param(params, "status"),
            limit=limit,
            offset=offset,
        )
        data = [remediation.evidence_request_to_dict(row) for row in rows]
        return JSONResponse(
            api_v1.envelope(
                "remediation.evidence_requests",
                _redact_payload(data, identity),
                meta=_page_meta(limit, offset, len(data)),
            )
        )

    @router.post("/api/v1/remediation/evidence-requests", status_code=status.HTTP_201_CREATED)
    def create_evidence_request(
        body: CreateEvidenceRequestRequest,
        identity: Identity = Depends(_require_evidence_request),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            req = remediation.create_evidence_request(
                session,
                tenant_id=identity.tenant_id,
                control_id=body.control_id,
                requested_from=body.requested_from,
                note=body.note,
                due_at=_parse_dt(body.due_at),
                created_by=identity.email,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        session.commit()
        return JSONResponse(
            api_v1.envelope("remediation.evidence_requests", remediation.evidence_request_to_dict(req)),
            status_code=status.HTTP_201_CREATED,
        )

    @router.patch("/api/v1/remediation/evidence-requests/{request_id}")
    def update_evidence_request(
        request_id: str,
        body: EvidenceRequestStatusRequest,
        identity: Identity = Depends(_require_evidence_request),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            req = remediation.set_evidence_request_status(
                session, tenant_id=identity.tenant_id, request_id=request_id, status=body.status
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        if req is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence request not found")
        session.commit()
        return JSONResponse(api_v1.envelope("remediation.evidence_requests", remediation.evidence_request_to_dict(req)))

    @router.get("/api/v1/remediation/exceptions")
    def list_exceptions(
        request: Request, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        params = _params(request)
        limit, offset = _pagination(params)
        active_raw = api_v1.first_param(params, "active")
        rows = remediation.list_exceptions(
            session,
            tenant_id=identity.tenant_id,
            active_only=bool(active_raw and active_raw.lower() in {"1", "true", "yes"}),
            limit=limit,
            offset=offset,
        )
        data = [remediation.exception_to_dict(row) for row in rows]
        return JSONResponse(
            api_v1.envelope(
                "remediation.exceptions", _redact_payload(data, identity), meta=_page_meta(limit, offset, len(data))
            )
        )

    @router.post("/api/v1/remediation/exceptions", status_code=status.HTTP_201_CREATED)
    def create_exception(
        body: CreateExceptionRequest,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            exc_row = remediation.create_exception(
                session,
                tenant_id=identity.tenant_id,
                control_id=body.control_id,
                reason=body.reason,
                requested_by_id=identity.user_id,
                expires_at=_parse_dt(body.expires_at),
                created_by=identity.email,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        session.commit()
        return JSONResponse(
            api_v1.envelope("remediation.exceptions", remediation.exception_to_dict(exc_row)),
            status_code=status.HTTP_201_CREATED,
        )

    @router.post("/api/v1/remediation/exceptions/{exception_id}/approve")
    def approve_exception(
        exception_id: str,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        require_human(identity)
        try:
            row = remediation.approve_exception(
                session,
                tenant_id=identity.tenant_id,
                exception_id=exception_id,
                reviewer_id=identity.user_id,
                reviewer=identity.email,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        session.commit()
        return JSONResponse(api_v1.envelope("remediation.exceptions", remediation.exception_to_dict(row)))

    @router.delete("/api/v1/remediation/exceptions/{exception_id}")
    def revoke_exception(
        exception_id: str,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        revoked = remediation.revoke_exception(session, tenant_id=identity.tenant_id, exception_id=exception_id)
        if revoked is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="exception not found or not active")
        session.commit()
        return JSONResponse(api_v1.envelope("remediation.exceptions", remediation.exception_to_dict(revoked)))

    return router

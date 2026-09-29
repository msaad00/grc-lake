"""Gov-compliance routes: SPRS scoring and POA&M tracking."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from security_lakehouse import api_v1
from security_lakehouse.auth.dependencies import get_session, require_scope
from security_lakehouse.auth.rbac import Identity
from security_lakehouse.server_routes.deps import page_meta, pagination, parse_dt, query_params, redact_for_identity
from security_lakehouse.server_routes.schemas.poam import CreatePoamItemRequest, UpdatePoamItemRequest
from security_lakehouse.services import NotFound, ValidationError
from security_lakehouse.services import poam as poam_services

_require_read = require_scope("read")
_require_write = require_scope("write")


def build_gov_compliance_router(*, lake_for: Callable[[Identity], Path]) -> APIRouter:
    """Return gov-compliance routes bound to the per-request lake resolver."""
    router = APIRouter(prefix="/api/v1/gov-compliance", tags=["gov-compliance"])

    @router.get("/sprs")
    def sprs_score_route(identity: Identity = Depends(_require_read)) -> JSONResponse:
        from security_lakehouse.sprs import build_sprs_report

        data = build_sprs_report(lake_for(identity))
        return JSONResponse(api_v1.envelope("gov-compliance.sprs", data))

    @router.get("/poam")
    def list_poam_route(
        request: Request,
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        params = query_params(request)
        limit, offset = pagination(params)
        rows = poam_services.list_poam_items(
            session,
            identity.tenant_id,
            framework_id=api_v1.first_param(params, "framework_id"),
            status=api_v1.first_param(params, "status"),
            limit=limit,
            offset=offset,
        )
        return JSONResponse(
            api_v1.envelope(
                "gov-compliance.poam",
                redact_for_identity(rows, identity),
                meta=page_meta(limit, offset, len(rows)),
            )
        )

    @router.post("/poam", status_code=status.HTTP_201_CREATED)
    def create_poam_route(
        body: CreatePoamItemRequest,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            item = poam_services.create_poam_item(
                session,
                identity.tenant_id,
                requirement_id=body.requirement_id,
                control_id=body.control_id,
                title=body.title,
                weakness=body.weakness,
                framework_id=body.framework_id,
                owner=body.owner,
                milestone=body.milestone,
                sprs_points=body.sprs_points,
                poam_eligible=body.poam_eligible,
                due_at=parse_dt(body.due_at),
                remediation_task_id=body.remediation_task_id,
                created_by=identity.email,
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("gov-compliance.poam", item), status_code=status.HTTP_201_CREATED)

    @router.post("/poam/sync")
    def sync_poam_route(
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        data = poam_services.sync_poam_from_posture(
            session,
            identity.tenant_id,
            lake_for(identity),
            created_by=identity.email,
        )
        return JSONResponse(api_v1.envelope("gov-compliance.poam.sync", data))

    @router.patch("/poam/{item_id}")
    def update_poam_route(
        item_id: str,
        body: UpdatePoamItemRequest,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        changes = body.model_dump(exclude_unset=True)
        if "due_at" in changes:
            changes["due_at"] = parse_dt(changes["due_at"])
        try:
            item = poam_services.update_poam_item(session, identity.tenant_id, item_id, changes=changes)
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("gov-compliance.poam", item))

    return router

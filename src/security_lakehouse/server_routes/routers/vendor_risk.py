"""Vendor risk routes, registered before generic dispatch."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from security_lakehouse import api_v1, remediation_guidance
from security_lakehouse.auth.dependencies import get_session, require_scope
from security_lakehouse.auth.rbac import Identity
from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.server_routes.deps import parse_dt as _parse_dt
from security_lakehouse.server_routes.payloads import _page_meta, _pagination, _params, _redact_payload
from security_lakehouse.server_routes.schemas.workflows import (
    CreateVendorAssessmentRequest,
    UpdateVendorAssessmentRequest,
)
from security_lakehouse.services import NotFound, ValidationError
from security_lakehouse.services import vendor_risk as vendor_risk_services

_require_control_manage = require_scope("control_manage")
_require_read = require_scope("read")


def build_vendor_risk_router() -> APIRouter:
    """Build the authenticated workflow routes."""
    router = APIRouter()

    @router.get("/api/v1/vendor-questionnaires")
    def list_vendor_questionnaires(identity: Identity = Depends(_require_read)) -> JSONResponse:
        data = vendor_risk_services.list_templates()
        return JSONResponse(
            api_v1.envelope("vendor-questionnaires", _redact_payload(data, identity), meta={"count": len(data)})
        )

    @router.get("/api/v1/vendor-questionnaires/{template_id}")
    def get_vendor_questionnaire(template_id: str, identity: Identity = Depends(_require_read)) -> JSONResponse:
        try:
            data = vendor_risk_services.get_template(template_id)
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("vendor-questionnaires", _redact_payload(data, identity)))

    @router.get("/api/v1/vendor-assessments")
    def list_vendor_assessments(
        request: Request, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        params = _params(request)
        limit, offset = _pagination(params)
        data = vendor_risk_services.list_assessments(
            session,
            identity.tenant_id,
            status=api_v1.first_param(params, "status"),
            limit=limit,
            offset=offset,
        )
        return JSONResponse(
            api_v1.envelope(
                "vendor-assessments", _redact_payload(data, identity), meta=_page_meta(limit, offset, len(data))
            )
        )

    @router.post("/api/v1/vendor-assessments", status_code=status.HTTP_201_CREATED)
    def create_vendor_assessment(
        body: CreateVendorAssessmentRequest,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            assessment = vendor_risk_services.create_assessment(
                session,
                identity.tenant_id,
                vendor_name=body.vendor_name,
                template_id=body.template_id,
                owner=body.owner,
                control_id=body.control_id,
                due_at=_parse_dt(body.due_at),
                created_by=identity.email,
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("vendor-assessments", assessment), status_code=status.HTTP_201_CREATED)

    @router.get("/api/v1/vendor-assessments/{assessment_id}")
    def get_vendor_assessment(
        assessment_id: str, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        try:
            data = vendor_risk_services.get_assessment(session, identity.tenant_id, assessment_id)
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("vendor-assessments", _redact_payload(data, identity)))

    @router.patch("/api/v1/vendor-assessments/{assessment_id}")
    def update_vendor_assessment(
        assessment_id: str,
        body: UpdateVendorAssessmentRequest,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        changes = body.model_dump(exclude_unset=True)
        if "due_at" in changes:
            changes["due_at"] = _parse_dt(changes["due_at"])
        try:
            assessment = vendor_risk_services.update_assessment(
                session, identity.tenant_id, assessment_id, changes=changes
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("vendor-assessments", assessment))

    @router.post("/api/v1/vendor-assessments/{assessment_id}/submit")
    def submit_vendor_assessment(
        assessment_id: str,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            assessment = vendor_risk_services.submit_assessment(session, identity.tenant_id, assessment_id)
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("vendor-assessments", assessment))

    # --- remediation guidance ---
    @router.get("/api/v1/controls/{control_id}/remediation")
    def control_remediation(
        control_id: str, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        control = load_control_catalog().get(control_id)
        if control is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="control not found")
        data = remediation_guidance.guidance_for_control(control)
        return JSONResponse(api_v1.envelope("controls.remediation", data))

    return router

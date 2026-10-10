"""Policies routes, registered before generic dispatch."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from security_lakehouse import api_v1
from security_lakehouse.auth.dependencies import get_session, require_human, require_scope
from security_lakehouse.auth.rbac import Identity
from security_lakehouse.server_routes.payloads import _page_meta, _pagination, _params, _redact_payload
from security_lakehouse.server_routes.schemas.workflows import (
    AdoptPolicyTemplateRequest,
    RecordPolicyAcknowledgmentRequest,
    UpdatePolicyDocumentRequest,
)
from security_lakehouse.services import NotFound, ValidationError
from security_lakehouse.services import policy_documents as policy_document_services

_require_control_manage = require_scope("control_manage")
_require_read = require_scope("read")


def build_policies_router() -> APIRouter:
    """Build the authenticated workflow routes."""
    router = APIRouter()

    @router.get("/api/v1/policy-templates")
    def list_policy_templates(identity: Identity = Depends(_require_read)) -> JSONResponse:
        data = policy_document_services.list_templates()
        return JSONResponse(
            api_v1.envelope("policy-templates", _redact_payload(data, identity), meta={"count": len(data)})
        )

    @router.get("/api/v1/policy-templates/{template_id}")
    def get_policy_template(template_id: str, identity: Identity = Depends(_require_read)) -> JSONResponse:
        try:
            data = policy_document_services.get_template(template_id)
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("policy-templates", _redact_payload(data, identity)))

    @router.get("/api/v1/policies/coverage")
    def policy_coverage(
        identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        data = policy_document_services.control_coverage(session, identity.tenant_id)
        return JSONResponse(
            api_v1.envelope("policies.coverage", _redact_payload(data, identity), meta={"count": len(data)})
        )

    @router.get("/api/v1/policies/attestation-summary")
    def policy_attestation_summary(
        identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        data = policy_document_services.attestation_summary(session, identity.tenant_id)
        return JSONResponse(api_v1.envelope("policies.attestation", _redact_payload(data, identity)))

    @router.get("/api/v1/policies")
    def list_policies(
        request: Request, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        params = _params(request)
        limit, offset = _pagination(params)
        data = policy_document_services.list_documents(
            session,
            identity.tenant_id,
            status=api_v1.first_param(params, "status"),
            limit=limit,
            offset=offset,
        )
        return JSONResponse(
            api_v1.envelope("policies", _redact_payload(data, identity), meta=_page_meta(limit, offset, len(data)))
        )

    @router.post("/api/v1/policies", status_code=status.HTTP_201_CREATED)
    def adopt_policy(
        body: AdoptPolicyTemplateRequest,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            document = policy_document_services.adopt_template(
                session,
                identity.tenant_id,
                template_id=body.template_id,
                variables=body.variables,
                owner=body.owner,
                created_by=identity.email,
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("policies", document), status_code=status.HTTP_201_CREATED)

    @router.get("/api/v1/policies/{document_id}")
    def get_policy(
        document_id: str, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        try:
            data = policy_document_services.get_document(session, identity.tenant_id, document_id)
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("policies", _redact_payload(data, identity)))

    @router.patch("/api/v1/policies/{document_id}")
    def update_policy(
        document_id: str,
        body: UpdatePolicyDocumentRequest,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            document = policy_document_services.update_document(
                session,
                identity.tenant_id,
                document_id,
                changes=body.model_dump(exclude_unset=True),
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("policies", document))

    @router.post("/api/v1/policies/{document_id}/publish")
    def publish_policy(
        document_id: str,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            document = policy_document_services.publish_document(session, identity.tenant_id, document_id)
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("policies", document))

    @router.get("/api/v1/policies/{document_id}/acknowledgments")
    def list_policy_acknowledgments(
        document_id: str, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        try:
            data = policy_document_services.list_acknowledgments(session, identity.tenant_id, document_id)
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(
            api_v1.envelope("policies.acknowledgments", _redact_payload(data, identity), meta={"count": len(data)})
        )

    @router.post("/api/v1/policies/{document_id}/acknowledgments", status_code=status.HTTP_201_CREATED)
    def record_policy_acknowledgment(
        document_id: str,
        body: RecordPolicyAcknowledgmentRequest,
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        require_human(identity)
        target_email = (body.user_email or identity.email or "").strip()
        if body.user_email and target_email.lower() != (identity.email or "").lower():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="acknowledgments must be recorded by the employee themselves",
            )
        try:
            row = policy_document_services.record_acknowledgment(
                session,
                identity.tenant_id,
                document_id,
                user_email=target_email,
                display_name=body.display_name,
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("policies.acknowledgments", row), status_code=status.HTTP_201_CREATED)

    return router

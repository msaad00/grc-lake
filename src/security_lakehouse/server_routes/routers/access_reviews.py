"""Access reviews routes, registered before generic dispatch."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from security_lakehouse import api_v1
from security_lakehouse.auth.dependencies import get_session, require_human, require_scope
from security_lakehouse.auth.rbac import Identity
from security_lakehouse.server_routes.deps import parse_dt as _parse_dt
from security_lakehouse.server_routes.payloads import _page_meta, _pagination, _params, _redact_payload
from security_lakehouse.server_routes.schemas.workflows import (
    AddReviewItemRequest,
    CampaignStatusRequest,
    CreateCampaignRequest,
    ReviewDecisionRequest,
)
from security_lakehouse.services import NotFound, ValidationError
from security_lakehouse.services import access_reviews as access_review_services

_require_control_manage = require_scope("control_manage")
_require_read = require_scope("read")


def build_access_reviews_router(*, lake_for: Callable[[Identity], Path]) -> APIRouter:
    """Bind this workflow to the current request tenant lake."""
    router = APIRouter()

    @router.get("/api/v1/access-reviews")
    def list_access_reviews(
        request: Request, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        params = _params(request)
        limit, offset = _pagination(params)
        data = access_review_services.list_campaigns(
            session,
            identity.tenant_id,
            status=api_v1.first_param(params, "status"),
            limit=limit,
            offset=offset,
        )
        return JSONResponse(
            api_v1.envelope(
                "access-reviews", _redact_payload(data, identity), meta=_page_meta(limit, offset, len(data))
            )
        )

    @router.post("/api/v1/access-reviews", status_code=status.HTTP_201_CREATED)
    def create_access_review(
        body: CreateCampaignRequest,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            campaign = access_review_services.create_campaign(
                session,
                identity.tenant_id,
                name=body.name,
                description=body.description,
                scope=body.scope,
                control_id=body.control_id,
                due_at=_parse_dt(body.due_at),
                created_by=identity.email,
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("access-reviews", campaign), status_code=status.HTTP_201_CREATED)

    # Registered before the ``/{campaign_id}`` route so the static segment wins.
    @router.get("/api/v1/access-reviews/coverage")
    def access_review_coverage(
        identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        data = access_review_services.control_coverage(session, identity.tenant_id)
        return JSONResponse(
            api_v1.envelope("access-reviews.coverage", _redact_payload(data, identity), meta={"count": len(data)})
        )

    @router.get("/api/v1/access-reviews/{campaign_id}")
    def get_access_review(
        campaign_id: str, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        try:
            data = access_review_services.get_campaign(session, identity.tenant_id, campaign_id)
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("access-reviews", _redact_payload(data, identity)))

    @router.patch("/api/v1/access-reviews/{campaign_id}")
    def update_access_review_status(
        campaign_id: str,
        body: CampaignStatusRequest,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            campaign = access_review_services.set_campaign_status(
                session, identity.tenant_id, campaign_id, status=body.status
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("access-reviews", campaign))

    @router.get("/api/v1/access-reviews/{campaign_id}/items")
    def list_access_review_items(
        campaign_id: str,
        request: Request,
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        params = _params(request)
        limit, offset = _pagination(params)
        try:
            data = access_review_services.list_items(
                session,
                identity.tenant_id,
                campaign_id,
                decision=api_v1.first_param(params, "decision"),
                limit=limit,
                offset=offset,
            )
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(
            api_v1.envelope(
                "access-reviews.items", _redact_payload(data, identity), meta=_page_meta(limit, offset, len(data))
            )
        )

    @router.post("/api/v1/access-reviews/{campaign_id}/items", status_code=status.HTTP_201_CREATED)
    def add_access_review_item(
        campaign_id: str,
        body: AddReviewItemRequest,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            item = access_review_services.add_item(
                session,
                identity.tenant_id,
                campaign_id,
                subject_id=body.subject_id,
                subject_name=body.subject_name,
                source=body.source,
                access_summary=body.access_summary,
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("access-reviews.items", item), status_code=status.HTTP_201_CREATED)

    @router.post("/api/v1/access-reviews/{campaign_id}/seed")
    def seed_access_review(
        campaign_id: str,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            result = access_review_services.seed_campaign_from_evidence(
                session, lake_for(identity), identity.tenant_id, campaign_id
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("access-reviews", result))

    @router.post("/api/v1/access-reviews/items/{item_id}/decision")
    def decide_access_review_item(
        item_id: str,
        body: ReviewDecisionRequest,
        identity: Identity = Depends(_require_control_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        require_human(identity)
        try:
            item = access_review_services.record_decision(
                session,
                identity.tenant_id,
                item_id,
                decision=body.decision,
                reviewer=identity.email,
                note=body.note,
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("access-reviews.items", _redact_payload(item, identity)))

    return router

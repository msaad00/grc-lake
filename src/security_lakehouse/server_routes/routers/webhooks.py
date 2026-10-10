"""Webhooks routes, registered before generic dispatch."""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from security_lakehouse import api_v1
from security_lakehouse.auth.dependencies import get_session, require_scope
from security_lakehouse.auth.rbac import Identity
from security_lakehouse.db.base import MAX_PAGE_LIMIT
from security_lakehouse.server_routes.payloads import _applied_filters, _page_meta, _page_window, _pagination, _params
from security_lakehouse.server_routes.schemas.workflows import CreateWebhookRequest, UpdateWebhookRequest
from security_lakehouse.services import NotFound, ValidationError
from security_lakehouse.services import webhooks as webhook_services

_require_connector_manage = require_scope("connector_manage")
_require_read = require_scope("read")


def build_webhooks_router() -> APIRouter:
    """Build the authenticated workflow routes."""
    router = APIRouter()

    @router.get("/api/v1/webhooks", tags=["webhooks"])
    def list_webhooks(
        request: Request, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        params = _params(request)
        limit, offset = _page_window(params, maximum=MAX_PAGE_LIMIT)
        enabled_raw = api_v1.first_param(params, "enabled")
        enabled = {"true": True, "false": False}.get((enabled_raw or "").lower())
        event_type = api_v1.first_param(params, "event_type")
        data = webhook_services.list_subscriptions(
            session, identity.tenant_id, enabled=enabled, event_type=event_type, limit=limit, offset=offset
        )
        total = webhook_services.count_subscriptions(
            session, identity.tenant_id, enabled=enabled, event_type=event_type
        )
        return JSONResponse(
            api_v1.collection_page_response(
                "webhooks",
                data,
                count=total,
                limit=limit,
                offset=offset,
                sort=None,
                filters=_applied_filters(enabled=enabled_raw if enabled is not None else None, event_type=event_type),
            )
        )

    @router.post("/api/v1/webhooks", status_code=status.HTTP_201_CREATED, tags=["webhooks"])
    def create_webhook(
        body: CreateWebhookRequest,
        identity: Identity = Depends(_require_connector_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        secret = body.secret or secrets.token_urlsafe(32)
        try:
            subscription = webhook_services.create_subscription(
                session,
                identity.tenant_id,
                url=body.url,
                secret=secret,
                event_types=body.event_types,
                description=body.description,
                enabled=body.enabled,
                created_by=identity.email,
            )
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        # The secret is included here, in full, exactly once -- the caller must
        # store it now; every later read of this subscription omits it.
        return JSONResponse(api_v1.envelope("webhooks", subscription), status_code=status.HTTP_201_CREATED)

    @router.get("/api/v1/webhooks/{subscription_id}", tags=["webhooks"])
    def get_webhook(
        subscription_id: str,
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            data = webhook_services.get_subscription(session, identity.tenant_id, subscription_id)
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("webhooks", data))

    @router.patch("/api/v1/webhooks/{subscription_id}", tags=["webhooks"])
    def update_webhook(
        subscription_id: str,
        body: UpdateWebhookRequest,
        identity: Identity = Depends(_require_connector_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        changes = body.model_dump(exclude_unset=True)
        try:
            data = webhook_services.update_subscription(session, identity.tenant_id, subscription_id, changes=changes)
        except ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("webhooks", data))

    @router.delete("/api/v1/webhooks/{subscription_id}", tags=["webhooks"])
    def delete_webhook(
        subscription_id: str,
        identity: Identity = Depends(_require_connector_manage),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            result = webhook_services.delete_subscription(session, identity.tenant_id, subscription_id)
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return JSONResponse(api_v1.envelope("webhooks", result))

    @router.get("/api/v1/webhooks/{subscription_id}/deliveries", tags=["webhooks"])
    def list_webhook_deliveries(
        subscription_id: str,
        request: Request,
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            webhook_services.get_subscription(session, identity.tenant_id, subscription_id)
        except NotFound as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        limit, offset = _pagination(_params(request))
        data = webhook_services.list_deliveries(
            session, identity.tenant_id, subscription_id=subscription_id, limit=limit, offset=offset
        )
        return JSONResponse(api_v1.envelope("webhooks.deliveries", data, meta=_page_meta(limit, offset, len(data))))

    return router

"""Saved views routes, registered before generic dispatch."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from security_lakehouse import api_v1
from security_lakehouse.auth.dependencies import get_session, require_scope
from security_lakehouse.auth.rbac import Identity
from security_lakehouse.db import tags as tags_db
from security_lakehouse.server_routes.payloads import _page_meta, _pagination, _params, _redact_payload
from security_lakehouse.server_routes.schemas.workflows import CreateSavedViewRequest

_require_read = require_scope("read")
_require_write = require_scope("write")


def build_saved_views_router() -> APIRouter:
    """Build the authenticated workflow routes."""
    router = APIRouter()

    @router.get("/api/v1/saved-views")
    def list_saved_views(
        request: Request,
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        params = _params(request)
        limit, offset = _pagination(params)
        surface = api_v1.first_param(params, "surface")
        rows = tags_db.list_saved_views(
            session, tenant_id=identity.tenant_id, surface=surface, limit=limit, offset=offset
        )
        data = [tags_db.saved_view_to_dict(v) for v in rows]
        return JSONResponse(
            api_v1.envelope("saved_views", _redact_payload(data, identity), meta=_page_meta(limit, offset, len(data)))
        )

    @router.post("/api/v1/saved-views", status_code=status.HTTP_201_CREATED)
    def create_saved_view(
        body: CreateSavedViewRequest,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            view = tags_db.create_saved_view(
                session,
                tenant_id=identity.tenant_id,
                surface=body.surface,
                name=body.name,
                filters=body.filters,
                created_by=identity.email,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        session.commit()
        return JSONResponse(
            api_v1.envelope("saved_views", tags_db.saved_view_to_dict(view)), status_code=status.HTTP_201_CREATED
        )

    @router.delete("/api/v1/saved-views/{view_id}")
    def delete_saved_view(
        view_id: str,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        deleted = tags_db.delete_saved_view(session, tenant_id=identity.tenant_id, view_id=view_id)
        if not deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="saved view not found")
        session.commit()
        return JSONResponse(api_v1.envelope("saved_views", {"id": view_id, "deleted": True}))

    return router

"""Tags routes, registered before generic dispatch."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from security_lakehouse import api_v1
from security_lakehouse.auth.dependencies import get_session, require_scope
from security_lakehouse.auth.rbac import Identity
from security_lakehouse.db import tags as tags_db
from security_lakehouse.server_routes.payloads import _page_meta, _pagination, _params, _redact_payload
from security_lakehouse.server_routes.schemas.workflows import AttachTagRequest, CreateTagRequest

_require_read = require_scope("read")
_require_write = require_scope("write")


def build_tags_router() -> APIRouter:
    """Build the authenticated workflow routes."""
    router = APIRouter()

    @router.get("/api/v1/tags")
    def list_tags(
        request: Request, identity: Identity = Depends(_require_read), session: Session = Depends(get_session)
    ) -> JSONResponse:
        limit, offset = _pagination(_params(request))
        rows = tags_db.list_tags(session, tenant_id=identity.tenant_id, limit=limit, offset=offset)
        data = [tags_db.tag_to_dict(t) for t in rows]
        return JSONResponse(
            api_v1.envelope("tags", _redact_payload(data, identity), meta=_page_meta(limit, offset, len(data)))
        )

    @router.post("/api/v1/tags", status_code=status.HTTP_201_CREATED)
    def create_tag(
        body: CreateTagRequest,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            tag = tags_db.create_tag(session, tenant_id=identity.tenant_id, name=body.name, color=body.color)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        session.commit()
        return JSONResponse(api_v1.envelope("tags", tags_db.tag_to_dict(tag)), status_code=status.HTTP_201_CREATED)

    @router.delete("/api/v1/tags/{tag_id}")
    def delete_tag(
        tag_id: str,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        deleted = tags_db.delete_tag(session, tenant_id=identity.tenant_id, tag_id=tag_id)
        if not deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tag not found")
        session.commit()
        return JSONResponse(api_v1.envelope("tags", {"id": tag_id, "deleted": True}))

    @router.post("/api/v1/tags/attach", status_code=status.HTTP_201_CREATED)
    def attach_tag(
        body: AttachTagRequest,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            et = tags_db.attach_tag(
                session,
                tenant_id=identity.tenant_id,
                tag_id=body.tag_id,
                entity_type=body.entity_type,
                entity_id=body.entity_id,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        session.commit()
        return JSONResponse(
            api_v1.envelope("tags.attach", tags_db.entity_tag_to_dict(et)), status_code=status.HTTP_201_CREATED
        )

    @router.post("/api/v1/tags/detach")
    def detach_tag(
        body: AttachTagRequest,
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        try:
            removed = tags_db.detach_tag(
                session,
                tenant_id=identity.tenant_id,
                tag_id=body.tag_id,
                entity_type=body.entity_type,
                entity_id=body.entity_id,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        if not removed:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="association not found")
        session.commit()
        return JSONResponse(api_v1.envelope("tags.detach", {"detached": True}))

    @router.get("/api/v1/tags/for")
    def tags_for_entity(
        request: Request,
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        params = _params(request)
        entity_type = api_v1.first_param(params, "entity_type")
        entity_id = api_v1.first_param(params, "entity_id")
        if not entity_type or not entity_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="entity_type and entity_id are required"
            )
        rows = tags_db.tags_for_entity(
            session, tenant_id=identity.tenant_id, entity_type=entity_type, entity_id=entity_id
        )
        data = [tags_db.tag_to_dict(t) for t in rows]
        return JSONResponse(api_v1.envelope("tags.for", data, meta={"count": len(data)}))

    @router.get("/api/v1/tags/entities")
    def tag_entities(
        request: Request,
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        params = _params(request)
        tag_id = api_v1.first_param(params, "tag_id")
        entity_type = api_v1.first_param(params, "entity_type")
        if not tag_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="tag_id is required")
        entity_ids = tags_db.entity_ids_for_tag(
            session,
            tenant_id=identity.tenant_id,
            tag_id=str(tag_id),
            entity_type=str(entity_type) if entity_type else None,
        )
        return JSONResponse(
            api_v1.envelope(
                "tags.entities",
                entity_ids,
                meta={"count": len(entity_ids), "tag_id": tag_id, "entity_type": entity_type or "all"},
            )
        )

    return router

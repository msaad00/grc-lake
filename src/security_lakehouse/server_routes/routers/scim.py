"""SCIM 2.0 routes (commercial hosted) and per-tenant SCIM token administration.

SCIM endpoints speak the SCIM wire format that identity providers parse:
``application/scim+json`` bodies without the GRC Lake API envelope, and SCIM
error objects. Each request is authenticated by a per-tenant SCIM bearer token,
which also selects the tenant. Token administration uses the normal GRC Lake
admin API and envelope.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from security_lakehouse import api_v1
from security_lakehouse.auth.dependencies import get_session, require_scope
from security_lakehouse.auth.rbac import Identity
from security_lakehouse.commercial import scim as scim_settings
from security_lakehouse.commercial import scim_provision as scim
from security_lakehouse.commercial.limits import UsageLimitError

SCIM_MEDIA_TYPE = "application/scim+json"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
_require_admin = require_scope("auth_admin")


def _scim_json(payload: dict[str, Any], status_code: int = status.HTTP_200_OK) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code, media_type=SCIM_MEDIA_TYPE)


def _scim_error(status_code: int, detail: str, scim_type: str | None = None) -> JSONResponse:
    body: dict[str, Any] = {"schemas": [ERROR_SCHEMA], "status": str(status_code), "detail": detail}
    if scim_type:
        body["scimType"] = scim_type
    return _scim_json(body, status_code)


def _disabled() -> JSONResponse | None:
    if scim_settings.scim_enabled():
        return None
    return _scim_error(status.HTTP_501_NOT_IMPLEMENTED, scim_settings.scim_not_implemented_detail())


async def _json_body(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except ValueError as exc:
        raise scim.ScimError(400, "request body must be JSON", "invalidSyntax") from exc
    if not isinstance(body, dict):
        raise scim.ScimError(400, "request body must be a JSON object", "invalidSyntax")
    return body


def _page(request: Request) -> tuple[int, int]:
    try:
        return int(request.query_params.get("startIndex", "1")), int(request.query_params.get("count", "100"))
    except ValueError as exc:
        raise scim.ScimError(400, "startIndex and count must be integers", "invalidValue") from exc


def _handle(
    session: Session,
    request: Request,
    action: Callable[[str], Any],
    *,
    success_status: int = status.HTTP_200_OK,
) -> Response:
    """Authenticate, run ``action(tenant_id)``, commit, and render SCIM output or errors."""
    disabled = _disabled()
    if disabled is not None:
        return disabled
    try:
        tenant_id = scim.authenticate_scim_request(session, request.headers.get("Authorization"))
        result = action(tenant_id)
    except scim.ScimError as exc:
        session.rollback()
        return _scim_error(exc.status, exc.detail, exc.scim_type)
    except UsageLimitError:
        session.rollback()
        return _scim_error(status.HTTP_403_FORBIDDEN, "the tenant's plan user limit has been reached")
    session.commit()
    if result is None:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    return _scim_json(result, success_status)


def build_scim_router() -> APIRouter:
    router = APIRouter(tags=["commercial"])
    base = "/api/v1/scim/v2"

    @router.get(f"{base}/ServiceProviderConfig")
    def service_provider_config() -> Response:
        disabled = _disabled()
        if disabled is not None:
            return disabled
        return _scim_json(
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
                "patch": {"supported": True},
                "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
                "filter": {"supported": True, "maxResults": scim.MAX_COUNT},
                "changePassword": {"supported": False},
                "sort": {"supported": False},
                "etag": {"supported": False},
                "authenticationSchemes": [
                    {
                        "type": "oauthbearertoken",
                        "name": "OAuth Bearer Token",
                        "description": "Per-tenant SCIM token issued from /api/v1/platform/scim/tokens",
                        "primary": True,
                    }
                ],
            }
        )

    @router.get(f"{base}/Users")
    def list_users(request: Request, session: Session = Depends(get_session)) -> Response:
        def action(tenant_id: str) -> dict[str, Any]:
            start_index, count = _page(request)
            return scim.list_scim_users(
                session,
                tenant_id=tenant_id,
                filter_expr=request.query_params.get("filter"),
                start_index=start_index,
                count=count,
            )

        return _handle(session, request, action)

    @router.post(f"{base}/Users")
    async def create_user(request: Request, session: Session = Depends(get_session)) -> Response:
        try:
            body = await _json_body(request)
        except scim.ScimError as exc:
            return _disabled() or _scim_error(exc.status, exc.detail, exc.scim_type)
        return _handle(
            session,
            request,
            lambda tenant_id: scim.create_scim_user(session, tenant_id=tenant_id, body=body),
            success_status=status.HTTP_201_CREATED,
        )

    @router.get(f"{base}/Users/{{user_id}}")
    def get_user(user_id: str, request: Request, session: Session = Depends(get_session)) -> Response:
        return _handle(
            session, request, lambda tenant_id: scim.get_scim_user(session, tenant_id=tenant_id, user_id=user_id)
        )

    @router.put(f"{base}/Users/{{user_id}}")
    async def replace_user(user_id: str, request: Request, session: Session = Depends(get_session)) -> Response:
        try:
            body = await _json_body(request)
        except scim.ScimError as exc:
            return _disabled() or _scim_error(exc.status, exc.detail, exc.scim_type)
        return _handle(
            session,
            request,
            lambda tenant_id: scim.replace_scim_user(session, tenant_id=tenant_id, user_id=user_id, body=body),
        )

    @router.patch(f"{base}/Users/{{user_id}}")
    async def patch_user(user_id: str, request: Request, session: Session = Depends(get_session)) -> Response:
        try:
            body = await _json_body(request)
        except scim.ScimError as exc:
            return _disabled() or _scim_error(exc.status, exc.detail, exc.scim_type)
        operations = body.get("Operations") or []
        return _handle(
            session,
            request,
            lambda tenant_id: scim.patch_scim_user(
                session, tenant_id=tenant_id, user_id=user_id, operations=operations
            ),
        )

    @router.delete(f"{base}/Users/{{user_id}}")
    def delete_user(user_id: str, request: Request, session: Session = Depends(get_session)) -> Response:
        return _handle(
            session, request, lambda tenant_id: scim.delete_scim_user(session, tenant_id=tenant_id, user_id=user_id)
        )

    @router.get(f"{base}/Groups")
    def list_groups(request: Request, session: Session = Depends(get_session)) -> Response:
        def action(tenant_id: str) -> dict[str, Any]:
            start_index, count = _page(request)
            return scim.list_scim_groups(
                session,
                tenant_id=tenant_id,
                filter_expr=request.query_params.get("filter"),
                start_index=start_index,
                count=count,
            )

        return _handle(session, request, action)

    @router.post(f"{base}/Groups")
    async def create_group(request: Request, session: Session = Depends(get_session)) -> Response:
        try:
            body = await _json_body(request)
        except scim.ScimError as exc:
            return _disabled() or _scim_error(exc.status, exc.detail, exc.scim_type)
        return _handle(
            session,
            request,
            lambda tenant_id: scim.create_scim_group(session, tenant_id=tenant_id, body=body),
            success_status=status.HTTP_201_CREATED,
        )

    @router.get(f"{base}/Groups/{{group_id}}")
    def get_group(group_id: str, request: Request, session: Session = Depends(get_session)) -> Response:
        return _handle(
            session, request, lambda tenant_id: scim.get_scim_group(session, tenant_id=tenant_id, group_id=group_id)
        )

    @router.put(f"{base}/Groups/{{group_id}}")
    async def replace_group(group_id: str, request: Request, session: Session = Depends(get_session)) -> Response:
        try:
            body = await _json_body(request)
        except scim.ScimError as exc:
            return _disabled() or _scim_error(exc.status, exc.detail, exc.scim_type)
        return _handle(
            session,
            request,
            lambda tenant_id: scim.replace_scim_group(session, tenant_id=tenant_id, group_id=group_id, body=body),
        )

    @router.patch(f"{base}/Groups/{{group_id}}")
    async def patch_group(group_id: str, request: Request, session: Session = Depends(get_session)) -> Response:
        try:
            body = await _json_body(request)
        except scim.ScimError as exc:
            return _disabled() or _scim_error(exc.status, exc.detail, exc.scim_type)
        operations = body.get("Operations") or []
        return _handle(
            session,
            request,
            lambda tenant_id: scim.patch_scim_group(
                session, tenant_id=tenant_id, group_id=group_id, operations=operations
            ),
        )

    @router.delete(f"{base}/Groups/{{group_id}}")
    def delete_group(group_id: str, request: Request, session: Session = Depends(get_session)) -> Response:
        return _handle(
            session, request, lambda tenant_id: scim.delete_scim_group(session, tenant_id=tenant_id, group_id=group_id)
        )

    # --- token administration (GRC Lake admin API) ---------------------------

    @router.post("/api/v1/platform/scim/tokens", status_code=status.HTTP_201_CREATED)
    async def create_token(
        request: Request, identity: Identity = Depends(_require_admin), session: Session = Depends(get_session)
    ) -> JSONResponse:
        if not scim_settings.scim_enabled():
            return JSONResponse(
                api_v1.error_envelope("not_implemented", scim_settings.scim_not_implemented_detail()),
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
            )
        try:
            body = await request.json()
        except ValueError:
            body = None
        name = str(body.get("name") or "") if isinstance(body, dict) else ""
        if not name.strip():
            return JSONResponse(
                api_v1.error_envelope("bad_request", "token name is required"),
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        row, plaintext = scim.create_scim_token(
            session, tenant_id=identity.tenant_id, name=name, created_by=identity.email
        )
        session.commit()
        # The plaintext token is returned exactly once and never stored.
        return JSONResponse(
            api_v1.envelope("platform.scim.token", {**scim.scim_token_view(row), "token": plaintext}),
            status_code=status.HTTP_201_CREATED,
        )

    @router.get("/api/v1/platform/scim/tokens")
    def list_tokens(
        identity: Identity = Depends(_require_admin), session: Session = Depends(get_session)
    ) -> JSONResponse:
        if not scim_settings.scim_enabled():
            return JSONResponse(
                api_v1.error_envelope("not_implemented", scim_settings.scim_not_implemented_detail()),
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
            )
        rows = scim.list_scim_tokens(session, tenant_id=identity.tenant_id)
        return JSONResponse(api_v1.envelope("platform.scim.tokens", [scim.scim_token_view(row) for row in rows]))

    @router.delete("/api/v1/platform/scim/tokens/{token_id}")
    def revoke_token(
        token_id: str, identity: Identity = Depends(_require_admin), session: Session = Depends(get_session)
    ) -> Response:
        try:
            scim.revoke_scim_token(session, tenant_id=identity.tenant_id, token_id=token_id)
        except scim.ScimError as exc:
            return JSONResponse(api_v1.error_envelope("not_found", exc.detail), status_code=status.HTTP_404_NOT_FOUND)
        session.commit()
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return router

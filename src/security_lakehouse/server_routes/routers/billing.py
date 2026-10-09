"""Stripe billing routes (commercial hosted): status, checkout, portal, webhook."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from security_lakehouse import api_v1
from security_lakehouse.auth.dependencies import get_identity, get_session
from security_lakehouse.auth.rbac import Identity, scopes_for_role
from security_lakehouse.commercial import billing

logger = logging.getLogger(__name__)
_ERRORS = {
    400: ("bad_request", "invalid billing request"),
    409: ("conflict", "no Stripe customer is linked to this workspace yet; start a checkout first"),
    500: ("server_error", "billing is misconfigured"),
    501: ("not_implemented", "billing is not enabled"),
}


def _require_billing_admin(identity: Identity = Depends(get_identity)) -> Identity:
    """Admin check on the role's full scopes, so a read-only workspace can still fix billing."""
    if "auth_admin" not in scopes_for_role(identity.role):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="requires scope: auth_admin")
    return identity


def _error(status_code: int, detail: str | None = None) -> JSONResponse:
    code, default = _ERRORS.get(status_code, ("error", "billing request failed"))
    return JSONResponse(api_v1.error_envelope(code, detail or default), status_code=status_code)


def _disabled() -> JSONResponse | None:
    return None if billing.billing_enabled() else _error(status.HTTP_501_NOT_IMPLEMENTED)


def build_billing_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1/billing", tags=["commercial"])

    @router.get("")
    def billing_status(
        identity: Identity = Depends(get_identity), session: Session = Depends(get_session)
    ) -> JSONResponse:
        disabled = _disabled()
        if disabled is not None:
            return disabled
        return JSONResponse(api_v1.envelope("billing", billing.billing_view(session, tenant_id=identity.tenant_id)))

    @router.post("/checkout")
    async def checkout(
        request: Request, identity: Identity = Depends(_require_billing_admin), session: Session = Depends(get_session)
    ) -> JSONResponse:
        disabled = _disabled()
        if disabled is not None:
            return disabled
        try:
            body = await request.json()
        except ValueError:
            body = None
        plan = str(body.get("plan") or "") if isinstance(body, dict) else ""
        try:
            url = billing.create_checkout_session(
                session, tenant_id=identity.tenant_id, plan=plan, email=identity.email
            )
        except billing.BillingError as exc:
            detail = "plan is not available for self-serve checkout" if exc.status == 400 else None
            return _error(exc.status, detail)
        return JSONResponse(api_v1.envelope("billing.checkout", {"url": url}))

    @router.post("/portal")
    def portal(
        identity: Identity = Depends(_require_billing_admin), session: Session = Depends(get_session)
    ) -> JSONResponse:
        disabled = _disabled()
        if disabled is not None:
            return disabled
        try:
            url = billing.create_portal_session(session, tenant_id=identity.tenant_id)
        except billing.BillingError as exc:
            return _error(exc.status)
        return JSONResponse(api_v1.envelope("billing.portal", {"url": url}))

    @router.post("/stripe/webhook")
    async def stripe_webhook(request: Request, session: Session = Depends(get_session)) -> JSONResponse:
        disabled = _disabled()
        if disabled is not None:
            return disabled
        payload = await request.body()
        try:
            outcome = billing.handle_webhook(session, payload, request.headers.get("Stripe-Signature"))
        except billing.BillingError:
            session.rollback()
            return _error(status.HTTP_400_BAD_REQUEST, "invalid Stripe webhook")
        except Exception:  # answer 5xx so Stripe retries; details stay in logs
            session.rollback()
            logger.exception("stripe webhook processing failed")
            return _error(status.HTTP_500_INTERNAL_SERVER_ERROR, "webhook processing failed; Stripe will retry")
        session.commit()
        return JSONResponse({"received": True, "outcome": outcome})

    return router

"""FastAPI dependencies for authentication and scope enforcement."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import replace
from datetime import UTC, datetime

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from security_lakehouse.auth.rbac import Identity, scopes_for_role
from security_lakehouse.auth.sessions import SESSION_COOKIE, decode_session_cookie
from security_lakehouse.db import repository
from security_lakehouse.db.models import ApiKey

_bearer = HTTPBearer(auto_error=False)

_INSECURE_IDENTITY = Identity(
    user_id="insecure",
    tenant_id="insecure",
    email="insecure@localhost",
    role="admin",
    scopes=scopes_for_role("admin"),
    workspace_id="insecure",
    auth_method="insecure",
)


def get_session(request: Request) -> Iterator[Session]:
    """Yield a per-request session from the app's session factory."""
    factory = request.app.state.sessionmaker
    session = factory()
    try:
        yield session
    finally:
        session.close()


def get_identity(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    session: Session = Depends(get_session),
) -> Identity:
    """Resolve the authenticated identity, or raise 401."""
    if not getattr(request.app.state, "require_auth", True):
        return _request_identity(request, _INSECURE_IDENTITY)
    now = datetime.now(UTC)

    # 1. API key (agents/CI): Authorization: Bearer <token>
    if credentials is not None and credentials.credentials:
        key = repository.resolve_api_key(session, credentials.credentials)
        if key is None or not key.is_active(now=now):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid or inactive token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not key.user.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="user is disabled")
        key.last_used_at = now
        session.commit()
        identity = Identity(
            user_id=key.user_id,
            tenant_id=key.tenant_id,
            email=key.user.email,
            role=key.user.role,
            scopes=scopes_for_role(key.user.role),
            workspace_id=key.workspace_id,
            api_key_id=key.id,
            auth_method="api_key",
        )
        identity = _apply_billing_state(session, identity)
        return _request_identity(request, identity)

    # 2. Browser session (SSO): httpOnly cookie
    cookie_raw = request.cookies.get(SESSION_COOKIE)
    if cookie_raw:
        session_token = decode_session_cookie(cookie_raw)
        if session_token is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or expired session")
        sess = repository.resolve_user_session(session, session_token)
        if sess is None or not sess.is_active(now=now):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or expired session")
        if not sess.user.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="user is disabled")
        source_key = None
        if sess.idp == "api_key":
            source_key = session.get(ApiKey, sess.source_api_key_id) if sess.source_api_key_id else None
            if (
                source_key is None
                or not source_key.is_active(now=now)
                or source_key.user_id != sess.user_id
                or source_key.tenant_id != sess.tenant_id
            ):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or expired session")
        identity = Identity(
            user_id=sess.user_id,
            tenant_id=sess.tenant_id,
            email=sess.user.email,
            role=sess.user.role,
            scopes=scopes_for_role(sess.user.role),
            workspace_id=source_key.workspace_id if source_key is not None else sess.tenant_id,
            auth_method=f"session:{sess.idp or 'unknown'}",
            session_id=sess.id,
            api_key_id=source_key.id if source_key is not None else None,
        )
        identity = _apply_billing_state(session, identity)
        return _request_identity(request, identity)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="missing credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _request_identity(request: Request, identity: Identity) -> Identity:
    # A caller may deliberately narrow its view. This never grants authority:
    # even writes from a normally privileged session become forbidden.
    if request.headers.get("X-Trust-Role", "").lower() == "auditor" or (
        request.url.path == "/api/v1/stream" and request.query_params.get("role") == "auditor"
    ):
        identity = replace(identity, role="auditor", scopes=identity.scopes & frozenset({"read"}))
    request.state.identity = identity
    return identity


def _apply_billing_state(session: Session, identity: Identity) -> Identity:
    """Narrow a lapsed commercial workspace to read scopes (no-op unless billing is enabled)."""
    from security_lakehouse.commercial.billing import billing_access, billing_enabled

    if not billing_enabled() or billing_access(session, tenant_id=identity.tenant_id) != "read_only":
        return identity
    return replace(identity, scopes=identity.scopes & frozenset({"read"}), billing_read_only=True)


def require_scope(scope: str) -> Callable[..., Identity]:
    """Build a dependency that enforces ``scope`` on top of authentication."""

    def dependency(identity: Identity = Depends(get_identity)) -> Identity:
        if not identity.has_scope(scope):
            detail = f"requires scope: {scope}"
            if identity.billing_read_only:
                detail = (
                    "this workspace is read-only until billing is resolved; "
                    "an admin can update payment at /api/v1/billing/portal"
                )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)
        return identity

    return dependency


def require_human(identity: Identity) -> Identity:
    """A machine key or a cookie derived from one cannot attest for a person."""
    if identity.auth_method not in {"session:oidc", "session:saml"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="this action requires a signed-in human SSO session"
        )
    return identity

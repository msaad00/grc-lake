"""FastAPI dependencies for authentication and scope enforcement."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from security_lakehouse.auth.authority import (
    INSECURE_IDENTITY as _INSECURE_IDENTITY,
)
from security_lakehouse.auth.authority import (
    AuthorityError,
    CredentialReference,
    narrow_to_auditor,
    resolve_authority,
)
from security_lakehouse.auth.rbac import Identity
from security_lakehouse.auth.sessions import SESSION_COOKIE, decode_session_cookie
from security_lakehouse.db import repository

_bearer = HTTPBearer(auto_error=False)


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
        return _request_identity(
            request,
            resolve_authority(
                session,
                CredentialReference.from_identity(_INSECURE_IDENTITY),
                allow_insecure=True,
            ),
        )
    reference = None
    key = None
    upgraded_session = False
    failure_detail = "missing credentials"
    if credentials is not None and credentials.credentials:
        failure_detail = "invalid or inactive token"
        key = repository.resolve_api_key(session, credentials.credentials)
        if key is not None:
            reference = CredentialReference(key.user_id, key.tenant_id, "api_key", api_key_id=key.id)
    else:
        cookie_raw = request.cookies.get(SESSION_COOKIE)
        if cookie_raw:
            failure_detail = "invalid or expired session"
        token = decode_session_cookie(cookie_raw) if cookie_raw else None
        login = repository.resolve_user_session(session, token) if token else None
        upgraded_session = login is not None and login in session.dirty
        if login is not None:
            reference = CredentialReference(
                login.user_id,
                login.tenant_id,
                f"session:{login.idp}",
                api_key_id=login.source_api_key_id,
                session_id=login.id,
            )
    try:
        if reference is None:
            raise AuthorityError()
        identity = resolve_authority(session, reference)
    except AuthorityError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN if exc.disabled else status.HTTP_401_UNAUTHORIZED,
            detail=str(exc) if exc.disabled else failure_detail,
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    if key is not None:
        key.last_used_at = datetime.now(UTC)
        session.commit()
    elif upgraded_session:
        session.commit()
    return _request_identity(request, identity)


def auditor_view_requested(request: Request) -> bool:
    return request.headers.get("X-Trust-Role", "").lower() == "auditor" or (
        request.url.path == "/api/v1/stream" and request.query_params.get("role") == "auditor"
    )


def _request_identity(request: Request, identity: Identity) -> Identity:
    # A caller may deliberately narrow its view. This never grants authority:
    # even writes from a normally privileged session become forbidden.
    identity = narrow_to_auditor(identity, auditor_view=auditor_view_requested(request))
    request.state.identity = identity
    return identity


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

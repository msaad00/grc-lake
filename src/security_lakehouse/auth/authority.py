"""Current persistent authority shared by requests, queued work, and live reads.

References identify credentials already authenticated by a transport. They are
not bearer credentials and must never be accepted directly from client input.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from security_lakehouse.auth.rbac import Identity, scopes_for_role
from security_lakehouse.db.models import ApiKey, User, UserSession

INSECURE_IDENTITY = Identity(
    user_id="insecure",
    tenant_id="insecure",
    email="insecure@localhost",
    role="admin",
    scopes=scopes_for_role("admin"),
    workspace_id="insecure",
    auth_method="insecure",
)


class AuthorityError(ValueError):
    """The persisted credential no longer grants authority."""

    def __init__(self, *, disabled: bool = False) -> None:
        super().__init__("user is disabled" if disabled else "invalid or inactive credentials")
        self.disabled = disabled


@dataclass(frozen=True)
class CredentialReference:
    user_id: str
    tenant_id: str
    auth_method: str
    api_key_id: str | None = None
    session_id: str | None = None

    @classmethod
    def from_identity(cls, identity: Identity) -> CredentialReference:
        return cls(identity.user_id, identity.tenant_id, identity.auth_method, identity.api_key_id, identity.session_id)


def narrow_to_auditor(identity: Identity, *, auditor_view: bool) -> Identity:
    if auditor_view:
        return replace(identity, role="auditor", scopes=identity.scopes & frozenset({"read"}))
    return identity


def apply_billing_state(session: Session, identity: Identity) -> Identity:
    from security_lakehouse.commercial.billing import billing_access, billing_enabled

    if billing_enabled() and billing_access(session, tenant_id=identity.tenant_id) == "read_only":
        return replace(identity, scopes=identity.scopes & frozenset({"read"}), billing_read_only=True)
    return identity


def resolve_authority(
    session: Session,
    reference: CredentialReference,
    *,
    allow_insecure: bool = False,
    auditor_view: bool = False,
    now: datetime | None = None,
) -> Identity:
    """Reload authoritative rows, validate bindings, then derive current grants.

    No credential usage writes occur here. Long-lived callers use a fresh DB
    session per check, without retaining transactions or identity-map objects.
    ``allow_insecure`` comes only from the application's validated startup mode.
    """
    if reference.auth_method == "insecure":
        if not allow_insecure or reference != CredentialReference.from_identity(INSECURE_IDENTITY):
            raise AuthorityError()
        return narrow_to_auditor(INSECURE_IDENTITY, auditor_view=auditor_view)
    moment = now or datetime.now(UTC)
    user = session.get(User, reference.user_id, populate_existing=True)
    if user is None or user.tenant_id != reference.tenant_id:
        raise AuthorityError()
    if not user.is_active:
        raise AuthorityError(disabled=True)
    if reference.auth_method in {"session:oidc", "session:saml", "session:api_key"}:
        login = session.get(UserSession, reference.session_id, populate_existing=True) if reference.session_id else None
        if (
            login is None
            or not login.is_active(now=moment)
            or login.user_id != user.id
            or login.tenant_id != reference.tenant_id
            or reference.auth_method != f"session:{login.idp}"
            or login.source_api_key_id != reference.api_key_id
        ):
            raise AuthorityError()
        if login.idp == "api_key":
            if not reference.api_key_id:
                raise AuthorityError()
        elif reference.api_key_id is not None:
            raise AuthorityError()
    elif reference.auth_method != "api_key" or not reference.api_key_id or reference.session_id:
        raise AuthorityError()
    key = session.get(ApiKey, reference.api_key_id, populate_existing=True) if reference.api_key_id else None
    if reference.api_key_id and (
        key is None or not key.is_active(now=moment) or key.user_id != user.id or key.tenant_id != reference.tenant_id
    ):
        raise AuthorityError()
    identity = Identity(
        tenant_id=user.tenant_id,
        user_id=user.id,
        email=user.email,
        role=user.role,
        scopes=scopes_for_role(user.role),
        workspace_id=key.workspace_id if key is not None else user.tenant_id,
        api_key_id=reference.api_key_id,
        session_id=reference.session_id,
        auth_method=reference.auth_method,
    )
    return narrow_to_auditor(apply_billing_state(session, identity), auditor_view=auditor_view)

"""SCIM 2.0 provisioning for commercial hosted tenants (RFC 7643 / 7644 subset).

* **Tenancy by token.** Each tenant issues its own SCIM bearer tokens
  (:func:`create_scim_token`); only the SHA-256 hash is stored, and the token
  resolves the tenant for every request. Rotation is "create new, revoke old".
  ``GRC_LAKE_SCIM_BEARER_TOKEN`` + ``GRC_LAKE_SCIM_TENANT_SLUG`` still work as a
  deprecated single-tenant fallback.
* **Users.** Create, PUT replace, PATCH (path and path-less operations, as sent
  by Okta and Entra ID), ``userName``/``externalId eq`` filters, and DELETE as a
  soft delete: the user is deactivated and hidden from SCIM (404) but kept for
  the audit trail; re-creating the same ``userName`` restores it.
* **Groups.** Group membership maps to GRC Lake roles through
  ``GRC_LAKE_SCIM_ROLE_MAP`` (``{"IdP group": "role"}``), using the same
  highest-privilege rule as OIDC/SAML claims. Without a role map, groups never
  change roles.

Errors are raised as :class:`ScimError` and rendered by the router as SCIM
error responses.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from security_lakehouse.auth.idp_roles import load_role_map, resolve_role_from_claims
from security_lakehouse.commercial.limits import assert_within_limit
from security_lakehouse.db.models import USER_ROLES, ScimGroup, ScimGroupMember, ScimToken, Tenant, User
from security_lakehouse.runtime_environment import runtime_env

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
TOKEN_PREFIX = "tscim_"
MAX_COUNT = 200
_FILTER = re.compile(r'^\s*(\w+)\s+eq\s+"([^"]*)"\s*$', re.IGNORECASE)
_MEMBER_PATH = re.compile(r'^members\[value eq "([^"]+)"\]$', re.IGNORECASE)


class ScimError(Exception):
    """A SCIM protocol error with an HTTP status and optional ``scimType``."""

    def __init__(self, status: int, detail: str, scim_type: str | None = None) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.scim_type = scim_type


def _now() -> datetime:
    return datetime.now(UTC)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# --- tokens -----------------------------------------------------------------


def create_scim_token(session: Session, *, tenant_id: str, name: str, created_by: str) -> tuple[ScimToken, str]:
    label = name.strip()
    if not label:
        raise ScimError(400, "token name is required", "invalidValue")
    plaintext = TOKEN_PREFIX + secrets.token_urlsafe(32)
    row = ScimToken(
        tenant_id=tenant_id,
        name=label[:255],
        token_hash=_hash(plaintext),
        token_prefix=plaintext[:12],
        created_by=created_by[:255],
    )
    session.add(row)
    session.flush()
    return row, plaintext


def scim_token_view(row: ScimToken) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "token_prefix": row.token_prefix,
        "created_by": row.created_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "last_used_at": row.last_used_at.isoformat() if row.last_used_at else None,
        "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
    }


def list_scim_tokens(session: Session, *, tenant_id: str) -> list[ScimToken]:
    return list(
        session.scalars(select(ScimToken).where(ScimToken.tenant_id == tenant_id).order_by(ScimToken.created_at))
    )


def revoke_scim_token(session: Session, *, tenant_id: str, token_id: str) -> None:
    row = session.get(ScimToken, token_id)
    if row is None or row.tenant_id != tenant_id:
        raise ScimError(404, "token not found")
    if row.revoked_at is None:
        row.revoked_at = _now()
    session.flush()


def scim_bearer_from_authorization(header_value: str | None) -> str:
    """Extract the bearer token from an Authorization header without logging it."""
    if not header_value or not header_value.lower().startswith("bearer "):
        return ""
    return header_value[7:].strip()


def authenticate_scim_request(session: Session, header_value: str | None) -> str:
    """Return the tenant id the bearer token belongs to, or raise a 401."""
    token = scim_bearer_from_authorization(header_value)
    if token:
        row = session.scalars(select(ScimToken).where(ScimToken.token_hash == _hash(token))).one_or_none()
        if row is not None and row.revoked_at is None:
            row.last_used_at = _now()
            session.flush()
            return row.tenant_id
        legacy = runtime_env().get("GRC_LAKE_SCIM_BEARER_TOKEN", "").strip()
        if legacy and secrets.compare_digest(token, legacy):
            return _legacy_tenant_id(session)
    raise ScimError(401, "invalid SCIM bearer token")


def _legacy_tenant_id(session: Session) -> str:
    slug = (
        runtime_env()
        .get("GRC_LAKE_SCIM_TENANT_SLUG", runtime_env().get("GRC_LAKE_OIDC_TENANT_SLUG", "default"))
        .strip()
    )
    tenant = session.scalars(select(Tenant).where(Tenant.slug == slug)).one_or_none()
    if tenant is None:
        raise ScimError(401, "SCIM tenant for the configured bearer token does not exist")
    return tenant.id


# --- users ------------------------------------------------------------------


def _scim_user(row: User) -> dict[str, Any]:
    return {
        "schemas": [USER_SCHEMA],
        "id": row.id,
        "externalId": row.scim_external_id,
        "userName": row.email,
        "displayName": row.display_name or row.email,
        "name": {"formatted": row.display_name or row.email},
        "emails": [{"value": row.email, "primary": True, "type": "work"}],
        "active": bool(row.is_active),
        "meta": {
            "resourceType": "User",
            "created": row.created_at.isoformat() if row.created_at else None,
            "location": f"/api/v1/scim/v2/Users/{row.id}",
        },
        "trustopsRole": row.role,
    }


def _visible_users(tenant_id: str) -> Any:
    return select(User).where(User.tenant_id == tenant_id, User.scim_deleted_at.is_(None))


def _parse_filter(expression: str | None, allowed: dict[str, str]) -> tuple[str, str] | None:
    if not expression:
        return None
    match = _FILTER.match(expression)
    if not match or match.group(1).lower() not in allowed:
        raise ScimError(
            400, f'unsupported filter; use one of: {", ".join(sorted(allowed))} eq "value"', "invalidFilter"
        )
    return allowed[match.group(1).lower()], match.group(2)


def _list_response(resources: list[dict[str, Any]], total: int, start_index: int) -> dict[str, Any]:
    return {
        "schemas": [LIST_SCHEMA],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


def list_scim_users(
    session: Session, *, tenant_id: str, filter_expr: str | None = None, start_index: int = 1, count: int = 100
) -> dict[str, Any]:
    query = _visible_users(tenant_id)
    parsed = _parse_filter(filter_expr, {"username": "email", "externalid": "scim_external_id"})
    if parsed:
        column, value = parsed
        query = query.where(getattr(User, column) == (value.strip().lower() if column == "email" else value))
    start_index, count = max(1, start_index), max(0, min(count, MAX_COUNT))
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = session.scalars(query.order_by(User.created_at, User.id).offset(start_index - 1).limit(count))
    return _list_response([_scim_user(row) for row in rows], int(total), start_index)


def _visible_user(session: Session, tenant_id: str, user_id: str) -> User:
    row = session.get(User, user_id)
    if row is None or row.tenant_id != tenant_id or row.scim_deleted_at is not None:
        raise ScimError(404, "user not found")
    return row


def get_scim_user(session: Session, *, tenant_id: str, user_id: str) -> dict[str, Any]:
    return _scim_user(_visible_user(session, tenant_id, user_id))


def _display_name(body: dict[str, Any], fallback: str) -> str:
    if str(body.get("displayName") or "").strip():
        return str(body["displayName"]).strip()
    raw_name = body.get("name")
    name: dict[str, Any] = raw_name if isinstance(raw_name, dict) else {}
    if str(name.get("formatted") or "").strip():
        return str(name["formatted"]).strip()
    joined = " ".join(str(name.get(part) or "").strip() for part in ("givenName", "familyName")).strip()
    return joined or fallback


def _user_name(body: dict[str, Any]) -> str:
    value = str(body.get("userName") or "").strip().lower()
    if not value or "@" not in value:
        raise ScimError(400, "userName must be an email address", "invalidValue")
    return value


def _role(value: Any) -> str:
    role = str(value)
    if role not in USER_ROLES:
        raise ScimError(400, f"invalid trustopsRole {role!r}", "invalidValue")
    return role


def _bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes"}
    return bool(value)


def create_scim_user(session: Session, *, tenant_id: str, body: dict[str, Any]) -> dict[str, Any]:
    email = _user_name(body)
    existing = session.scalars(select(User).where(User.tenant_id == tenant_id, User.email == email)).one_or_none()
    if existing is not None and existing.scim_deleted_at is None:
        raise ScimError(409, "a user with this userName already exists", "uniqueness")
    tenant = session.get(Tenant, tenant_id)
    if tenant is not None:
        assert_within_limit(session, tenant=tenant, resource="users")
    row = existing or User(tenant_id=tenant_id, email=email, role="read_only")
    row.display_name = _display_name(body, email.split("@", 1)[0])
    row.is_active = _bool(body.get("active", True))
    row.scim_external_id = str(body["externalId"]) if body.get("externalId") else row.scim_external_id
    row.scim_deleted_at = None
    if body.get("trustopsRole") is not None:
        row.role = _role(body["trustopsRole"])
    if existing is None:
        session.add(row)
    session.flush()
    _recompute_roles(session, tenant_id, [row.id])
    return _scim_user(row)


def replace_scim_user(session: Session, *, tenant_id: str, user_id: str, body: dict[str, Any]) -> dict[str, Any]:
    row = _visible_user(session, tenant_id, user_id)
    email = _user_name(body)
    if email != row.email:
        clash = session.scalars(select(User).where(User.tenant_id == tenant_id, User.email == email)).one_or_none()
        if clash is not None:
            raise ScimError(409, "a user with this userName already exists", "uniqueness")
        row.email = email
    row.display_name = _display_name(body, email.split("@", 1)[0])
    row.is_active = _bool(body.get("active", True))
    row.scim_external_id = str(body["externalId"]) if body.get("externalId") else None
    if body.get("trustopsRole") is not None:
        row.role = _role(body["trustopsRole"])
    session.flush()
    return _scim_user(row)


def _apply_user_attribute(row: User, path: str, value: Any) -> None:
    key = path.lower()
    if key == "active":
        row.is_active = _bool(value)
    elif key in {"displayname", "name.formatted"}:
        row.display_name = str(value or "").strip() or row.display_name
    elif key == "externalid":
        row.scim_external_id = str(value) if value else None
    elif key == "trustopsrole":
        row.role = _role(value)
    elif key == "username":
        row.email = _user_name({"userName": value})
    # Unmodelled attributes (phone numbers, addresses, ...) are accepted and ignored.


def patch_scim_user(session: Session, *, tenant_id: str, user_id: str, operations: list[Any]) -> dict[str, Any]:
    row = _visible_user(session, tenant_id, user_id)
    for op in operations:
        if not isinstance(op, dict):
            raise ScimError(400, "each PATCH operation must be an object", "invalidSyntax")
        kind = str(op.get("op") or "").lower()
        if kind not in {"add", "replace", "remove"}:
            raise ScimError(400, f"unsupported PATCH op {op.get('op')!r}", "invalidSyntax")
        path, value = str(op.get("path") or ""), op.get("value")
        if kind == "remove":
            if path.lower() == "externalid":
                row.scim_external_id = None
            continue
        if path:
            _apply_user_attribute(row, path, value)
        elif isinstance(value, dict):
            for key, item in value.items():
                _apply_user_attribute(row, key, item)
        else:
            raise ScimError(400, "PATCH without a path needs an object value", "invalidSyntax")
    session.flush()
    return _scim_user(row)


def delete_scim_user(session: Session, *, tenant_id: str, user_id: str) -> None:
    """Soft delete: deactivate and hide from SCIM; keep the row for audit history."""
    row = _visible_user(session, tenant_id, user_id)
    row.is_active = False
    row.scim_deleted_at = _now()
    for membership in session.scalars(select(ScimGroupMember).where(ScimGroupMember.user_id == row.id)):
        session.delete(membership)
    session.flush()


# --- groups -----------------------------------------------------------------


def _scim_group(session: Session, group: ScimGroup) -> dict[str, Any]:
    members = session.scalars(
        select(User)
        .join(ScimGroupMember, ScimGroupMember.user_id == User.id)
        .where(ScimGroupMember.group_id == group.id)
        .order_by(User.email)
    )
    return {
        "schemas": [GROUP_SCHEMA],
        "id": group.id,
        "externalId": group.external_id,
        "displayName": group.display_name,
        "members": [{"value": user.id, "display": user.email} for user in members],
        "meta": {"resourceType": "Group", "location": f"/api/v1/scim/v2/Groups/{group.id}"},
    }


def _group(session: Session, tenant_id: str, group_id: str) -> ScimGroup:
    group = session.get(ScimGroup, group_id)
    if group is None or group.tenant_id != tenant_id:
        raise ScimError(404, "group not found")
    return group


def _member_ids(session: Session, tenant_id: str, members: Any) -> list[str]:
    ids = [str(member.get("value")) for member in members or [] if isinstance(member, dict) and member.get("value")]
    for user_id in ids:
        _visible_user_or_400(session, tenant_id, user_id)
    return ids


def _visible_user_or_400(session: Session, tenant_id: str, user_id: str) -> None:
    try:
        _visible_user(session, tenant_id, user_id)
    except ScimError as exc:
        raise ScimError(400, f"member {user_id!r} is not a user in this tenant", "invalidValue") from exc


def _current_member_ids(session: Session, group_id: str) -> set[str]:
    return set(session.scalars(select(ScimGroupMember.user_id).where(ScimGroupMember.group_id == group_id)))


def _set_members(session: Session, group: ScimGroup, user_ids: set[str]) -> set[str]:
    current = _current_member_ids(session, group.id)
    for user_id in user_ids - current:
        session.add(ScimGroupMember(group_id=group.id, user_id=user_id))
    for user_id in current - user_ids:
        member = session.get(ScimGroupMember, {"group_id": group.id, "user_id": user_id})
        if member is not None:
            session.delete(member)
    session.flush()
    return current | user_ids


def list_scim_groups(
    session: Session, *, tenant_id: str, filter_expr: str | None = None, start_index: int = 1, count: int = 100
) -> dict[str, Any]:
    query = select(ScimGroup).where(ScimGroup.tenant_id == tenant_id)
    parsed = _parse_filter(filter_expr, {"displayname": "display_name", "externalid": "external_id"})
    if parsed:
        column, value = parsed
        query = query.where(getattr(ScimGroup, column) == value)
    start_index, count = max(1, start_index), max(0, min(count, MAX_COUNT))
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = session.scalars(query.order_by(ScimGroup.display_name).offset(start_index - 1).limit(count))
    return _list_response([_scim_group(session, row) for row in rows], int(total), start_index)


def get_scim_group(session: Session, *, tenant_id: str, group_id: str) -> dict[str, Any]:
    return _scim_group(session, _group(session, tenant_id, group_id))


def create_scim_group(session: Session, *, tenant_id: str, body: dict[str, Any]) -> dict[str, Any]:
    name = str(body.get("displayName") or "").strip()
    if not name:
        raise ScimError(400, "displayName is required", "invalidValue")
    if session.scalars(
        select(ScimGroup).where(ScimGroup.tenant_id == tenant_id, ScimGroup.display_name == name)
    ).first():
        raise ScimError(409, "a group with this displayName already exists", "uniqueness")
    members = _member_ids(session, tenant_id, body.get("members"))
    group = ScimGroup(tenant_id=tenant_id, display_name=name, external_id=str(body.get("externalId") or "") or None)
    session.add(group)
    session.flush()
    touched = _set_members(session, group, set(members))
    _recompute_roles(session, tenant_id, touched)
    return _scim_group(session, group)


def replace_scim_group(session: Session, *, tenant_id: str, group_id: str, body: dict[str, Any]) -> dict[str, Any]:
    group = _group(session, tenant_id, group_id)
    name = str(body.get("displayName") or "").strip()
    if name:
        group.display_name = name
    group.external_id = str(body.get("externalId") or "") or None
    touched = _set_members(session, group, set(_member_ids(session, tenant_id, body.get("members"))))
    _recompute_roles(session, tenant_id, touched | _current_member_ids(session, group.id))
    return _scim_group(session, group)


def patch_scim_group(session: Session, *, tenant_id: str, group_id: str, operations: list[Any]) -> dict[str, Any]:
    group = _group(session, tenant_id, group_id)
    before = _current_member_ids(session, group.id)
    members = set(before)
    renamed = False
    for op in operations:
        if not isinstance(op, dict):
            raise ScimError(400, "each PATCH operation must be an object", "invalidSyntax")
        kind = str(op.get("op") or "").lower()
        path, value = str(op.get("path") or ""), op.get("value")
        member_match = _MEMBER_PATH.match(path)
        if kind == "remove" and member_match:
            members.discard(member_match.group(1))
        elif path.lower() == "members" and kind in {"add", "replace", "remove"}:
            ids = set(_member_ids(session, tenant_id, value if isinstance(value, list) else [value]))
            if kind == "add":
                members |= ids
            elif kind == "replace":
                members = ids
            else:
                members = members - ids if ids else set()
        elif kind in {"add", "replace"} and (path.lower() == "displayname" or (not path and isinstance(value, dict))):
            new_name = value if path else value.get("displayName")  # type: ignore[union-attr]
            if new_name:
                group.display_name = str(new_name).strip()
                renamed = True
        else:
            raise ScimError(400, f"unsupported group PATCH operation on {path or '(no path)'!r}", "invalidPath")
    touched = _set_members(session, group, members)
    if renamed:
        touched |= members
    _recompute_roles(session, tenant_id, touched | before)
    return _scim_group(session, group)


def delete_scim_group(session: Session, *, tenant_id: str, group_id: str) -> None:
    group = _group(session, tenant_id, group_id)
    members = _current_member_ids(session, group.id)
    session.delete(group)
    session.flush()
    _recompute_roles(session, tenant_id, members)


def _recompute_roles(session: Session, tenant_id: str, user_ids: Any) -> None:
    """Set each user's role from their SCIM groups when a role map is configured."""
    role_map = load_role_map("GRC_LAKE_SCIM_ROLE_MAP")
    if not role_map:
        return
    default_role = runtime_env().get("GRC_LAKE_SCIM_DEFAULT_ROLE", "read_only").strip() or "read_only"
    for user_id in set(user_ids):
        user = session.get(User, user_id)
        if user is None or user.tenant_id != tenant_id:
            continue
        groups = list(
            session.scalars(
                select(ScimGroup.display_name)
                .join(ScimGroupMember, ScimGroupMember.group_id == ScimGroup.id)
                .where(ScimGroupMember.user_id == user_id)
            )
        )
        user.role = resolve_role_from_claims(groups, role_map=role_map, default_role=default_role)
    session.flush()


__all__ = [
    "ScimError",
    "authenticate_scim_request",
    "create_scim_group",
    "create_scim_token",
    "create_scim_user",
    "delete_scim_group",
    "delete_scim_user",
    "get_scim_group",
    "get_scim_user",
    "list_scim_groups",
    "list_scim_tokens",
    "list_scim_users",
    "patch_scim_group",
    "patch_scim_user",
    "replace_scim_group",
    "replace_scim_user",
    "revoke_scim_token",
    "scim_bearer_from_authorization",
    "scim_token_view",
]

"""Resolve only tenant-owned identity bindings for separation of duties."""

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from security_lakehouse.db.models import User


def identity_key(value: str) -> str:
    return value.strip().casefold().removeprefix("mailto:")


def identity_aliases(session: Session, tenant_id: str, reviewer: str) -> set[str]:
    key = identity_key(reviewer)
    if not key:
        return set()
    aliases = {key}
    # Only tenant-owned identity bindings establish aliases. Never infer that an
    # arbitrary provider ARN or display name belongs to an authenticated user.
    users = session.scalars(
        select(User).where(
            User.tenant_id == tenant_id,
            or_(func.lower(User.email) == key, func.lower(User.id) == key, func.lower(User.scim_external_id) == key),
        )
    )
    for user in users:
        aliases.update(identity_key(value) for value in (user.id, user.email, user.scim_external_id) if value)
    return aliases

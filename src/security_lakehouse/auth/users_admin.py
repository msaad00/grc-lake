"""Admin operations for tenant user directory."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from security_lakehouse.db.models import USER_ROLES, User


class UserAdminError(ValueError):
    """Raised when a user admin mutation is rejected."""


class UserNotFoundError(UserAdminError):
    """Raised when the user does not exist in the caller's tenant."""


def list_tenant_users(session: Session, *, tenant_id: str) -> list[User]:
    stmt = select(User).where(User.tenant_id == tenant_id).order_by(User.created_at, User.email)
    return list(session.scalars(stmt))


def count_active_admins(session: Session, *, tenant_id: str, exclude_user_id: str | None = None) -> int:
    stmt = (
        select(func.count())
        .select_from(User)
        .where(
            User.tenant_id == tenant_id,
            User.role == "admin",
            User.is_active.is_(True),
        )
    )
    if exclude_user_id:
        stmt = stmt.where(User.id != exclude_user_id)
    return int(session.scalar(stmt) or 0)


def update_tenant_user(
    session: Session,
    *,
    tenant_id: str,
    user_id: str,
    actor_user_id: str,
    role: str | None = None,
    is_active: bool | None = None,
    display_name: str | None = None,
) -> User:
    user = session.get(User, user_id)
    if user is None or user.tenant_id != tenant_id:
        raise UserNotFoundError("user not found")
    if role is not None:
        if role not in USER_ROLES:
            raise UserAdminError(f"role must be one of {USER_ROLES}")
        if user.role == "admin" and role != "admin" and count_active_admins(session, tenant_id=tenant_id) <= 1:
            raise UserAdminError("cannot demote the last active admin")
        user.role = role
    if is_active is not None:
        if user.id == actor_user_id and not is_active:
            raise UserAdminError("cannot deactivate your own account")
        if user.role == "admin" and not is_active and count_active_admins(session, tenant_id=tenant_id) <= 1:
            raise UserAdminError("cannot deactivate the last active admin")
        user.is_active = is_active
    if display_name is not None:
        user.display_name = display_name.strip()
    session.flush()
    return user


def user_to_dict(user: User) -> dict[str, object]:
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }

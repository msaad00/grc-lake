"""Data-access + serialization for tags and saved views.

Tags are tenant-scoped labels that can be attached to any entity type
(control, violation, task, evidence, connector). SavedViews persist named
filter sets per UI surface. SLA state is not applicable here; all state
is stored directly.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from security_lakehouse.db.base import apply_pagination
from security_lakehouse.db.models import EntityTag, SavedView, Tag
from security_lakehouse.timeutil import iso_offset

# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------


def create_tag(
    session: Session,
    *,
    tenant_id: str,
    name: str,
    color: str = "",
) -> Tag:
    """Create a new tag scoped to ``tenant_id``.

    Raises ``ValueError`` if the name is blank or already exists in the tenant.
    """
    name = name.strip()
    if not name:
        raise ValueError("tag name must not be blank")
    tag = Tag(tenant_id=tenant_id, name=name, color=color)
    session.add(tag)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise ValueError(f"tag {name!r} already exists in this tenant") from exc
    return tag


def list_tags(session: Session, *, tenant_id: str, limit: int | None = None, offset: int | None = None) -> list[Tag]:
    stmt = select(Tag).where(Tag.tenant_id == tenant_id).order_by(Tag.name)
    stmt = apply_pagination(stmt, limit=limit, offset=offset)
    return list(session.scalars(stmt))


def get_tag(session: Session, *, tenant_id: str, tag_id: str) -> Tag | None:
    tag = session.get(Tag, tag_id)
    return tag if tag is not None and tag.tenant_id == tenant_id else None


def delete_tag(session: Session, *, tenant_id: str, tag_id: str) -> bool:
    """Delete the tag and all its entity associations. Returns True if found."""
    tag = get_tag(session, tenant_id=tenant_id, tag_id=tag_id)
    if tag is None:
        return False
    session.delete(tag)
    session.flush()
    return True


def tag_to_dict(tag: Tag) -> dict[str, Any]:
    return {
        "id": tag.id,
        "tenant_id": tag.tenant_id,
        "name": tag.name,
        "color": tag.color,
        "created_at": iso_offset(tag.created_at),
    }


# ---------------------------------------------------------------------------
# EntityTag (attach / detach)
# ---------------------------------------------------------------------------


def attach_tag(
    session: Session,
    *,
    tenant_id: str,
    tag_id: str,
    entity_type: str,
    entity_id: str,
) -> EntityTag:
    """Attach ``tag_id`` to ``(entity_type, entity_id)``.

    Idempotent: if the association already exists it is returned as-is.
    Raises ``ValueError`` if the tag does not belong to this tenant.
    """
    tag = get_tag(session, tenant_id=tenant_id, tag_id=tag_id)
    if tag is None:
        raise ValueError(f"tag {tag_id!r} not found in this tenant")
    entity_type = entity_type.strip()
    if not entity_type:
        raise ValueError("entity_type must not be blank")
    if not entity_id.strip():
        raise ValueError("entity_id must not be blank")

    # Check for existing association first to be idempotent
    stmt = (
        select(EntityTag)
        .where(EntityTag.tag_id == tag_id)
        .where(EntityTag.entity_type == entity_type)
        .where(EntityTag.entity_id == entity_id)
    )
    existing = session.scalars(stmt).first()
    if existing is not None:
        return existing

    et = EntityTag(
        tenant_id=tenant_id,
        tag_id=tag_id,
        entity_type=entity_type,
        entity_id=entity_id,
    )
    session.add(et)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        # Race: already inserted by concurrent request; fetch and return
        stmt = (
            select(EntityTag)
            .where(EntityTag.tag_id == tag_id)
            .where(EntityTag.entity_type == entity_type)
            .where(EntityTag.entity_id == entity_id)
        )
        et = session.scalars(stmt).one()
    return et


def detach_tag(
    session: Session,
    *,
    tenant_id: str,
    tag_id: str,
    entity_type: str,
    entity_id: str,
) -> bool:
    """Remove the association between ``tag_id`` and ``(entity_type, entity_id)``.

    Returns True if the row existed and was deleted.
    Raises ``ValueError`` if the tag does not belong to this tenant.
    """
    tag = get_tag(session, tenant_id=tenant_id, tag_id=tag_id)
    if tag is None:
        raise ValueError(f"tag {tag_id!r} not found in this tenant")
    stmt = (
        select(EntityTag)
        .where(EntityTag.tag_id == tag_id)
        .where(EntityTag.entity_type == entity_type)
        .where(EntityTag.entity_id == entity_id)
    )
    et = session.scalars(stmt).first()
    if et is None:
        return False
    session.delete(et)
    session.flush()
    return True


def tags_for_entity(
    session: Session,
    *,
    tenant_id: str,
    entity_type: str,
    entity_id: str,
) -> list[Tag]:
    """Return all tags attached to ``(entity_type, entity_id)`` for a tenant."""
    stmt = (
        select(Tag)
        .join(EntityTag, EntityTag.tag_id == Tag.id)
        .where(Tag.tenant_id == tenant_id)
        .where(EntityTag.entity_type == entity_type)
        .where(EntityTag.entity_id == entity_id)
        .order_by(Tag.name)
    )
    return list(session.scalars(stmt))


def entity_ids_for_tag(
    session: Session,
    *,
    tenant_id: str,
    tag_id: str,
    entity_type: str | None = None,
) -> list[str]:
    """Return entity ids attached to ``tag_id``, optionally filtered by type."""
    if get_tag(session, tenant_id=tenant_id, tag_id=tag_id) is None:
        return []
    stmt = select(EntityTag.entity_id).where(EntityTag.tenant_id == tenant_id).where(EntityTag.tag_id == tag_id)
    if entity_type:
        stmt = stmt.where(EntityTag.entity_type == entity_type.strip())
    stmt = stmt.order_by(EntityTag.entity_type, EntityTag.entity_id)
    return list(session.scalars(stmt))


def entity_tag_to_dict(et: EntityTag) -> dict[str, Any]:
    return {
        "id": et.id,
        "tenant_id": et.tenant_id,
        "tag_id": et.tag_id,
        "entity_type": et.entity_type,
        "entity_id": et.entity_id,
        "created_at": iso_offset(et.created_at),
    }


# ---------------------------------------------------------------------------
# SavedViews
# ---------------------------------------------------------------------------


def create_saved_view(
    session: Session,
    *,
    tenant_id: str,
    surface: str,
    name: str,
    filters: dict[str, Any],
    created_by: str = "",
) -> SavedView:
    surface = surface.strip()
    name = name.strip()
    if not surface:
        raise ValueError("saved view requires a surface")
    if not name:
        raise ValueError("saved view requires a name")
    view = SavedView(
        tenant_id=tenant_id,
        surface=surface,
        name=name,
        filters=json.dumps(filters),
        created_by=created_by,
    )
    session.add(view)
    session.flush()
    return view


def list_saved_views(
    session: Session,
    *,
    tenant_id: str,
    surface: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> list[SavedView]:
    stmt = select(SavedView).where(SavedView.tenant_id == tenant_id)
    if surface:
        stmt = stmt.where(SavedView.surface == surface)
    stmt = apply_pagination(stmt.order_by(SavedView.name), limit=limit, offset=offset)
    return list(session.scalars(stmt))


def get_saved_view(session: Session, *, tenant_id: str, view_id: str) -> SavedView | None:
    view = session.get(SavedView, view_id)
    return view if view is not None and view.tenant_id == tenant_id else None


def delete_saved_view(session: Session, *, tenant_id: str, view_id: str) -> bool:
    view = get_saved_view(session, tenant_id=tenant_id, view_id=view_id)
    if view is None:
        return False
    session.delete(view)
    session.flush()
    return True


def saved_view_to_dict(view: SavedView) -> dict[str, Any]:
    try:
        filters = json.loads(view.filters)
    except (ValueError, TypeError):
        filters = {}
    return {
        "id": view.id,
        "tenant_id": view.tenant_id,
        "surface": view.surface,
        "name": view.name,
        "filters": filters,
        "created_by": view.created_by,
        "created_at": iso_offset(view.created_at),
    }


__all__ = [
    "attach_tag",
    "create_saved_view",
    "create_tag",
    "delete_saved_view",
    "delete_tag",
    "detach_tag",
    "entity_ids_for_tag",
    "entity_tag_to_dict",
    "get_saved_view",
    "get_tag",
    "list_saved_views",
    "list_tags",
    "saved_view_to_dict",
    "tag_to_dict",
    "tags_for_entity",
]

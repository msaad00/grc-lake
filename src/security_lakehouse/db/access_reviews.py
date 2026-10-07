"""Data-access + serialization for access-review campaigns and items.

Access reviews live in the application-state database (server mode). Every query
is tenant-scoped so one workspace can never read or mutate another's campaigns.
A campaign walks ``draft → active → completed``; each item carries one reviewer
decision (``certified`` / ``revoked`` / ``flagged``), and the set of decisions is
the audit evidence that access was reviewed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import case, func, select, update
from sqlalchemy.orm import Session

from security_lakehouse.db.base import apply_pagination
from security_lakehouse.db.identity_aliases import identity_aliases, identity_key
from security_lakehouse.db.models import (
    ACCESS_REVIEW_DECISIONS,
    ACCESS_REVIEW_STATUSES,
    AccessReviewCampaign,
    AccessReviewItem,
    _as_aware,
)


def _now(now: datetime | None) -> datetime:
    return now or datetime.now(UTC)


def _iso(value: datetime | None) -> str | None:
    return _as_aware(value).astimezone(UTC).isoformat() if value else None


def _lock_campaign(
    session: Session, *, tenant_id: str, campaign_id: str | None = None, item_id: str | None = None
) -> AccessReviewCampaign | None:
    """Serialize membership, decisions and completion in one DB transaction.

    A no-op UPDATE locks the campaign on both SQLite and PostgreSQL. A plain
    SELECT FOR UPDATE would silently omit locking on SQLite. Refresh ORM state
    after acquiring the lock so previously loaded objects cannot bypass it.
    """
    target = (
        select(AccessReviewItem.campaign_id)
        .where(AccessReviewItem.id == item_id, AccessReviewItem.tenant_id == tenant_id)
        .scalar_subquery()
        if item_id is not None
        else campaign_id
    )
    locked = session.scalar(
        update(AccessReviewCampaign)
        .where(AccessReviewCampaign.id == target, AccessReviewCampaign.tenant_id == tenant_id)
        .values(updated_at=AccessReviewCampaign.updated_at)
        .returning(AccessReviewCampaign.id)
        .execution_options(synchronize_session=False)
    )
    if locked is None:
        return None
    return session.scalar(
        select(AccessReviewCampaign)
        .where(AccessReviewCampaign.id == locked, AccessReviewCampaign.tenant_id == tenant_id)
        .execution_options(populate_existing=True)
    )


def get_mutable_campaign(session: Session, *, tenant_id: str, campaign_id: str) -> AccessReviewCampaign | None:
    campaign = _lock_campaign(session, tenant_id=tenant_id, campaign_id=campaign_id)
    if campaign is not None and campaign.status not in {"draft", "active"}:
        raise ValueError("cannot add subjects to a terminal campaign")
    return campaign


# --- campaigns ---------------------------------------------------------------


def create_campaign(
    session: Session,
    *,
    tenant_id: str,
    name: str,
    description: str = "",
    scope: str = "all",
    control_id: str | None = None,
    due_at: datetime | None = None,
    created_by: str = "",
) -> AccessReviewCampaign:
    if not name.strip():
        raise ValueError("access review campaign requires a name")
    campaign = AccessReviewCampaign(
        tenant_id=tenant_id,
        name=name,
        description=description,
        scope=scope or "all",
        control_id=control_id,
        due_at=due_at,
        created_by=created_by,
    )
    session.add(campaign)
    session.flush()
    return campaign


def get_campaign(session: Session, *, tenant_id: str, campaign_id: str) -> AccessReviewCampaign | None:
    campaign = session.get(AccessReviewCampaign, campaign_id)
    return campaign if campaign is not None and campaign.tenant_id == tenant_id else None


def list_campaigns(
    session: Session,
    *,
    tenant_id: str,
    status: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> list[AccessReviewCampaign]:
    stmt = select(AccessReviewCampaign).where(AccessReviewCampaign.tenant_id == tenant_id)
    if status:
        stmt = stmt.where(AccessReviewCampaign.status == status)
    stmt = apply_pagination(stmt.order_by(AccessReviewCampaign.created_at.desc()), limit=limit, offset=offset)
    return list(session.scalars(stmt))


def set_campaign_status(
    session: Session,
    *,
    tenant_id: str,
    campaign_id: str,
    status: str,
    now: datetime | None = None,
) -> AccessReviewCampaign | None:
    if status not in ACCESS_REVIEW_STATUSES:
        raise ValueError(f"status must be one of {list(ACCESS_REVIEW_STATUSES)}, got {status!r}")
    campaign = _lock_campaign(session, tenant_id=tenant_id, campaign_id=campaign_id)
    if campaign is None:
        return None
    if campaign.status == status:
        return campaign
    transitions = {"draft": {"active", "cancelled"}, "active": {"completed", "cancelled"}}
    if status not in transitions.get(campaign.status, set()):
        raise ValueError(f"campaign cannot transition from {campaign.status} to {status}")
    if status == "completed":
        progress = campaign_progress(session, tenant_id=tenant_id, campaign_id=campaign_id)
        if not progress["total"]:
            raise ValueError("cannot complete an empty campaign")
        if progress["pending"]:
            raise ValueError("cannot complete a campaign with pending decisions")
    moment = _now(now)
    campaign.status = status
    campaign.completed_at = moment if status == "completed" else None
    campaign.updated_at = moment
    session.flush()
    return campaign


# --- items -------------------------------------------------------------------


def add_item(
    session: Session,
    *,
    tenant_id: str,
    campaign_id: str,
    subject_id: str,
    subject_name: str = "",
    source: str = "",
    access_summary: str = "",
) -> AccessReviewItem:
    if not subject_id.strip():
        raise ValueError("access review item requires a subject_id")
    campaign = get_mutable_campaign(session, tenant_id=tenant_id, campaign_id=campaign_id)
    if campaign is None:
        raise ValueError("campaign not found in this tenant")
    item = AccessReviewItem(
        tenant_id=tenant_id,
        campaign_id=campaign_id,
        subject_id=subject_id,
        subject_name=subject_name,
        source=source,
        access_summary=access_summary,
    )
    session.add(item)
    session.flush()
    return item


def get_item(session: Session, *, tenant_id: str, item_id: str) -> AccessReviewItem | None:
    item = session.get(AccessReviewItem, item_id)
    return item if item is not None and item.tenant_id == tenant_id else None


def list_items(
    session: Session,
    *,
    tenant_id: str,
    campaign_id: str,
    decision: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> list[AccessReviewItem]:
    stmt = select(AccessReviewItem).where(
        AccessReviewItem.tenant_id == tenant_id,
        AccessReviewItem.campaign_id == campaign_id,
    )
    if decision:
        stmt = stmt.where(AccessReviewItem.decision == decision)
    stmt = apply_pagination(
        stmt.order_by(AccessReviewItem.subject_name, AccessReviewItem.subject_id), limit=limit, offset=offset
    )
    return list(session.scalars(stmt))


def record_decision(
    session: Session,
    *,
    tenant_id: str,
    item_id: str,
    decision: str,
    reviewer: str = "",
    note: str = "",
    now: datetime | None = None,
) -> AccessReviewItem | None:
    if decision not in ACCESS_REVIEW_DECISIONS:
        raise ValueError(f"decision must be one of {list(ACCESS_REVIEW_DECISIONS)}, got {decision!r}")
    campaign = _lock_campaign(session, tenant_id=tenant_id, item_id=item_id)
    if campaign is None:
        return None
    if campaign.status != "active":
        raise ValueError("decisions require an active campaign")
    if not reviewer.strip():
        raise ValueError("a named reviewer is required")
    item = session.scalar(
        select(AccessReviewItem)
        .where(AccessReviewItem.id == item_id, AccessReviewItem.tenant_id == tenant_id)
        .execution_options(populate_existing=True)
    )
    if item is None:
        return None
    if decision == "certified" and identity_aliases(session, tenant_id, reviewer) & {
        identity_key(item.subject_id),
        identity_key(item.subject_name),
    }:
        raise ValueError("access certification requires an independent reviewer")
    if item.decision != "pending":
        if (item.decision, item.reviewer, item.note) == (decision, reviewer, note):
            return item
        raise ValueError("a recorded decision cannot be replaced; create a new review campaign")
    if decision == "pending":
        return item
    item.decision = decision
    item.reviewer = reviewer
    item.note = note
    item.decided_at = None if decision == "pending" else _now(now)
    session.flush()
    return item


def campaign_progress(session: Session, *, tenant_id: str, campaign_id: str) -> dict[str, int]:
    """Per-decision counts for a campaign — the reviewer's burn-down."""
    rows = session.execute(
        select(AccessReviewItem.decision, func.count())
        .where(AccessReviewItem.tenant_id == tenant_id, AccessReviewItem.campaign_id == campaign_id)
        .group_by(AccessReviewItem.decision)
    ).all()
    counts = {decision: 0 for decision in ACCESS_REVIEW_DECISIONS}
    for decision, count in rows:
        counts[str(decision)] = int(count)
    counts["total"] = sum(counts[d] for d in ACCESS_REVIEW_DECISIONS)
    counts["reviewed"] = counts["total"] - counts["pending"]
    return counts


def control_coverage(session: Session, *, tenant_id: str) -> dict[str, dict[str, Any]]:
    """Aggregate access-review activity per mapped control_id.

    For each control a campaign targets, report how many campaigns exist, how
    many completed, the most recent completion, and the per-decision item counts
    across those campaigns — the raw inputs for "is this access control under a
    current review?".
    """
    coverage: dict[str, dict[str, Any]] = {}
    campaign_rows = session.execute(
        select(
            AccessReviewCampaign.control_id,
            func.count(),
            func.sum(case((AccessReviewCampaign.status == "completed", 1), else_=0)),
            func.max(AccessReviewCampaign.completed_at),
        )
        .where(AccessReviewCampaign.tenant_id == tenant_id, AccessReviewCampaign.control_id.is_not(None))
        .group_by(AccessReviewCampaign.control_id)
    ).all()
    for control_id, campaigns, completed, last_completed in campaign_rows:
        coverage[str(control_id)] = {
            "control_id": str(control_id),
            "campaigns": int(campaigns),
            "completed_campaigns": int(completed or 0),
            "last_completed_at": last_completed,
            "decisions": {decision: 0 for decision in ACCESS_REVIEW_DECISIONS},
        }

    item_rows = session.execute(
        select(AccessReviewCampaign.control_id, AccessReviewItem.decision, func.count())
        .join(AccessReviewItem, AccessReviewItem.campaign_id == AccessReviewCampaign.id)
        .where(AccessReviewCampaign.tenant_id == tenant_id, AccessReviewCampaign.control_id.is_not(None))
        .group_by(AccessReviewCampaign.control_id, AccessReviewItem.decision)
    ).all()
    for control_id, decision, count in item_rows:
        entry = coverage.get(str(control_id))
        if entry is not None:
            entry["decisions"][str(decision)] = int(count)
    return coverage


# --- serialization -----------------------------------------------------------


def campaign_to_dict(campaign: AccessReviewCampaign) -> dict[str, Any]:
    return {
        "id": campaign.id,
        "name": campaign.name,
        "description": campaign.description,
        "scope": campaign.scope,
        "status": campaign.status,
        "control_id": campaign.control_id,
        "due_at": _iso(campaign.due_at),
        "created_by": campaign.created_by,
        "created_at": _iso(campaign.created_at),
        "updated_at": _iso(campaign.updated_at),
        "completed_at": _iso(campaign.completed_at),
    }


def item_to_dict(item: AccessReviewItem) -> dict[str, Any]:
    return {
        "id": item.id,
        "campaign_id": item.campaign_id,
        "subject_id": item.subject_id,
        "subject_name": item.subject_name,
        "source": item.source,
        "access_summary": item.access_summary,
        "decision": item.decision,
        "reviewer": item.reviewer,
        "note": item.note,
        "decided_at": _iso(item.decided_at),
        "created_at": _iso(item.created_at),
    }


__all__ = [
    "add_item",
    "campaign_progress",
    "campaign_to_dict",
    "control_coverage",
    "create_campaign",
    "get_campaign",
    "get_item",
    "item_to_dict",
    "list_campaigns",
    "list_items",
    "record_decision",
    "set_campaign_status",
]

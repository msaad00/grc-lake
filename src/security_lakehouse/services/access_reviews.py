"""Shared access-review service functions (campaigns + items).

Transport-agnostic wrappers over the ``db.access_reviews`` repository plus
serialization, mirroring :mod:`security_lakehouse.services.grc`. Write functions
own their commit so any caller — FastAPI routes, the MCP server, the SDK, or the
CLI — gets durable DB-backed writes. Repository ``ValueError`` is surfaced as
:class:`ValidationError`; missing rows as :class:`NotFound`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.db import access_reviews as ar
from security_lakehouse.io import read_jsonl
from security_lakehouse.services import NotFound, ValidationError

# Silver asset types that represent a reviewable identity (a user/principal whose
# access a reviewer certifies). Group/policy/config rows are not per-subject access.
IDENTITY_ASSET_TYPES = {"identity_account", "identity_user", "okta_user", "iam_role"}
# A completed access review counts as current evidence for this long (a year is
# the common audit cadence for access certification).
COVERAGE_FRESHNESS_DAYS = 365


def list_campaigns(
    session: Session,
    tenant_id: str,
    *,
    status: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> list[dict[str, Any]]:
    rows = ar.list_campaigns(session, tenant_id=tenant_id, status=status, limit=limit, offset=offset)
    return [ar.campaign_to_dict(row) for row in rows]


def create_campaign(
    session: Session,
    tenant_id: str,
    *,
    name: str,
    description: str = "",
    scope: str = "all",
    control_id: str | None = None,
    due_at: datetime | None = None,
    created_by: str = "",
) -> dict[str, Any]:
    try:
        campaign = ar.create_campaign(
            session,
            tenant_id=tenant_id,
            name=name,
            description=description,
            scope=scope,
            control_id=control_id,
            due_at=due_at,
            created_by=created_by,
        )
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    session.commit()
    return ar.campaign_to_dict(campaign)


def get_campaign(session: Session, tenant_id: str, campaign_id: str) -> dict[str, Any]:
    campaign = ar.get_campaign(session, tenant_id=tenant_id, campaign_id=campaign_id)
    if campaign is None:
        raise NotFound("access review campaign not found")
    data = ar.campaign_to_dict(campaign)
    data["progress"] = ar.campaign_progress(session, tenant_id=tenant_id, campaign_id=campaign_id)
    return data


def set_campaign_status(session: Session, tenant_id: str, campaign_id: str, *, status: str) -> dict[str, Any]:
    try:
        campaign = ar.set_campaign_status(session, tenant_id=tenant_id, campaign_id=campaign_id, status=status)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    if campaign is None:
        raise NotFound("access review campaign not found")
    session.commit()
    return ar.campaign_to_dict(campaign)


def list_items(
    session: Session,
    tenant_id: str,
    campaign_id: str,
    *,
    decision: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> list[dict[str, Any]]:
    if ar.get_campaign(session, tenant_id=tenant_id, campaign_id=campaign_id) is None:
        raise NotFound("access review campaign not found")
    rows = ar.list_items(
        session, tenant_id=tenant_id, campaign_id=campaign_id, decision=decision, limit=limit, offset=offset
    )
    return [ar.item_to_dict(row) for row in rows]


def add_item(
    session: Session,
    tenant_id: str,
    campaign_id: str,
    *,
    subject_id: str,
    subject_name: str = "",
    source: str = "",
    access_summary: str = "",
) -> dict[str, Any]:
    try:
        item = ar.add_item(
            session,
            tenant_id=tenant_id,
            campaign_id=campaign_id,
            subject_id=subject_id,
            subject_name=subject_name,
            source=source,
            access_summary=access_summary,
        )
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    session.commit()
    return ar.item_to_dict(item)


def record_decision(
    session: Session,
    tenant_id: str,
    item_id: str,
    *,
    decision: str,
    reviewer: str = "",
    note: str = "",
) -> dict[str, Any]:
    try:
        item = ar.record_decision(
            session, tenant_id=tenant_id, item_id=item_id, decision=decision, reviewer=reviewer, note=note
        )
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    if item is None:
        raise NotFound("access review item not found")
    session.commit()
    return ar.item_to_dict(item)


def identity_subjects_from_silver(lake_dir: str | Path, *, scope: str = "all") -> list[dict[str, Any]]:
    """Derive reviewable identity subjects from the lake's normalized evidence.

    Reads ``silver/normalized_events.jsonl``, keeps identity rows, and collapses
    them to one subject per ``asset_id`` — so a user with several signals (access,
    MFA, key hygiene) becomes a single review item summarizing their event types
    and open-finding count. ``scope`` (other than ``all``) filters by source, so a
    campaign scoped to one connector reviews only that connector's identities.
    """
    silver = Path(lake_dir) / "silver" / "normalized_events.jsonl"
    by_subject: dict[str, dict[str, Any]] = {}
    for row in read_jsonl(silver, missing_ok=True):
        if str(row.get("asset_type")) not in IDENTITY_ASSET_TYPES:
            continue
        source = str(row.get("source") or "")
        if scope not in {"all", ""} and source and source not in scope:
            continue
        subject_id = str(row.get("asset_id") or "")
        if not subject_id:
            continue
        agg = by_subject.setdefault(
            subject_id, {"subject_id": subject_id, "source": source, "event_types": set(), "open": 0}
        )
        agg["event_types"].add(str(row.get("event_type") or ""))
        if str(row.get("status")) == "open":
            agg["open"] += 1
    subjects: list[dict[str, Any]] = []
    for subject_id, agg in sorted(by_subject.items()):
        name = subject_id.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
        event_types = ", ".join(sorted(t for t in agg["event_types"] if t))
        summary = event_types + (f" — {agg['open']} open finding(s)" if agg["open"] else "")
        subjects.append(
            {"subject_id": subject_id, "subject_name": name, "source": agg["source"], "access_summary": summary}
        )
    return subjects


def seed_campaign_from_evidence(
    session: Session,
    lake_dir: str | Path,
    tenant_id: str,
    campaign_id: str,
    *,
    scope: str | None = None,
) -> dict[str, Any]:
    """Populate a campaign with one review item per identity in the lake evidence.

    Idempotent: subjects already in the campaign are skipped, so re-seeding after
    a fresh sync only adds newly-discovered identities. Uses the campaign's own
    ``scope`` unless an explicit ``scope`` overrides it.
    """
    try:
        campaign = ar.get_mutable_campaign(session, tenant_id=tenant_id, campaign_id=campaign_id)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    if campaign is None:
        raise NotFound("access review campaign not found")
    effective_scope = scope or campaign.scope or "all"
    candidates = identity_subjects_from_silver(lake_dir, scope=effective_scope)
    existing = {item.subject_id for item in ar.list_items(session, tenant_id=tenant_id, campaign_id=campaign_id)}
    added = 0
    for candidate in candidates:
        if candidate["subject_id"] in existing:
            continue
        ar.add_item(session, tenant_id=tenant_id, campaign_id=campaign_id, **candidate)
        added += 1
    session.commit()
    return {"added": added, "skipped": len(candidates) - added, "candidates": len(candidates)}


def control_coverage(session: Session, tenant_id: str, *, now: datetime | None = None) -> list[dict[str, Any]]:
    """Map access-review activity to the access controls it satisfies.

    Joins each campaign's ``control_id`` to the control catalog (framework +
    title) and computes whether the control is under a *current* review — a
    completed campaign within :data:`COVERAGE_FRESHNESS_DAYS`. This is the
    access-control evidence an auditor asks for (SOC 2 CC6.x, ISO 27001 A.5.18):
    not just "was access reviewed" but "is the review still in date, and what did
    it find".
    """
    moment = now or datetime.now(UTC)
    raw = ar.control_coverage(session, tenant_id=tenant_id)
    catalog = load_control_catalog()
    rows: list[dict[str, Any]] = []
    for control_id, agg in raw.items():
        control = catalog.get(control_id, {})
        last_completed = agg["last_completed_at"]
        last_aware = (
            last_completed.replace(tzinfo=UTC) if last_completed and last_completed.tzinfo is None else last_completed
        )
        is_current = bool(last_aware and (moment - last_aware).days <= COVERAGE_FRESHNESS_DAYS)
        rows.append(
            {
                "control_id": control_id,
                "framework": control.get("framework"),
                "title": control.get("title"),
                "campaigns": agg["campaigns"],
                "completed_campaigns": agg["completed_campaigns"],
                "last_completed_at": last_aware.isoformat() if last_aware else None,
                "current": is_current,
                "decisions": agg["decisions"],
            }
        )
    return sorted(rows, key=lambda row: str(row["control_id"]))


__all__ = [
    "add_item",
    "control_coverage",
    "create_campaign",
    "get_campaign",
    "identity_subjects_from_silver",
    "list_campaigns",
    "list_items",
    "record_decision",
    "seed_campaign_from_evidence",
    "set_campaign_status",
]

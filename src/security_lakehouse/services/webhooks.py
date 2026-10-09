"""Shared webhook subscription + event-dispatch service functions.

Pure, transport-agnostic functions that wrap the ``db.webhooks`` repository
plus outbound delivery. They take a SQLAlchemy session, a ``tenant_id``, and
plain params, and return plain dicts ready to drop into any response
envelope. Write functions own their commit, matching ``services.grc``.

``dispatch_event`` is the orchestration entry point called after a finding or
assessment write completes: it fans an event out to every enabled matching
subscription and never raises, regardless of how many receivers are slow or
dead, so it is always safe to call from the write path without risking that
write's success.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from security_lakehouse.db import webhooks as webhooks_db
from security_lakehouse.services import NotFound, ValidationError
from security_lakehouse.webhook_delivery import build_envelope, deliver_webhook

logger = logging.getLogger(__name__)

# Caps how many subscriptions ONE dispatch_event(...) call (i.e. one event,
# such as a single finding.created) delivers to -- protects a tenant with many
# registered subscriptions from a single event fanning out unboundedly.
MAX_EVENTS_PER_DISPATCH_CALL = 200

# Separately caps how many finding.created/control.failed events ONE snapshot
# write can trigger in total (dispatch_snapshot_events calls dispatch_event
# once per new violation/newly-failing control, with no bound of its own).
# Delivery is synchronous, so without this a snapshot surfacing thousands of
# new violations at once (a bulk-imported lake, a noisy source) would block
# the request thread for minutes doing sequential deliveries. The remainder
# beyond this cap is logged and skipped rather than sent; assessment.completed
# always fires regardless, so a subscriber can still ask GET /api/v1/snapshots
# for the full violations list when this cap is hit.
MAX_SNAPSHOT_EVENTS_PER_DISPATCH = 200

# --- subscriptions -------------------------------------------------------------


def list_subscriptions(
    session: Session,
    tenant_id: str,
    *,
    enabled: bool | None = None,
    event_type: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> list[dict[str, Any]]:
    rows = webhooks_db.list_subscriptions(
        session, tenant_id=tenant_id, enabled=enabled, event_type=event_type, limit=limit, offset=offset
    )
    return [webhooks_db.subscription_to_dict(row) for row in rows]


def create_subscription(
    session: Session,
    tenant_id: str,
    *,
    url: str,
    secret: str,
    event_types: list[str],
    description: str = "",
    enabled: bool = True,
    created_by: str = "",
) -> dict[str, Any]:
    try:
        subscription = webhooks_db.create_subscription(
            session,
            tenant_id=tenant_id,
            url=url,
            secret=secret,
            event_types=event_types,
            description=description,
            enabled=enabled,
            created_by=created_by,
        )
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    session.commit()
    # The secret is returned in full exactly once, at creation — like an API
    # key's plaintext token, it is never shown again by list/get.
    return webhooks_db.subscription_to_dict(subscription, include_secret=True)


def get_subscription(session: Session, tenant_id: str, subscription_id: str) -> dict[str, Any]:
    subscription = webhooks_db.get_subscription(session, tenant_id=tenant_id, subscription_id=subscription_id)
    if subscription is None:
        raise NotFound("webhook subscription not found")
    return webhooks_db.subscription_to_dict(subscription)


def update_subscription(
    session: Session,
    tenant_id: str,
    subscription_id: str,
    *,
    changes: dict[str, Any],
) -> dict[str, Any]:
    try:
        subscription = webhooks_db.update_subscription(
            session, tenant_id=tenant_id, subscription_id=subscription_id, changes=changes
        )
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    if subscription is None:
        raise NotFound("webhook subscription not found")
    session.commit()
    return webhooks_db.subscription_to_dict(subscription)


def delete_subscription(session: Session, tenant_id: str, subscription_id: str) -> dict[str, Any]:
    deleted = webhooks_db.delete_subscription(session, tenant_id=tenant_id, subscription_id=subscription_id)
    if not deleted:
        raise NotFound("webhook subscription not found")
    session.commit()
    return {"id": subscription_id, "deleted": True}


def list_deliveries(
    session: Session,
    tenant_id: str,
    *,
    subscription_id: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> list[dict[str, Any]]:
    rows = webhooks_db.list_deliveries(
        session, tenant_id=tenant_id, subscription_id=subscription_id, limit=limit, offset=offset
    )
    return [webhooks_db.delivery_to_dict(row) for row in rows]


# --- dispatch --------------------------------------------------------------


def dispatch_event(
    session: Session,
    tenant_id: str,
    *,
    event_type: str,
    data: dict[str, Any],
    occurred_at: str | None = None,
    deliver: Any = None,
) -> list[dict[str, Any]]:
    """Fan ``event_type`` out to every enabled matching subscription for ``tenant_id``.

    Best-effort and defensive by design: an error looking up subscriptions, a
    delivery failure, or a DB error recording the outcome is logged and
    swallowed, never raised, so this can always be called after a write
    completes without risking that write's already-committed result. Returns
    the list of delivery outcomes for callers that want to inspect them (tests
    do; the write path does not).

    ``deliver`` defaults to :func:`webhook_delivery.deliver_webhook`, resolved
    at call time (not bound as a default argument) so tests can monkeypatch
    this module's ``deliver_webhook`` name and have it take effect even for
    callers — like the FastAPI routes — that never pass ``deliver`` explicitly.

    This function never commits or rolls back ``session`` itself. It can run
    mid-request, before the caller's own pending work is committed (e.g. an
    agent-decision approval flow that still has to write its execution record
    and commit *after* this returns) — committing here would finalize that
    unrelated work early, and if the caller's later commit then failed, a
    client retry would re-invoke this function and double-deliver. Every
    read/write below runs inside its own SAVEPOINT (``session.begin_nested()``),
    so a failure is isolated to that one sub-unit of work: it rolls back only
    the savepoint (never poisoning the caller's outer transaction the way an
    unhandled failed statement would on Postgres), and a success is retained
    in the still-open, uncommitted outer transaction for the caller to commit
    on its own terms.
    """
    if deliver is None:
        deliver = deliver_webhook
    results: list[dict[str, Any]] = []
    try:
        with session.begin_nested():
            subscriptions = webhooks_db.list_subscriptions_for_event(
                session, tenant_id=tenant_id, event_type=event_type
            )
    except Exception:
        logger.exception("webhook dispatch: failed to list subscriptions for tenant=%s event=%s", tenant_id, event_type)
        return results

    occurred = occurred_at or datetime.now(UTC).isoformat()
    for subscription in subscriptions[:MAX_EVENTS_PER_DISPATCH_CALL]:
        envelope = build_envelope(event_type=event_type, tenant_id=tenant_id, occurred_at=occurred, data=data)
        try:
            outcome = deliver(
                subscription.url,
                secret=subscription.secret,
                event_type=event_type,
                envelope=envelope,
            )
        except Exception as exc:  # a delivery failure must never break the caller
            logger.exception(
                "webhook dispatch: delivery raised for subscription=%s event=%s", subscription.id, event_type
            )
            outcome = {"ok": False, "status_code": None, "attempts": 0, "error": f"{type(exc).__name__}: {exc}"}
        try:
            with session.begin_nested():
                webhooks_db.record_delivery_result(
                    session,
                    tenant_id=tenant_id,
                    subscription_id=subscription.id,
                    event_type=event_type,
                    event_id=envelope["event_id"],
                    ok=bool(outcome.get("ok")),
                    attempts=int(outcome.get("attempts") or 0),
                    response_status=outcome.get("status_code"),
                    error=str(outcome.get("error") or ""),
                )
        except Exception:
            logger.exception(
                "webhook dispatch: failed to record delivery result for subscription=%s event=%s",
                subscription.id,
                event_type,
            )
        results.append({"subscription_id": subscription.id, **outcome})
    if len(subscriptions) > MAX_EVENTS_PER_DISPATCH_CALL:
        logger.warning(
            "webhook dispatch: tenant=%s event=%s had %d matching subscriptions, delivered to first %d",
            tenant_id,
            event_type,
            len(subscriptions),
            MAX_EVENTS_PER_DISPATCH_CALL,
        )
    return results


def dispatch_snapshot_events(
    session: Session,
    tenant_id: str,
    *,
    snapshot_path: Path,
    assessment: dict[str, Any],
    new_violations: list[dict[str, Any]],
    newly_failing_controls: list[str],
    deliver: Any = None,
) -> None:
    """Build and dispatch the webhook events one snapshot write can produce.

    ``deliver`` defaults to :func:`webhook_delivery.deliver_webhook`, resolved
    at call time for the same reason as :func:`dispatch_event`.

    Always fires ``assessment.completed``. Fires ``finding.created`` for each
    violation newly present since the prior snapshot, and ``control.failed``
    for each control that had zero open violations in the prior snapshot but
    has at least one now (see ``assessment._diff_violations`` for exactly how
    that transition is derived). On the very first snapshot of a lake there is
    no prior snapshot to diff against, so only ``assessment.completed`` fires.

    This is the function server-mode call sites (the FastAPI routes) pass as
    ``write_assessment_snapshot``'s ``on_snapshot_written`` hook, invoked after
    the snapshot's chain lock is already released.

    ``new_violations``/``newly_failing_controls`` are each capped at
    ``MAX_SNAPSHOT_EVENTS_PER_DISPATCH`` before dispatch -- a snapshot
    surfacing more than that in one write still always dispatches
    ``assessment.completed``, but stops issuing individual
    ``finding.created``/``control.failed`` deliveries beyond the cap (logged),
    since delivery is synchronous and unbounded fan-out here would block the
    triggering request.
    """
    posture = assessment.get("posture") or {}
    occurred_at = str(assessment.get("evaluated_at") or datetime.now(UTC).isoformat())
    snapshot_id = snapshot_path.stem

    if len(new_violations) > MAX_SNAPSHOT_EVENTS_PER_DISPATCH:
        logger.warning(
            "webhook dispatch: tenant=%s snapshot=%s had %d new violations, dispatching finding.created for first %d",
            tenant_id,
            snapshot_id,
            len(new_violations),
            MAX_SNAPSHOT_EVENTS_PER_DISPATCH,
        )
        new_violations = new_violations[:MAX_SNAPSHOT_EVENTS_PER_DISPATCH]
    if len(newly_failing_controls) > MAX_SNAPSHOT_EVENTS_PER_DISPATCH:
        logger.warning(
            "webhook dispatch: tenant=%s snapshot=%s had %d newly-failing controls, dispatching control.failed for"
            " first %d",
            tenant_id,
            snapshot_id,
            len(newly_failing_controls),
            MAX_SNAPSHOT_EVENTS_PER_DISPATCH,
        )
        newly_failing_controls = newly_failing_controls[:MAX_SNAPSHOT_EVENTS_PER_DISPATCH]

    dispatch_event(
        session,
        tenant_id,
        event_type="assessment.completed",
        occurred_at=occurred_at,
        deliver=deliver,
        data={
            "snapshot_id": snapshot_id,
            "assessment_hash": assessment.get("assessment_hash"),
            "prev_hash": assessment.get("prev_hash"),
            "snapshot_reason": assessment.get("snapshot_reason"),
            "evaluated_at": assessment.get("evaluated_at"),
            "posture_score": posture.get("score"),
            "posture_state": posture.get("state"),
            "open_violation_count": posture.get("open_violation_count"),
            "critical_violation_count": posture.get("critical_violation_count"),
            "high_violation_count": posture.get("high_violation_count"),
        },
    )

    for violation in new_violations:
        dispatch_event(
            session,
            tenant_id,
            event_type="finding.created",
            occurred_at=occurred_at,
            deliver=deliver,
            data={
                "snapshot_id": snapshot_id,
                "violation_id": violation.get("violation_id"),
                "control_id": violation.get("control_id"),
                "event_id": violation.get("event_id"),
                "asset_id": violation.get("asset_id"),
                "severity": violation.get("severity"),
                "state": violation.get("state"),
                "source": violation.get("source"),
                "event_type": violation.get("event_type"),
                "detected_at": violation.get("detected_at"),
                "evidence_ref": violation.get("evidence_ref"),
            },
        )

    for control_id in newly_failing_controls:
        dispatch_event(
            session,
            tenant_id,
            event_type="control.failed",
            occurred_at=occurred_at,
            deliver=deliver,
            data={
                "snapshot_id": snapshot_id,
                "control_id": control_id,
                "evaluated_at": assessment.get("evaluated_at"),
            },
        )


__all__ = [
    "MAX_EVENTS_PER_DISPATCH_CALL",
    "MAX_SNAPSHOT_EVENTS_PER_DISPATCH",
    "create_subscription",
    "delete_subscription",
    "dispatch_event",
    "dispatch_snapshot_events",
    "get_subscription",
    "list_deliveries",
    "list_subscriptions",
    "update_subscription",
]

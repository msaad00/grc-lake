"""Snapshot event hooks shared by HTTP requests and queued operations."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from security_lakehouse.assessment import SnapshotWrittenHook
from security_lakehouse.services import webhooks as webhook_services


def snapshot_written_hook(session: Session, tenant_id: str) -> SnapshotWrittenHook:
    """Build the ``write_assessment_snapshot`` hook that dispatches webhook events.

    Captures ``session``/``tenant_id`` by closure so ``assessment.py`` itself
    never needs to know about the application-state DB or tenancy; see
    ``assessment.write_assessment_snapshot`` for why the hook fires only after
    its chain lock is released.

    ``dispatch_snapshot_events``/``dispatch_event`` never commit or roll back
    ``session`` themselves (see ``services.webhooks.dispatch_event``) -- every
    caller of this hook must commit ``session`` itself afterward (once, atomic
    with whatever else that caller's own transaction is doing) or the staged
    delivery-log rows are silently discarded when the request-scoped session
    closes.
    """

    def _hook(
        snapshot_path: Path,
        assessment: dict[str, Any],
        new_violations: list[dict[str, Any]],
        newly_failing_controls: list[str],
    ) -> None:
        webhook_services.dispatch_snapshot_events(
            session,
            tenant_id,
            snapshot_path=snapshot_path,
            assessment=assessment,
            new_violations=new_violations,
            newly_failing_controls=newly_failing_controls,
        )

    return _hook

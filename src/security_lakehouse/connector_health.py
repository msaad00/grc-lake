"""Connector health: detect sources that have gone silent.

Evidence freshness already flags *stale evidence*. This adds the complementary
signal the continuous loop needs — **silent failure**: a connector that synced
fine before but has had no *successful* sync within its freshness SLO. A failing
or never-running connector that still looks "configured" is exactly how a
compliance pipeline silently rots, so health is keyed on the latest sync whose
``result`` is ``ok`` (a failed sync does not reset the clock).

Health per enabled connector:

* ``healthy``        — a successful sync within one SLO window.
* ``degraded``       — last success older than one SLO window (overdue).
* ``silent``         — last success older than ``SILENT_SLO_FACTOR`` windows, or
                       a connector that has never succeeded since being enabled.
* ``never_succeeded``— enabled but no successful sync on record yet.

Disabled connectors are reported as ``disabled`` and excluded from the rollup.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse.connector_state import (
    DEFAULT_FRESHNESS_SLO_MINUTES,
    build_catalog_view,
    connector_state_reader,
    latest_successful_run,
)
from security_lakehouse.models import parse_event_time, utc_iso

# How many freshness-SLO windows a connector can miss before it is "silent"
# rather than merely "degraded".
SILENT_SLO_FACTOR = 3


def evaluate_connector_health(
    *,
    connector_id: str,
    enabled: bool,
    freshness_slo_minutes: int,
    last_success_at: datetime | None,
    now: datetime,
) -> dict[str, Any]:
    """Classify one connector's health from its last successful sync vs SLO."""
    base = {
        "connector_id": connector_id,
        "freshness_slo_minutes": freshness_slo_minutes,
        "last_success_at": utc_iso(last_success_at) if last_success_at else None,
        "seconds_since_success": None,
    }
    if not enabled:
        return {**base, "health": "disabled"}
    if last_success_at is None:
        return {**base, "health": "never_succeeded"}
    age = (now - last_success_at).total_seconds()
    slo_seconds = max(1, freshness_slo_minutes) * 60
    if age > SILENT_SLO_FACTOR * slo_seconds:
        health = "silent"
    elif age > slo_seconds:
        health = "degraded"
    else:
        health = "healthy"
    return {**base, "health": health, "seconds_since_success": int(age)}


@connector_state_reader
def build_connector_health(lake_dir: str | Path, *, now: datetime | None = None) -> dict[str, Any]:
    """Per-connector health plus a rollup of how many sources have gone silent."""
    evaluated_at = (now or datetime.now(UTC)).astimezone(UTC)
    connectors: list[dict[str, Any]] = []
    for row in build_catalog_view(lake_dir):
        connector_id = str(row.get("connector_id") or "")
        enabled = row.get("state") == "enabled"
        try:
            slo = int(row.get("freshness_slo_minutes") or DEFAULT_FRESHNESS_SLO_MINUTES)
        except (TypeError, ValueError):
            slo = DEFAULT_FRESHNESS_SLO_MINUTES
        success = latest_successful_run(lake_dir, connector_id, kind="sync") if enabled else None
        last_success_at = parse_event_time(str(success["occurred_at"])) if success else None
        connectors.append(
            evaluate_connector_health(
                connector_id=connector_id,
                enabled=enabled,
                freshness_slo_minutes=slo,
                last_success_at=last_success_at,
                now=evaluated_at,
            )
        )
    tracked = [c for c in connectors if c["health"] != "disabled"]
    summary = {
        state: sum(1 for c in tracked if c["health"] == state)
        for state in ("healthy", "degraded", "silent", "never_succeeded")
    }
    summary["enabled"] = len(tracked)
    summary["unhealthy"] = summary["silent"] + summary["never_succeeded"]
    return {"evaluated_at": utc_iso(evaluated_at), "summary": summary, "connectors": connectors}

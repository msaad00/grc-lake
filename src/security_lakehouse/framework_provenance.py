"""Framework + control catalog provenance.

Frameworks must be versioned, live, and trusted — not hand-typed lookup
tables. Each framework declares:
  * ``official_source_url``     (e.g. eur-lex.europa.eu/eli/reg/2016/679)
  * ``official_source_name``
  * ``version`` + ``effective_date`` + ``superseded_by``
  * ``source_sha256`` + ``pulled_at`` populated by the sync job
  * ``sync_cadence_days`` (how often the source is expected to be re-checked)

This module joins the registry with the control catalog and computes a
freshness state the UI can render so reviewers can see at a glance:

    "GDPR · pulled 3 days ago · sha256 a1b2c3… · 86 controls mapped · fresh"

The actual source-sync job is intentionally separate (a GitHub Action or
cron) so this module remains pure and deterministic.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from security_lakehouse.catalog import (
    DEFAULT_CONTROL_CATALOG,
    DEFAULT_FRAMEWORK_REGISTRY,
    load_control_catalog,
    load_framework_registry,
)

PackState = Literal["seeded", "planned", "superseded"]


def framework_pack_state(framework: Mapping[str, Any], seeded_control_count: int) -> PackState:
    """Classify a registry entry. Only ``seeded`` entries count as framework packs.

    A registry entry without seeded controls is a stub: a superseded edition
    (``superseded_by`` set) or a pack that is planned but not catalogued.
    """
    if seeded_control_count > 0:
        return "seeded"
    if framework.get("superseded_by"):
        return "superseded"
    return "planned"


def framework_pack_counts(states: Iterable[str]) -> dict[str, int]:
    """Count pack states; the single source for every framework-pack count."""
    counts = Counter(states)
    planned = counts["planned"]
    superseded = counts["superseded"]
    return {
        "registered_framework_count": sum(counts.values()),
        "seeded_framework_count": counts["seeded"],
        "planned_stub_framework_count": planned,
        "superseded_framework_count": superseded,
        "stub_framework_count": planned + superseded,
    }


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        text = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    except ValueError:
        return None


def _freshness_state(pulled_at: datetime | None, cadence_days: int, now: datetime) -> str:
    if pulled_at is None:
        return "never_pulled"
    age = now - pulled_at
    sla = timedelta(days=cadence_days)
    if age <= sla:
        return "fresh"
    if age <= sla * 2:
        return "stale"
    return "expired"


def build_framework_view(
    registry_path: str | Path | None = None,
    controls_path: str | Path | None = None,
    *,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Return the framework registry joined with control counts + freshness."""
    frameworks = load_framework_registry(registry_path or DEFAULT_FRAMEWORK_REGISTRY)
    controls = load_control_catalog(controls_path or DEFAULT_CONTROL_CATALOG)
    now_utc = (now or datetime.now(UTC)).astimezone(UTC)

    controls_by_framework: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for control in controls.values():
        framework_id = str(control.get("framework_id") or "")
        if framework_id:
            controls_by_framework[framework_id].append(control)

    out: list[dict[str, Any]] = []
    for framework in frameworks.values():
        framework_id = str(framework.get("framework_id") or "")
        cadence = int(framework.get("sync_cadence_days") or 90)
        pulled_at = _parse_iso(framework.get("pulled_at"))
        freshness = _freshness_state(pulled_at, cadence, now_utc)
        controls = controls_by_framework.get(framework_id, [])
        mapped = sum(1 for c in controls if c.get("implementation_status", "").startswith("implemented"))
        out.append(
            {
                **framework,
                "superseded_by": framework.get("superseded_by"),
                "pack_state": framework_pack_state(framework, len(controls)),
                "control_count": len(controls),
                "implemented_control_count": mapped,
                "mapping_coverage_pct": (round(mapped / len(controls) * 100, 1) if controls else 0.0),
                "freshness_state": freshness,
                "pulled_age_days": ((now_utc - pulled_at).days if pulled_at is not None else None),
                "next_pull_due": (
                    (pulled_at + timedelta(days=cadence)).isoformat().replace("+00:00", "Z")
                    if pulled_at is not None
                    else None
                ),
            }
        )
    out.sort(key=lambda f: f.get("framework_id", ""))
    return out

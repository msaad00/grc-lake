"""Canonical event and analytics models."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from security_lakehouse.timeutil import parse_iso, utc_iso_z
from security_lakehouse.vocabulary import Severity

SEVERITY_SCORE: dict[str, int] = {
    Severity.CRITICAL.value: 100,
    Severity.HIGH.value: 80,
    Severity.MEDIUM.value: 50,
    Severity.LOW.value: 20,
    Severity.INFO.value: 5,
    Severity.NONE.value: 0,
}


@dataclass(frozen=True)
class PipelineResult:
    output_dir: str
    raw_count: int
    silver_count: int
    control_count: int
    asset_count: int
    mart_path: str
    metrics_path: str
    dashboard_data_path: str
    duckdb_mart_path: str | None = None


def parse_event_time(value: str) -> datetime:
    return parse_iso(value)


utc_iso = utc_iso_z


def instant_sort_key(value: object) -> datetime:
    """Order read projections by UTC time; absent/invalid dates sort oldest.

    This is not timestamp validation or evidence of freshness. Write boundaries
    continue to reject malformed dates; historical displays can contain blanks.
    """
    try:
        return parse_event_time(str(value or ""))
    except (ValueError, OverflowError):
        return datetime.min.replace(tzinfo=UTC)

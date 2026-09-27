"""Canonical event and analytics models."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

SEVERITY_SCORE = {
    "critical": 100,
    "high": 80,
    "medium": 50,
    "low": 20,
    "info": 5,
    "none": 0,
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
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def utc_iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")

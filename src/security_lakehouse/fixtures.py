"""Mockup company fixtures + CLI loader.

Each company directory under ``mockup_companies/<name>/`` ships a
``raw/security_events.jsonl`` shaped like real connector output. The
``fixtures load`` CLI command pipes that raw evidence through the
existing ``pipeline run`` so the workbench can demo a realistic lake
without standing up real connectors.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from security_lakehouse.catalog import _data_root

ROOT = _data_root()
FIXTURES_DIR = ROOT / "mockup_companies"


@dataclass(frozen=True)
class Fixture:
    company: str
    raw_path: Path
    event_count: int
    sources: list[str]
    controls: list[str]


def _summary(raw_path: Path) -> tuple[int, list[str], list[str]]:
    count = 0
    sources: set[str] = set()
    controls: set[str] = set()
    with raw_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            count += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if source := row.get("source"):
                sources.add(str(source))
            for control_id in row.get("controls") or []:
                controls.add(str(control_id))
    return count, sorted(sources), sorted(controls)


def list_fixtures(root: Path | None = None) -> list[Fixture]:
    base = root or FIXTURES_DIR
    if not base.is_dir():
        return []
    out: list[Fixture] = []
    for company_dir in sorted(p for p in base.iterdir() if p.is_dir()):
        raw = company_dir / "raw" / "security_events.jsonl"
        if not raw.is_file():
            continue
        count, sources, controls = _summary(raw)
        out.append(
            Fixture(
                company=company_dir.name,
                raw_path=raw,
                event_count=count,
                sources=sources,
                controls=controls,
            )
        )
    return out


def find_fixture(company: str, root: Path | None = None) -> Fixture | None:
    for fixture in list_fixtures(root):
        if fixture.company == company:
            return fixture
    return None


def _is_timestamp_key(key: str) -> bool:
    return key.endswith("_time") or key.endswith("_at")


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or "T" not in value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _timestamps(node: Any) -> list[datetime]:
    found: list[datetime] = []
    if isinstance(node, dict):
        for key, value in node.items():
            parsed = _parse_timestamp(value) if _is_timestamp_key(key) else None
            if parsed is not None:
                found.append(parsed)
            else:
                found.extend(_timestamps(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_timestamps(item))
    return found


def _shift(node: Any, delta: timedelta) -> Any:
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for key, value in node.items():
            parsed = _parse_timestamp(value) if _is_timestamp_key(key) else None
            if parsed is not None:
                out[key] = (parsed + delta).astimezone(UTC).isoformat().replace("+00:00", "Z")
            else:
                out[key] = _shift(value, delta)
        return out
    if isinstance(node, list):
        return [_shift(item, delta) for item in node]
    return node


# How old the newest demo row is right after a rebase. Demo sources use
# freshness SLOs of 5, 10, 60 minutes and 24 hours, and the golden rows span
# about 40 minutes. Three hours back puts every sub-hour-SLO row past twice its
# SLO (expired) and keeps every daily-SLO row well inside it (fresh), so no row
# changes status for roughly 20 hours. Anchoring nearer ``now`` puts rows on the
# 60-minute boundaries and the demo's counts change minute to minute.
DEMO_NEWEST_EVIDENCE_AGE = timedelta(hours=3)


def rebase_fixture_times(
    rows: list[dict[str, Any]],
    *,
    now: datetime | None = None,
    newest_age: timedelta = DEMO_NEWEST_EVIDENCE_AGE,
) -> list[dict[str, Any]]:
    """Shift every ``*_time``/``*_at`` timestamp so the newest is ``newest_age`` before ``now``.

    Demo fixtures are dated when they were authored; without this their evidence
    ages past every freshness SLA and the demo reads as fully expired. Relative
    spacing between rows is preserved.
    """
    stamps = _timestamps(rows)
    if not stamps:
        return [dict(row) for row in rows]
    target = (now or datetime.now(UTC)) - newest_age
    delta = target - max(stamps)
    return [_shift(row, delta) for row in rows]

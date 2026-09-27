"""Demo fixtures can be re-dated so evidence reads as current, not months stale."""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

from security_lakehouse.cli import main
from security_lakehouse.fixtures import DEMO_NEWEST_EVIDENCE_AGE, FIXTURES_DIR, rebase_fixture_times


def test_rebase_shifts_every_timestamp_and_keeps_spacing() -> None:
    rows = [
        {"event_time": "2026-06-30T12:00:00Z", "evidence": {"collected_at": "2026-06-30T12:01:00Z"}},
        {"event_time": "2026-06-30T12:10:00Z", "evidence": {"collected_at": "2026-06-30T12:11:00Z"}, "note": "x"},
    ]
    now = datetime(2026, 9, 24, 18, 0, tzinfo=UTC)

    out = rebase_fixture_times(rows, now=now)

    newest = datetime.fromisoformat(out[1]["event_time"].replace("Z", "+00:00"))
    oldest = datetime.fromisoformat(out[0]["event_time"].replace("Z", "+00:00"))
    collected = datetime.fromisoformat(out[1]["evidence"]["collected_at"].replace("Z", "+00:00"))
    assert collected == now - DEMO_NEWEST_EVIDENCE_AGE
    assert newest - oldest == timedelta(minutes=10)
    assert out[1]["evidence"]["collected_at"].endswith("Z")
    assert out[1]["note"] == "x"
    assert rows[0]["event_time"] == "2026-06-30T12:00:00Z"


def test_fixtures_load_rebase_times_makes_golden_evidence_current(tmp_path: Path) -> None:
    out = tmp_path / "lake"

    assert main(["fixtures", "load", "--company", "golden", "--out", str(out), "--rebase-times"]) == 0

    silver = [json.loads(line) for line in (out / "silver" / "normalized_events.jsonl").read_text().splitlines()]
    newest = max(datetime.fromisoformat(row["event_time"].replace("Z", "+00:00")) for row in silver)
    assert datetime.now(UTC) - newest < DEMO_NEWEST_EVIDENCE_AGE + timedelta(hours=1)


def _golden_status_counts(now: datetime, at: datetime) -> Counter[str]:
    from security_lakehouse.evidence_freshness import build_evidence_freshness
    from security_lakehouse.pipeline import _silver_row

    path = FIXTURES_DIR / "golden" / "raw" / "security_events.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    silver = [_silver_row(row, "sha") for row in rebase_fixture_times(rows, now=now)]
    return Counter(record["status"] for record in build_evidence_freshness(silver, now=at))


def test_rebased_golden_posture_holds_for_a_working_day() -> None:
    """Right after a load, no demo row may sit near its source's freshness SLO boundary.

    Otherwise fresh/stale/expired counts (and the posture score) change minute to
    minute while someone is looking at the demo or capturing screenshots.
    """
    loaded = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
    baseline = _golden_status_counts(loaded, loaded)
    for minutes in (1, 5, 15, 30, 45, 60, 90, 120, 240, 480):
        assert _golden_status_counts(loaded, loaded + timedelta(minutes=minutes)) == baseline, minutes
    assert baseline["fresh"] > 0

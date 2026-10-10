"""Inline posture violations are capped by violation count; counts and full-detail readers stay complete."""

from __future__ import annotations

from datetime import UTC, datetime
from http import HTTPStatus
from pathlib import Path

import pytest

from security_lakehouse import api_legacy, api_v1, assessment
from security_lakehouse.io import write_jsonl

MOMENT = datetime(2026, 5, 21, 9, 30, tzinfo=UTC)
CAP = assessment.INLINE_VIOLATION_CAP


def _event(index: int, score: int) -> dict:
    return {
        "event_id": f"evt-{index:06d}",
        "event_time": "2026-05-20T13:01:00Z",
        "event_type": "identity.mfa",
        "control_ids": ["SOC2-CC6.1"],
        "asset_id": "asset-1",
        "asset_owner": "it",
        "environment": "prod",
        "source": "okta",
        "severity": "critical" if score >= 90 else "high",
        "severity_score": score,
        "status": "open",
        "evidence_ref": f"s3://evidence/{index}.json",
        "raw_sha256": "0" * 64,
    }


def _lake(root: Path, count: int) -> Path:
    # One low-severity row; every other row outranks it.
    events = [_event(0, 10)] + [_event(index, 95 if index % 2 else 70) for index in range(1, count)]
    write_jsonl(root / "silver/normalized_events.jsonl", events)
    write_jsonl(
        root / "gold/control_posture.jsonl",
        [{"control_id": "SOC2-CC6.1", "framework": "SOC 2", "status": "fail", "risk_score": 80}],
    )
    write_jsonl(root / "gold/control_tests.jsonl", [{"control_id": "SOC2-CC6.1", "result": "fail"}])
    write_jsonl(root / "gold/asset_risk.jsonl", [{"asset_id": "asset-1", "asset_name": "Primary"}])
    return root


@pytest.fixture(scope="module")
def large_lake(tmp_path_factory) -> Path:
    return _lake(tmp_path_factory.mktemp("cap") / "lake", CAP + 1)


def test_cap_is_ten_thousand() -> None:
    assert CAP == 10_000


def test_posture_caps_inline_violations_by_count(large_lake: Path) -> None:
    capped = assessment.build_current_posture(large_lake, now=MOMENT)
    full = assessment.build_current_posture(large_lake, now=MOMENT, inline_violation_cap=None)

    assert len(capped["violations"]) == CAP
    assert "evt-000000" not in {row["event_id"] for row in capped["violations"]}
    assert capped["violation_summary"]["truncated"] is True
    assert capped["violation_summary"]["total_count"] == CAP + 1
    assert capped["violation_summary"]["returned_count"] == CAP
    assert capped["violation_summary"]["max_violations"] == CAP
    assert capped["posture"]["open_violation_count"] == CAP + 1

    assert len(full["violations"]) == CAP + 1
    assert full["violation_summary"]["truncated"] is False
    # Counts and framework scores come from every violation either way.
    assert capped["posture"] == full["posture"]
    assert capped["frameworks"] == full["frameworks"]
    assert capped["violation_summary"]["severity_counts"] == full["violation_summary"]["severity_counts"]


def test_small_lakes_are_not_truncated(tmp_path: Path) -> None:
    posture = assessment.build_current_posture(_lake(tmp_path / "lake", 5), now=MOMENT)
    assert len(posture["violations"]) == 5
    assert posture["violation_summary"]["truncated"] is False


def test_api_posture_is_capped_while_violation_listings_stay_complete(large_lake: Path) -> None:
    status, body = api_v1.handle_get("/api/v1/posture/current", {}, large_lake)
    assert status == HTTPStatus.OK
    assert len(body["data"]["violations"]) == CAP
    assert body["data"]["violation_summary"]["truncated"] is True
    assert body["data"]["violation_summary"]["total_count"] == CAP + 1

    status, legacy = api_legacy.handle_get("/api/violations", {}, large_lake)
    assert status == HTTPStatus.OK
    assert legacy["count"] == CAP + 1


def test_gold_posture_file_is_capped_by_violation_count(large_lake: Path, tmp_path: Path) -> None:
    from security_lakehouse.io import read_json

    output = assessment.write_current_posture(large_lake)
    written = read_json(output)
    assert len(written["violations"]) == CAP
    assert written["violation_summary"]["total_count"] == CAP + 1

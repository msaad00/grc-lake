"""Historical observations cannot permanently poison current evidence health."""

from datetime import UTC, datetime

from security_lakehouse.evidence_freshness import (
    build_evidence_freshness,
    stale_control_ids,
    summarize_control_freshness,
)
from test_evidence_freshness import _event

NOW = datetime(2026, 5, 24, 0, 45, tzinfo=UTC)
CONTROL = "NIST-AI-RMF-MEASURE-2.7"


def history():
    return [
        _event(event_id="old", evidence_collected_at="2026-05-24T00:00:00Z"),
        _event(event_id="new", evidence_collected_at="2026-05-24T00:45:00Z"),
    ]


def test_current_observation_supersedes_expired_history():
    records = build_evidence_freshness(history(), now=NOW)
    assert {record["status"] for record in records} == {"fresh", "expired"}
    assert stale_control_ids(records) == set()


def test_fresh_asset_cannot_hide_another_assets_expired_evidence():
    rows = history()
    rows[1]["asset_id"] = "agent:other"
    records = build_evidence_freshness(rows, now=NOW)
    assert stale_control_ids(records) == {CONTROL}
    summary = summarize_control_freshness(rows, required_evidence_types=["runtime.tool_call"], now=NOW)
    assert summary["status"] == "expired"


def test_latest_means_parsed_instant_not_string_order():
    rows = [
        _event(event_id="old", evidence_collected_at="2026-05-24T01:00:00+01:00"),
        _event(event_id="new", evidence_collected_at="2026-05-24T00:45:00Z"),
    ]
    summary = summarize_control_freshness(rows, required_evidence_types=["runtime.tool_call"], now=NOW)
    assert summary["status"] == "fresh"
    assert summary["latest_evidence_at"] == "2026-05-24T00:45:00Z"


def test_future_collection_never_establishes_freshness():
    rows = [_event(evidence_collected_at="2099-01-01T00:00:00Z")]
    records = build_evidence_freshness(rows, now=NOW)
    assert records[0]["status"] == "missing"
    assert "future" in records[0]["reason"]
    summary = summarize_control_freshness(rows, required_evidence_types=["runtime.tool_call"], now=NOW)
    assert summary["status"] == "missing"
    assert summary["score"] == 0


def test_distinct_sources_and_required_types_do_not_mask_each_other():
    rows = history()
    rows[1]["source"] = "another-source"
    records = build_evidence_freshness(rows, now=NOW)
    assert stale_control_ids(records) == {CONTROL}


def test_untyped_control_keeps_separate_asset_health():
    rows = history()
    rows[1]["asset_id"] = "agent:other"
    summary = summarize_control_freshness(rows, required_evidence_types=[], now=NOW)
    assert summary["status"] == "expired"


def test_required_types_ignore_unrelated_history_but_not_missing_requirements():
    rows = history()
    rows[0]["event_type"] = "unrelated.optional"
    records = build_evidence_freshness(rows, now=NOW)
    assert stale_control_ids(records, required_types={CONTROL: ["runtime.tool_call"]}) == set()
    assert stale_control_ids(records, required_types={CONTROL: ["runtime.tool_call", "required.missing"]}) == {CONTROL}


def test_control_evaluation_uses_current_observation_without_removing_history():
    from security_lakehouse.pipeline import _build_control_rows

    rows = history()
    for row in rows:
        row["status"] = "passed"
    current = stale_control_ids(build_evidence_freshness(rows, now=NOW))
    controls = _build_control_rows(
        rows,
        {
            CONTROL: {
                "control_id": CONTROL,
                "framework": "Test",
                "evaluation_rule": "fail_when_open_violation_or_stale_evidence",
            }
        },
        current,
    )
    assert controls[0]["status"] == "pass"
    assert controls[0]["event_count"] == 2

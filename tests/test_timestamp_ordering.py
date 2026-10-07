"""Read projections compare UTC instants, including fractions and offsets."""

import pytest

from security_lakehouse.io import write_jsonl

TIMES = [("2026-10-06T01:00:00Z", "2026-10-06T01:00:00.500000Z"), ("2026-10-06T05:00:00+04:00", "2026-10-06T02:00:00Z")]


@pytest.mark.parametrize("older,newer", TIMES)
def test_tracking_selects_latest_instant(tmp_path, older, newer):
    from security_lakehouse.tracking import latest_state

    write_jsonl(
        tmp_path / "gold/violation_tracking.jsonl",
        [
            {"violation_id": "v", "state": "open", "occurred_at": older},
            {"violation_id": "v", "state": "resolved", "occurred_at": newer},
        ],
    )
    assert latest_state(tmp_path, violation_id="v")["state"] == "resolved"


@pytest.mark.parametrize("older,newer", TIMES)
def test_workflow_feed_selects_latest_instant(tmp_path, older, newer):
    from security_lakehouse.workflows import list_runs

    write_jsonl(
        tmp_path / "gold/workflow_runs.jsonl",
        [{"run_id": "older", "started_at": older}, {"run_id": "newer", "started_at": newer}],
    )
    assert list_runs(tmp_path, limit=1)[0]["run_id"] == "newer"


@pytest.mark.parametrize("older,newer", TIMES)
def test_job_feed_selects_latest_instant(tmp_path, older, newer):
    from security_lakehouse.platform_jobs import build_platform_jobs

    rows = [
        {"id": "older", "kind": "operation", "started_at": older},
        {"id": "newer", "kind": "operation", "started_at": newer},
    ]
    assert build_platform_jobs(str(tmp_path), operations=rows, limit=1)["jobs"][0]["id"] == "newer"


@pytest.mark.parametrize("older,newer", TIMES)
def test_freshness_summary_selects_latest_instant(older, newer):
    from security_lakehouse.evidence_freshness import summarize_source_freshness

    rows = [{"source": "fixture", "status": "fresh", "evidence_collected_at": stamp} for stamp in (older, newer)]
    assert summarize_source_freshness(rows)[0]["latest_evidence_at"] == newer


@pytest.mark.parametrize("older,newer", TIMES)
def test_share_revocation_cannot_be_hidden_by_string_order(tmp_path, older, newer):
    from security_lakehouse.trust_share import list_shares

    rows = [
        {"share_id": "s", "created_at": older, "expires_at": "2090-01-01T00:00:00Z"},
        {"share_id": "s", "created_at": newer, "expires_at": "2090-01-01T00:00:00Z", "revoked_at": newer},
    ]
    write_jsonl(tmp_path / "gold/trust_shares.jsonl", rows)
    assert list_shares(tmp_path) == []


def test_sql_posture_summary_retains_latest_fractional_instant(tmp_path):
    import sqlite3

    from security_lakehouse.models import parse_event_time
    from security_lakehouse.pipeline import run_pipeline
    from test_assurance_truth import event

    raw, lake = tmp_path / "events.jsonl", tmp_path / "lake"
    rows = [
        {**event(), "event_id": "old", "event_time": "2026-01-01T00:00:00Z", "controls": ["SOC2-CC6.1"]},
        {**event(), "event_id": "new", "event_time": "2026-01-01T00:00:00.123456Z", "controls": ["SOC2-CC7.2"]},
    ]
    write_jsonl(raw, rows)
    run_pipeline(raw, lake)
    with sqlite3.connect(lake / "mart/security_lakehouse.sqlite") as connection:
        observed = connection.execute("SELECT evaluated_through FROM daily_posture_summary").fetchone()[0]
    assert parse_event_time(observed) == parse_event_time(rows[1]["event_time"])

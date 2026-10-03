"""Behavioral regressions for imported verdicts, freshness, and frozen exports."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from security_lakehouse import evidence_freshness, pipeline
from security_lakehouse.assessment import build_current_posture, write_assessment_snapshot
from security_lakehouse.generations import active_generation
from security_lakehouse.io import read_jsonl, write_jsonl
from security_lakehouse.oscal import build_assessment_results


def event(status="pass"):
    now = datetime.now(UTC).isoformat()
    return {
        "event_id": "assurance-1",
        "tenant_id": "audit",
        "event_time": now,
        "source": "assurance-fixture",
        "event_type": "iam.access_review",
        "entity": {"asset_id": "role-1", "asset_type": "iam_role"},
        "severity": "info",
        "status": status,
        "controls": ["SOC2-CC6.1"],
        "evidence": {"uri": "fixture://role-1", "collected_at": now},
    }


@pytest.mark.parametrize(
    "status,expected",
    [
        ("unknown", "not_evaluated"),
        ("error", "not_evaluated"),
        ("not_evaluated", "not_evaluated"),
        ("invented-status", "not_evaluated"),
        ("fail", "fail"),
        ("failed", "fail"),
        ("pass", "pass"),
    ],
)
def test_imported_status_never_silently_passes(tmp_path, status, expected):
    raw = tmp_path / "raw.jsonl"
    write_jsonl(raw, [event(status)])
    lake = tmp_path / "lake"
    pipeline.run_pipeline(raw, lake, tenant_id="audit")
    assert read_jsonl(lake / "gold/control_posture.jsonl")[0]["status"] == expected
    tests = read_jsonl(lake / "gold/control_tests.jsonl")
    if expected != "pass":
        assert all(row["result"] != "pass" for row in tests)
    if expected == "not_evaluated":
        posture = build_current_posture(lake)
        assert posture["posture"]["state"] != "ready"
        assert posture["frameworks"][0]["state"] != "ready"
        assert posture["posture"]["score"] == 0
    finding = build_assessment_results(lake)["assessment-results"]["results"][0]["findings"][0]
    assert finding["target"]["status"]["state"] == ("satisfied" if expected == "pass" else "not-satisfied")


def test_incremental_evaluation_refreshes_expired_unchanged_evidence(tmp_path, monkeypatch):
    raw = tmp_path / "raw.jsonl"
    write_jsonl(raw, [event()])
    lake = tmp_path / "lake"
    pipeline.run_pipeline(raw, lake, tenant_id="audit")
    previous = active_generation(lake)
    later = datetime.now(UTC) + timedelta(days=30)
    original = evidence_freshness.build_evidence_freshness

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return later

    monkeypatch.setattr(pipeline, "datetime", Clock)
    monkeypatch.setattr(pipeline, "build_evidence_freshness", lambda rows, **kwargs: original(rows, now=later))
    pipeline.run_pipeline_incremental(raw, lake, tenant_id="audit")
    assert active_generation(lake) != previous
    assert read_jsonl(lake / "gold/control_posture.jsonl")[0]["status"] == "stale"
    assert read_jsonl(previous / "gold/control_posture.jsonl")[0]["status"] == "pass"


def test_historical_oscal_findings_and_identity_stay_frozen(tmp_path):
    lake = tmp_path / "lake"
    raw = tmp_path / "raw.jsonl"
    row = event("open")
    write_jsonl(raw, [row])
    pipeline.run_pipeline(raw, lake, tenant_id="audit")
    snapshot = write_assessment_snapshot(lake)
    before = build_assessment_results(lake, snapshot_id=snapshot.stem)
    write_jsonl(raw, [{**row, "status": "pass"}])
    pipeline.run_pipeline(raw, lake, tenant_id="audit")
    assert build_assessment_results(lake, snapshot_id=snapshot.stem) == before


def test_historical_oscal_rejects_changed_snapshot(tmp_path):
    lake = tmp_path / "lake"
    raw = tmp_path / "raw.jsonl"
    write_jsonl(raw, [event()])
    pipeline.run_pipeline(raw, lake, tenant_id="audit")
    snapshot = write_assessment_snapshot(lake)
    payload = json.loads(snapshot.read_text())
    payload["evaluated_at"] = "2000-01-01T00:00:00Z"
    snapshot.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="snapshot"):
        build_assessment_results(lake, snapshot_id=snapshot.stem)


def test_historical_oscal_missing_generation_never_falls_back(tmp_path):
    lake = tmp_path / "lake"
    raw = tmp_path / "raw.jsonl"
    write_jsonl(raw, [event()])
    pipeline.run_pipeline(raw, lake, tenant_id="audit")
    generation = active_generation(lake)
    snapshot = write_assessment_snapshot(lake)
    (generation / "generation.json").unlink()
    with pytest.raises((ValueError, FileNotFoundError)):
        build_assessment_results(lake, snapshot_id=snapshot.stem)


def test_historical_oscal_api_identifies_the_historical_generation(tmp_path):
    from security_lakehouse.api_v1 import handle_get
    from security_lakehouse.generations import generation_identity

    raw, lake = tmp_path / "raw.jsonl", tmp_path / "lake"
    write_jsonl(raw, [event("open")])
    pipeline.run_pipeline(raw, lake, tenant_id="audit")
    identity = generation_identity(lake)
    snapshot = write_assessment_snapshot(lake)
    write_jsonl(raw, [event("pass")])
    pipeline.run_pipeline(raw, lake, tenant_id="audit")
    status, body = handle_get("/api/v1/oscal/assessment-results", {"snapshot_id": [snapshot.stem]}, lake)
    assert status == 200
    assert body["meta"]["generation"] == identity

"""Activity observations retain provenance without overriding evaluated outcomes."""

from datetime import UTC, datetime

import pytest

from security_lakehouse import pipeline
from security_lakehouse.assessment import build_current_posture
from security_lakehouse.event_status import PASS_STATUSES
from security_lakehouse.generations import active_generation
from security_lakehouse.golden_fixture import build_golden_events
from security_lakehouse.io import canonical_sha256, read_json, read_jsonl, write_jsonl
from test_assurance_truth import event


def silver(status, *, evidence_ref="fixture://verdict"):
    raw = event(status)
    row = pipeline._silver_row(raw, canonical_sha256(raw))
    return {**row, "evidence_ref": evidence_ref}


def evaluate(rows, *, rule="fail_when_open_violation", stale=False):
    mapping = {"SOC2-CC6.1": {"control_id": "SOC2-CC6.1", "evaluation_rule": rule}}
    return pipeline._build_control_rows(rows, mapping, {"SOC2-CC6.1"} if stale else set())[0]


@pytest.mark.parametrize("status", sorted(PASS_STATUSES))
@pytest.mark.parametrize("observed_first", [False, True])
def test_activity_does_not_override_a_passing_verdict(status, observed_first):
    rows = [silver(status), silver("observed")]
    if observed_first:
        rows.reverse()
    result = evaluate(rows)
    assert result["status"] == "pass"
    assert result["rule_reasons"] == []
    assert result["event_count"] == result["evidence_count"] == 2


@pytest.mark.parametrize("unknown", ["not_evaluated", "provider-unknown"])
def test_activity_does_not_hide_an_explicit_unknown(unknown):
    assert evaluate([silver("pass"), silver(unknown), silver("observed")])["status"] == "not_evaluated"


def test_activity_alone_cannot_pass():
    assert evaluate([silver("observed"), silver("observed")])["status"] == "not_evaluated"


def test_activity_preserves_failures_and_configured_thresholds():
    low_failure = {**silver("open"), "severity": "low", "severity_score": 25}
    rows = [low_failure, silver("observed")]
    assert evaluate(rows)["status"] == "fail"
    assert evaluate(rows, rule="fail_when_high_severity_open")["status"] == "pass"


def test_activity_does_not_clear_staleness():
    assert evaluate([silver("pass"), silver("observed")], stale=True)["status"] == "stale"


def test_activity_cannot_supply_missing_verdict_evidence():
    assert evaluate([silver("pass", evidence_ref=""), silver("observed")])["status"] == "stale"


def test_activity_does_not_dilute_rule_evidence_coverage():
    result = evaluate(
        [silver("pass"), silver("observed", evidence_ref="")],
        rule={"fail_if": {"min_evidence_coverage": {"below": 0.75}}},
    )
    assert result["status"] == "pass"
    assert result["rule_reasons"] == []
    # Aggregate provenance still describes every collected row.
    assert result["event_count"] == 2
    assert result["evidence_count"] == 1
    assert result["evidence_coverage"] == 0.5


def test_golden_scores_survive_added_activity(tmp_path):
    now = datetime.now(UTC).isoformat()
    rows = build_golden_events()
    for row in rows:
        row["event_time"] = now
        row["evidence"]["collected_at"] = now
    raw, lake = tmp_path / "raw.jsonl", tmp_path / "lake"
    write_jsonl(raw, rows)
    pipeline.run_pipeline(raw, lake)
    baseline = build_current_posture(lake)
    controls = read_jsonl(lake / "gold/control_posture.jsonl")
    passing = {row["control_id"] for row in controls if row["status"] == "pass"}
    assert passing
    for index, control_id in enumerate(sorted(passing)):
        activity = event("observed")
        activity.update(event_id=f"activity-{index}", controls=[control_id], tenant_id=rows[0]["tenant_id"])
        rows.append(activity)
    write_jsonl(raw, rows)
    pipeline.run_pipeline(raw, lake)
    updated = build_current_posture(lake)
    assert updated["frameworks"] == baseline["frameworks"]
    assert updated["posture"]["score"] == baseline["posture"]["score"]
    assert {
        row["control_id"] for row in read_jsonl(lake / "gold/control_posture.jsonl") if row["status"] == "pass"
    } == passing
    assert len(read_jsonl(lake / "silver/normalized_events.jsonl")) == len(rows)


def test_incremental_refreshes_v2_verdict_without_rewriting_history(tmp_path, monkeypatch):
    raw, lake = tmp_path / "raw.jsonl", tmp_path / "lake"
    write_jsonl(raw, [event("pass"), {**event("observed"), "event_id": "activity"}])
    current_builder = pipeline._build_control_rows

    def v2_builder(*args, **kwargs):
        rows = current_builder(*args, **kwargs)
        for row in rows:
            row["status"] = "not_evaluated"
        return rows

    with monkeypatch.context() as legacy:
        legacy.setattr(pipeline, "CONTROL_EVALUATION_VERSION", "trustops.control_evaluation.v2")
        legacy.setattr(pipeline, "_build_control_rows", v2_builder)
        pipeline.run_pipeline(raw, lake, tenant_id="audit")
    previous = active_generation(lake)
    previous_bytes = (previous / "gold/control_posture.jsonl").read_bytes()
    pipeline.run_pipeline_incremental(raw, lake, tenant_id="audit")
    current = active_generation(lake)
    assert current != previous
    assert read_jsonl(lake / "gold/control_posture.jsonl")[0]["status"] == "pass"
    assert read_json(lake / "manifest.json")["control_evaluation_version"] == "trustops.control_evaluation.v3"
    assert (previous / "gold/control_posture.jsonl").read_bytes() == previous_bytes
    assert read_jsonl(previous / "gold/control_posture.jsonl")[0]["status"] == "not_evaluated"
    pipeline.run_pipeline_incremental(raw, lake, tenant_id="audit")
    assert active_generation(lake) == current

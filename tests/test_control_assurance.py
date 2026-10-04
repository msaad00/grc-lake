"""Separate design documentation from reproducible period testing."""

import copy
import json
from pathlib import Path

import pytest

from security_lakehouse.pipeline import run_pipeline


def case(tmp_path):
    plan = {
        "schema_version": "trustops.control_test_plan.v1",
        "tenant_id": "audit-demo",
        "period_start": "2026-01-01T00:00:00Z",
        "period_end": "2026-01-03T00:00:00Z",
        "as_of": "2026-01-04T00:00:00Z",
        "controls": [
            {
                "safeguard_id": "SG-IDENTITY-001",
                "activity": "Restrict privileged access",
                "owner": "security",
                "system": "identity",
                "frequency": "daily",
                "procedure": "Inspect the policy and daily access configuration",
                "cadence_days": 1,
                "sample_per_window": 1,
                "sampling_rationale": "One illustrative observation per daily window; no statistical extrapolation",
                "design_event_ids": ["design"],
            }
        ],
    }
    base = json.loads(
        (Path(__file__).resolve().parents[1] / "data/raw/security_events.jsonl").read_text().splitlines()[0]
    )
    events = []
    for event_id, timestamp in [
        ("design", "2025-12-31T00:00:00Z"),
        ("op1", "2026-01-01T01:00:00Z"),
        ("op2", "2026-01-02T01:00:00Z"),
    ]:
        row = copy.deepcopy(base)
        row.update(
            event_id=event_id, status="pass", severity="info", event_time=timestamp, safeguard_ids=["SG-IDENTITY-001"]
        )
        row["evidence"]["collected_at"] = timestamp
        row["evidence"]["evidence_id"] = event_id
        events.append(row)
    return plan, events


def evaluate(tmp_path, plan, events):
    from security_lakehouse.control_assurance import assess_control_plan

    source = tmp_path / "raw.jsonl"
    source.write_text("".join(json.dumps(row) + "\n" for row in events))
    run_pipeline(source, tmp_path / "lake", tenant_id=plan["tenant_id"])
    return assess_control_plan(tmp_path / "lake", plan)


def test_documented_design_and_period_samples_are_separate_and_reproducible(tmp_path):
    plan, events = case(tmp_path)
    result = evaluate(tmp_path, plan, events)
    control = result["controls"][0]
    assert control["design"]["status"] == "documented"
    assert control["operating"]["status"] == "sample_pass"
    assert control["operating"]["tested_windows"] == 2
    assert result["review_status"] == "pending_human_review"
    assert result["population_completeness"] == "not_established"
    assert all(row["raw_sha256"] for row in control["operating"]["samples"])
    from security_lakehouse.control_assurance import assess_control_plan

    assert assess_control_plan(tmp_path / "lake", plan) == result


@pytest.mark.parametrize("failure", ["gap", "fail", "unknown", "future_collection", "missing_design", "wrong_binding"])
def test_missing_and_adverse_evidence_cannot_become_effective(tmp_path, failure):
    plan, events = case(tmp_path)
    if failure == "gap":
        events.pop()
    if failure == "fail":
        events[-1]["status"] = "fail"
    if failure == "unknown":
        events[-1]["status"] = "observed"
    if failure == "future_collection":
        events[-1]["evidence"]["collected_at"] = "2027-01-01T00:00:00Z"
    if failure == "missing_design":
        events.pop(0)
    if failure == "wrong_binding":
        events[-1]["safeguard_ids"] = []
    result = evaluate(tmp_path, plan, events)["controls"][0]
    if failure == "missing_design":
        assert result["design"]["status"] == "insufficient_evidence"
    else:
        assert result["operating"]["status"] != "sample_pass"
    assert result["conclusion"] == "pending_human_review"


def test_historical_failure_is_not_hidden_by_later_passing_sample(tmp_path):
    plan, events = case(tmp_path)
    old = copy.deepcopy(events[1])
    old.update(event_id="earlier-failure", status="fail")
    events.append(old)
    result = evaluate(tmp_path, plan, events)["controls"][0]
    assert result["operating"]["status"] == "sample_fail"
    assert "earlier-failure" in result["operating"]["deviation_event_ids"]


@pytest.mark.parametrize(
    "field,value", [("cadence_days", 0), ("sample_per_window", True), ("owner", ""), ("unexpected", "x")]
)
def test_invalid_test_plan_rejected(tmp_path, field, value):
    plan, events = case(tmp_path)
    plan["controls"][0][field] = value
    with pytest.raises(ValueError):
        evaluate(tmp_path, plan, events)


def test_five_control_demo_cli_and_evidence_integrity(tmp_path, capsys):
    from security_lakehouse.cli import main
    from security_lakehouse.control_assurance import assess_control_plan

    root = Path(__file__).resolve().parents[1]
    plan = json.loads((root / "examples/control-assurance/plan.json").read_text())
    lake = tmp_path / "lake"
    run_pipeline(root / "examples/control-assurance/events.jsonl", lake)
    exit_code = main(
        ["assessment", "test-plan", "--lake", str(lake), "--plan", str(root / "examples/control-assurance/plan.json")]
    )
    assert exit_code == 0
    result = json.loads(capsys.readouterr().out)
    assert [row["operating"]["status"] for row in result["controls"]] == [
        "sample_pass",
        "sample_fail",
        "sample_pass",
        "sample_pass",
        "insufficient_evidence",
    ]
    with pytest.raises(ValueError, match="owned"):
        assess_control_plan(lake, {**plan, "tenant_id": "foreign"})
    (lake / "silver/normalized_events.jsonl").write_text("{}\n")
    with pytest.raises(ValueError, match="integrity"):
        assess_control_plan(lake, plan)

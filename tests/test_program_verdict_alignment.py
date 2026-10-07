"""Program-required evidence cannot disagree with materialized readiness."""

import pytest

from security_lakehouse.programs import _test_result


@pytest.mark.parametrize("status", ["stale", "warn", "unknown", "observed", ""])
def test_program_test_never_upgrades_a_nonpassing_control(status):
    assert (
        _test_result({"status": status, "evidence_count": 1}, [{"status": "pass"}], [], {"status": "fresh"})
        == "needs_evidence"
    )


def test_program_test_preserves_failure_precedence_without_evidence():
    assert _test_result({"status": "fail", "evidence_count": 0}, [], [], {"status": "missing"}) == "fail"


def test_materialized_control_and_assessment_require_program_evidence(tmp_path):
    from security_lakehouse.assessment import build_current_posture
    from security_lakehouse.io import read_jsonl, write_jsonl
    from security_lakehouse.pipeline import run_pipeline
    from test_assurance_truth import event

    raw, lake = tmp_path / "raw.jsonl", tmp_path / "lake"
    write_jsonl(raw, [event()])
    run_pipeline(raw, lake)
    control = read_jsonl(lake / "gold/control_posture.jsonl")[0]
    program = read_jsonl(lake / "gold/control_tests.jsonl")[0]
    assert program["result"] == "needs_evidence"
    assert control["status"] == "stale"
    assert build_current_posture(lake)["frameworks"][0]["passing_control_count"] == 0


def test_timestamp_ordering_handles_fractional_seconds():
    from security_lakehouse.pipeline import _build_control_rows
    from test_observed_control_verdicts import silver

    controls = {"SOC2-CC6.1": {"control_id": "SOC2-CC6.1", "evaluation_rule": "fail_when_open_violation"}}
    rows = [
        {**silver("pass"), "event_time": "2026-10-06T00:00:00Z"},
        {**silver("pass"), "event_time": "2026-10-06T00:00:00.500000Z"},
    ]
    assert _build_control_rows(rows, controls)[0]["latest_event_time"] == rows[1]["event_time"]


def test_program_latest_evidence_compares_instants():
    from security_lakehouse.programs import _latest_evidence_at

    assert (
        _latest_evidence_at(
            [{"evidence_collected_at": "2026-10-06T12:00:00+04:00"}, {"evidence_collected_at": "2026-10-06T09:00:00Z"}]
        )
        == "2026-10-06T09:00:00Z"
    )


def test_reviewed_ccf_requirement_cannot_omit_required_evidence_types():
    from security_lakehouse.ccf_evaluation import evaluate_safeguards
    from test_verdict_consistency import NOW, row

    controls = {"REQ": {"control_id": "REQ", "required_evidence_types": ["missing.required.type"]}}
    payload = {
        "review_log_verified": True,
        "safeguards": [
            {
                "safeguard_id": "SG-0",
                "title": "Fixture",
                "asset_types": ["iam_role"],
                "evaluation_rule": "fail_when_open_violation",
                "satisfies": [{"control_id": "REQ", "effective_review_state": "maintainer_reviewed"}],
            }
        ],
    }
    result = evaluate_safeguards([row()], payload, controls, now=NOW)
    assert result["safeguards"][0]["status"] == "pass"
    assert result["requirements"][0]["status"] == "stale"

"""Fresh passing coverage cannot improve when a fixed-scope result worsens."""

import pytest

from security_lakehouse.assessment import _framework_scores, _weighted_posture_score
from security_lakehouse.pipeline import _build_control_rows
from test_observed_control_verdicts import silver


def control(name, status="pass", severity=25):
    return {"control_id": name, "framework": "F", "status": status, "risk_score": severity}


def score(rows, stale=()):
    return _framework_scores(rows, None, set(stale))[0]


@pytest.mark.parametrize("state", ["fail", "stale", "not_evaluated", "observed", "warn", "unrecognized"])
def test_nonpassing_controls_never_contribute_score(state):
    result = score([control("A"), control("B", state)])
    assert result["score"] == 50
    assert result["state"] == "attention_required"
    assert result["passing_control_count"] == 1


@pytest.mark.parametrize("severity", [0, 25, 50, 80, 100])
def test_replacing_unknown_or_stale_with_failure_cannot_improve_score(severity):
    failed = score([control("A"), control("B", "fail", severity)])["score"]
    assert failed <= score([control("A"), control("B", "not_evaluated")])["score"]
    assert failed <= score([control("A"), control("B", "stale")], {"B"})["score"]


def test_appending_a_failing_control_cannot_improve_framework_or_overall_score():
    before = [control("A", "fail", 100), control("B")]
    after = [*before, control("C", "fail", 25)]
    assert score(after)["score"] <= score(before)["score"]
    assert _weighted_posture_score(_framework_scores(after, None, set())) <= _weighted_posture_score(
        _framework_scores(before, None, set())
    )


def test_freshness_and_persisted_stale_status_both_block_credit():
    assert score([control("A")], {"A"})["score"] == 0
    assert score([control("A", "stale")])["score"] == 0


def test_high_severity_passing_evidence_cannot_inflate_control_risk():
    mapping = {"SOC2-CC6.1": {"control_id": "SOC2-CC6.1", "evaluation_rule": "fail_when_open_violation"}}
    fail = {**silver("open"), "severity": "low", "severity_score": 25}
    passing = {**silver("pass"), "severity": "critical", "severity_score": 100}
    before = _build_control_rows([fail], mapping)[0]
    after = _build_control_rows([fail, passing], mapping)[0]
    assert before["risk_score"] == after["risk_score"] == 25


def test_score_ignores_violation_detail_limits_and_retains_severity_counts():
    rows = [control("A"), {**control("B", "fail", 100), "open_event_count": 1}]
    capped = _framework_scores(rows, None, set())[0]
    full = _framework_scores(rows, [{"control_id": "B", "severity": "critical"}], set())[0]
    assert capped["score"] == full["score"] == 50
    assert capped["critical_violation_count"] == full["critical_violation_count"] == 1


def test_partial_pass_percentage_is_not_ready():
    from security_lakehouse.assessment import _posture_state

    assert _posture_state(90, False, set()) == "attention_required"


def test_new_snapshots_identify_the_scoring_contract(tmp_path):
    from security_lakehouse.assessment import build_current_posture, load_snapshot, write_assessment_snapshot

    current = build_current_posture(tmp_path)
    assert current["posture"]["scoring_version"] == "trustops.assessment_scoring.v2"
    assert current["posture"]["score_scope"] == "observed_controls"
    snapshot = write_assessment_snapshot(tmp_path)
    assert load_snapshot(tmp_path, snapshot.stem)["posture"]["scoring_version"] == current["posture"]["scoring_version"]


def test_audit_room_does_not_call_a_partially_passing_framework_ready():
    from security_lakehouse.audit_readiness import _framework_readiness

    (result,) = _framework_readiness(
        [
            {
                "framework": "SOC 2",
                "score": 90,
                "control_count": 61,
                "failing_control_count": 6,
                "state": "attention_required",
            }
        ]
    )
    assert result["ready"] is False


def test_materialized_pass_without_any_source_evidence_receives_no_credit(tmp_path):
    from security_lakehouse.assessment import build_current_posture
    from security_lakehouse.io import write_jsonl

    write_jsonl(tmp_path / "gold/control_posture.jsonl", [control("A")])
    assert build_current_posture(tmp_path)["posture"]["score"] == 0

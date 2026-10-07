"""AI framework summaries retain assessment freshness and weighting."""

from datetime import UTC, datetime, timedelta

import pytest

from security_lakehouse.ai_governance import _framework_rows, _framework_score

CONTROL = "NIST-AI-RMF-GOVERN-1.1"


@pytest.mark.parametrize("evidence", ["missing", "expired", "unavailable"])
def test_ai_materialized_pass_cannot_ignore_missing_or_stale_evidence(evidence):
    moment = datetime.now(UTC)
    events = (
        []
        if evidence == "missing"
        else [
            {
                "event_id": "one",
                "source": "fixture",
                "control_ids": [CONTROL],
                "event_time": (moment - timedelta(days=100) if evidence == "expired" else moment).isoformat(),
                "evidence_ref": "fixture://one",
                "evidence_available": evidence != "unavailable",
            }
        ]
    )
    result = _framework_rows(controls=[{"control_id": CONTROL, "status": "pass"}], events=events)
    row = next(row for row in result if row["framework_id"] == "nist-ai-rmf")
    assert row["passing_controls"] == 0
    assert row["score"] == 0


def test_ai_overall_score_uses_control_counts_instead_of_equal_pack_weights():
    assert (
        _framework_score(
            [
                {"score": 100, "passing_controls": 1, "controls_with_evidence": 1},
                {"score": 0, "passing_controls": 0, "controls_with_evidence": 9},
            ]
        )
        == 10
    )


def test_ai_framework_can_use_noninventory_evidence_for_its_controls(tmp_path):
    from security_lakehouse.ai_governance import build_ai_governance_status
    from security_lakehouse.io import write_jsonl

    write_jsonl(tmp_path / "gold/control_posture.jsonl", [{"control_id": CONTROL, "status": "pass"}])
    write_jsonl(
        tmp_path / "silver/normalized_events.jsonl",
        [
            {
                "event_id": "review",
                "source": "fixture",
                "event_type": "compliance.evidence_bundle",
                "control_ids": [CONTROL],
                "event_time": datetime.now(UTC).isoformat(),
                "evidence_ref": "fixture://review",
                "asset_id": "policy",
                "asset_type": "document",
            }
        ],
    )
    result = build_ai_governance_status(lake=tmp_path)
    row = next(row for row in result["frameworks"] if row["framework_id"] == "nist-ai-rmf")
    assert row["passing_controls"] == 1

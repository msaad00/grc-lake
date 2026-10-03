"""CCF evaluation needs explicit evidence bindings, asset scope and reviewed links."""

from security_lakehouse import api_v1
from security_lakehouse.io import read_json, write_jsonl
from security_lakehouse.pipeline import run_pipeline
from test_assurance_truth import event


def test_pipeline_publishes_ccf_assessment_from_explicit_safeguard_evidence(tmp_path):
    raw = tmp_path / "raw.jsonl"
    write_jsonl(raw, [{**event(), "safeguard_ids": ["SG-IDENTITY-001"]}])
    lake = tmp_path / "lake"
    run_pipeline(raw, lake, tenant_id="audit")
    result = read_json(lake / "gold/ccf_assessment.json")
    safeguard = next(row for row in result["safeguards"] if row["safeguard_id"] == "SG-IDENTITY-001")
    assert safeguard["status"] == "pass"
    assert safeguard["assessed_asset_count"] == 1
    assert safeguard["unassessed_asset_count"] == 0
    status, body = api_v1.handle_get("/api/v1/ccf/assessment", {}, lake)
    assert status == 200
    detail = result.pop("asset_results")
    assert body["data"] == {**result, "asset_result_count": len(detail)}


def test_framework_tags_do_not_implicitly_assert_a_safeguard(tmp_path):
    raw = tmp_path / "raw.jsonl"
    write_jsonl(raw, [event()])
    lake = tmp_path / "lake"
    run_pipeline(raw, lake, tenant_id="audit")
    result = read_json(lake / "gold/ccf_assessment.json")
    assert not any(row["status"] == "pass" for row in result["safeguards"])
    assert result["population_completeness"] == "not_established"


# These normalized fixtures isolate the aggregation contract from catalog size.
def assessment(events, *, states=("maintainer_reviewed",), verified=True):
    from datetime import UTC, datetime

    from security_lakehouse.ccf_evaluation import evaluate_safeguards

    payload = {
        "review_log_verified": verified,
        "safeguards": [
            {
                "safeguard_id": f"SG-{i}",
                "title": f"Safeguard {i}",
                "asset_types": ["iam_role"],
                "evaluation_rule": "fail_when_open_violation",
                "satisfies": [
                    {
                        "control_id": "REQ",
                        "effective_review_state": state,
                        "review_status": "reviewed" if state == "maintainer_reviewed" else "proposed",
                    }
                ],
            }
            for i, state in enumerate(states)
        ],
    }
    return evaluate_safeguards(events, payload, {"REQ": {"framework_id": "fixture"}}, now=datetime.now(UTC))


def normalized(asset="a", status="pass", bindings=None, **overrides):
    from datetime import UTC, datetime

    return {
        "event_id": asset,
        "asset_id": asset,
        "asset_type": "iam_role",
        "source": "fixture",
        "event_time": datetime.now(UTC).isoformat(),
        "evidence_collected_at": datetime.now(UTC).isoformat(),
        "evidence_ref": f"fixture://{asset}",
        "raw_sha256": "a" * 64,
        "severity": "info",
        "severity_score": 0,
        "status": status,
        "control_ids": ["REQ"],
        "safeguard_ids": bindings if bindings is not None else ["SG-0"],
        **overrides,
    }


def test_unobserved_binding_for_an_observed_applicable_asset_blocks_pass():
    data = assessment([normalized(), normalized("b", bindings=[])])
    assert data["safeguards"][0]["unassessed_asset_count"] == 1
    assert data["requirements"][0]["status"] == "not_evaluated"


def test_all_reviewed_safeguards_must_pass():
    data = assessment([normalized()], states=("maintainer_reviewed", "maintainer_reviewed"))
    assert data["requirements"][0]["status"] == "not_evaluated"
    data = assessment([normalized(bindings=["SG-0", "SG-1"])], states=("maintainer_reviewed", "maintainer_reviewed"))
    assert data["requirements"][0]["status"] == "pass"


def test_pending_mapping_and_unverified_review_log_block_pass():
    assert assessment([normalized()], states=("proposed",))["requirements"][0]["status"] == "not_evaluated"
    assert assessment([normalized()], verified=False)["requirements"][0]["status"] == "not_evaluated"
    assert assessment([normalized()], states=("rejected",))["requirements"][0]["status"] == "unmapped"


def test_failure_dominates_unknown_and_missing_assets():
    data = assessment([normalized(status="failed"), normalized("b", status="unknown"), normalized("c", bindings=[])])
    assert data["requirements"][0]["status"] == "fail"


def test_wrong_or_conflicting_asset_type_cannot_pass():
    assert assessment([normalized(asset_type="repository")])["safeguards"][0]["status"] == "not_evaluated"
    rows = [normalized(), normalized(asset_type="repository", event_id="other")]
    data = assessment(rows)
    assert data["ambiguous_asset_count"] == 1
    assert data["requirements"][0]["status"] == "not_evaluated"


def test_observation_is_not_an_explicit_safeguard_outcome():
    assert assessment([normalized(status="observed")])["requirements"][0]["status"] == "not_evaluated"


def test_ccf_stale_evidence_cannot_pass():
    row = normalized(event_time="2000-01-01T00:00:00Z", evidence_collected_at="2000-01-01T00:00:00Z")
    assert assessment([row])["requirements"][0]["status"] == "stale"


def test_unknown_safeguard_rejects_generation_without_replacing_current(tmp_path):
    import pytest

    from security_lakehouse.generations import active_generation

    raw = tmp_path / "raw.jsonl"
    lake = tmp_path / "lake"
    write_jsonl(raw, [event()])
    run_pipeline(raw, lake, tenant_id="audit")
    before = active_generation(lake)
    write_jsonl(raw, [{**event(), "safeguard_ids": ["SG-does-not-exist"]}])
    with pytest.raises(ValueError, match="unknown safeguard"):
        run_pipeline(raw, lake, tenant_id="audit")
    assert active_generation(lake) == before


def test_mapping_review_invalidates_unchanged_incremental_assessment(tmp_path):
    from security_lakehouse.generations import active_generation
    from security_lakehouse.mapping_review import record_decisions
    from security_lakehouse.pipeline import run_pipeline_incremental

    raw, lake = tmp_path / "raw.jsonl", tmp_path / "lake"
    write_jsonl(raw, [{**event(), "safeguard_ids": ["SG-IDENTITY-001"]}])
    run_pipeline(raw, lake, tenant_id="audit")
    original = active_generation(lake)
    run_pipeline_incremental(raw, lake, tenant_id="audit")
    assert active_generation(lake) == original
    record_decisions(
        lake,
        items=[{"safeguard_id": "SG-IDENTITY-001", "control_id": "SOC2-CC6.1", "framework_id": "soc2"}],
        decision="needs_changes",
        rationale="Need evidence of obligation equivalence.",
        reviewer="fixture-reviewer",
    )
    run_pipeline_incremental(raw, lake, tenant_id="audit")
    assert active_generation(lake) != original
    data = read_json(lake / "gold/ccf_assessment.json")
    requirement = next(row for row in data["requirements"] if row["control_id"] == "SOC2-CC6.1")
    assert requirement["status"] == "not_evaluated"
    assert requirement["pending_mapping_count"] >= 1


def test_same_asset_id_from_two_source_tenants_does_not_share_evidence():
    data = assessment([normalized(tenant_id="source-a"), normalized(tenant_id="source-b", event_id="b", bindings=[])])
    assert data["asset_count"] == 2
    assert data["safeguards"][0]["unassessed_asset_count"] == 1
    assert data["requirements"][0]["status"] == "not_evaluated"


def test_asset_details_are_paginated_outside_the_summary(tmp_path):
    raw, lake = tmp_path / "raw.jsonl", tmp_path / "lake"
    rows = [
        {
            **event(),
            "event_id": f"event-{i}",
            "entity": {"asset_id": f"asset-{i}", "asset_type": "iam_role"},
            "safeguard_ids": ["SG-IDENTITY-001"],
        }
        for i in range(3)
    ]
    write_jsonl(raw, rows)
    run_pipeline(raw, lake, tenant_id="audit")
    status, summary = api_v1.handle_get("/api/v1/ccf/assessment", {}, lake)
    assert status == 200
    assert "asset_results" not in summary["data"]
    assert summary["data"]["asset_result_count"] == 3
    status, detail = api_v1.handle_get(
        "/api/v1/ccf/asset-results", {"limit": ["1"], "offset": ["1"], "sort": ["asset_id"]}, lake
    )
    assert status == 200
    assert detail["meta"]["count"] == 3
    assert len(detail["data"]) == 1
    assert detail["data"][0]["asset_id"] == "asset-1"
    assert detail["data"][0]["event_ids"] == ["event-1"]
    assert detail["meta"]["generation"] == summary["meta"]["generation"]

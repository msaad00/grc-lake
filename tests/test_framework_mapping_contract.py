"""Framework mapping counts must share one tenant-aware curation contract."""

from __future__ import annotations

import copy

import pytest

from security_lakehouse import ai_governance, framework_coverage, mapping_review, safeguards

CONTROL = "NIST-AI-RMF-GOVERN-1.1"
FRAMEWORK = "nist-ai-rmf"
PAYLOAD = {
    "schema": "trustops.safeguards.v1",
    "safeguards": [
        {
            "safeguard_id": "SG-TEST-AI",
            "title": "AI governance fixture",
            "risk_domain": "governance",
            "satisfies": [
                {"control_id": CONTROL, "framework_id": FRAMEWORK, "role": "primary", "review_status": "proposed"}
            ],
        }
    ],
}


def _install_payload(monkeypatch, payload):
    monkeypatch.setenv("GRC_LAKE_COOKIE_SIGNING_KEY", "framework-contract-test-key")
    for module in (safeguards, framework_coverage, mapping_review):
        monkeypatch.setattr(module, "load_safeguards", lambda: copy.deepcopy(payload))


def _row(lake):
    return next(
        row
        for row in ai_governance.build_ai_governance_status(lake=lake)["frameworks"]
        if row["framework_id"] == FRAMEWORK
    )


def _decide(lake, decision):
    mapping_review.record_decisions(
        lake,
        items=[{"safeguard_id": "SG-TEST-AI", "control_id": CONTROL, "framework_id": FRAMEWORK}],
        decision=decision,
        reviewer="reviewer@example.test",
        rationale="Bounded fixture review of this mapping.",
        payload=PAYLOAD,
    )


@pytest.mark.parametrize("decision,mapped,reviewed", [("approve", 1, 1), ("reject", 0, 0), ("needs_changes", 1, 0)])
def test_ai_framework_and_ccf_counts_share_tenant_decisions(tmp_path, monkeypatch, decision, mapped, reviewed):
    _install_payload(monkeypatch, PAYLOAD)
    tenant_a, tenant_b = tmp_path / "tenant-a", tmp_path / "tenant-b"
    _decide(tenant_a, decision)
    effective = mapping_review.effective_safeguards(tenant_a)
    ccf = safeguards.coverage_by_framework(effective)["frameworks"][FRAMEWORK]
    ledger = next(
        row
        for row in framework_coverage.build_framework_coverage(lake_dir=tenant_a)
        if row["framework_id"] == FRAMEWORK
    )
    ai = _row(tenant_a)
    assert ai["mapped_requirements"] == ledger["evaluatable_requirement_count"] == ccf["covered"] == mapped
    assert ai["reviewed_requirements"] == ledger["attestable_requirement_count"] == reviewed
    assert ai["requirements"] == ledger["seeded_control_count"] == ccf["controls"]
    assert ai["review_log_verified"] is True
    assert ai["score"] is None
    # The second tenant retains its shipped proposed relationship.
    other = _row(tenant_b)
    assert other["mapped_requirements"] == 1
    assert other["reviewed_requirements"] == 0
    assert _row(tenant_a) == ai


def test_contextual_review_counts_are_separate_from_implementation_reviews(monkeypatch):
    payload = copy.deepcopy(PAYLOAD)
    member = payload["safeguards"][0]["satisfies"][0]
    member.update(role="supporting", effective_review_state="org_reviewed")
    _install_payload(monkeypatch, payload)
    ledger = next(row for row in framework_coverage.build_framework_coverage() if row["framework_id"] == FRAMEWORK)
    ccf = safeguards.coverage_by_framework(payload)["frameworks"][FRAMEWORK]
    assert ledger["org_reviewed_mapping_count"] == 0
    assert ccf["org_reviewed_mappings"] == 0
    assert ledger["contextual_mapping_count"] == ccf["contextual_mappings"] == 1
    assert ledger["attestable_requirement_count"] == 0


def test_invalid_review_history_reports_fallback_without_retaining_org_coverage(tmp_path, monkeypatch):
    _install_payload(monkeypatch, PAYLOAD)
    _decide(tmp_path, "approve")
    assert _row(tmp_path)["reviewed_requirements"] == 1
    mapping_review.review_log_path(tmp_path).write_text('{"tampered":true}\n')
    result = _row(tmp_path)
    assert result["review_log_verified"] is False
    assert result["mapped_requirements"] == 1
    assert result["reviewed_requirements"] == 0
    assert result["org_reviewed_requirements"] == 0


def test_shared_ledger_preserves_catalog_versions_and_disjoint_review_buckets():
    catalog = {
        "A": {"framework_id": "example"},
        "B": {"framework_id": "example"},
        "C": {"framework_id": "example"},
    }
    members = [
        {"control_id": "A", "review_status": "reviewed", "control_version": "1", "current_control_version": "2"},
        {"control_id": "B", "review_status": "reviewed", "control_version": "1", "current_control_version": "1"},
        {"control_id": "B", "review_status": "proposed"},
        {"control_id": "B", "effective_review_state": "org_reviewed"},
        {"control_id": "C", "role": "inherited", "effective_review_state": "org_reviewed"},
    ]
    payload = {
        "safeguards": [{"safeguard_id": f"SG-{index}", "satisfies": [member]} for index, member in enumerate(members)]
    }
    row = safeguards.framework_mapping_coverage(payload, catalog=catalog)["frameworks"]["example"]
    assert row["controls"] == 3
    assert row["covered"] == 2
    assert row["reviewed"] == row["maintainer_reviewed"] == 1
    assert row["org_reviewed"] == 0  # A requirement is never counted twice.
    assert row["proposed"] == row["uncovered"] == 1
    assert row["proposed_mappings"] == 2
    assert row["org_reviewed_mappings"] == row["maintainer_reviewed_mappings"] == 1
    assert row["contextual_mappings"] == 1
    assert row["coverage_pct"] == 66.7
    assert row["reviewed_pct"] == 33.3


def test_empty_catalog_denominator_never_becomes_coverage():
    result = safeguards.framework_mapping_coverage(PAYLOAD, catalog={})
    assert result["controls"] == result["covered"] == result["reviewed"] == 0
    assert result["coverage_pct"] == result["reviewed_pct"] == 0
    assert result["frameworks"] == {}


def test_api_framework_and_ccf_adapters_report_same_tenant_coverage(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from security_lakehouse.server_app import create_app

    _install_payload(monkeypatch, PAYLOAD)
    _decide(tmp_path, "approve")
    (tmp_path / "silver").mkdir()
    client = TestClient(create_app(tmp_path, require_auth=False))
    response = client.get("/api/v1/frameworks/coverage")
    assert response.status_code == 200
    framework_body = response.json()
    ledger = next(row for row in framework_body["data"]["frameworks"] if row["framework_id"] == FRAMEWORK)
    response = client.get("/api/v1/ccf/coverage")
    assert response.status_code == 200
    ccf_body = response.json()
    ccf = ccf_body["data"]["frameworks"]["frameworks"][FRAMEWORK]
    assert ledger["attestable_requirement_count"] == ccf["reviewed"] == 1
    assert ledger["org_reviewed_mapping_count"] == ccf["org_reviewed_mappings"] == 1
    assert ledger["seeded_control_count"] == ccf["controls"]
    assert ledger["attestable_coverage_pct"] == ccf["reviewed_pct"]
    from security_lakehouse import mcp_server
    from test_mcp_server import call_tool

    monkeypatch.delenv("GRC_LAKE_API_URL", raising=False)
    monkeypatch.delenv("GRC_LAKE_API_KEY", raising=False)
    payload = call_tool(mcp_server.build_server(tmp_path), "get_framework_coverage")
    mcp_row = next(row for row in payload["frameworks"] if row["framework_id"] == FRAMEWORK)
    assert mcp_row == ledger


def _seed_complete_inventory_and_one_control(tmp_path):
    from datetime import UTC, datetime

    from security_lakehouse.io import write_jsonl

    now = datetime.now(UTC).isoformat()
    events = [
        {
            "event_id": "model",
            "event_type": "ai.model_inventory",
            "event_time": now,
            "asset_id": "model:a",
            "asset_type": "ai_model",
            "status": "pass",
            "evidence_ref": "fixture://model",
            "attributes": {"model_card": True, "lineage_complete": True},
        },
        {
            "event_id": "lineage",
            "event_type": "model.lineage",
            "event_time": now,
            "asset_id": "model:a",
            "asset_type": "ai_model",
            "status": "pass",
            "evidence_ref": "fixture://lineage",
        },
        {
            "event_id": "agent",
            "event_type": "runtime.tool_call",
            "event_time": now,
            "asset_id": "agent:a",
            "asset_type": "ai_agent",
            "status": "pass",
            "evidence_ref": "fixture://agent",
        },
        {
            "event_id": "control",
            "event_time": now,
            "control_ids": [CONTROL],
            "status": "pass",
            "evidence_ref": "fixture://control",
        },
    ]
    write_jsonl(tmp_path / "silver/normalized_events.jsonl", events)
    write_jsonl(tmp_path / "gold/control_posture.jsonl", [{"control_id": CONTROL, "status": "pass"}])


def test_complete_inventory_and_one_passing_control_does_not_claim_governed(tmp_path):
    _seed_complete_inventory_and_one_control(tmp_path)
    result = ai_governance.build_ai_governance_status(lake=tmp_path)
    assert result["governance_score"] == 100
    assert result["frameworks_ready"] == 0
    assert result["state"] == "on_track"
    assert result["coverage_sufficient"] is False


def test_non_catalog_ids_cannot_supply_passing_or_evaluated_ai_coverage():
    from datetime import UTC, datetime

    rows = ai_governance._framework_rows(
        controls=[{"control_id": "NIST-AI-RMF-DOES-NOT-EXIST", "status": "pass"}],
        events=[
            {
                "control_ids": ["NIST-AI-RMF-DOES-NOT-EXIST"],
                "status": "pass",
                "event_time": datetime.now(UTC).isoformat(),
                "evidence_ref": "fixture://unknown",
            }
        ],
    )
    row = next(row for row in rows if row["framework_id"] == FRAMEWORK)
    assert row["passing_controls"] == 0
    assert row["evaluated_control_count"] == 0
    assert row["unknown_control_count"] == 1
    assert row["coverage_sufficient"] is False


@pytest.mark.parametrize("status", ["unknown", "warn", "observed", "not_evaluated"])
def test_unknown_verdicts_remain_observed_but_do_not_fill_coverage(status):
    from datetime import UTC, datetime

    rows = ai_governance._framework_rows(
        controls=[{"control_id": CONTROL, "status": status}],
        events=[
            {
                "control_ids": [CONTROL],
                "status": status,
                "event_time": datetime.now(UTC).isoformat(),
                "evidence_ref": "fixture://unknown",
            }
        ],
    )
    row = next(row for row in rows if row["framework_id"] == FRAMEWORK)
    assert row["controls_with_evidence"] == 1
    assert row["evaluated_control_count"] == 0
    assert row["passing_controls"] == 0
    assert row["coverage_sufficient"] is False


def test_coverage_gate_uses_current_known_evidence_and_catalog_denominator(monkeypatch):
    from datetime import UTC, datetime

    catalog = {
        CONTROL: {"framework_id": FRAMEWORK},
        "NIST-AI-RMF-GOVERN-1.2": {"framework_id": FRAMEWORK},
    }
    monkeypatch.setattr(ai_governance, "load_control_catalog", lambda: catalog)
    monkeypatch.setattr(ai_governance, "with_program_requirements", lambda value: value)
    rows = ai_governance._framework_rows(
        controls=[{"control_id": CONTROL, "status": "pass"}],
        events=[
            {
                "control_ids": [CONTROL],
                "status": "pass",
                "event_time": datetime.now(UTC).isoformat(),
                "evidence_ref": "fixture://known",
            }
        ],
        mapping_coverage={"frameworks": {FRAMEWORK: {"controls": 2}}, "review_log_verified": True},
    )
    row = next(row for row in rows if row["framework_id"] == FRAMEWORK)
    assert row["evaluated_control_count"] == 1
    assert row["catalog_control_count"] == 2
    assert row["coverage_pct"] == 50.0
    assert row["coverage_sufficient"] is True


@pytest.mark.parametrize(
    "populations,sufficient",
    [
        ([(50, 100), (0, 100)], True),
        ([(50, 100), (49, 100)], False),
        ([(50, 100), (50, 100)], True),
        ([(0, 100)], False),
        ([(1, None)], False),
    ],
)
def test_governed_gate_requires_every_observed_framework_coverage(tmp_path, monkeypatch, populations, sufficient):
    from security_lakehouse.readiness_coverage import readiness_coverage

    _seed_complete_inventory_and_one_control(tmp_path)
    rows = []
    for evaluated, total in populations:
        _percentage, enough = readiness_coverage(evaluated, total)
        rows.append(
            {
                "score": 100 if evaluated else None,
                "controls_with_evidence": evaluated,
                "passing_controls": evaluated,
                "coverage_sufficient": enough,
            }
        )
    monkeypatch.setattr(ai_governance, "_framework_rows", lambda **_kwargs: rows)
    result = ai_governance.build_ai_governance_status(lake=tmp_path)
    assert result["coverage_sufficient"] is sufficient
    assert result["coverage_scope"] == "observed_ai_frameworks"
    assert (result["state"] == "governed") is sufficient
    if not sufficient:
        assert result["state_reason"].startswith("Insufficient framework coverage")

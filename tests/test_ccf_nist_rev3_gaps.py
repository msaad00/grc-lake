"""Explicit Rev. 3 safeguards close coverage gaps without inventing attestation."""

from security_lakehouse.safeguards import coverage_by_framework, load_safeguards, validate_safeguards

NEW = {"SG-INFORMATIONEXCHANGE-001": "03.12.05", "SG-PERSONNELSCREENING-001": "03.09.01"}


def test_new_safeguards_are_source_pinned_proposed_and_scoped():
    payload = load_safeguards()
    by_id = {row["safeguard_id"]: row for row in payload["safeguards"]}
    assert validate_safeguards(payload) == []
    for sid, requirement in NEW.items():
        safeguard = by_id[sid]
        primary = [row for row in safeguard["satisfies"] if row["role"] == "primary"]
        assert len(primary) == 1
        assert primary[0]["control_id"] == "NIST-800-171R3-" + requirement
        for mapping in safeguard["satisfies"]:
            assert mapping["review_status"] == "proposed"
            assert "review_basis" not in mapping
            source = mapping["mapping_source"]
            assert source["sha256"] == "3e4631df8b5d61f40a6e542b52779ef30ddbbfff31e09214fa94ad6e6f5e6d08"
            assert requirement in source["locator"]
            if mapping["framework_id"] != "nist-800-171-rev3":
                assert mapping["role"] == "supporting"
        assert safeguard["reviewed_by"] is None and safeguard["reviewed_at"] is None
    assert "rescreen" in by_id["SG-PERSONNELSCREENING-001"]["evidence_requirement"].lower()
    assert "frequency" in by_id["SG-INFORMATIONEXCHANGE-001"]["evidence_requirement"].lower()


def test_two_new_requirements_remain_unattestable_until_review():
    payload = load_safeguards()
    without = {**payload, "safeguards": [row for row in payload["safeguards"] if row["safeguard_id"] not in NEW]}
    before = coverage_by_framework(without)
    after = coverage_by_framework(payload)
    assert after["safeguards"] == before["safeguards"] + 2
    assert after["covered"] == before["covered"] + 2
    assert after["reviewed"] == before["reviewed"]
    assert after["frameworks"]["nist-800-171-rev3"]["covered"] == 85


def test_gap_refresh_tracks_implementation_mappings_and_restores_removed_gaps():
    from tools.sync_nist_800_171r3 import refresh_coverage_gaps

    manifest = {
        "rows": [{"id": "03.12.05"}, {"id": "03.09.01"}],
        "unmapped": [{"id": "03.12.05", "reason": "needs agreement evidence"}],
    }
    payload = {
        "safeguards": [
            {
                "satisfies": [
                    {"control_id": "NIST-800-171R3-03.12.05", "framework_id": "nist-800-171-rev3", "role": "primary"},
                    {
                        "control_id": "NIST-800-171R3-03.09.01",
                        "framework_id": "nist-800-171-rev3",
                        "role": "supporting",
                    },
                ]
            }
        ]
    }
    refreshed = refresh_coverage_gaps(manifest, payload)
    assert [row["id"] for row in refreshed] == ["03.09.01"]
    assert all(row["reason"] for row in refreshed)
    assert refresh_coverage_gaps(manifest, {"safeguards": []})[1]["reason"] == "needs agreement evidence"


def test_explicit_assessment_outcomes_do_not_promote_proposed_mappings():
    from datetime import UTC, datetime

    from security_lakehouse.catalog import load_control_catalog
    from security_lakehouse.ccf_evaluation import evaluate_safeguards
    from test_ccf_operational_assessment import normalized

    payload = load_safeguards()
    payload["safeguards"] = [row for row in payload["safeguards"] if row["safeguard_id"] in NEW]
    for status, expected in [
        ("pass", "pass"),
        ("failed", "fail"),
        ("unknown", "not_evaluated"),
        ("observed", "not_evaluated"),
    ]:
        events = [normalized(sid, status=status, bindings=[sid], asset_type="service") for sid in NEW]
        # Both safeguards apply to the observed services, so bind both to each
        # service to establish the complete observed (not declared) population.
        for event in events:
            event["safeguard_ids"] = list(NEW)
        result = evaluate_safeguards(events, payload, load_control_catalog(), now=datetime.now(UTC))
        assert {row["status"] for row in result["safeguards"]} == {expected}
        assert not any(row["status"] == "pass" for row in result["requirements"])
    event = normalized(
        "stale",
        bindings=list(NEW),
        asset_type="service",
        event_time="2000-01-01T00:00:00Z",
        evidence_collected_at="2000-01-01T00:00:00Z",
    )
    result = evaluate_safeguards([event], payload, load_control_catalog(), now=datetime.now(UTC))
    assert not any(row["status"] == "pass" for row in result["safeguards"])

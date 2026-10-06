"""Common Control Framework: safeguards as the operated object."""

from __future__ import annotations

import json
from pathlib import Path

from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.safeguards import (
    SCHEMA,
    coverage_by_family,
    coverage_by_framework,
    load_safeguards,
    mapping_review_queue,
    mapping_review_report,
    requirement_status,
    safeguards_by_requirement,
    validate_safeguards,
)


def test_shipped_safeguards_are_internally_consistent() -> None:
    problems = validate_safeguards(load_safeguards())
    assert problems == [], f"shipped CCF is inconsistent: {problems}"


def test_every_mapped_requirement_exists_in_the_catalog() -> None:
    """A safeguard pointing at a control_id that does not exist claims coverage it has not got."""
    known = set(load_control_catalog())
    unknown = sorted(set(safeguards_by_requirement()) - known)
    assert unknown == []


def test_each_safeguard_names_exactly_one_primary() -> None:
    for entry in load_safeguards()["safeguards"]:
        primaries = [m for m in entry["satisfies"] if m.get("role") == "primary"]
        assert len(primaries) == 1, f"{entry['safeguard_id']} has {len(primaries)} primaries"


def test_a_requirement_needing_two_safeguards_fails_when_either_fails() -> None:
    """SOC2 CC7.2 wants detection *and* audit logging.

    Treating "any mapped safeguard passes" as sufficient would let a green logging
    safeguard report the monitoring requirement as met, which is the failure mode
    a CCF exists to prevent.
    """
    mapping = safeguards_by_requirement(reviewed_only=True)
    shared = [cid for cid, sids in mapping.items() if len(sids) > 1]
    assert shared, "expected at least one requirement satisfied by multiple safeguards"

    control_id = shared[0]
    sids = mapping[control_id]
    assert requirement_status(control_id, dict.fromkeys(sids, "pass")) == "pass"

    one_failing = dict.fromkeys(sids, "pass")
    one_failing[sids[0]] = "fail"
    assert requirement_status(control_id, one_failing) == "fail"


def test_an_unmapped_requirement_is_not_reported_as_failing() -> None:
    """ "Not modelled yet" and "tested and failed" are different answers to an auditor."""
    unmapped = sorted(set(load_control_catalog()) - set(safeguards_by_requirement()))
    assert unmapped, "expected uncovered controls while the CCF is partial"
    assert requirement_status(unmapped[0], {}) == "unmapped"


def test_coverage_matches_a_direct_count() -> None:
    controls = load_control_catalog()
    mapped = set(safeguards_by_requirement())
    cov = coverage_by_framework()
    assert cov["controls"] == len(controls)
    assert cov["covered"] == len(mapped & set(controls))
    assert cov["covered"] + cov["uncovered"] == cov["controls"]


def test_ccf_family_ledger_separates_reviewed_and_proposed_mappings() -> None:
    families = coverage_by_family()

    assert families
    assert [row["family_id"] for row in families] == sorted(row["family_id"] for row in families)
    assert all(row["safeguard_count"] > 0 for row in families)
    assert all(row["frameworks"] == sorted(row["frameworks"]) for row in families)
    assert all(
        row["reviewed_mapping_count"] + row["proposed_mapping_count"] == row["mapping_count"] for row in families
    )
    assert {"identity", "data-protection", "ai-governance"} <= {row["family_id"] for row in families}


def _expected_ledger_state(row: dict) -> str:
    if row["reviewed_mapping_count"] == 0:
        return "proposed_only"
    if row["proposed_mapping_count"] == 0:
        return "reviewed"
    return "partially_reviewed"


def test_ccf_family_state_never_calls_a_mostly_proposed_family_reviewed() -> None:
    families = coverage_by_family()

    for row in families:
        assert row["state"] == _expected_ledger_state(row), row["family_id"]
    ai = next(row for row in families if row["family_id"] == "ai-governance")
    assert ai["reviewed_mapping_count"] > 0 and ai["proposed_mapping_count"] > 0
    assert ai["state"] == "partially_reviewed"


def test_validation_rejects_a_safeguard_claiming_an_unknown_control(tmp_path: Path) -> None:
    payload = json.loads(json.dumps(load_safeguards()))
    payload["safeguards"][0]["satisfies"].append(
        {"control_id": "NOT-A-REAL-CONTROL", "framework_id": "soc2", "role": "equivalent"}
    )
    problems = validate_safeguards(payload)
    assert any("NOT-A-REAL-CONTROL" in p for p in problems)


def test_validation_rejects_a_wrong_schema_marker() -> None:
    payload = json.loads(json.dumps(load_safeguards()))
    payload["schema"] = "something.else.v9"
    assert any(SCHEMA in p for p in validate_safeguards(payload))


def test_validation_rejects_unverifiable_mapping_provenance() -> None:
    payload = json.loads(json.dumps(load_safeguards()))
    payload["safeguards"][0]["satisfies"][0]["mapping_source"] = {
        "name": "A crosswalk",
        "url": "http://example.test/crosswalk.pdf",
        "sha256": "not-a-digest",
        "locator": "",
    }

    problems = validate_safeguards(payload)

    assert any("mapping_source.url must use https" in problem for problem in problems)
    assert any("mapping_source.sha256 must be 64 lowercase hexadecimal characters" in problem for problem in problems)
    assert any("mapping_source.locator must be a non-empty string" in problem for problem in problems)


def test_the_ccf_doc_quotes_the_numbers_the_data_actually_reports() -> None:
    """The README once claimed 741 controls while the catalog held 942.

    Coverage figures in prose drift the moment curation moves, and a compliance
    product overstating its own coverage is exactly the wrong failure. Pin them.
    """
    doc = (Path(__file__).resolve().parents[1] / "docs" / "COMMON_CONTROL_FRAMEWORK.md").read_text(encoding="utf-8")
    cov = coverage_by_framework()

    headline = f"{cov['safeguards']} safeguards map {cov['covered']} of {cov['controls']} requirements"
    assert headline in doc, f"doc headline is stale; expected {headline!r}"

    for name, row in cov["frameworks"].items():
        expected = f"| {name:19s} | {row['controls']:12d} | {row['covered']:6d} | {row['coverage_pct']:5.1f}% |"
        assert expected in doc, f"doc table row for {name} is stale; expected {expected!r}"


def test_proposed_mappings_are_not_counted_as_reviewed_coverage() -> None:
    """Unconfirmed curation must never be reported as attested coverage.

    A compliance product that overstates its own coverage fails in the same
    direction as a false attestation, so the two counts stay separate and
    attestation reads the reviewed one.
    """
    cov = coverage_by_framework()
    assert cov["reviewed"] + cov["proposed"] == cov["covered"]
    assert cov["reviewed"] < cov["covered"], "expected some mappings still awaiting review"

    reviewed_only = safeguards_by_requirement(reviewed_only=True)
    everything = safeguards_by_requirement()
    assert set(reviewed_only) < set(everything)


def test_review_queue_lists_only_proposed_mappings_with_reviewed_anchors() -> None:
    """The queue is the backlog that grows attestable coverage.

    It surfaces every proposed (unreviewed) mapping — never a reviewed one, which
    would be busywork — and pairs each with the reviewed anchors on the same
    safeguard, giving a reviewer trusted mappings to judge the equivalence against.
    """
    queue = mapping_review_queue()
    proposed = [
        (entry["safeguard_id"], member["control_id"])
        for entry in load_safeguards()["safeguards"]
        for member in entry["satisfies"]
        if member.get("review_status", "reviewed") == "proposed"
        or member.get("control_version") != member.get("current_control_version")
    ]
    assert {(item["safeguard_id"], item["control_id"]) for item in queue} == set(proposed)
    assert queue, "expected a real review backlog today"

    reviewed = set(safeguards_by_requirement(reviewed_only=True))
    for item in queue:
        # A queued item is proposed, so it is not already attestable coverage.
        assert item["control_id"] not in reviewed or len(safeguards_by_requirement()[item["control_id"]]) > 1
        # Anchors are the reviewer's trusted reference points, all confirmed.
        assert all(anchor in reviewed for anchor in item["reviewed_anchors"])


def test_review_queue_filters_to_a_single_framework() -> None:
    everything = mapping_review_queue()
    target = everything[0]["framework_id"]
    filtered = mapping_review_queue(framework_id=target)
    assert filtered
    assert {item["framework_id"] for item in filtered} == {target}
    assert len(filtered) == sum(1 for item in everything if item["framework_id"] == target)


def test_review_queue_filters_to_a_cross_framework_risk_domain() -> None:
    everything = mapping_review_queue()
    filtered = mapping_review_queue(risk_domain="detection")

    assert filtered
    assert {item["risk_domain"] for item in filtered} == {"detection"}
    assert {item["framework_id"] for item in filtered} >= {
        "cmmc-2-level2",
        "fedramp-moderate",
        "iso-42001-2023",
        "nist-ai-rmf",
        "soc2",
    }
    assert len(filtered) == sum(1 for item in everything if item["risk_domain"] == "detection")


def test_review_report_groups_frameworks_categories_and_source_gaps() -> None:
    report = mapping_review_report()

    assert report["proposed_mapping_count"] == len(report["items"])
    assert sum(report["by_framework"].values()) == report["proposed_mapping_count"]
    assert sum(report["by_risk_domain"].values()) == report["proposed_mapping_count"]
    assert report["source_backed_mapping_count"] + report["unsourced_mapping_count"] == report["proposed_mapping_count"]
    assert sum(report["source_backed_by_framework"].values()) == report["source_backed_mapping_count"]
    assert sum(report["unsourced_by_framework"].values()) == report["unsourced_mapping_count"]
    assert set(report["source_backed_by_framework"]) == {
        "cmmc-2-level2",
        "fedramp-moderate",
        "nist-800-53-rev5",
        "nist-csf-2.0",
        "nist-ai-rmf",
        "nist-rmf-800-37r2",
        "nist-800-171-rev3",
        "nis2-2022-2555",
        "dora-2022-2554",
        "eu-ai-act-2024-1689",
    }


def test_review_queue_falls_back_to_safeguard_level_provenance() -> None:
    safeguards = {entry["safeguard_id"]: entry for entry in load_safeguards()["safeguards"]}
    queue = mapping_review_queue()
    item = next(entry for entry in queue if entry["control_id"] == "CMMC-3.1.4")

    assert item["mapping_source"] == safeguards["SG-SEPARATIONOFDUTIES-001"]["mapping_source"]


def test_review_queue_never_promotes_a_mapping() -> None:
    """Calling the queue must not change what attestation reads."""
    before = dict(safeguards_by_requirement(reviewed_only=True))
    mapping_review_queue()
    after = dict(safeguards_by_requirement(reviewed_only=True))
    assert before == after


def test_review_queue_cli_reports_the_backlog(capsys) -> None:
    from security_lakehouse.cli import main

    assert main(["frameworks", "review-queue"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["proposed_mapping_count"] == len(mapping_review_queue())
    assert out["proposed_mapping_count"] == sum(out["by_framework"].values())
    assert out["proposed_mapping_count"] == sum(out["by_risk_domain"].values())
    assert out["source_backed_mapping_count"] + out["unsourced_mapping_count"] == out["proposed_mapping_count"]
    sourced = next(item for item in out["items"] if item["control_id"] == "CMMC-3.2.1")
    assert sourced["mapping_source"]["url"].startswith("https://")
    assert "domain-expert" in out["note"]


def test_review_queue_cli_filters_to_a_category_family(capsys) -> None:
    from security_lakehouse.cli import main

    assert main(["frameworks", "review-queue", "--risk-domain", "governance"]) == 0
    out = json.loads(capsys.readouterr().out)

    assert set(out["by_risk_domain"]) == {"governance"}
    assert {item["risk_domain"] for item in out["items"]} == {"governance"}


def test_every_mapping_declares_a_known_review_state() -> None:
    for entry in load_safeguards()["safeguards"]:
        for member in entry["satisfies"]:
            assert member.get("review_status", "reviewed") in {"reviewed", "proposed"}


def test_enrichment_rejects_a_title_that_only_repeats_the_identifier() -> None:
    """NIST's CSF OSCAL titles GV.OC-01 as "GV.OC-01".

    Accepting that would fill 106 titles with no content — coverage that looks
    enriched while saying nothing, which is worse than an honest placeholder
    because it hides the gap instead of reporting it.
    """
    import json as _json
    import tempfile
    from pathlib import Path as _Path

    from security_lakehouse.framework_enrich import enrich_catalog

    with tempfile.TemporaryDirectory() as tmp:
        path = _Path(tmp) / "catalog.json"
        path.write_text(
            _json.dumps(
                {
                    "controls": [
                        {
                            "control_id": "FEDRAMP-AC-2",
                            "framework_id": "fedramp-moderate",
                            "title": "FedRAMP Moderate AC-2 — assessed from cloud posture and audit evidence",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        report = enrich_catalog(
            path,
            titles_by_framework={"fedramp-moderate": ({"AC-2": "AC-2"}, "https://example.test", "d" * 64)},
            apply=True,
        )
        assert report["filled"] == 0
        assert report["unresolved"] == ["FEDRAMP-AC-2"]


def test_enrichment_records_verifiable_provenance() -> None:
    """An imported title is only better than an invented one if it is checkable."""
    import json as _json
    from pathlib import Path as _Path

    catalog = _json.loads((_Path(__file__).resolve().parents[1] / "controls" / "catalog.json").read_text())
    enriched = [c for c in catalog["controls"] if c.get("title_source_sha256")]
    assert enriched, "expected enriched controls"
    for control in enriched:
        assert control["title_source_url"].startswith("https://")
        assert len(control["title_source_sha256"]) == 64
        assert control["title_source_name"]


def test_every_safeguard_says_what_it_applies_to() -> None:
    """Evaluation targets resources, not frameworks.

    The catalog records `asset_types` on all 942 requirements. A safeguard that
    does not carry the union of its members' asset types cannot be pointed at
    anything, which makes it undeployable as the operated object.
    """
    catalog = load_control_catalog()
    for entry in load_safeguards()["safeguards"]:
        expected = sorted({t for m in entry["satisfies"] for t in (catalog[m["control_id"]].get("asset_types") or [])})
        assert entry.get("asset_types") == expected, f"{entry['safeguard_id']} asset_types drifted from its members"


def test_asset_type_lookup_finds_the_safeguards_that_apply() -> None:
    from security_lakehouse.safeguards import safeguards_for_asset_type

    for asset_type in ("iam_role", "ai_model", "data_store"):
        found = safeguards_for_asset_type(asset_type)
        assert found, f"no safeguard applies to {asset_type}"
        assert found == sorted(set(found))
    assert safeguards_for_asset_type("not-an-asset-type") == []


def test_validation_rejects_a_safeguard_that_applies_to_nothing() -> None:
    import json as _json

    payload = _json.loads(_json.dumps(load_safeguards()))
    payload["safeguards"][0]["asset_types"] = []
    assert any("asset_types" in p for p in validate_safeguards(payload))

"""Org mapping review overlay: persistence, supersession, effective status, coverage math."""

from __future__ import annotations

import json
import multiprocessing
from pathlib import Path

import pytest

from security_lakehouse import mapping_review
from security_lakehouse.assessment import write_assessment_snapshot
from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.mapping_review import (
    MappingReviewError,
    decision_history,
    effective_safeguards,
    latest_decisions,
    list_decisions,
    list_review_items,
    record_decisions,
    review_log_path,
    review_progress,
    verify_review_log,
)
from security_lakehouse.oscal import build_component_definition
from security_lakehouse.safeguards import (
    coverage_by_family,
    coverage_by_framework,
    effective_review_state,
    load_safeguards,
    mapping_review_queue,
    safeguards_by_requirement,
)

_PAYLOAD = {
    "schema": "trustops.safeguards.v1",
    "safeguards": [
        {
            "safeguard_id": "SG-A",
            "title": "Access reviews",
            "risk_domain": "identity",
            "satisfies": [
                {"control_id": "SOC2-CC6.1", "framework_id": "soc2", "role": "primary", "review_status": "reviewed"},
                {
                    "control_id": "ISO27001-A.5.15",
                    "framework_id": "iso-27001-2022",
                    "role": "equivalent",
                    "review_status": "proposed",
                    "mapping_basis": "title_theme",
                },
                {
                    "control_id": "HIPAA-164.308(a)(4)",
                    "framework_id": "hipaa-security-rule",
                    "role": "equivalent",
                    "review_status": "proposed",
                    "mapping_source": {
                        "name": "Crosswalk",
                        "url": "https://example.test/crosswalk.pdf",
                        "sha256": "a" * 64,
                        "locator": "Table 3 row 7",
                    },
                },
            ],
        },
        {
            "safeguard_id": "SG-B",
            "title": "Logging",
            "risk_domain": "logging",
            "satisfies": [
                {"control_id": "SOC2-CC7.2", "framework_id": "soc2", "role": "primary", "review_status": "reviewed"},
                {"control_id": "SOC2-CC6.1", "framework_id": "soc2", "role": "equivalent", "review_status": "proposed"},
            ],
        },
    ],
}

_CATALOG = {
    "SOC2-CC6.1": {"control_id": "SOC2-CC6.1", "framework_id": "soc2"},
    "SOC2-CC7.2": {"control_id": "SOC2-CC7.2", "framework_id": "soc2"},
    "SOC2-CC8.1": {"control_id": "SOC2-CC8.1", "framework_id": "soc2"},
    "ISO27001-A.5.15": {"control_id": "ISO27001-A.5.15", "framework_id": "iso-27001-2022"},
    "HIPAA-164.308(a)(4)": {"control_id": "HIPAA-164.308(a)(4)", "framework_id": "hipaa-security-rule"},
}


def _item(safeguard_id: str, control_id: str, framework_id: str) -> dict[str, str]:
    return {"safeguard_id": safeguard_id, "control_id": control_id, "framework_id": framework_id}


def _decide(lake: Path, decision: str, *items: dict[str, str], reviewer: str = "grc@acme.test", **kwargs):
    return record_decisions(
        lake,
        items=list(items),
        decision=decision,
        rationale=kwargs.pop("rationale", "Evidence verifies the requirement text."),
        reviewer=reviewer,
        payload=_PAYLOAD,
        **kwargs,
    )


ISO = _item("SG-A", "ISO27001-A.5.15", "iso-27001-2022")
HIPAA = _item("SG-A", "HIPAA-164.308(a)(4)", "hipaa-security-rule")
SOC2_REVIEWED = _item("SG-A", "SOC2-CC6.1", "soc2")


# --- persistence + supersession ------------------------------------------------


def test_decision_is_appended_to_a_hash_chained_log_under_the_lake(tmp_path: Path) -> None:
    records = _decide(tmp_path, "approve", ISO, evidence_ref="s3://evidence/access-review-q3.pdf")
    assert len(records) == 1
    record = records[0]
    assert review_log_path(tmp_path) == tmp_path / "gold" / "mapping_reviews.jsonl"
    assert review_log_path(tmp_path).is_file()
    assert record["decision"] == "approve"
    assert record["reviewer"] == "grc@acme.test"
    assert record["rationale"] == "Evidence verifies the requirement text."
    assert record["evidence_ref"] == "s3://evidence/access-review-q3.pdf"
    assert record["shipped_review_status"] == "proposed"
    assert record["supersedes"] is None
    assert record["decided_at"].endswith("Z")
    assert record["record_hash"] and record["prev_hash"] is None
    assert verify_review_log(tmp_path)["ok"] is True


def test_latest_decision_wins_and_history_is_kept(tmp_path: Path) -> None:
    first = _decide(tmp_path, "approve", ISO)[0]
    second = _decide(tmp_path, "reject", ISO, rationale="Different obligation on reread.", reviewer="lead@acme.test")[0]
    assert second["supersedes"] == first["decision_id"]
    latest = latest_decisions(tmp_path)
    assert latest[("SG-A", "ISO27001-A.5.15")]["decision"] == "reject"
    history = decision_history(tmp_path, safeguard_id="SG-A", control_id="ISO27001-A.5.15")
    assert [row["decision"] for row in history] == ["approve", "reject"]
    assert [row["reviewer"] for row in history] == ["grc@acme.test", "lead@acme.test"]
    assert len(list_decisions(tmp_path)) == 2
    assert verify_review_log(tmp_path) == {**verify_review_log(tmp_path), "ok": True, "length": 2}


def test_bulk_decision_shares_one_rationale_and_batch(tmp_path: Path) -> None:
    records = _decide(tmp_path, "needs_changes", ISO, HIPAA, rationale="Cite the exact clause.")
    assert {r["control_id"] for r in records} == {"ISO27001-A.5.15", "HIPAA-164.308(a)(4)"}
    assert len({r["batch_id"] for r in records}) == 1
    assert {r["rationale"] for r in records} == {"Cite the exact clause."}


def test_source_anchor_is_captured_from_the_mapping(tmp_path: Path) -> None:
    record = _decide(tmp_path, "approve", HIPAA)[0]
    assert record["source_anchor"] == {
        "name": "Crosswalk",
        "url": "https://example.test/crosswalk.pdf",
        "sha256": "a" * 64,
        "locator": "Table 3 row 7",
    }
    # title_theme members never inherit a citation.
    assert _decide(tmp_path, "approve", ISO)[0]["source_anchor"] is None


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"rationale": "   "}, "rationale is required"),
        ({"reviewer": ""}, "reviewer is required"),
        ({"decision": "promote"}, "decision must be one of"),
    ],
)
def test_invalid_decisions_are_refused(tmp_path: Path, kwargs: dict, message: str) -> None:
    decision = kwargs.pop("decision", "approve")
    with pytest.raises(MappingReviewError, match=message):
        _decide(tmp_path, decision, ISO, **kwargs)
    assert not review_log_path(tmp_path).exists()


def test_unknown_mapping_or_framework_mismatch_is_refused_and_nothing_is_written(tmp_path: Path) -> None:
    with pytest.raises(MappingReviewError, match="no shipped mapping"):
        _decide(tmp_path, "approve", ISO, _item("SG-A", "SOC2-CC8.1", "soc2"))
    with pytest.raises(MappingReviewError, match="framework"):
        _decide(tmp_path, "approve", _item("SG-A", "ISO27001-A.5.15", "soc2"))
    with pytest.raises(MappingReviewError, match="at least one mapping"):
        _decide(tmp_path, "approve")
    assert not review_log_path(tmp_path).exists()


def test_rationale_and_evidence_ref_are_bounded(tmp_path: Path) -> None:
    with pytest.raises(MappingReviewError, match="rationale"):
        _decide(tmp_path, "approve", ISO, rationale="x" * 4001)
    with pytest.raises(MappingReviewError, match="evidence_ref"):
        _decide(tmp_path, "approve", ISO, evidence_ref="x" * 1001)


def test_tenants_are_isolated_by_lake(tmp_path: Path) -> None:
    lake_a, lake_b = tmp_path / "tenants" / "a", tmp_path / "tenants" / "b"
    _decide(lake_a, "approve", ISO)
    _decide(lake_b, "reject", ISO)
    assert latest_decisions(lake_a)[("SG-A", "ISO27001-A.5.15")]["decision"] == "approve"
    assert latest_decisions(lake_b)[("SG-A", "ISO27001-A.5.15")]["decision"] == "reject"
    assert len(list_decisions(lake_a)) == 1 and len(list_decisions(lake_b)) == 1


def _append_from_process(lake: str, index: int) -> None:
    record_decisions(
        Path(lake),
        items=[ISO],
        decision="approve" if index % 2 else "needs_changes",
        rationale=f"writer {index}",
        reviewer=f"r{index}@acme.test",
        payload=_PAYLOAD,
    )


def test_concurrent_writers_across_processes_never_fork_the_chain(tmp_path: Path) -> None:
    ctx = multiprocessing.get_context("spawn")
    procs = [ctx.Process(target=_append_from_process, args=(str(tmp_path), i)) for i in range(6)]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(timeout=60)
        assert proc.exitcode == 0
    rows = list_decisions(tmp_path)
    assert len(rows) == 6
    assert len({row["prev_hash"] for row in rows}) == 6
    assert verify_review_log(tmp_path)["ok"] is True
    # supersession is computed under the same lock, so each supersedes the one before it.
    assert [row["supersedes"] for row in rows[1:]] == [row["decision_id"] for row in rows[:-1]]


# --- effective status (the one function) ---------------------------------------


@pytest.mark.parametrize(
    ("shipped", "decision", "expected"),
    [
        ("reviewed", None, "maintainer_reviewed"),
        ("proposed", None, "proposed"),
        (None, None, "maintainer_reviewed"),
        ("proposed", "approve", "org_reviewed"),
        ("reviewed", "approve", "maintainer_reviewed"),
        ("proposed", "needs_changes", "needs_changes"),
        ("reviewed", "needs_changes", "needs_changes"),
        ("proposed", "reject", "rejected"),
        ("reviewed", "reject", "rejected"),
    ],
)
def test_effective_review_state(shipped: str | None, decision: str | None, expected: str) -> None:
    member = {"control_id": "X"} if shipped is None else {"control_id": "X", "review_status": shipped}
    assert effective_review_state(member, decision) == expected


def test_overlay_never_mutates_the_shipped_payload(tmp_path: Path) -> None:
    before = json.dumps(_PAYLOAD, sort_keys=True)
    _decide(tmp_path, "approve", ISO)
    _decide(tmp_path, "reject", SOC2_REVIEWED)
    effective = effective_safeguards(tmp_path, payload=_PAYLOAD)
    assert json.dumps(_PAYLOAD, sort_keys=True) == before
    members = {m["control_id"]: m for m in effective["safeguards"][0]["satisfies"]}
    assert members["ISO27001-A.5.15"]["effective_review_state"] == "org_reviewed"
    assert members["ISO27001-A.5.15"]["org_review"]["reviewer"] == "grc@acme.test"
    assert members["SOC2-CC6.1"]["effective_review_state"] == "rejected"


def test_shipped_safeguards_json_is_untouched_by_decisions(tmp_path: Path) -> None:
    shipped = load_safeguards()
    member = next(m for e in shipped["safeguards"] for m in e["satisfies"] if m.get("review_status") == "proposed")
    entry = next(e for e in shipped["safeguards"] if member in e["satisfies"])
    path = mapping_review.DEFAULT_SAFEGUARDS
    digest_before = path.read_bytes()
    record_decisions(
        tmp_path,
        items=[_item(entry["safeguard_id"], member["control_id"], member["framework_id"])],
        decision="approve",
        rationale="ok",
        reviewer="grc@acme.test",
    )
    assert path.read_bytes() == digest_before


# --- coverage math separation --------------------------------------------------


def test_coverage_without_decisions_matches_the_shipped_numbers(tmp_path: Path) -> None:
    shipped = coverage_by_framework(_PAYLOAD, catalog=_CATALOG)
    overlaid = coverage_by_framework(effective_safeguards(tmp_path, payload=_PAYLOAD), catalog=_CATALOG)
    assert overlaid == shipped
    assert shipped["covered"] == 4
    assert shipped["reviewed"] == 2
    assert shipped["maintainer_reviewed"] == 2
    assert shipped["org_reviewed"] == 0
    assert shipped["rejected_mappings"] == 0


def test_org_approval_and_rejection_are_counted_separately(tmp_path: Path) -> None:
    _decide(tmp_path, "approve", ISO)
    _decide(tmp_path, "reject", HIPAA)
    _decide(tmp_path, "needs_changes", _item("SG-B", "SOC2-CC6.1", "soc2"))
    coverage = coverage_by_framework(effective_safeguards(tmp_path, payload=_PAYLOAD), catalog=_CATALOG)
    # HIPAA's only mapping is rejected: it leaves evaluated coverage entirely.
    assert coverage["covered"] == 3
    assert coverage["maintainer_reviewed"] == 2  # SOC2-CC6.1, SOC2-CC7.2
    assert coverage["org_reviewed"] == 1  # ISO via org approval only
    assert coverage["reviewed"] == 3
    assert coverage["proposed"] == 0
    assert coverage["rejected_mappings"] == 1
    assert coverage["rejected_requirements"] == 1
    assert coverage["org_reviewed_mappings"] == 1
    assert coverage["maintainer_reviewed_mappings"] == 2
    assert coverage["needs_changes_mappings"] == 1
    assert coverage["frameworks"]["hipaa-security-rule"]["covered"] == 0
    assert coverage["frameworks"]["hipaa-security-rule"]["rejected_mappings"] == 1
    assert coverage["frameworks"]["iso-27001-2022"]["org_reviewed"] == 1
    assert coverage["frameworks"]["iso-27001-2022"]["maintainer_reviewed"] == 0


def test_rejecting_a_maintainer_reviewed_mapping_removes_it_from_attestation(tmp_path: Path) -> None:
    _decide(tmp_path, "reject", SOC2_REVIEWED)
    effective = effective_safeguards(tmp_path, payload=_PAYLOAD)
    attestable = safeguards_by_requirement(effective, reviewed_only=True)
    evaluated = safeguards_by_requirement(effective)
    assert "SG-A" not in attestable.get("SOC2-CC6.1", [])
    assert "SG-A" not in evaluated.get("SOC2-CC6.1", [])
    # SG-B still (proposed-)maps CC6.1, so it stays evaluatable but not attestable.
    assert evaluated["SOC2-CC6.1"] == ["SG-B"]
    assert "SOC2-CC6.1" not in attestable


def test_family_counts_split_maintainer_org_and_rejected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "security_lakehouse.safeguards.load_ccf_families",
        lambda: {"identity": {"label": "Identity"}, "logging": {"label": "Logging"}},
    )
    _decide(tmp_path, "approve", ISO)
    _decide(tmp_path, "reject", HIPAA)
    identity = next(
        row
        for row in coverage_by_family(effective_safeguards(tmp_path, payload=_PAYLOAD))
        if row["family_id"] == "identity"
    )
    assert identity["mapping_count"] == 3
    assert identity["maintainer_reviewed_mapping_count"] == 1
    assert identity["org_reviewed_mapping_count"] == 1
    assert identity["reviewed_mapping_count"] == 2
    assert identity["rejected_mapping_count"] == 1
    assert identity["proposed_mapping_count"] == 0


def test_review_queue_reflects_org_decisions(tmp_path: Path) -> None:
    _decide(tmp_path, "approve", ISO)
    queue = mapping_review_queue(effective_safeguards(tmp_path, payload=_PAYLOAD))
    keys = {(row["safeguard_id"], row["control_id"]) for row in queue}
    assert ("SG-A", "ISO27001-A.5.15") not in keys
    assert ("SG-A", "HIPAA-164.308(a)(4)") in keys


def test_list_review_items_carries_basis_anchor_and_latest_decision(tmp_path: Path) -> None:
    _decide(tmp_path, "needs_changes", ISO, rationale="Cite the clause.")
    rows = list_review_items(tmp_path, payload=_PAYLOAD)
    assert len(rows) == 5
    by_key = {(row["safeguard_id"], row["control_id"]): row for row in rows}
    iso = by_key[("SG-A", "ISO27001-A.5.15")]
    assert iso["review_state"] == "needs_changes"
    assert iso["review_label"] == "needs changes"
    assert iso["mapping_basis"] == "title_theme"
    assert iso["mapping_source"] is None
    assert iso["latest_decision"]["rationale"] == "Cite the clause."
    assert iso["reviewed_anchors"] == ["SOC2-CC6.1"]
    hipaa = by_key[("SG-A", "HIPAA-164.308(a)(4)")]
    assert hipaa["mapping_source"]["locator"] == "Table 3 row 7"
    assert hipaa["latest_decision"] is None
    assert by_key[("SG-A", "SOC2-CC6.1")]["review_label"] == "maintainer-reviewed"


def test_review_progress_per_framework(tmp_path: Path) -> None:
    _decide(tmp_path, "approve", ISO)
    _decide(tmp_path, "reject", HIPAA)
    progress = {row["framework_id"]: row for row in review_progress(tmp_path, payload=_PAYLOAD)["frameworks"]}
    assert progress["soc2"] == {
        "framework_id": "soc2",
        "mapped": 3,
        "maintainer_reviewed": 2,
        "org_reviewed": 0,
        "needs_changes": 0,
        "rejected": 0,
        "pending": 1,
    }
    assert progress["iso-27001-2022"]["org_reviewed"] == 1
    assert progress["hipaa-security-rule"]["rejected"] == 1
    assert progress["hipaa-security-rule"]["pending"] == 0


# --- OSCAL + snapshot ----------------------------------------------------------


def test_oscal_includes_org_reviewed_mappings_with_reviewer_attribution(tmp_path: Path) -> None:
    catalog = {cid: {**row, "evidence_requirement": f"{cid} evidence"} for cid, row in _CATALOG.items()}
    before = build_component_definition(_PAYLOAD, catalog)
    record = _decide(tmp_path, "approve", ISO)[0]
    _decide(tmp_path, "reject", SOC2_REVIEWED)
    doc = build_component_definition(effective_safeguards(tmp_path, payload=_PAYLOAD), catalog)

    def implemented(document: dict) -> dict[str, dict]:
        out = {}
        for component in document["component-definition"]["components"]:
            for impl in component.get("control-implementations", []):
                for req in impl["implemented-requirements"]:
                    props = {p["name"]: p["value"] for p in req["props"]}
                    out[(props["trustops-safeguard-id"], props["trustops-control-id"])] = props
        return out

    assert ("SG-A", "ISO27001-A.5.15") not in implemented(before)
    after = implemented(doc)
    iso = after[("SG-A", "ISO27001-A.5.15")]
    assert iso["trustops-review-state"] == "org-reviewed"
    assert iso["trustops-reviewed-by"] == "grc@acme.test"
    assert iso["trustops-reviewed-at"] == record["decided_at"]
    assert iso["trustops-review-decision-id"] == record["decision_id"]
    assert ("SG-A", "SOC2-CC6.1") not in after  # org-rejected maintainer mapping is withheld
    assert after[("SG-B", "SOC2-CC7.2")]["trustops-review-state"] == "maintainer-reviewed"
    assert ("SG-A", "HIPAA-164.308(a)(4)") not in after  # still proposed


def test_snapshot_pins_review_counts_and_log_tip(tmp_path: Path) -> None:
    record = record_decisions(
        tmp_path,
        items=[_first_proposed_item()],
        decision="approve",
        rationale="Confirmed against the requirement text.",
        reviewer="grc@acme.test",
    )[0]
    path = write_assessment_snapshot(tmp_path, reason="audit")
    snapshot = json.loads(path.read_text(encoding="utf-8"))
    review = snapshot["mapping_review"]
    assert review["decision_log"]["tip_hash"] == record["record_hash"]
    assert review["decision_log"]["length"] == 1
    assert review["decision_log"]["ok"] is True
    summary = review["summary"]
    for key in ("catalogued", "mapped", "maintainer_reviewed", "org_reviewed", "rejected_mappings", "proposed"):
        assert key in summary
    assert summary["org_reviewed_mappings"] == 1
    assert summary["catalogued"] == len(load_control_catalog())


def _first_proposed_item() -> dict[str, str]:
    shipped = load_safeguards()
    for entry in shipped["safeguards"]:
        for member in entry["satisfies"]:
            if member.get("review_status") == "proposed":
                return _item(entry["safeguard_id"], member["control_id"], member["framework_id"])
    raise AssertionError("no proposed mapping shipped")

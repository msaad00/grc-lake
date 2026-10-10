"""Inherited reviews cannot outlive the same-safeguard review they cite."""

import json

import pytest

from security_lakehouse import safeguards


def load(tmp_path, monkeypatch, members, *, source_version="1"):
    catalog = {
        "SOURCE": {"version": source_version},
        "TWIN": {"version": "1"},
        "THIRD": {"version": "1"},
    }
    monkeypatch.setattr(safeguards, "load_control_catalog", lambda: catalog)
    path = tmp_path / "safeguards.json"
    path.write_text(json.dumps({"safeguards": [{"safeguard_id": "SG", "satisfies": members}]}))
    return {m["control_id"]: m for m in safeguards.load_safeguards(path)["safeguards"][0]["satisfies"]}


def member(control, *, source=None, status="reviewed"):
    row = {"control_id": control, "control_version": "1", "review_status": status}
    if source is not None:
        row["review_basis"] = {"inherited_from": source, "reason": "identical requirement"}
    return row


@pytest.mark.parametrize("failure", ["changed", "proposed", "missing", "cycle", "self"])
def test_invalid_inheritance_is_proposed_and_can_receive_its_own_org_review(tmp_path, monkeypatch, failure):
    source = member("SOURCE", status="proposed" if failure == "proposed" else "reviewed")
    twin = member("TWIN", source="TWIN" if failure == "self" else "SOURCE")
    if failure == "cycle":
        source["review_basis"] = {"inherited_from": "TWIN"}
    members = [twin] if failure == "missing" else [source, twin]
    rows = load(tmp_path, monkeypatch, members, source_version="2" if failure == "changed" else "1")
    assert safeguards.effective_review_state(rows["TWIN"]) == "proposed"
    assert safeguards.effective_review_state(rows["TWIN"], "approve") == "org_reviewed"
    assert safeguards.effective_review_state(rows["TWIN"], "reject") == "rejected"


def test_valid_chain_preserves_review_and_existing_decision_fingerprints(tmp_path, monkeypatch):
    rows = load(
        tmp_path, monkeypatch, [member("SOURCE"), member("TWIN", source="SOURCE"), member("THIRD", source="TWIN")]
    )
    for row in rows.values():
        assert safeguards.effective_review_state(row) == "maintainer_reviewed"
        assert "inherited_review_valid" not in row


def test_invalid_ancestor_demotes_entire_inheritance_chain(tmp_path, monkeypatch):
    rows = load(
        tmp_path,
        monkeypatch,
        [member("SOURCE", status="proposed"), member("TWIN", source="SOURCE"), member("THIRD", source="TWIN")],
    )
    assert safeguards.effective_review_state(rows["THIRD"]) == "proposed"


def test_ambiguous_source_cannot_establish_inherited_review(tmp_path, monkeypatch):
    rows = load(
        tmp_path, monkeypatch, [member("SOURCE", status="proposed"), member("SOURCE"), member("TWIN", source="SOURCE")]
    )
    assert safeguards.effective_review_state(rows["TWIN"]) == "proposed"


def test_missing_catalog_source_invalidates_review_even_when_versions_match(tmp_path, monkeypatch):
    rows = load(tmp_path, monkeypatch, [member("REMOVED"), member("TWIN", source="REMOVED")])
    assert safeguards.effective_review_state(rows["TWIN"]) == "proposed"


def test_invalid_review_is_excluded_from_attestable_coverage(tmp_path, monkeypatch):
    rows = load(tmp_path, monkeypatch, [member("SOURCE", status="proposed"), member("TWIN", source="SOURCE")])
    payload = {"safeguards": [{"safeguard_id": "SG", "satisfies": list(rows.values())}]}
    coverage = safeguards.framework_mapping_coverage(payload)
    assert coverage["covered"] == 2
    assert coverage["reviewed"] == 0
    assert safeguards.safeguards_by_requirement(payload, reviewed_only=True) == {}
    assert safeguards.requirement_status("TWIN", {"SG": "pass"}, payload) != "pass"

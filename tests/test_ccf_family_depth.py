"""Deeper CCF families: sub-objective safeguards and the first NIST RMF task mappings."""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest

from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.policy import ControlContext, evaluate_control, validate_rule
from security_lakehouse.safeguards import (
    coverage_by_family,
    coverage_by_framework,
    load_safeguards,
    mapping_review_report,
    validate_safeguards,
)

ROOT = Path(__file__).resolve().parents[1]
RMF_MANIFEST = json.loads((ROOT / "frameworks/packs/data/nist_rmf_800_37r2.json").read_text())

# The 44 safeguards that existed before this deepening pass. New safeguards are
# appended after them so edits to these objects stay isolated from this change.
ORIGINAL_IDS = [
    "SG-IDENTITY-001",
    "SG-IDENTITY-002",
    "SG-DATAPROTECTION-001",
    "SG-DETECTION-001",
    "SG-LOGGING-001",
    "SG-CHANGEMANAGEMENT-001",
    "SG-VULNERABILITYMANAGEMENT-001",
    "SG-THIRDPARTYRISK-001",
    "SG-RISKMANAGEMENT-001",
    "SG-AVAILABILITY-001",
    "SG-AIGOVERNANCE-001",
    "SG-INCIDENTRESPONSE-001",
    "SG-GOVERNANCE-002",
    "SG-TRAINING-001",
    "SG-PHYSICAL-001",
    "SG-SECUREDEV-001",
    "SG-NETWORK-001",
    "SG-PRIVACYRIGHTS-001",
    "SG-DATAINVENTORY-001",
    "SG-DATARETENTION-001",
    "SG-PROCESSINGINTEGRITY-001",
    "SG-SEPARATIONOFDUTIES-001",
    "SG-MAINTENANCE-001",
    "SG-IDENTITY-003",
    "SG-MAINTENANCE-002",
    "SG-SECURITYENGINEERING-001",
    "SG-IDENTITY-004",
    "SG-CHANGEMANAGEMENT-002",
    "SG-PERSONNELSECURITY-001",
    "SG-SECURITYASSESSMENT-001",
    "SG-SHAREDRESOURCEISOLATION-001",
    "SG-FUNCTIONSEPARATION-001",
    "SG-LEASTFUNCTIONALITY-001",
    "SG-RISKASSESSMENT-002",
    "SG-MALWARESCANNING-001",
    "SG-AUDITEVENTREVIEW-001",
    "SG-SOFTWAREAUTHORIZATION-001",
    "SG-AIINVENTORY-001",
    "SG-AICONTEXT-001",
    "SG-AICATEGORIZATION-001",
    "SG-RISKPRIORITY-001",
    "SG-RISKRESPONSE-001",
    "SG-AIMONITORING-001",
    "SG-AIPOSTDEPLOYMENT-001",
]

NEW_SAFEGUARDS = {
    "SG-POLICYMANAGEMENT-001": "governance",
    "SG-ROLESRESPONSIBILITIES-001": "governance",
    "SG-MANAGEMENTREVIEW-001": "governance",
    "SG-COMPLIANCEOBLIGATIONS-001": "governance",
    "SG-RISKSTRATEGY-001": "governance",
    "SG-SECURITYPLAN-001": "governance",
    "SG-AUTHORIZATION-001": "governance",
    "SG-INCIDENTPLAN-001": "incident-response",
    "SG-INCIDENTHANDLING-001": "incident-response",
    "SG-INCIDENTNOTIFICATION-001": "incident-response",
    "SG-DATASUBJECTRIGHTS-001": "privacy",
    "SG-PRIVACYNOTICE-001": "privacy",
    "SG-PROCESSINGRECORDS-001": "privacy",
    "SG-CROSSBORDERTRANSFER-001": "privacy",
    "SG-VULNSCANNING-001": "vulnerability-management",
    "SG-VULNREMEDIATION-001": "vulnerability-management",
    "SG-CHANGEAPPROVAL-001": "change-management",
    "SG-CHANGESEGREGATION-001": "change-management",
    "SG-CODESCANNING-001": "secure-development",
    "SG-SECURESDLC-001": "secure-development",
    "SG-CONFIGBASELINE-001": "configuration-management",
    "SG-CONFIGDRIFT-001": "configuration-management",
    "SG-ARCHITECTUREREVIEW-001": "secure-architecture",
    "SG-INPUTVALIDATION-001": "processing-integrity",
    "SG-INTEGRITYVERIFICATION-001": "processing-integrity",
    "SG-SECURITYCATEGORIZATION-001": "risk-management",
    "SG-SYSTEMCHARACTERIZATION-001": "risk-management",
    "SG-CONTINUOUSMONITORING-001": "risk-management",
    "SG-CONTROLASSESSMENT-001": "risk-management",
    "SG-POAM-001": "risk-management",
    "SG-SUPPLYCHAINPROGRAM-001": "third-party-risk",
    "SG-SUPPLIERINVENTORY-001": "third-party-risk",
    "SG-NONLOCALMAINTENANCE-001": "system-maintenance",
    "SG-TIMELYMAINTENANCE-001": "system-maintenance",
}

# Families that held one or two safeguards (or no reviewed mapping) before this pass.
THIN_FAMILIES = {
    "governance",
    "incident-response",
    "privacy",
    "change-management",
    "vulnerability-management",
    "secure-development",
    "processing-integrity",
    "third-party-risk",
    "configuration-management",
    "system-maintenance",
    "secure-architecture",
}

KNOWN_OWNERS = {
    "detection-engineering",
    "engineering",
    "grc",
    "platform-engineering",
    "privacy-office",
    "risk-owner",
    "security-platform",
}

CSF_SOURCE = {
    "name": "NIST Cybersecurity Framework (CSF) 2.0",
    "url": "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf",
    "sha256": "3c31f46fee98cac0c4323453e5109291a213b4de7fef8c058af9bf67f717433c",
}

RMF_STEP_SECTIONS = {
    "P": "3.1 (Prepare)",
    "C": "3.2 (Categorize)",
    "S": "3.3 (Select)",
    "I": "3.4 (Implement)",
    "A": "3.5 (Assess)",
    "R": "3.6 (Authorize)",
    "M": "3.7 (Monitor)",
}

# RMF tasks the new safeguards leave to existing ones: P-3/P-14 sit on the
# existing risk assessment safeguard and M-7 (disposal) on the existing
# retention/disposal safeguard. I-1 ("implement the controls") is every
# safeguard at once and stays unmapped.
EXISTING_RMF_HOMES = {
    ("SG-RISKMANAGEMENT-001", "NIST-RMF-P-3"),
    ("SG-RISKMANAGEMENT-001", "NIST-RMF-P-14"),
    ("SG-DATARETENTION-001", "NIST-RMF-M-7"),
}
RMF_FLOOR = 46


def _entries() -> dict[str, dict]:
    return {entry["safeguard_id"]: entry for entry in load_safeguards()["safeguards"]}


def _without_new(payload: dict) -> dict:
    trimmed = copy.deepcopy(payload)
    trimmed["safeguards"] = [s for s in trimmed["safeguards"] if s["safeguard_id"] not in NEW_SAFEGUARDS]
    return trimmed


def test_new_safeguards_are_appended_after_the_existing_ones() -> None:
    ids = [entry["safeguard_id"] for entry in load_safeguards()["safeguards"]]
    assert ids[: len(ORIGINAL_IDS)] == ORIGINAL_IDS
    assert set(ids[len(ORIGINAL_IDS) :]) == set(NEW_SAFEGUARDS)
    assert len(ids) == len(set(ids))


def test_new_safeguards_follow_the_schema() -> None:
    payload = load_safeguards()
    assert validate_safeguards(payload) == []
    catalog = load_control_catalog()
    entries = _entries()
    for sid, family in NEW_SAFEGUARDS.items():
        entry = entries[sid]
        assert re.fullmatch(r"SG-[A-Z]+-\d{3}", sid)
        assert entry["risk_domain"] == family
        for field in ("title", "objective", "evidence_requirement"):
            assert isinstance(entry[field], str) and len(entry[field]) >= 40 or field == "title"
        assert validate_rule(entry["evaluation_rule"]) == [], sid
        assert entry["frequency"] in {"continuous", "annually"}
        assert entry["owner"] in KNOWN_OWNERS
        assert entry["reviewed_by"] is None and entry["reviewed_at"] is None
        assert "mapping_source" not in entry, "provenance is per member so it cannot leak across frameworks"
        members = entry["satisfies"]
        assert sum(m["role"] == "primary" for m in members) == 1
        assert len({m["control_id"] for m in members}) == len(members), f"{sid} maps a requirement twice"
        for member in members:
            assert catalog[member["control_id"]]["framework_id"] == member["framework_id"]
        expected_assets = sorted({t for m in members for t in catalog[m["control_id"]].get("asset_types") or []})
        assert entry["asset_types"] == expected_assets


def test_new_mappings_are_proposed_and_add_no_attestable_coverage() -> None:
    payload = load_safeguards()
    for sid in NEW_SAFEGUARDS:
        for member in _entries()[sid]["satisfies"]:
            assert member["review_status"] == "proposed", (sid, member["control_id"])
            assert "review_basis" not in member

    before, after = coverage_by_framework(_without_new(payload)), coverage_by_framework(payload)
    assert after["reviewed"] == before["reviewed"]
    assert after["covered"] > before["covered"]
    assert after["proposed"] - before["proposed"] == after["covered"] - before["covered"]


def test_citations_are_limited_to_the_requirement_source() -> None:
    """Only CSF and RMF members carry provenance, and it cites their own publication."""
    for sid in NEW_SAFEGUARDS:
        for member in _entries()[sid]["satisfies"]:
            source = member.get("mapping_source")
            if member["framework_id"] == "nist-csf-2.0":
                subcategory = member["control_id"].removeprefix("NIST-CSF-")
                assert source == {**CSF_SOURCE, "locator": f"NIST CSF 2.0 Core, Appendix A, {subcategory}"}
            elif member["framework_id"] == "nist-rmf-800-37r2":
                task = member["control_id"].removeprefix("NIST-RMF-")
                assert source["url"] == RMF_MANIFEST["source"]["pdf"]
                assert source["sha256"] == RMF_MANIFEST["source"]["pdf_sha256"]
                assert source["locator"] == f"Chapter 3, Section {RMF_STEP_SECTIONS[task[0]]}, Task {task}"
            else:
                assert source is None, (sid, member["control_id"])


def test_nist_rmf_tasks_meet_the_mapping_floor() -> None:
    cov = coverage_by_framework()["frameworks"]["nist-rmf-800-37r2"]
    assert cov["controls"] == 47
    assert cov["covered"] >= RMF_FLOOR

    rmf_members = [
        (entry["safeguard_id"], member)
        for entry in load_safeguards()["safeguards"]
        for member in entry["satisfies"]
        if member["framework_id"] == "nist-rmf-800-37r2"
    ]
    on_existing = {(sid, member["control_id"]) for sid, member in rmf_members if sid not in NEW_SAFEGUARDS}
    assert on_existing == EXISTING_RMF_HOMES
    for sid, member in rmf_members:
        if (sid, member["control_id"]) in EXISTING_RMF_HOMES:
            task = member["control_id"].removeprefix("NIST-RMF-")
            assert member["review_status"] == "proposed"
            assert member["mapping_source"] == {
                "name": "NIST SP 800-37 Rev. 2",
                "url": RMF_MANIFEST["source"]["pdf"],
                "sha256": RMF_MANIFEST["source"]["pdf_sha256"],
                "locator": f"Chapter 3, Section {RMF_STEP_SECTIONS[task[0]]}, Task {task}",
            }
    # Governance and risk-management safeguards carry the RMF lane.
    new_homes = {NEW_SAFEGUARDS[sid] for sid, _ in rmf_members if sid in NEW_SAFEGUARDS}
    assert new_homes <= {"governance", "risk-management", "secure-architecture"}
    report = mapping_review_report(framework_id="nist-rmf-800-37r2")
    assert report["unsourced_mapping_count"] == 0


def test_every_fedramp_mapping_carries_its_800_53_twin() -> None:
    for sid in NEW_SAFEGUARDS:
        members = {m["control_id"]: m for m in _entries()[sid]["satisfies"]}
        for control_id in [c for c in members if c.startswith("FEDRAMP-")]:
            twin = members.get("NIST-800-53-" + control_id.removeprefix("FEDRAMP-"))
            assert twin is not None, (sid, control_id)
            assert twin["review_status"] == members[control_id]["review_status"]


def test_evidence_requirement_names_its_evidence_basis() -> None:
    """A safeguard says whether a read-only connector can derive it or a person must attest it.

    Claiming connector evaluation for evidence no connector collects would make a
    manual control look automated.
    """
    catalog = json.loads((ROOT / "connectors/catalog.json").read_text())
    connector_ids = {row["connector_id"] for row in catalog["connectors"]}
    for sid in NEW_SAFEGUARDS:
        text = _entries()[sid]["evidence_requirement"]
        named = {cid for cid in connector_ids if f"`{cid}`" in text}
        assert named or "Attested evidence" in text, sid
        assert not (set(re.findall(r"`([a-z0-9-]+)`", text)) - connector_ids), f"{sid} names an unknown connector"


def test_thin_families_now_hold_at_least_three_safeguards() -> None:
    rows = {row["family_id"]: row for row in coverage_by_family()}
    for family in THIN_FAMILIES:
        assert rows[family]["safeguard_count"] >= 3, family


@pytest.mark.parametrize(
    "facts,expected",
    [
        ({"event_count": 0, "evidence_count": 0}, "fail"),
        ({"event_count": 1, "evidence_count": 1, "evidence_status": "stale"}, "fail"),
        ({"event_count": 1, "evidence_count": 1, "open_violation_count": 1, "max_severity": "high"}, "fail"),
        ({"event_count": 1, "evidence_count": 1, "evidence_status": "fresh"}, "pass"),
    ],
)
def test_new_safeguards_evaluate_to_the_expected_status(facts: dict, expected: str) -> None:
    entries = _entries()
    for sid in NEW_SAFEGUARDS:
        result = evaluate_control(ControlContext(control_id=sid, **facts), entries[sid]["evaluation_rule"])
        assert result.status == expected, (sid, facts)

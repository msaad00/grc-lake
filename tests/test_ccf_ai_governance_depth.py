"""AI governance depth: lifecycle safeguards for AI systems and their NIST AI RMF, ISO 42001 and EU AI Act mappings."""

from __future__ import annotations

import copy
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.connectors_runtime import RuntimeGatewayFixtureClient, collect_runtime_gateway_evidence
from security_lakehouse.policy import ControlContext, evaluate_control, validate_rule
from security_lakehouse.safeguards import (
    coverage_by_framework,
    load_safeguards,
    safeguards_by_requirement,
    validate_safeguards,
)

ROOT = Path(__file__).resolve().parents[1]
AI_RMF_MANIFEST = json.loads((ROOT / "frameworks/packs/data/nist_ai_rmf.json").read_text())

# Appended after the 78 safeguards that existed before this pass.
PRIOR_SAFEGUARD_COUNT = 78
AI_SAFEGUARDS = {
    "SG-AIEVALUATION-001": "ai-governance",
    "SG-AITRUSTWORTHINESS-001": "ai-governance",
    "SG-AIPERFORMANCEMONITORING-001": "detection",
    "SG-AIINCIDENT-001": "incident-response",
    "SG-AIPROVENANCE-001": "third-party-risk",
    "SG-AIOVERSIGHT-001": "ai-governance",
    "SG-AIDATAGOVERNANCE-001": "ai-governance",
    "SG-AITRANSPARENCY-001": "ai-governance",
    "SG-AIRUNTIMEACCESS-001": "identity",
    "SG-AIFEEDBACK-001": "ai-governance",
    "SG-AILIFECYCLECHANGE-001": "change-management",
    "SG-AIIMPACT-001": "ai-governance",
    "SG-AISYSTEMSPEC-001": "secure-development",
    "SG-AIRISKTREATMENT-001": "risk-management",
    "SG-AIMEASUREMENTREVIEW-001": "risk-management",
    "SG-AICOMPUTE-001": "availability",
}

# Subcategories about workforce diversity and organizational culture. No
# operated safeguard produces evidence for them, so they stay unmapped rather
# than being attached to a safeguard that does not test them.
AI_RMF_INTENTIONALLY_UNMAPPED = {
    "NIST-AI-RMF-GOVERN-3.1",
    "NIST-AI-RMF-GOVERN-4.1",
    "NIST-AI-RMF-MAP-1.2",
}
# A.2.3 (alignment with other organizational policies) and A.10.4 (customers)
# are policy-level obligations with no AI-system evidence of their own.
ISO_42001_INTENTIONALLY_UNMAPPED = {"ISO42001-2.3", "ISO42001-10.4"}

AI_RMF_SOURCE = {
    "name": "NIST AI 100-1, Artificial Intelligence Risk Management Framework (AI RMF 1.0)",
    "url": AI_RMF_MANIFEST["source"]["pdf"],
    "sha256": AI_RMF_MANIFEST["source"]["pdf_sha256"],
}
AI_RMF_TABLES = {"GOVERN": 1, "MAP": 2, "MEASURE": 3, "MANAGE": 4}
CSF_SOURCE = {
    "name": "NIST Cybersecurity Framework (CSF) 2.0",
    "url": "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf",
    "sha256": "3c31f46fee98cac0c4323453e5109291a213b4de7fef8c058af9bf67f717433c",
}
KNOWN_OWNERS = {"ai-governance", "platform-engineering", "risk-owner", "security-platform"}


def _entries() -> dict[str, dict]:
    return {entry["safeguard_id"]: entry for entry in load_safeguards()["safeguards"]}


def _without_new(payload: dict) -> dict:
    trimmed = copy.deepcopy(payload)
    trimmed["safeguards"] = [s for s in trimmed["safeguards"] if s["safeguard_id"] not in AI_SAFEGUARDS]
    return trimmed


def test_ai_safeguards_are_appended_after_the_existing_ones() -> None:
    ids = [entry["safeguard_id"] for entry in load_safeguards()["safeguards"]]
    assert ids[PRIOR_SAFEGUARD_COUNT : PRIOR_SAFEGUARD_COUNT + len(AI_SAFEGUARDS)] == list(AI_SAFEGUARDS)
    assert not set(ids[:PRIOR_SAFEGUARD_COUNT]) & set(AI_SAFEGUARDS)


def test_ai_safeguards_follow_the_schema() -> None:
    assert validate_safeguards(load_safeguards()) == []
    catalog = load_control_catalog()
    entries = _entries()
    for sid, family in AI_SAFEGUARDS.items():
        entry = entries[sid]
        assert re.fullmatch(r"SG-[A-Z]+-\d{3}", sid)
        assert entry["risk_domain"] == family
        assert len(entry["objective"]) >= 40 and len(entry["evidence_requirement"]) >= 40
        assert validate_rule(entry["evaluation_rule"]) == [], sid
        assert entry["frequency"] == "continuous"
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


def test_every_ai_safeguard_maps_an_ai_framework_requirement() -> None:
    ai_frameworks = {"nist-ai-rmf", "iso-42001-2023", "eu-ai-act-2024-1689"}
    for sid in AI_SAFEGUARDS:
        assert {m["framework_id"] for m in _entries()[sid]["satisfies"]} & ai_frameworks, sid


def test_ai_mappings_are_proposed_and_add_no_attestable_coverage() -> None:
    payload = load_safeguards()
    for sid in AI_SAFEGUARDS:
        for member in _entries()[sid]["satisfies"]:
            assert member["review_status"] == "proposed", (sid, member["control_id"])
            assert "review_basis" not in member
            assert "mapping_basis" not in member

    before, after = coverage_by_framework(_without_new(payload)), coverage_by_framework(payload)
    assert after["reviewed"] == before["reviewed"]
    assert after["maintainer_reviewed_mappings"] == before["maintainer_reviewed_mappings"]
    assert after["covered"] > before["covered"]


def test_citations_point_at_the_pinned_publication_of_each_requirement() -> None:
    """AI RMF members cite NIST AI 100-1 and CSF members cite CSF 2.0; nothing else claims a source."""
    for sid in AI_SAFEGUARDS:
        for member in _entries()[sid]["satisfies"]:
            source = member.get("mapping_source")
            control_id = member["control_id"]
            if member["framework_id"] == "nist-ai-rmf":
                function, number = control_id.removeprefix("NIST-AI-RMF-").split("-", 1)
                locator = f"AI RMF Core, Table {AI_RMF_TABLES[function]}, {function} {number}"
                assert source == {**AI_RMF_SOURCE, "locator": locator}
            elif member["framework_id"] == "nist-csf-2.0":
                subcategory = control_id.removeprefix("NIST-CSF-")
                assert source == {**CSF_SOURCE, "locator": f"NIST CSF 2.0 Core, Appendix A, {subcategory}"}
            else:
                assert source is None, (sid, control_id)


def test_evidence_requirement_names_its_evidence_basis() -> None:
    catalog = json.loads((ROOT / "connectors/catalog.json").read_text())
    connector_ids = {row["connector_id"] for row in catalog["connectors"]}
    for sid in AI_SAFEGUARDS:
        text = _entries()[sid]["evidence_requirement"]
        named = {cid for cid in connector_ids if f"`{cid}`" in text}
        assert named or "Attested evidence" in text, sid
        assert not (set(re.findall(r"`([a-z0-9-]+)`", text)) - connector_ids), f"{sid} names an unknown connector"


def test_nist_ai_rmf_coverage_leaves_only_the_documented_gaps() -> None:
    catalog = load_control_catalog()
    ai_rmf = {cid for cid, row in catalog.items() if row["framework_id"] == "nist-ai-rmf"}
    assert len(ai_rmf) == 72
    unmapped = ai_rmf - set(safeguards_by_requirement())
    assert unmapped == AI_RMF_INTENTIONALLY_UNMAPPED
    assert coverage_by_framework()["frameworks"]["nist-ai-rmf"]["covered"] == 69


def test_iso_42001_annex_a_coverage_leaves_only_the_documented_gaps() -> None:
    catalog = load_control_catalog()
    iso = {cid for cid, row in catalog.items() if row["framework_id"] == "iso-42001-2023"}
    assert iso - set(safeguards_by_requirement()) == ISO_42001_INTENTIONALLY_UNMAPPED


def test_runtime_gateway_evidence_reaches_the_runtime_access_safeguard() -> None:
    """Every runtime-gateway row carries a requirement the runtime access safeguard claims.

    Without that link the safeguard would name a connector whose evidence never
    lands on any of its requirements.
    """
    claimed = {m["control_id"] for m in _entries()["SG-AIRUNTIMEACCESS-001"]["satisfies"]}
    rows = collect_runtime_gateway_evidence(
        RuntimeGatewayFixtureClient(ROOT / "tests" / "fixtures" / "runtime-gateway"),
        collected_at=datetime(2026, 6, 1, 12, 0, tzinfo=UTC),
    )
    assert rows
    for row in rows:
        assert set(row["controls"]) & claimed, row["event_id"]


@pytest.mark.parametrize(
    "facts,expected",
    [
        ({"event_count": 0, "evidence_count": 0}, "fail"),
        ({"event_count": 1, "evidence_count": 1, "evidence_status": "stale"}, "fail"),
        ({"event_count": 1, "evidence_count": 1, "open_violation_count": 1, "max_severity": "high"}, "fail"),
        ({"event_count": 1, "evidence_count": 1, "evidence_status": "fresh"}, "pass"),
    ],
)
def test_ai_safeguards_evaluate_to_the_expected_status(facts: dict, expected: str) -> None:
    entries = _entries()
    for sid in AI_SAFEGUARDS:
        result = evaluate_control(ControlContext(control_id=sid, **facts), entries[sid]["evaluation_rule"])
        assert result.status == expected, (sid, facts)


def test_ai_context_doc_lists_every_ai_safeguard_and_every_documented_gap() -> None:
    doc = (ROOT / "docs" / "CCF_AI_CONTEXT.md").read_text(encoding="utf-8")
    entries = _entries()
    for sid in AI_SAFEGUARDS:
        assert f"`{sid}` {entries[sid]['title']}" in doc, sid
    for control_id in AI_RMF_INTENTIONALLY_UNMAPPED:
        function, number = control_id.removeprefix("NIST-AI-RMF-").split("-", 1)
        assert f"{function} {number}" in doc, control_id
    for control_id in ISO_42001_INTENTIONALLY_UNMAPPED:
        assert "A." + control_id.removeprefix("ISO42001-") in doc, control_id

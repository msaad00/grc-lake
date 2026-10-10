"""Semantic accuracy guards for the shipped catalog and safeguard mappings."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from security_lakehouse.safeguards import load_safeguards

ROOT = Path(__file__).resolve().parents[1]


def _labels_by_framework_id(rows: list[dict]) -> dict[str, set[str]]:
    labels: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        labels[row["framework_id"]].add(row["framework"])
    return labels


def test_each_framework_id_has_one_display_label() -> None:
    # Scores group by label, so two labels split one framework into two score rows.
    catalog = json.loads((ROOT / "controls/catalog.json").read_text())["controls"]
    split = {fid: sorted(labels) for fid, labels in _labels_by_framework_id(catalog).items() if len(labels) > 1}
    assert split == {}


def test_control_map_labels_match_catalog() -> None:
    catalog = {
        row["control_id"]: row["framework"]
        for row in json.loads((ROOT / "controls/catalog.json").read_text())["controls"]
    }
    control_map = json.loads((ROOT / "mappings/control_map.json").read_text())["controls"]
    mismatched = [
        row["control_id"] for row in control_map if catalog.get(row["control_id"], row["framework"]) != row["framework"]
    ]
    assert mismatched == []


def test_hipaa_references_use_cfr_citation_form() -> None:
    catalog = json.loads((ROOT / "controls/catalog.json").read_text())["controls"]
    refs = [row["framework_ref"] for row in catalog if row["framework_id"] == "hipaa-security-rule"]
    assert refs and all(ref.startswith("45 CFR §164.") for ref in refs), refs


def _members(safeguard_id: str) -> set[str]:
    safeguard = next(s for s in load_safeguards()["safeguards"] if s["safeguard_id"] == safeguard_id)
    return {member["control_id"] for member in safeguard["satisfies"]}


@pytest.mark.parametrize(
    ("control_id", "home"),
    [
        ("HIPAA-164.310(a)", "SG-PHYSICAL-001"),
        ("NIST-800-53-PE-5", "SG-PHYSICAL-001"),
        ("NIST-800-53-SC-7.7", "SG-NETWORK-001"),
        ("NIST-800-53-SC-7.8", "SG-NETWORK-001"),
        ("CIS-AWS-5.2", "SG-NETWORK-001"),
        ("NIST-800-171R3-03.07.05", "SG-NONLOCALMAINTENANCE-001"),
        ("CMMC-3.7.5", "SG-NONLOCALMAINTENANCE-001"),
        ("CMMC-3.1.21", "SG-DATAPROTECTION-001"),
        ("NIST-800-53-AU-9.4", "SG-LOGGING-001"),
        ("NIST-800-53-CP-7.2", "SG-AVAILABILITY-001"),
        ("NIST-800-53-RA-5.5", "SG-VULNSCANNING-001"),
        ("CMMC-3.14.1", "SG-VULNREMEDIATION-001"),
        ("CIS-AWS-1.1", "SG-INCIDENTPLAN-001"),
        ("SOC2-P3.1", "SG-PROCESSINGRECORDS-001"),
    ],
)
def test_non_identity_requirements_live_with_their_own_safeguard(control_id: str, home: str) -> None:
    assert control_id not in _members("SG-IDENTITY-001")
    assert control_id in _members(home)


def test_hipaa_person_or_entity_authentication_maps_to_identity() -> None:
    assert "HIPAA-164.312(d)" in _members("SG-IDENTITY-001")

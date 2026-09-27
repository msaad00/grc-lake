"""Coverage floors for the frameworks buyers audit against most.

Floors only move up: a curation change that drops a requirement out of the CCF
for one of these frameworks must be a deliberate decision, not a side effect.
Title-theme mappings are evaluatable coverage, never attested coverage.
"""

from __future__ import annotations

import pytest

from security_lakehouse.safeguards import coverage_by_framework, load_safeguards

COVERED_FLOORS = {
    "iso-27001-2022": 81,
    "nist-csf-2.0": 101,
    "iso-27017-2015": 44,
    "nist-ai-rmf": 28,
    "fedramp-moderate": 262,
    "nist-800-53-rev5": 285,
    "gdpr-2016-679": 19,
    "nist-rmf-800-37r2": 46,
}


@pytest.mark.parametrize(("framework_id", "floor"), sorted(COVERED_FLOORS.items()))
def test_priority_framework_coverage_does_not_regress(framework_id: str, floor: int) -> None:
    covered = coverage_by_framework()["frameworks"][framework_id]["covered"]
    assert covered >= floor, f"{framework_id} covers {covered} requirements, floor is {floor}"


def test_title_theme_mappings_are_never_counted_as_reviewed() -> None:
    for safeguard in load_safeguards()["safeguards"]:
        for member in safeguard["satisfies"]:
            if member.get("mapping_basis") == "title_theme":
                assert member["review_status"] == "proposed", (safeguard["safeguard_id"], member["control_id"])
                assert "review_basis" not in member, (safeguard["safeguard_id"], member["control_id"])


def test_source_backed_lane_safeguards_carry_no_title_theme_members() -> None:
    """A safeguard built from one published crosswalk row stays that narrow."""
    for safeguard in load_safeguards()["safeguards"]:
        if "mapping_source" not in safeguard:
            continue
        themed = [m["control_id"] for m in safeguard["satisfies"] if m.get("mapping_basis") == "title_theme"]
        assert themed == [], (safeguard["safeguard_id"], themed)


def test_a_requirement_is_mapped_at_most_once_per_safeguard() -> None:
    for safeguard in load_safeguards()["safeguards"]:
        ids = [m["control_id"] for m in safeguard["satisfies"]]
        assert len(ids) == len(set(ids)), safeguard["safeguard_id"]

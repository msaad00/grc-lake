"""CCF categories: a small, stable grouping above the control families."""

from __future__ import annotations

import json
from http import HTTPStatus
from pathlib import Path

import pytest

from security_lakehouse import api_v1
from security_lakehouse.cli import main
from security_lakehouse.oscal import build_component_definition
from security_lakehouse.safeguards import (
    DEFAULT_FAMILIES,
    coverage_by_category,
    coverage_by_family,
    coverage_by_framework,
    load_ccf_categories,
    load_ccf_families,
    load_safeguards,
    validate_ccf_taxonomy,
)

# Category ids are joined on by the API, CLI, console and OSCAL export, so the
# set and order are pinned. Adding or renaming one is a deliberate change.
EXPECTED_CATEGORIES = [
    "governance-risk",
    "identity-access",
    "data-privacy",
    "secure-engineering",
    "infrastructure-security",
    "detection-response",
    "resilience",
    "third-party",
    "people-physical",
    "ai-governance",
]


def _families_payload() -> dict:
    return json.loads(Path(DEFAULT_FAMILIES).read_text(encoding="utf-8"))


def test_categories_are_the_pinned_small_set() -> None:
    categories = load_ccf_categories()
    assert [row["category_id"] for row in categories] == EXPECTED_CATEGORIES
    for row in categories:
        assert row["label"] and len(row["description"]) >= 30


def test_every_family_belongs_to_exactly_one_known_category() -> None:
    categories = {row["category_id"] for row in load_ccf_categories()}
    families = load_ccf_families()
    assert len(families) == 21
    for family_id, family in families.items():
        assert family["category"] in categories, family_id
    used = {family["category"] for family in families.values()}
    assert used == categories, "a category with no families is dead taxonomy"
    assert validate_ccf_taxonomy(_families_payload()) == []


def test_taxonomy_validation_rejects_missing_and_unknown_categories() -> None:
    payload = _families_payload()
    payload["families"][0].pop("category")
    payload["families"][1]["category"] = "not-a-category"
    payload["categories"].append({"category_id": "empty", "label": "Empty", "description": "No family uses it."})
    problems = validate_ccf_taxonomy(payload)
    assert any("missing category" in p for p in problems)
    assert any("unknown category 'not-a-category'" in p for p in problems)
    assert any("category 'empty' has no families" in p for p in problems)


def test_taxonomy_validation_rejects_duplicate_category_ids() -> None:
    payload = _families_payload()
    payload["categories"].append(dict(payload["categories"][0]))
    assert any("duplicate category" in p for p in validate_ccf_taxonomy(payload))


def test_family_rows_carry_their_category() -> None:
    labels = {row["category_id"]: row["label"] for row in load_ccf_categories()}
    families = load_ccf_families()
    for row in coverage_by_family():
        assert row["category_id"] == families[row["family_id"]]["category"]
        assert row["category_label"] == labels[row["category_id"]]


def test_category_rollup_reconciles_with_the_family_ledger() -> None:
    families = coverage_by_family()
    categories = coverage_by_category()
    assert [row["category_id"] for row in categories] == EXPECTED_CATEGORIES
    assert sum(row["safeguard_count"] for row in categories) == len(load_safeguards()["safeguards"])
    assert sum(row["mapping_count"] for row in categories) == sum(row["mapping_count"] for row in families)
    assert sum(row["reviewed_mapping_count"] for row in categories) == sum(
        row["reviewed_mapping_count"] for row in families
    )
    by_family = {row["family_id"]: row for row in families}
    for row in categories:
        assert row["family_ids"]
        assert row["safeguard_count"] == sum(by_family[f]["safeguard_count"] for f in row["family_ids"])
        assert row["family_count"] == len(row["family_ids"])
        # Distinct requirements, not a sum: two families can touch the same one.
        assert row["mapped_requirement_count"] <= sum(
            by_family[f]["mapped_requirement_count"] for f in row["family_ids"]
        )
        assert row["state"] in {"reviewed", "partially_reviewed", "proposed_only"}


def test_coverage_payload_includes_categories() -> None:
    cov = coverage_by_framework()
    assert [row["category_id"] for row in cov["categories"]] == EXPECTED_CATEGORIES


def test_ccf_coverage_api_returns_categories(tmp_path: Path) -> None:
    status, body = api_v1.handle_get("/api/v1/ccf/coverage", {}, tmp_path)
    assert status == HTTPStatus.OK
    data = body["data"]
    assert [row["category_id"] for row in data["categories"]] == EXPECTED_CATEGORIES
    assert all(row["category_id"] in EXPECTED_CATEGORIES for row in data["families"])


def test_oscal_components_name_their_category() -> None:
    families = load_ccf_families()
    safeguards = {s["safeguard_id"]: s for s in load_safeguards()["safeguards"]}
    doc = build_component_definition()
    components = doc["component-definition"]["components"]
    assert components
    for component in components:
        props = {p["name"]: p["value"] for p in component.get("props", [])}
        sid = props["trustops-safeguard-id"]
        assert props["trustops-category"] == families[safeguards[sid]["risk_domain"]]["category"]


def test_cli_groups_families_under_categories(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["frameworks", "safeguards", "--format", "table"]) == 0
    out = capsys.readouterr().out
    labels = [row["label"] for row in load_ccf_categories()]
    positions = [out.index(f"{label} (") for label in labels]
    assert positions == sorted(positions), "categories print in taxonomy order"
    # Each family line sits under its own category heading.
    families = load_ccf_families()
    category_labels = {row["category_id"]: row["label"] for row in load_ccf_categories()}
    for family in families.values():
        family_at = out.index(f"  {family['label']}")
        heading_at = out.index(f"{category_labels[family['category']]} (")
        later_headings = [p for p in positions if p > heading_at]
        assert heading_at < family_at < (later_headings[0] if later_headings else len(out))

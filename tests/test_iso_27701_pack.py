"""ISO/IEC 27701:2025 privacy pack: source provenance, catalog integrity, evidence wiring."""

from __future__ import annotations

import json
import re
from pathlib import Path

from security_lakehouse.catalog import load_control_catalog, load_framework_registry, validate_catalog
from security_lakehouse.evidence_hints import resolve_connector_hints
from security_lakehouse.io import read_jsonl
from security_lakehouse.limited_packs import LIMITED_PACK_MINIMUMS, iso_27701_2025_limited_pack_specs
from security_lakehouse.mappings import load_control_article_mappings
from security_lakehouse.pack_data import PACK_DATA_DIR
from security_lakehouse.pipeline import run_pipeline
from security_lakehouse.safeguards import load_safeguards, validate_safeguards

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((PACK_DATA_DIR / "iso_27701_2025.json").read_text(encoding="utf-8"))
FIXTURE = ROOT / "tests" / "fixtures" / "iso_27701_privacy_events.jsonl"
FRAMEWORK_ID = "iso-27701-2025"
REPUTABLE_KINDS = {"standards_body", "certification_body"}


def _annex_a_2025_ids() -> set[str]:
    """Annex A structure: tables A.1 (31), A.2 (18), A.3 (29) = 78 controls."""
    ranges = {
        "A.1.2": range(2, 10),
        "A.1.3": range(2, 12),
        "A.1.4": range(2, 11),
        "A.1.5": range(2, 6),
        "A.2.2": range(2, 8),
        "A.2.3": range(2, 3),
        "A.2.4": range(2, 5),
        "A.2.5": range(2, 10),
    }
    ids = {f"{prefix}.{n}" for prefix, numbers in ranges.items() for n in numbers}
    ids |= {f"A.3.{n}" for n in range(3, 32)}
    return ids


def _pack_controls() -> dict[str, dict]:
    return {cid: c for cid, c in load_control_catalog().items() if c["framework_id"] == FRAMEWORK_ID}


def test_annex_a_structure_has_78_controls() -> None:
    ids = _annex_a_2025_ids()
    assert len(ids) == 78
    assert sum(1 for i in ids if i.startswith("A.1.")) == 31
    assert sum(1 for i in ids if i.startswith("A.2.")) == 18
    assert sum(1 for i in ids if i.startswith("A.3.")) == 29


def test_every_source_is_pinned() -> None:
    sources = MANIFEST["verification_sources"]
    assert sources
    for key, source in sources.items():
        assert source["url"].startswith("https://"), key
        assert re.fullmatch(r"[0-9a-f]{64}", source["sha256"]), key
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", source["pulled_at"]), key
        assert source["kind"] in REPUTABLE_KINDS | {"vendor"}, key
        assert source["publisher"], key


def test_every_seeded_row_has_two_independent_reputable_sources() -> None:
    sources = MANIFEST["verification_sources"]
    for row in MANIFEST["rows"]:
        cited = row["verified_by"]
        assert set(cited) <= set(sources), row["id"]
        publishers = {sources[key]["publisher"] for key in cited if sources[key]["kind"] in REPUTABLE_KINDS}
        assert len(publishers) >= 2, f"{row['id']} needs two independent non-vendor sources, has {publishers}"


def test_rows_and_gaps_partition_annex_a_exactly() -> None:
    seeded = {row["id"] for row in MANIFEST["rows"]}
    gaps = {gap["id"] for gap in MANIFEST["gaps"]}
    assert not seeded & gaps
    assert seeded | gaps == _annex_a_2025_ids()
    for gap in MANIFEST["gaps"]:
        assert gap["reason"], gap["id"]
        assert "title" not in gap, "gaps must not carry unverified titles"


def test_titles_are_short_identifiers_only() -> None:
    for row in MANIFEST["rows"]:
        title = row["title"]
        assert 0 < len(title) <= 60, row["id"]
        assert len(title.split()) <= 8, row["id"]


def test_catalog_seeds_exactly_the_verified_rows() -> None:
    controls = _pack_controls()
    expected = {f"ISO27701-{row['id']}" for row in MANIFEST["rows"]}
    assert set(controls) == expected
    assert LIMITED_PACK_MINIMUMS[FRAMEWORK_ID] == len(expected)
    mappings = load_control_article_mappings()
    for control_id, control in controls.items():
        article_id = control_id.removeprefix("ISO27701-")
        assert control["framework_ref"] == f"ISO/IEC 27701:2025 {article_id}"
        assert control["review_status"] == "proposed"
        assert control["source_reconciled_by"] == "automated-source-reconciliation"
        assert control["source_url"] == "https://www.iso.org/standard/27701"
        assert [a["article_id"] for a in mappings[control_id]["articles"]] == [article_id]
    assert validate_catalog() == []


def test_builder_matches_manifest() -> None:
    specs = list(iso_27701_2025_limited_pack_specs())
    assert [s.article_id for s in specs] == [row["id"] for row in MANIFEST["rows"]]
    for spec in specs:
        assert spec.required_evidence_types


def test_registry_marks_2019_withdrawn_and_2025_limited() -> None:
    registry = load_framework_registry()
    current = registry["iso-27701-2025"]
    assert current["implementation_status"] == "implemented_limited_mapping"
    assert current["effective_date"] == "2025-10-14"
    assert current["official_source_url"] == "https://www.iso.org/standard/27701"
    assert str(len(MANIFEST["rows"])) in current["coverage_boundary"]
    withdrawn = registry["iso-27701-2019"]
    assert withdrawn["implementation_status"] == "planned"
    assert withdrawn["superseded_by"] == "iso-27701-2025"
    assert "withdrawn" in withdrawn["coverage_boundary"]
    assert not [c for c in load_control_catalog().values() if c["framework_id"] == "iso-27701-2019"]


def test_every_control_has_evidence_types_and_connector_hints() -> None:
    for control_id, control in _pack_controls().items():
        assert control["required_evidence_types"], control_id
        hints = resolve_connector_hints(
            framework_id=FRAMEWORK_ID,
            control=control,
            article_ids=[control_id.removeprefix("ISO27701-")],
        )
        assert hints, control_id
        assert hints[0]["priority"] == "primary"


def test_safeguard_mappings_are_proposed_and_valid() -> None:
    payload = load_safeguards()
    assert validate_safeguards(payload) == []
    members = [m for s in payload["safeguards"] for m in s["satisfies"] if m["framework_id"] == FRAMEWORK_ID]
    assert members
    assert all(m["review_status"] == "proposed" for m in members)
    assert all(m["role"] != "primary" for m in members)
    mapped = {
        m["control_id"]: s["safeguard_id"]
        for s in payload["safeguards"]
        for m in s["satisfies"]
        if m["framework_id"] == FRAMEWORK_ID
    }
    assert mapped == {
        "ISO27701-A.1.4.7": "SG-DATARETENTION-001",
        "ISO27701-A.2.4.2": "SG-DATARETENTION-001",
        "ISO27701-A.1.5.5": "SG-DATAINVENTORY-001",
        "ISO27701-A.2.5.4": "SG-DATAINVENTORY-001",
        "ISO27701-A.2.5.7": "SG-THIRDPARTYRISK-001",
        "ISO27701-A.2.5.9": "SG-THIRDPARTYRISK-001",
        "ISO27701-A.1.5.2": "SG-CROSSBORDERTRANSFER-001",
        "ISO27701-A.2.5.2": "SG-CROSSBORDERTRANSFER-001",
    }


def test_fixture_covers_every_privacy_evidence_type_through_pipeline(tmp_path: Path) -> None:
    required = {t for c in _pack_controls().values() for t in c["required_evidence_types"]}
    new_privacy_types = {t for t in required if t.startswith("privacy.")}
    events = read_jsonl(FIXTURE)
    assert new_privacy_types <= {e["event_type"] for e in events}

    run_pipeline(FIXTURE, tmp_path)
    tests = {row["control_id"]: row for row in read_jsonl(tmp_path / "gold" / "control_tests.jsonl")}
    for control_id, control in _pack_controls().items():
        if not set(control["required_evidence_types"]) <= new_privacy_types:
            continue
        row = tests[control_id]
        assert row["required_evidence_types"] == control["required_evidence_types"]
        assert row["missing_evidence_types"] == [], control_id

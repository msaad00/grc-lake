"""EU NIS2 (Directive (EU) 2022/2555) and DORA (Regulation (EU) 2022/2554) packs.

Each pack seeds article/paragraph identifiers with short titles, pins the
Official Journal PDF served by the EU Publications Office by sha256, and maps
requirements to existing CCF safeguards as proposed only.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from security_lakehouse.catalog import load_control_catalog, load_framework_registry, validate_catalog
from security_lakehouse.evidence_hints import resolve_connector_hints
from security_lakehouse.framework_packs import (
    PACK_BUILDERS,
    SOURCE_RECONCILED_PACKS,
    pack_control_row,
    pack_mapping_row,
)
from security_lakehouse.graph import _framework_from_control
from security_lakehouse.io import read_jsonl
from security_lakehouse.limited_packs import LIMITED_PACK_MINIMUMS, dora_limited_pack_specs, nis2_limited_pack_specs
from security_lakehouse.mappings import load_control_article_mappings
from security_lakehouse.pipeline import run_pipeline
from security_lakehouse.safeguards import coverage_by_framework, load_safeguards, validate_safeguards

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "frameworks" / "packs" / "data"
FIXTURE = ROOT / "tests" / "fixtures" / "eu_resilience_events.jsonl"
ARTICLE_ID = re.compile(r"^Art(\d+)(\.(\d+)(\(([a-z])\))?)?$")
NEW_EVIDENCE_TYPES = {"incident.regulatory_report", "resilience.test_report", "third_party.register"}

PACKS = {
    "nis2-2022-2555": {
        "manifest": "nis2_2022_2555.json",
        "prefix": "NIS2-",
        "pack": "nis2",
        "builder": nis2_limited_pack_specs,
        "celex": "32022L2555",
        "eli": "http://data.europa.eu/eli/dir/2022/2555/oj",
        "official_source_url": "https://eur-lex.europa.eu/eli/dir/2022/2555/oj",
        "act": "Directive (EU) 2022/2555",
    },
    "dora-2022-2554": {
        "manifest": "dora_2022_2554.json",
        "prefix": "DORA-",
        "pack": "dora",
        "builder": dora_limited_pack_specs,
        "celex": "32022R2554",
        "eli": "http://data.europa.eu/eli/reg/2022/2554/oj",
        "official_source_url": "https://eur-lex.europa.eu/eli/reg/2022/2554/oj",
        "act": "Regulation (EU) 2022/2554",
    },
}

NIS2_IDS = {f"Art21.2({p})" for p in "abcdefghij"} | {"Art23.1", "Art23.2"} | {f"Art23.4({p})" for p in "abcde"}

# DORA chapters the pack seeds, by article, and how many rows each article has.
DORA_ARTICLE_ROWS = {
    5: 4,
    6: 8,
    7: 1,
    8: 7,
    9: 9,
    10: 3,
    11: 9,
    12: 6,
    13: 7,
    14: 3,
    16: 1,
    17: 3,
    18: 2,
    19: 5,
    24: 6,
    25: 1,
    26: 6,
    27: 3,
    28: 8,
    29: 2,
    30: 3,
    45: 2,
}

DORA_UNMAPPED = {
    "Art6.3",
    "Art11.7",
    "Art11.10",
    "Art13.7",
    "Art14.2",
    "Art16.1",
    "Art18.2",
    "Art24.3",
    "Art26.1",
    "Art26.2",
    "Art26.3",
    "Art26.5",
    "Art26.6",
    "Art26.8",
    "Art27.1",
    "Art27.2",
    "Art27.3",
    "Art29.1",
    "Art45.1",
    "Art45.3",
}


def _manifest(framework_id: str) -> dict:
    return json.loads((DATA / PACKS[framework_id]["manifest"]).read_text(encoding="utf-8"))


def _controls(framework_id: str) -> dict[str, dict]:
    return {cid: c for cid, c in load_control_catalog().items() if c["framework_id"] == framework_id}


def _members(framework_id: str) -> list[tuple[str, dict]]:
    return [
        (entry["safeguard_id"], member)
        for entry in load_safeguards()["safeguards"]
        for member in entry["satisfies"]
        if member["framework_id"] == framework_id
    ]


def article_ref(article_id: str) -> str:
    """``Art21.2(a)`` -> ``Article 21(2)(a)``."""
    match = ARTICLE_ID.match(article_id)
    assert match, article_id
    article, _, paragraph, _, point = match.groups()
    return f"Article {article}" + (f"({paragraph})" if paragraph else "") + (f"({point})" if point else "")


def test_article_ref_formats_eu_citations() -> None:
    assert article_ref("Art21.2(a)") == "Article 21(2)(a)"
    assert article_ref("Art23.1") == "Article 23(1)"
    assert article_ref("Art7") == "Article 7"


@pytest.mark.parametrize("framework_id", sorted(PACKS))
def test_source_is_pinned_to_the_official_journal(framework_id: str) -> None:
    spec = PACKS[framework_id]
    source = _manifest(framework_id)["source"]
    assert source["celex"] == spec["celex"]
    assert source["eli"] == spec["eli"]
    assert source["pdf"].startswith("https://publications.europa.eu/resource/cellar/")
    assert re.fullmatch(r"[0-9a-f]{64}", source["pdf_sha256"])
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", source["pulled_at"])
    assert source["official_journal"].startswith("OJ L 333, 27.12.2022")
    registry = load_framework_registry()[framework_id]
    assert registry["implementation_status"] == "implemented_limited_mapping"
    assert registry["official_source_url"] == spec["official_source_url"]
    assert registry["source_sha256"] == source["pdf_sha256"]
    assert registry["pulled_at"] == source["pulled_at"]
    assert str(len(_manifest(framework_id)["rows"])) in registry["coverage_boundary"]
    assert SOURCE_RECONCILED_PACKS[framework_id] == source["pulled_at"]


@pytest.mark.parametrize("framework_id", sorted(PACKS))
def test_rows_are_short_identifiers_with_evidence_wiring(framework_id: str) -> None:
    rows = _manifest(framework_id)["rows"]
    ids = [row["id"] for row in rows]
    assert len(ids) == len(set(ids))
    for row in rows:
        assert ARTICLE_ID.match(row["id"]), row["id"]
        assert 0 < len(row["title"]) <= 90, row["id"]
        assert len(row["title"].split()) <= 12, row["id"]
        assert row["required_evidence_types"], row["id"]
        assert row["asset_types"], row["id"]
        assert row["risk_domain"] and row["owner"], row["id"]


def test_nis2_seeds_article_21_measures_and_article_23_reporting() -> None:
    assert {row["id"] for row in _manifest("nis2-2022-2555")["rows"]} == NIS2_IDS


def test_dora_seeds_the_requested_chapters() -> None:
    manifest = _manifest("dora-2022-2554")
    per_article: dict[int, int] = {}
    for row in manifest["rows"]:
        article = int(ARTICLE_ID.match(row["id"]).group(1))
        per_article[article] = per_article.get(article, 0) + 1
    assert per_article == DORA_ARTICLE_ROWS
    not_seeded = {entry["article"]: entry for entry in manifest["not_seeded"]}
    assert {20, 21, 22, 23, 15} <= set(not_seeded)
    assert all(entry["reason"] for entry in not_seeded.values())
    rts = manifest["related_acts"][0]
    assert rts["celex"] == "32024R1774"
    assert rts["status"] == "not_seeded"
    assert re.fullmatch(r"[0-9a-f]{64}", rts["pdf_sha256"])


@pytest.mark.parametrize("framework_id", sorted(PACKS))
def test_catalog_rows_are_generated_from_the_builder(framework_id: str) -> None:
    spec = PACKS[framework_id]
    specs = list(spec["builder"]())
    manifest = _manifest(framework_id)
    assert [s.article_id for s in specs] == [row["id"] for row in manifest["rows"]]
    controls = _controls(framework_id)
    mappings = load_control_article_mappings()
    assert set(controls) == {s.control_id for s in specs}
    for s in specs:
        assert s.control_id == spec["prefix"] + s.article_id
        assert controls[s.control_id] == pack_control_row(s)
        assert mappings[s.control_id] == pack_mapping_row(s)
        assert controls[s.control_id]["framework_ref"] == f"{spec['act']} {article_ref(s.article_id)}"
        assert controls[s.control_id]["review_status"] == "proposed"
        assert controls[s.control_id]["reviewed_by"] == "automated-source-reconciliation"
        assert _framework_from_control(s.control_id) == framework_id
    assert spec["pack"] in PACK_BUILDERS
    assert LIMITED_PACK_MINIMUMS[framework_id] == len(specs)
    assert validate_catalog() == []


@pytest.mark.parametrize("framework_id", sorted(PACKS))
def test_every_control_has_connector_hints(framework_id: str) -> None:
    prefix = PACKS[framework_id]["prefix"]
    for control_id, control in _controls(framework_id).items():
        assert control["required_evidence_types"], control_id
        hints = resolve_connector_hints(
            framework_id=framework_id, control=control, article_ids=[control_id.removeprefix(prefix)]
        )
        assert hints and hints[0]["priority"] == "primary", control_id


@pytest.mark.parametrize("framework_id", sorted(PACKS))
def test_mappings_are_proposed_and_cite_the_pinned_article(framework_id: str) -> None:
    payload = load_safeguards()
    assert validate_safeguards(payload) == []
    source = _manifest(framework_id)["source"]
    prefix = PACKS[framework_id]["prefix"]
    lanes = {entry["safeguard_id"] for entry in payload["safeguards"] if "mapping_source" in entry}
    members = _members(framework_id)
    assert members
    for sid, member in members:
        assert sid not in lanes
        assert member["review_status"] == "proposed"
        assert member["role"] == "equivalent"
        assert member["mapping_source"] == {
            "name": source["name"],
            "url": source["pdf"],
            "sha256": source["pdf_sha256"],
            "locator": article_ref(member["control_id"].removeprefix(prefix)),
        }


@pytest.mark.parametrize("framework_id", sorted(PACKS))
def test_unmapped_rows_are_documented(framework_id: str) -> None:
    manifest = _manifest(framework_id)
    prefix = PACKS[framework_id]["prefix"]
    mapped = {member["control_id"].removeprefix(prefix) for _, member in _members(framework_id)}
    unmapped = {row["id"] for row in manifest["rows"]} - mapped
    documented = {gap["id"]: gap["reason"] for gap in manifest["unmapped"]}
    assert unmapped == set(documented)
    assert all(documented.values())
    if framework_id == "dora-2022-2554":
        assert unmapped == DORA_UNMAPPED
    else:
        assert unmapped == set()
    coverage = coverage_by_framework()["frameworks"][framework_id]
    assert coverage["controls"] == len(manifest["rows"])
    assert coverage["covered"] == len(manifest["rows"]) - len(unmapped)
    assert coverage["maintainer_reviewed"] == coverage["org_reviewed"] == 0


def test_fixture_covers_every_new_evidence_type_through_pipeline(tmp_path: Path) -> None:
    controls = {**_controls("nis2-2022-2555"), **_controls("dora-2022-2554")}
    required = {t for c in controls.values() for t in c["required_evidence_types"]}
    assert required >= NEW_EVIDENCE_TYPES
    events = read_jsonl(FIXTURE)
    assert {e["event_type"] for e in events} >= NEW_EVIDENCE_TYPES

    run_pipeline(FIXTURE, tmp_path)
    tests = {row["control_id"]: row for row in read_jsonl(tmp_path / "gold" / "control_tests.jsonl")}
    checked = 0
    for control_id, control in controls.items():
        if not set(control["required_evidence_types"]) <= NEW_EVIDENCE_TYPES:
            continue
        if control_id not in {c for e in events for c in e["controls"]}:
            continue
        row = tests[control_id]
        assert row["required_evidence_types"] == control["required_evidence_types"]
        assert row["missing_evidence_types"] == [], control_id
        checked += 1
    assert checked >= 3

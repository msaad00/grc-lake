"""EU AI Act rows carry the meaning of the article they cite.

Article 49 of Regulation (EU) 2024/1689 is "Registration"; the fundamental
rights impact assessment is Article 27. The catalog once gave Art.49 the FRIA
title, and a safeguard mapping followed that wrong meaning.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.catalog_versions import controls_as_of
from security_lakehouse.limited_packs import eu_ai_act_limited_pack_specs
from security_lakehouse.mappings import load_control_article_mappings
from security_lakehouse.safeguards import load_safeguards

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "frameworks/packs/data/eu_ai_act_2024_1689.json").read_text(encoding="utf-8"))
CONTROL_MAP = json.loads((ROOT / "mappings/control_map.json").read_text(encoding="utf-8"))


def _rows() -> dict[str, dict]:
    return {row["id"]: row for row in MANIFEST["rows"]}


def _homes(control_id: str) -> dict[str, dict]:
    return {
        entry["safeguard_id"]: member
        for entry in load_safeguards()["safeguards"]
        for member in entry["satisfies"]
        if member["control_id"] == control_id
    }


def test_manifest_pins_the_official_text() -> None:
    source = MANIFEST["source"]
    assert source["celex"] == "32024R1689"
    assert source["pdf"].startswith("https://publications.europa.eu/resource/cellar/")
    assert re.fullmatch(r"[0-9a-f]{64}", source["pdf_sha256"])


def test_article_49_is_registration_and_27_is_the_fria() -> None:
    rows = _rows()
    assert "registration" in rows["Art.49"]["title"].lower()
    assert "impact assessment" not in rows["Art.49"]["title"].lower()
    assert "fundamental rights impact assessment" in rows["Art.27"]["title"].lower()
    assert [spec.article_id for spec in eu_ai_act_limited_pack_specs()] == list(rows)


def test_catalog_and_mappings_follow_the_manifest() -> None:
    catalog = load_control_catalog()
    articles = load_control_article_mappings()
    control_map = {row["control_id"]: row for row in CONTROL_MAP["controls"]}
    for ref, row in _rows().items():
        control_id = f"EU-AI-ACT-{ref}"
        assert catalog[control_id]["title"] == row["title"], control_id
        assert articles[control_id]["articles"][0]["title"] == row["title"][:120], control_id
        assert control_map[control_id]["title"] == row["title"][:120], control_id


def test_corrected_rows_are_versioned_and_unreviewed() -> None:
    catalog = load_control_catalog()
    art49 = catalog["EU-AI-ACT-Art.49"]
    assert art49["version"] == "1.1.0"
    assert art49["supersedes"] == "EU-AI-ACT-Art.49@1.0.0"
    assert art49["review_status"] == "proposed"
    assert art49["source_reconciled_by"] == "automated-source-reconciliation"
    before = controls_as_of("2026-09-01")["EU-AI-ACT-Art.49"]
    assert before["version"] == "1.0.0"
    assert "impact assessment" in before["title"].lower()

    art27 = catalog["EU-AI-ACT-Art.27"]
    assert art27["review_status"] == "proposed"
    assert art27["source_reconciled_by"] == "automated-source-reconciliation"


def test_safeguard_mappings_follow_the_correct_meaning() -> None:
    art49 = _homes("EU-AI-ACT-Art.49")
    assert "SG-RISKMANAGEMENT-001" not in art49
    assert set(art49) == {"SG-AIGOVERNANCE-001"}
    art27 = _homes("EU-AI-ACT-Art.27")
    assert set(art27) == {"SG-RISKMANAGEMENT-001"}
    for member in [*art49.values(), *art27.values()]:
        assert member["review_status"] == "proposed"
        assert member["mapping_source"]["url"] == MANIFEST["source"]["pdf"]
        assert member["mapping_source"]["sha256"] == MANIFEST["source"]["pdf_sha256"]
    assert art49["SG-AIGOVERNANCE-001"]["mapping_source"]["locator"] == "Article 49"
    assert art27["SG-RISKMANAGEMENT-001"]["mapping_source"]["locator"] == "Article 27"

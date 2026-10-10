"""Framework identifiers must match the pinned official CSF 2.0 Core."""

import json
from pathlib import Path

from security_lakehouse.catalog import load_control_catalog

ROOT = Path(__file__).resolve().parents[1]


def test_csf_identifiers_match_official_outcomes_not_just_the_count():
    official = json.loads((ROOT / "frameworks/packs/data/nist_csf_2_core.json").read_text())["outcomes"]
    active = {
        cid.removeprefix("NIST-CSF-"): row
        for cid, row in load_control_catalog().items()
        if row["framework_id"] == "nist-csf-2.0"
    }
    assert len(official) == 106
    assert set(active) == set(official)
    for identifier, outcome in official.items():
        assert active[identifier]["title"] == outcome


def test_pack_generator_preserves_official_nonconsecutive_identifiers():
    from security_lakehouse.framework_packs import nist_csf_2_specs

    official = json.loads((ROOT / "frameworks/packs/data/nist_csf_2_core.json").read_text())["outcomes"]
    specs = nist_csf_2_specs()
    assert {spec.article_id: spec.title for spec in specs} == official


def test_generated_csf_rows_do_not_claim_human_review():
    from security_lakehouse.framework_packs import nist_csf_2_specs, pack_control_row, pack_mapping_row

    spec = nist_csf_2_specs()[0]
    control = pack_control_row(spec)
    article = pack_mapping_row(spec)["articles"][0]
    assert control["implementation_status"] == "implemented_limited_mapping"
    assert control["review_status"] == article["review_status"] == "proposed"
    assert control["source_reconciled_by"] is None
    assert article["source_reconciled_by"] is None

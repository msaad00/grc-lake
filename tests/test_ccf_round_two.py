import json
from pathlib import Path

from security_lakehouse.catalog import control_catalog_view, load_control_catalog
from security_lakehouse.framework_coverage import build_framework_coverage
from security_lakehouse.framework_packs import nist_800_171_rev3_specs, pack_control_row, pack_mapping_row
from security_lakehouse.mappings import article_mapping_reviewed, load_control_article_mappings

ROOT = Path(__file__).resolve().parents[1]


def test_ccf_roles_and_personnel_screening():
    rows = json.loads((ROOT / "controls/safeguards.json").read_text())["safeguards"]
    members = [(r["safeguard_id"], m) for r in rows for m in r["satisfies"]]
    assert [sg for sg, m in members if m["control_id"] == "CMMC-3.9.1"] == ["SG-PERSONNELSCREENING-001"]
    assert [sg for sg, m in members if m["control_id"] == "GDPR-Art.33" and m["role"] == "primary"] == [
        "SG-INCIDENTNOTIFICATION-001"
    ]
    assert all(m["role"] == "supporting" for _, m in members if m["control_id"] == "PCI-DSS-8")


def test_annex_titles_and_top_level_coverage():
    catalog = load_control_catalog()
    assert catalog["ISO27001-A.8.5"]["title"] == "Secure authentication"
    assert not any("assessed from ISMS" in r["title"] for r in catalog.values())
    coverage = {r["framework_id"]: r for r in build_framework_coverage()}
    for fid in ("pci-dss-v4", "cis-controls-v8.1"):
        assert coverage[fid]["coverage_level"] == "top_level"
        assert coverage[fid]["coverage_label"] == "Top-level coverage"


def test_proposed_provenance_is_not_reviewer_attestation(tmp_path):
    spec = nist_800_171_rev3_specs()[0]
    for row in (pack_control_row(spec), pack_mapping_row(spec)["articles"][0]):
        assert "reviewed_by" not in row
        assert row["source_reconciled_by"] == "automated-source-reconciliation"
        assert row["review_status"] == "proposed"
    old = {
        "control_id": "TEST",
        "review_status": "proposed",
        "reviewed_by": "source-job",
        "reviewed_date": "2026-01-01",
    }
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps({"controls": [old]}))
    for row in (load_control_catalog(path)["TEST"], control_catalog_view(path)["TEST"]):
        assert row["source_reconciled_by"] == "source-job"
        assert "reviewed_by" not in row
    path.write_text(json.dumps({"mappings": [{"control_id": "TEST", "articles": [old]}]}))
    mapping = load_control_article_mappings(path)["TEST"]
    assert mapping["articles"][0]["source_reconciled_by"] == "source-job"
    assert not article_mapping_reviewed(mapping)

"""Fixture collection must remain visibly synthetic through portable proof."""

from pathlib import Path

import pytest

from security_lakehouse import oscal
from security_lakehouse.assessment import write_assessment_snapshot
from security_lakehouse.connector_runner import run_connector_sync
from security_lakehouse.connector_state import append_config_event
from security_lakehouse.evidence_provenance import contains_synthetic_evidence
from security_lakehouse.io import read_jsonl
from security_lakehouse.scenarios import format_live_cloud_posture_summary, run_live_cloud_posture_scenario
from security_lakehouse.verification import verify_lake_integrity

FIXTURE = Path(__file__).parent / "fixtures" / "aws"


@pytest.mark.parametrize("stored", [False, True])
def test_fixture_origin_survives_collection_snapshot_and_export(tmp_path, stored):
    append_config_event(
        tmp_path,
        connector_id="aws-posture",
        state="enabled",
        actor="test",
        options={"fixture_dir": str(FIXTURE)} if stored else {},
    )
    run_connector_sync(tmp_path, connector_id="aws-posture", fixture_dir=None if stored else FIXTURE)
    rows = read_jsonl(tmp_path / "raw/connector_events.jsonl")
    assert rows and all(row["attributes"].get("synthetic") is True for row in rows)
    assert contains_synthetic_evidence(tmp_path)
    assert verify_lake_integrity(tmp_path)["ok"] is True
    snapshot = write_assessment_snapshot(tmp_path)
    doc = oscal.build_assessment_results(tmp_path, snapshot_id=snapshot.stem)
    assert any(
        prop["name"] == "trustops-synthetic-evidence" and prop["value"] == "true"
        for prop in doc["assessment-results"]["results"][0]["props"]
    )


def test_scenario_reports_fixture_boundary_in_json_summary_and_proof_pack(tmp_path):
    report = run_live_cloud_posture_scenario(
        tmp_path, connectors=["aws-posture"], fixture_dirs={"aws-posture": str(FIXTURE)}
    )
    assert report["summary"]["ok"] is True
    assert report["summary"]["synthetic_fixture"] is True
    assert "synthetic" in format_live_cloud_posture_summary(report).lower()
    proof = Path(report["artifacts"]["proof_pack"]).read_text()
    assert "synthetic" in proof.lower()
    assert "not production proof" in proof


def test_non_fixture_collection_does_not_invent_synthetic_marker(tmp_path, monkeypatch):
    import json

    row = json.loads((Path(__file__).parents[1] / "data/raw/security_events.jsonl").read_text().splitlines()[0])
    original = json.loads(json.dumps(row))
    monkeypatch.setattr("security_lakehouse.connector_runner._collect", lambda *args, **kwargs: [row])
    append_config_event(tmp_path, connector_id="aws-posture", state="enabled", actor="test")
    run_connector_sync(tmp_path, connector_id="aws-posture", materialize=False)
    assert read_jsonl(tmp_path / "raw/connector_events.jsonl") == [{**original, "connector_id": "aws-posture"}]
    assert row["attributes"] == original["attributes"]

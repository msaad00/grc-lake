"""Portable/public labels follow retained source markers, not current unrelated data."""

from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from security_lakehouse import dashboard, oscal
from security_lakehouse.assessment import _assessment_hash, write_assessment_snapshot
from security_lakehouse.golden_fixture import build_golden_events
from security_lakehouse.io import read_json, write_jsonl
from security_lakehouse.pipeline import run_pipeline
from security_lakehouse.server_app import _public_trust_summary
from test_oscal import _ASSESSMENT_RESULTS_SCHEMA

NOTICE = "Contains synthetic demonstration evidence; synthetic rows are not production proof."


def _materialize(lake: Path, synthetic: bool) -> None:
    rows = build_golden_events()[:1]
    rows[0]["attributes"]["demo"] = synthetic
    source = lake.parent / f"{lake.name}-source.jsonl"
    write_jsonl(source, rows)
    run_pipeline(source, lake)


def _marked(doc) -> bool:
    return any(
        prop["name"] == "trustops-synthetic-evidence" and prop["value"] == "true"
        for prop in doc["assessment-results"]["results"][0].get("props", [])
    )


@pytest.mark.parametrize("synthetic", [True, False])
def test_oscal_marks_explicit_synthetic_sources(tmp_path, synthetic):
    lake = tmp_path / "lake"
    _materialize(lake, synthetic)
    doc = oscal.build_assessment_results(lake)
    assert _marked(doc) is synthetic
    assert (NOTICE in doc["assessment-results"]["results"][0]["description"]) is synthetic
    Draft7Validator(_ASSESSMENT_RESULTS_SCHEMA).validate(doc)


@pytest.mark.parametrize("original", [True, False])
def test_oscal_snapshot_label_uses_its_own_historical_generation(tmp_path, original):
    lake = tmp_path / "lake"
    _materialize(lake, original)
    snapshot = write_assessment_snapshot(lake)
    original_bytes = snapshot.read_bytes()
    _materialize(lake, not original)
    assert _marked(oscal.build_assessment_results(lake, snapshot_id=snapshot.stem)) is original
    assert _marked(oscal.build_assessment_results(lake)) is not original
    assert snapshot.read_bytes() == original_bytes


def test_legacy_embedded_snapshot_never_borrows_current_synthetic_marker(tmp_path, monkeypatch):
    lake = tmp_path / "lake"
    _materialize(lake, True)
    payload = {"evaluated_at": "2026-10-06T12:00:00Z", "control_posture": []}
    payload["assessment_hash"] = _assessment_hash(payload)
    monkeypatch.setattr(oscal, "load_snapshot", lambda *args: payload)
    assert not _marked(oscal.build_assessment_results(lake, snapshot_id="legacy"))


@pytest.mark.parametrize("synthetic", [True, False])
def test_offline_dashboard_renders_label_without_altering_recorded_posture(tmp_path, monkeypatch, synthetic):
    lake = tmp_path / "lake"
    _materialize(lake, synthetic)
    app_data = dashboard._load_app_data(lake)
    assert app_data["synthetic_fixture"] is synthetic
    recorded = read_json(lake / "gold/current_posture.json") if (lake / "gold/current_posture.json").is_file() else None
    if recorded:
        assert app_data["posture"] == recorded
    body = dashboard.render_dashboard(lake, tmp_path / "report.html").read_text()
    assert (f'<aside role="note">{NOTICE}</aside>' in body) is synthetic
    # Reports preserve the frozen payload instead of requiring a React build.
    import json
    import re

    embedded = re.search(r'<script id="app-data"[^>]*>(.*?)</script>', body, re.S)
    assert embedded is not None
    assert json.loads(embedded[1])["posture"] == app_data["posture"]


@pytest.mark.parametrize("synthetic", [True, False])
def test_public_share_retains_synthetic_provenance(tmp_path, synthetic):
    lake = tmp_path / "lake"
    _materialize(lake, synthetic)
    payload = _public_trust_summary(lake, {"scope": "posture_full", "sensitivity_ceiling": "public"})
    assert payload["synthetic_fixture"] is synthetic
    assert "events" not in payload
    assert "evidence" not in payload


def test_mixed_source_exports_disclose_presence_without_claiming_all_rows_synthetic(tmp_path):
    lake = tmp_path / "lake"
    rows = build_golden_events()[:2]
    rows[0]["attributes"]["demo"] = False
    source = tmp_path / "mixed.jsonl"
    write_jsonl(source, rows)
    run_pipeline(source, lake)
    assert _marked(oscal.build_assessment_results(lake))
    assert dashboard._load_app_data(lake)["synthetic_fixture"] is True
    assert _public_trust_summary(lake, {"scope": "posture_full"})["synthetic_fixture"] is True

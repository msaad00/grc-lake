import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from security_lakehouse import assessment, pipeline
from security_lakehouse.generations import active_generation
from security_lakehouse.io import read_json, read_jsonl

RAW = Path(__file__).resolve().parents[1] / "data/raw/security_events.jsonl"


def test_dashboard_samples_keep_complete_gold_and_posture(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "DASHBOARD_DETAIL_CAP", 2, raising=False)
    lake = tmp_path / "lake"
    result = pipeline.run_pipeline(RAW, lake)
    dashboard = read_json(result.dashboard_data_path)
    generation = active_generation(lake)
    for name in ("evidence_freshness", "control_posture", "control_tests", "asset_risk"):
        rows = read_jsonl(generation / "gold" / (name + ".jsonl"))
        assert len(dashboard[name]) <= 2
        assert dashboard["detail_counts"][name] == len(rows)
        assert dashboard["detail_truncated"][name] == (len(rows) > 2)
    from security_lakehouse.dashboard import render_dashboard

    report = tmp_path / "report.html"
    render_dashboard(lake, report)
    assert "Sampled control results" in report.read_text()
    now = datetime(2026, 10, 10, tzinfo=UTC)
    before = assessment.build_current_posture(lake, now=now)
    # Use a copied unsealed legacy lake so the fallback reads exactly the same input.
    import shutil

    legacy = tmp_path / "legacy"
    shutil.copytree(generation / "gold", legacy / "gold")
    shutil.copytree(generation / "silver", legacy / "silver")
    shutil.copytree(generation / "bronze", legacy / "bronze")
    (legacy / "gold/dashboard_data.json").unlink()
    after = assessment.build_current_posture(legacy, now=now)
    for key in ("posture", "frameworks", "violations", "violation_summary", "top_risk_assets", "evidence_freshness"):
        assert before[key] == after[key]


def test_streamed_gold_write_preserves_bytes_and_rejects_invalid(tmp_path):
    from security_lakehouse.gold_io import write_gold_json

    path = tmp_path / "gold.json"
    payload = {"rows": [{"unicode": "é", "list": [1, None, True]}]}
    write_gold_json(path, payload)
    expected = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    assert path.read_text() == expected
    for invalid in ({"x": float("nan")}, {1: "bad key"}, {"x": "\ud800"}):
        with pytest.raises(ValueError):
            write_gold_json(path, invalid)
        assert path.read_text() == expected
        assert not list(tmp_path.glob("*.tmp"))


def test_asset_projection_falls_back_when_source_changes(tmp_path):
    from security_lakehouse.io import file_sha256, write_json, write_jsonl

    gold = tmp_path / "gold"
    source = gold / "asset_risk.jsonl"
    old = {"asset_id": "a", "asset_name": "Before"}
    write_jsonl(source, [old])
    write_json(
        gold / "dashboard_data.json",
        {
            "posture_assets": {
                "schema_version": "trustops.posture_assets.v1",
                "source_sha256": file_sha256(source),
                "asset_count": 1,
                "top_risk_assets": [old],
                "asset_names": {"a": "Before"},
            }
        },
    )
    assert assessment._posture_assets(tmp_path) == ([old], 1, {"a": "Before"})
    new = {"asset_id": "b", "asset_name": "After"}
    write_jsonl(source, [new])
    assert assessment._posture_assets(tmp_path) == ([new], 1, {"b": "After"})

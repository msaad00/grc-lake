"""Export verification must cover the normalized and rendered claims."""

from pathlib import Path

import pytest

from security_lakehouse.generations import active_generation
from security_lakehouse.io import read_jsonl
from security_lakehouse.oscal import build_assessment_results
from security_lakehouse.pipeline import run_pipeline
from security_lakehouse.verification import verify_event

RAW = Path(__file__).resolve().parents[1] / "data/raw/security_events.jsonl"


def test_live_oscal_rejects_modified_published_posture(tmp_path):
    run_pipeline(RAW, tmp_path)
    path = active_generation(tmp_path) / "gold/control_posture.jsonl"
    path.write_text(path.read_text().replace('"fail"', '"pass"'))
    with pytest.raises(ValueError, match="hash mismatch"):
        build_assessment_results(tmp_path)


def test_event_verification_rejects_modified_normalized_content(tmp_path):
    run_pipeline(RAW, tmp_path)
    path = active_generation(tmp_path) / "silver/normalized_events.jsonl"
    event_id = read_jsonl(path)[0]["event_id"]
    path.write_text(path.read_text().replace('"open"', '"passed"'))
    assert verify_event(tmp_path, event_id)["verified"] is False


def test_live_oscal_rejects_unsealed_posture(tmp_path):
    path = tmp_path / "gold/control_posture.jsonl"
    path.parent.mkdir()
    path.write_text('{"control_id":"x","status":"pass"}\n')
    with pytest.raises(ValueError, match="verified generation"):
        build_assessment_results(tmp_path)

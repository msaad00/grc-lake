"""Historical answers must come from verified ledger entries."""

import json

import pytest

from security_lakehouse.assessment import _assessment_hash, load_snapshot, posture_as_of, write_assessment_snapshot
from test_api_v1 import _seed_lake


def test_unledgered_self_hashed_snapshot_cannot_change_history(tmp_path):
    _seed_lake(tmp_path)
    original = write_assessment_snapshot(tmp_path)
    payload = json.loads(original.read_text())
    payload["evaluated_at"] = "2090-01-01T00:00:00Z"
    payload["posture"]["score"] = 100
    payload["assessment_hash"] = _assessment_hash(payload)
    forged = original.with_name("assessment-forged.json")
    forged.write_text(json.dumps(payload))
    before = forged.read_bytes()
    with pytest.raises(ValueError, match="snapshot.*integrity"):
        posture_as_of(tmp_path, as_of="2091-01-01")
    assert forged.read_bytes() == before


def test_snapshot_read_rejects_tampered_record(tmp_path):
    _seed_lake(tmp_path)
    path = write_assessment_snapshot(tmp_path)
    payload = json.loads(path.read_text())
    payload["posture"]["score"] = 100
    payload["assessment_hash"] = _assessment_hash(payload)
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="snapshot.*integrity"):
        load_snapshot(tmp_path, path.stem)


def test_snapshot_read_rejects_symlink(tmp_path):
    _seed_lake(tmp_path)
    path = write_assessment_snapshot(tmp_path)
    target = tmp_path / "elsewhere.json"
    path.rename(target)
    path.symlink_to(target)
    with pytest.raises(ValueError, match="snapshot.*integrity"):
        load_snapshot(tmp_path, path.stem)


def test_snapshot_export_keeps_a_resolvable_ledger_copy(tmp_path):
    from security_lakehouse.assessment import verify_snapshot_chain

    lake = tmp_path / "lake"
    lake.mkdir()
    _seed_lake(lake)
    output = tmp_path / "export.json"
    assert write_assessment_snapshot(lake, output=output) == output
    payload = json.loads(output.read_text())
    assert verify_snapshot_chain(lake)["ok"] is True
    assert load_snapshot(lake, payload["assessment_hash"]) == payload


def test_corrupt_snapshot_history_cannot_be_extended(tmp_path):
    _seed_lake(tmp_path)
    path = write_assessment_snapshot(tmp_path)
    path.write_text("{}")
    ledger = tmp_path / "gold/snapshots/_ledger.jsonl"
    before = ledger.read_bytes()
    files = set(path.parent.iterdir())
    with pytest.raises(ValueError, match="snapshot.*integrity"):
        write_assessment_snapshot(tmp_path)
    assert ledger.read_bytes() == before
    assert set(path.parent.iterdir()) == files


def test_corrupt_snapshot_http_responses_are_sanitized(tmp_path):
    from fastapi.testclient import TestClient

    from security_lakehouse.server_app import create_app

    _seed_lake(tmp_path)
    path = write_assessment_snapshot(tmp_path)
    path.write_text("{}")
    client = TestClient(create_app(tmp_path, require_auth=False))
    for route in [
        f"/api/v1/snapshots/{path.stem}",
        f"/api/v1/snapshots/{path.stem}/export.pdf",
        "/api/v1/posture/as-of?as_of=2091-01-01",
    ]:
        response = client.get(route)
        assert response.status_code == 503
        assert response.json()["errors"][0]["code"] == "invalid_stored_data"
        assert str(tmp_path) not in response.text

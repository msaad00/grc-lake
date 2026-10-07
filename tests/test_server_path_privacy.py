from fastapi.testclient import TestClient

from security_lakehouse.server_app import create_app
from test_api_v1 import _seed_lake


def test_snapshot_api_uses_portable_reference_without_server_directory(tmp_path):
    _seed_lake(tmp_path)
    client = TestClient(create_app(tmp_path, require_auth=False))
    created = client.post("/api/v1/snapshots", json={})
    assert created.status_code == 201
    assert str(tmp_path) not in created.text
    listed = client.get("/api/v1/snapshots")
    assert listed.status_code == 200
    assert str(tmp_path) not in listed.text
    assert listed.json()["data"][0]["snapshot_id"]


def test_legacy_snapshot_api_uses_portable_reference(tmp_path):
    _seed_lake(tmp_path)
    client = TestClient(create_app(tmp_path, require_auth=False))
    created = client.post("/api/snapshots", json={})
    assert created.status_code == 201
    assert str(tmp_path) not in created.text

"""Snapshot detail API for audit room timeline."""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from security_lakehouse.server_app import create_app
from test_api_v1 import _seed_lake


def test_snapshot_detail_returns_summary(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    client = TestClient(create_app(tmp_path, require_auth=False))
    created = client.post("/api/v1/snapshots", json={"reason": "audit_test"})
    assert created.status_code == HTTPStatus.CREATED
    listed = client.get("/api/v1/snapshots").json()["data"]
    assert listed
    snapshot_id = listed[0]["snapshot_id"]
    resp = client.get(f"/api/v1/snapshots/{snapshot_id}")
    assert resp.status_code == HTTPStatus.OK
    body = resp.json()["data"]
    assert body["snapshot_id"] == snapshot_id
    assert body["reason"]
    assert body["assessment_hash"]
    assert "violation_count" in body
    assert isinstance(body.get("evidence_refs"), list)


def test_snapshot_detail_not_found(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    client = TestClient(create_app(tmp_path, require_auth=False))
    resp = client.get("/api/v1/snapshots/does-not-exist")
    assert resp.status_code == HTTPStatus.NOT_FOUND

"""Server-mode (FastAPI) tests: prove the v1 contract matches local mode.

These run only when the ``server`` extra is installed. The headline guarantee
is parity: for deterministic resources the FastAPI app returns byte-for-byte
the same envelope as the zero-dependency stdlib server.
"""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from security_lakehouse.server_app import create_app
from test_api_v1 import _request, _seed_lake, _spin

# Resources whose payloads are pure functions of seeded lake files, so the two
# servers must return identical JSON. Posture/violations/snapshots embed a
# per-call ``evaluated_at`` timestamp and are checked structurally instead.
DETERMINISTIC_ROUTES = [
    "/api/v1/healthz",
    "/api/v1/controls",
    "/api/v1/control-tests",
    "/api/v1/evidence",
    "/api/v1/assets",
]


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    # Contract tests exercise the v1 envelope, not auth, so run without it.
    # Authentication and RBAC are covered in test_auth_rbac.py.
    _seed_lake(tmp_path)
    return TestClient(create_app(tmp_path, require_auth=False))


def test_server_mode_matches_stdlib_contract(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app_client = TestClient(create_app(tmp_path, require_auth=False))
    stdlib = _spin(tmp_path)
    try:
        for path in DETERMINISTIC_ROUTES:
            stdlib_status, stdlib_body = _request(stdlib, "GET", path)
            resp = app_client.get(path)
            assert resp.status_code == stdlib_status, path
            assert resp.json() == stdlib_body, path
    finally:
        stdlib.shutdown()


def test_server_mode_collection_controls(client: TestClient) -> None:
    resp = client.get("/api/v1/controls", params={"sort": "-risk_score", "limit": 1, "offset": 0})
    assert resp.status_code == HTTPStatus.OK
    body = resp.json()
    assert set(body) == {"data", "meta", "errors"}
    assert body["meta"]["api_version"] == "v1"
    assert body["meta"]["resource"] == "controls"
    assert body["meta"]["count"] == 2
    assert body["meta"]["returned"] == 1
    assert body["data"][0]["control_id"] == "SOC2-CC6.1"


def test_server_mode_filters_list_and_scalar_fields(client: TestClient) -> None:
    resp = client.get("/api/v1/evidence", params={"control_ids": "SOC2-CC6.1"})
    assert resp.json()["meta"]["count"] == 1
    assert resp.json()["data"][0]["event_id"] == "evt-001"

    resp = client.get("/api/v1/control-tests", params={"result": "pass"})
    assert resp.json()["meta"]["count"] == 1
    assert resp.json()["data"][0]["control_id"] == "NIST-AI-RMF-MAP-1.5"


def test_server_mode_singletons_are_enveloped(client: TestClient) -> None:
    for path, resource in [("/api/v1/healthz", "healthz"), ("/api/v1/posture/current", "posture.current")]:
        body = client.get(path).json()
        assert set(body) == {"data", "meta", "errors"}
        assert body["meta"]["resource"] == resource
        assert body["errors"] == []


def test_server_mode_snapshot_post(client: TestClient, tmp_path: Path) -> None:
    resp = client.post("/api/v1/snapshots", json={"reason": "vendor_review"})
    assert resp.status_code == HTTPStatus.CREATED
    body = resp.json()
    assert body["meta"]["resource"] == "snapshots"
    assert body["data"]["reason"] == "vendor_review"
    assert not Path(body["data"]["snapshot_path"]).is_absolute()
    assert (tmp_path / "gold/snapshots" / body["data"]["snapshot_path"]).is_file()


def test_server_mode_error_envelopes(client: TestClient) -> None:
    resp = client.get("/api/v1/controls", params={"limit": 0})
    assert resp.status_code == HTTPStatus.BAD_REQUEST
    assert resp.json()["data"] is None
    assert resp.json()["errors"][0]["code"] == "bad_request"

    resp = client.get("/api/v1/not-real")
    assert resp.status_code == HTTPStatus.NOT_FOUND
    assert resp.json()["errors"][0]["code"] == "not_found"


@pytest.mark.parametrize("route", ["/api/v1/snapshots", "/api/snapshots"])
@pytest.mark.parametrize("payload", [[1, 2], "text", 7, None])
def test_server_mode_non_object_json_body_is_a_bad_request(client: TestClient, route: str, payload: object) -> None:
    import json as _json

    resp = client.post(
        route,
        content=_json.dumps(payload),
        headers={"content-type": "application/json", "Idempotency-Key": "k-1"},
    )
    assert resp.status_code == HTTPStatus.BAD_REQUEST
    assert resp.json()["errors"][0]["code"] == "bad_request"


@pytest.mark.parametrize("route", ["/api/v1/snapshots", "/api/snapshots"])
def test_server_mode_empty_body_is_still_accepted(client: TestClient, route: str) -> None:
    resp = client.post(route, headers={"Idempotency-Key": "k-empty"})
    assert resp.status_code == HTTPStatus.CREATED

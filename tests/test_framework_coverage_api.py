from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.server_app import create_app


def test_framework_coverage_api_separates_proof_states(tmp_path) -> None:
    client = TestClient(create_app(tmp_path, require_auth=False))

    response = client.get("/api/v1/frameworks/coverage")

    assert response.status_code == 200
    body = response.json()
    assert body["meta"]["resource"] == "frameworks.coverage"
    summary = body["data"]["summary"]
    assert summary["seeded_control_count"] == len(load_control_catalog())
    assert (
        summary["attestable_requirement_count"]
        <= summary["evaluatable_requirement_count"]
        <= summary["seeded_control_count"]
    )
    assert body["data"]["frameworks"]
    for row in body["data"]["frameworks"]:
        assert row["attestable_requirement_count"] <= row["evaluatable_requirement_count"]
        assert row["evaluatable_requirement_count"] <= row["seeded_control_count"]

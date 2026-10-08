"""HTTP-level paging for FastAPI-only coverage routes and the evidence catch-all."""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient  # noqa: E402

from security_lakehouse import api_v1  # noqa: E402
from security_lakehouse.server_app import create_app  # noqa: E402
from test_api_paging import _seed_evidence  # noqa: E402


def test_framework_coverage_pages_frameworks_and_keeps_summary(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path, require_auth=False))
    full = client.get("/api/v1/frameworks/coverage").json()
    assert "next_cursor" not in full["meta"]
    frameworks = full["data"]["frameworks"]
    assert len(frameworks) > 2

    collected: list[dict[str, Any]] = []
    url = "/api/v1/frameworks/coverage?limit=2"
    pages = 0
    while url:
        body = client.get(url).json()
        pages += 1
        assert len(body["data"]["frameworks"]) <= 2
        assert body["data"]["summary"] == full["data"]["summary"]
        assert body["meta"]["count"] == len(frameworks)
        collected.extend(body["data"]["frameworks"])
        cursor = body["meta"]["next_cursor"]
        url = f"/api/v1/frameworks/coverage?limit=2&cursor={cursor}" if cursor else ""
        assert pages < 100
    assert collected == frameworks


@pytest.mark.parametrize("query", ["limit=1001", "limit=0", "cursor=bad", "offset=-1"])
def test_framework_coverage_rejects_invalid_page_params(tmp_path: Path, query: str) -> None:
    client = TestClient(create_app(tmp_path, require_auth=False))
    response = client.get(f"/api/v1/frameworks/coverage?{query}")
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json()["errors"][0]["code"] == "bad_request"


def test_streamed_evidence_over_http_matches_handle_get(tmp_path: Path) -> None:
    _seed_evidence(tmp_path, 30)
    client = TestClient(create_app(tmp_path, require_auth=False))
    body = client.get("/api/v1/evidence?limit=4&offset=8").json()
    assert [row["event_id"] for row in body["data"]] == ["evt-008", "evt-009", "evt-010", "evt-011"]
    assert body["meta"]["count"] == 30
    assert body["meta"]["next_cursor"] == api_v1.encode_cursor(12)


def test_unparameterized_graph_over_http_is_a_labeled_default_page(tmp_path: Path) -> None:
    from test_api_paging import _graph_lake

    _graph_lake(tmp_path)
    client = TestClient(create_app(tmp_path, require_auth=False))
    body = client.get("/api/v1/graph").json()
    assert body["meta"]["default_page"] is True
    assert body["meta"]["limit"] == 100
    assert len(body["data"]["nodes"]) <= 100
    assert len(body["data"]["edges"]) <= 100
    assert body["meta"]["next_cursor"] == api_v1.encode_cursor(100)

    nodes, edges = list(body["data"]["nodes"]), list(body["data"]["edges"])
    cursor = body["meta"]["next_cursor"]
    while cursor:
        page = client.get(f"/api/v1/graph?cursor={cursor}").json()
        nodes += page["data"]["nodes"]
        edges += page["data"]["edges"]
        cursor = page["meta"]["next_cursor"]
    assert len(nodes) == body["meta"]["parts"]["nodes"]["count"]
    assert len(edges) == body["meta"]["parts"]["edges"]["count"]

"""Cursor/limit paging for evidence, graph, and coverage v1 routes.

Evidence pages stream the pinned silver file and parse at most ``limit + 1``
rows when no sort is requested. Graph and coverage routes keep their full
object payload by default and page their list members in lockstep when a
caller sends ``limit``, ``offset``, or ``cursor``.
"""

from __future__ import annotations

import os
import subprocess
import sys
from http import HTTPStatus
from pathlib import Path
from typing import Any

import pytest

from security_lakehouse import api_v1, strict_json
from security_lakehouse.asset_names import load_asset_names, with_asset_names
from security_lakehouse.graph import build_compliance_graph, build_repository_graph
from security_lakehouse.projected_reads import read_projection
from test_api_v1 import _seed_lake, _write_jsonl

ROOT = Path(__file__).resolve().parents[1]
REPO_GRAPH_LAKE = ROOT / "tests" / "fixtures" / "repo-graph"


def _events(count: int) -> list[dict[str, Any]]:
    controls = ["SOC2-CC6.1", "SOC2-CC7.2", "ISO27001-A.5.15"]
    return [
        {
            "event_id": f"evt-{index:03d}",
            "event_time": f"2026-05-20T13:{index % 60:02d}:00Z",
            "event_type": f"type.{index % 4}",
            "control_ids": [controls[index % 3], controls[(index + 1) % 3]],
            "asset_id": f"asset-{index % 9}",
            "source": "okta" if index % 2 else "aws",
            "status": "observed",
        }
        for index in range(count)
    ]


def _seed_evidence(lake: Path, count: int = 50) -> list[dict[str, Any]]:
    rows = _events(count)
    _write_jsonl(lake / "silver" / "normalized_events.jsonl", rows)
    _write_jsonl(
        lake / "gold" / "asset_risk.jsonl",
        [{"asset_id": "asset-1", "asset_name": "Billing DB", "risk_score": 40}],
    )
    return rows


def _materialized(lake: Path, params: dict[str, list[str]]) -> dict[str, Any]:
    rows = with_asset_names(
        read_projection(lake / "silver" / "normalized_events.jsonl", None, missing_ok=True, base_dir=lake),
        load_asset_names(lake),
    )
    return api_v1.collection_response("evidence", rows, params)


def _get(path: str, params: dict[str, list[str]], lake: Path) -> tuple[HTTPStatus, dict[str, Any]]:
    status, body = api_v1.handle_get(path, params, lake)
    body["meta"].pop("generation", None)
    return status, body


def _walk(path: str, lake: Path, limit: int) -> list[dict[str, Any]]:
    pages = []
    params: dict[str, list[str]] = {"limit": [str(limit)]}
    while True:
        status, body = _get(path, params, lake)
        assert status == HTTPStatus.OK, body
        pages.append(body)
        cursor = body["meta"]["next_cursor"]
        if cursor is None:
            return pages
        params = {"limit": [str(limit)], "cursor": [cursor]}
        assert len(pages) < 1000


# --- evidence ---------------------------------------------------------------


def test_evidence_page_parses_at_most_limit_plus_one_rows(tmp_path: Path, monkeypatch) -> None:
    _seed_evidence(tmp_path, 50)
    real_loads = strict_json.loads
    parsed: list[str] = []

    def counting_loads(text: Any, *args: Any, **kwargs: Any) -> Any:
        value = real_loads(text, *args, **kwargs)
        if isinstance(value, dict) and "event_id" in value:
            parsed.append(value["event_id"])
        return value

    real_projection = api_v1.read_projection

    def counting_projection(path: Any, *args: Any, **kwargs: Any) -> Any:
        rows = real_projection(path, *args, **kwargs)
        if "normalized_events" in str(path):
            parsed.extend(str(row.get("event_id")) for row in rows)
        return rows

    monkeypatch.setattr(strict_json, "loads", counting_loads)
    monkeypatch.setattr(api_v1, "read_projection", counting_projection)

    # The first read of this file content validates every row once (fail-closed
    # on a bad row outside the page) without keeping any of them.
    status, _ = _get("/api/v1/evidence", {"limit": ["2"]}, tmp_path)
    assert status == HTTPStatus.OK
    parsed.clear()

    status, body = _get("/api/v1/evidence", {"limit": ["2"], "offset": ["10"]}, tmp_path)

    assert status == HTTPStatus.OK
    assert [row["event_id"] for row in body["data"]] == ["evt-010", "evt-011"]
    assert body["meta"]["count"] == 50
    assert body["meta"]["returned"] == 2
    assert api_v1.decode_cursor(body["meta"]["next_cursor"]) == 12
    # Rows before the offset are skipped unparsed and reading stops at the end
    # of the page, so a 50-row file costs at most limit + 1 parses.
    assert len(parsed) <= 3, parsed
    assert "evt-013" not in parsed


def test_evidence_page_fails_closed_on_an_invalid_row_outside_the_page(tmp_path: Path) -> None:
    _seed_evidence(tmp_path, 20)
    status, _ = _get("/api/v1/evidence", {"limit": ["2"]}, tmp_path)
    assert status == HTTPStatus.OK
    with (tmp_path / "silver" / "normalized_events.jsonl").open("a", encoding="utf-8") as stream:
        stream.write("{not json}\n")
    status, body = _get("/api/v1/evidence", {"limit": ["2"]}, tmp_path)
    assert status == HTTPStatus.BAD_REQUEST
    assert body["errors"][0]["code"] == "bad_request"


def test_evidence_page_does_not_materialize_the_silver_file(tmp_path: Path, monkeypatch) -> None:
    _seed_evidence(tmp_path, 20)
    real = api_v1.read_projection

    def guarded(path: Any, *args: Any, **kwargs: Any) -> Any:
        assert "normalized_events" not in str(path), "evidence page materialized the full silver file"
        return real(path, *args, **kwargs)

    monkeypatch.setattr(api_v1, "read_projection", guarded)

    status, body = _get("/api/v1/evidence", {"limit": ["5"]}, tmp_path)
    assert status == HTTPStatus.OK
    assert body["meta"]["returned"] == 5


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"limit": ["7"]},
        {"limit": ["7"], "offset": ["14"]},
        {"limit": ["1000"]},
        {"limit": ["5"], "offset": ["49"]},
        {"limit": ["5"], "offset": ["50"]},
        {"limit": ["5"], "offset": ["500"]},
        {"control_ids": ["SOC2-CC7.2"], "limit": ["4"], "offset": ["3"]},
        {"source": ["okta,aws"], "event_type": ["type.1"], "limit": ["3"]},
        {"asset_name": ["Billing DB"], "limit": ["2"]},
        {"source": ["nobody"]},
        {"sort": ["-event_time"], "limit": ["5"]},
        {"cursor": [api_v1.encode_cursor(20)], "limit": ["6"]},
    ],
)
def test_streamed_evidence_page_matches_materialized_contract(tmp_path: Path, params: dict[str, list[str]]) -> None:
    _seed_evidence(tmp_path, 50)
    status, body = _get("/api/v1/evidence", params, tmp_path)
    assert status == HTTPStatus.OK
    assert body == _materialized(tmp_path, params)


def test_evidence_cursor_round_trip_visits_every_row_once_in_file_order(tmp_path: Path) -> None:
    rows = _seed_evidence(tmp_path, 50)
    pages = _walk("/api/v1/evidence", tmp_path, 7)
    seen = [row["event_id"] for page in pages for row in page["data"]]
    assert seen == [row["event_id"] for row in rows]
    assert len(pages) == 8
    assert all(page["meta"]["count"] == 50 for page in pages)


@pytest.mark.parametrize(
    "params",
    [
        {"limit": ["1001"]},
        {"limit": ["0"]},
        {"limit": ["abc"]},
        {"offset": ["-1"]},
        {"cursor": ["not-a-cursor"]},
        {"no_such_field": ["x"]},
    ],
)
def test_evidence_rejects_invalid_page_params_like_other_collections(
    tmp_path: Path, params: dict[str, list[str]]
) -> None:
    _seed_evidence(tmp_path, 5)
    status, body = _get("/api/v1/evidence", params, tmp_path)
    assert status == HTTPStatus.BAD_REQUEST
    assert body["errors"][0]["code"] == "bad_request"


def test_evidence_max_limit_is_honoured_at_the_boundary(tmp_path: Path) -> None:
    _seed_evidence(tmp_path, 1001)
    status, body = _get("/api/v1/evidence", {"limit": ["1000"]}, tmp_path)
    assert status == HTTPStatus.OK
    assert body["meta"]["returned"] == 1000
    assert body["meta"]["limit"] == 1000
    assert api_v1.decode_cursor(body["meta"]["next_cursor"]) == 1000


def test_evidence_on_an_empty_lake_is_an_empty_page(tmp_path: Path) -> None:
    status, body = _get("/api/v1/evidence", {"limit": ["5"]}, tmp_path)
    assert status == HTTPStatus.OK
    assert body["data"] == []
    assert body["meta"]["count"] == 0
    assert body["meta"]["next_cursor"] is None


# --- graph and coverage -----------------------------------------------------


def _graph_lake(tmp_path: Path) -> Path:
    _seed_lake(tmp_path)
    _seed_evidence(tmp_path, 40)
    return tmp_path


@pytest.mark.parametrize(
    ("path", "builder", "lake_factory"),
    [
        ("/api/v1/graph", build_compliance_graph, _graph_lake),
        ("/api/v1/repo-graph", build_repository_graph, lambda _tmp: REPO_GRAPH_LAKE),
    ],
)
def test_graph_without_page_params_keeps_the_full_payload(path, builder, lake_factory, tmp_path: Path) -> None:
    lake = lake_factory(tmp_path)
    status, body = _get(path, {}, lake)
    assert status == HTTPStatus.OK
    assert body["data"] == builder(lake)
    assert "next_cursor" not in body["meta"]


@pytest.mark.parametrize(
    ("path", "builder", "lake_factory", "limit"),
    [
        ("/api/v1/graph", build_compliance_graph, _graph_lake, 100),
        ("/api/v1/repo-graph", build_repository_graph, lambda _tmp: REPO_GRAPH_LAKE, 3),
    ],
)
def test_graph_pages_nodes_and_edges_and_cursor_walk_rebuilds_the_graph(
    path, builder, lake_factory, limit, tmp_path: Path
) -> None:
    lake = lake_factory(tmp_path)
    full = builder(lake)
    assert max(len(full["nodes"]), len(full["edges"])) > limit, "fixture too small to page"

    pages = _walk(path, lake, limit)

    assert len(pages) > 1
    for page in pages:
        assert len(page["data"]["nodes"]) <= limit
        assert len(page["data"]["edges"]) <= limit
        assert page["data"]["counts"] == full["counts"]
        assert page["meta"]["count"] == max(len(full["nodes"]), len(full["edges"]))
        assert page["meta"]["parts"]["nodes"]["count"] == len(full["nodes"])
        assert page["meta"]["parts"]["edges"]["count"] == len(full["edges"])
        assert page["meta"]["returned"] == len(page["data"]["nodes"]) + len(page["data"]["edges"])
    assert [n for page in pages for n in page["data"]["nodes"]] == full["nodes"]
    assert [e for page in pages for e in page["data"]["edges"]] == full["edges"]


@pytest.mark.parametrize("path", ["/api/v1/graph", "/api/v1/repo-graph", "/api/v1/graph/coverage"])
@pytest.mark.parametrize(
    "params",
    [{"limit": ["1001"]}, {"limit": ["0"]}, {"offset": ["-2"]}, {"cursor": ["%%%"]}],
)
def test_graph_and_coverage_reject_invalid_page_params(path: str, params, tmp_path: Path) -> None:
    _graph_lake(tmp_path)
    status, body = _get(path, params, tmp_path)
    assert status == HTTPStatus.BAD_REQUEST
    assert body["errors"][0]["code"] == "bad_request"


def test_graph_page_default_limit_is_100(tmp_path: Path) -> None:
    _graph_lake(tmp_path)
    status, body = _get("/api/v1/graph", {"offset": ["0"]}, tmp_path)
    assert status == HTTPStatus.OK
    assert body["meta"]["limit"] == 100
    assert len(body["data"]["nodes"]) <= 100


def _coverage_lake(tmp_path: Path, asset_count: int) -> Path:
    _seed_lake(tmp_path)
    _seed_evidence(tmp_path, 10)
    _write_jsonl(
        tmp_path / "gold" / "asset_risk.jsonl",
        [{"asset_id": f"ghost-{index:04d}", "asset_type": "vm", "risk_score": 1} for index in range(asset_count)],
    )
    return tmp_path


def test_coverage_without_page_params_keeps_the_200_row_detail_cap(tmp_path: Path) -> None:
    _coverage_lake(tmp_path, 250)
    status, body = _get("/api/v1/graph/coverage", {}, tmp_path)
    assert status == HTTPStatus.OK
    data = body["data"]
    assert data["detail_limit"] == 200
    assert data["details_truncated"] is True
    assert len(data["assets"]) == 200
    assert len(data["orphans"]["assets"]) == 200
    assert "next_cursor" not in body["meta"]


def test_coverage_cursor_walk_reaches_every_asset_and_orphan_past_the_cap(tmp_path: Path) -> None:
    _coverage_lake(tmp_path, 250)
    _, unpaged = _get("/api/v1/graph/coverage", {}, tmp_path)
    summary = unpaged["data"]["summary"]

    pages = _walk("/api/v1/graph/coverage", tmp_path, 100)

    longest = max(summary["total_assets"], summary["orphan_controls"], summary["total_frameworks"])
    assert len(pages) == -(-longest // 100)
    assert all(page["meta"]["count"] == longest for page in pages)
    assets = [row for page in pages for row in page["data"]["assets"]]
    orphan_assets = [row for page in pages for row in page["data"]["orphans"]["assets"]]
    orphan_controls = [row for page in pages for row in page["data"]["orphans"]["controls"]]
    assert len(assets) == summary["total_assets"]
    assert len({row["asset_id"] for row in assets}) == len(assets)
    assert [row["asset_id"] for row in assets] == sorted(row["asset_id"] for row in assets)
    assert len(orphan_assets) == summary["uncovered_assets"]
    assert len(orphan_controls) == summary["orphan_controls"]
    for page in pages:
        assert page["data"]["summary"] == summary
        assert page["data"]["detail_limit"] is None
        assert page["meta"]["parts"]["assets"]["count"] == summary["total_assets"]
    # The first page of the uncapped walk equals the first rows of the capped view.
    assert assets[:100] == unpaged["data"]["assets"][:100]


def test_compliance_graph_order_is_stable_across_hash_seeds(tmp_path: Path) -> None:
    _graph_lake(tmp_path)
    script = (
        "import json,sys;"
        "from security_lakehouse.graph import build_compliance_graph;"
        "g=build_compliance_graph(sys.argv[1]);"
        "print(json.dumps([[n['id'] for n in g['nodes']],[e['id'] for e in g['edges']]]))"
    )
    outputs = set()
    for seed in ("1", "2", "3"):
        env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": str(ROOT / "src")}
        result = subprocess.run(
            [sys.executable, "-c", script, str(tmp_path)], capture_output=True, text=True, env=env, check=True
        )
        outputs.add(result.stdout)
    assert len(outputs) == 1, "graph order depends on the hash seed, so cursors would not be stable"


def test_catalog_documents_cursor_paging_for_graph_coverage_and_collections() -> None:
    catalog = {row["path"]: row for row in api_v1.resource_catalog()}
    for path in ("/api/v1/graph", "/api/v1/repo-graph", "/api/v1/graph/coverage"):
        assert {"limit", "offset", "cursor"} <= set(catalog[path]["query"]), path
    assert "cursor" in catalog["/api/v1/evidence"]["query"]
    assert catalog["/api/v1/graph/coverage"]["kind"] == "singleton"

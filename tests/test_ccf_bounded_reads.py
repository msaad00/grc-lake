"""CCF pages read only their pinned SQL projection, retaining v1 semantics."""

import pytest

from security_lakehouse import api_v1
from security_lakehouse.io import read_json, write_jsonl
from security_lakehouse.pipeline import run_pipeline
from test_assurance_truth import event


@pytest.fixture
def lake(tmp_path):
    raw = tmp_path / "events.jsonl"
    rows = [
        {
            **event("failed" if i % 2 else "pass"),
            "tenant_id": f"source-{i % 2}",
            "event_id": f"event-{i}",
            "entity": {"asset_id": f"asset-{i // 2}", "asset_type": "iam_role"},
            "safeguard_ids": ["SG-IDENTITY-001"],
        }
        for i in range(8)
    ]
    write_jsonl(raw, rows)
    target = tmp_path / "lake"
    run_pipeline(raw, target, tenant_id="platform")
    return target


def test_summary_and_page_never_load_full_asset_json(lake, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("CCF request loaded every asset")

    monkeypatch.setattr(api_v1, "_ccf_assessment", forbidden)
    status, summary = api_v1.handle_get("/api/v1/ccf/assessment", {}, lake)
    assert status == 200
    assert summary["data"]["asset_result_count"] == 8
    status, page = api_v1.handle_get("/api/v1/ccf/asset-results", {"limit": ["2"]}, lake)
    assert status == 200
    assert page["meta"]["count"] == 8
    assert len(page["data"]) == 2
    assert page["meta"]["generation"] == summary["meta"]["generation"]


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"limit": ["2"], "offset": ["1"], "sort": ["asset_id"]},
        {"status": ["pass,fail"], "source_tenant_id": ["source-1"], "sort": ["-asset_id"]},
        {"event_ids": ["event-0,event-3"], "sort": ["event_ids"]},
        {"sort": ["-reasons"]},
        {"sort": ["--asset_id"]},
        {"unknown": ["x' OR 1=1 --"]},
        {"sort": ["unknown"], "cursor": [api_v1.encode_cursor(3)], "limit": ["2"]},
        {"asset_id": [""]},
    ],
)
def test_indexed_page_matches_existing_collection_contract(lake, params):
    rows = read_json(lake / "gold/ccf_assessment.json")["asset_results"]
    expected = api_v1.collection_response("ccf.asset-results", rows, params)
    status, actual = api_v1.handle_get("/api/v1/ccf/asset-results", params, lake)
    assert status == 200
    actual["meta"].pop("generation")
    assert actual == expected


def test_broken_current_projection_fails_closed(lake):
    (lake / "mart/security_lakehouse.sqlite").write_bytes(b"broken sqlite")
    for route in ("/api/v1/ccf/assessment", "/api/v1/ccf/asset-results"):
        status, body = api_v1.handle_get(route, {}, lake)
        assert status == 409
        assert body["errors"][0]["code"] == "assessment_unavailable"


def test_request_does_not_materialize_raw_event_index(lake, monkeypatch):
    from pathlib import Path

    from security_lakehouse import ccf_queries

    original = ccf_queries.read_json

    def bounded(path, *args, **kwargs):
        assert Path(path).name != "manifest.json", "manifest includes the entire raw event index"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(ccf_queries, "read_json", bounded)
    assert api_v1.handle_get("/api/v1/ccf/assessment", {}, lake)[0] == 200
    assert api_v1.handle_get("/api/v1/ccf/asset-results", {}, lake)[0] == 200


def test_projection_cannot_redirect_to_a_different_generation(lake):
    import shutil

    from security_lakehouse.generations import active_generation

    generation = active_generation(lake)
    alternate = lake / "alternate"
    shutil.copytree(generation, alternate)
    mart = generation / "mart/security_lakehouse.sqlite"
    mart.unlink()
    mart.symlink_to(alternate / "mart/security_lakehouse.sqlite")
    assert api_v1.handle_get("/api/v1/ccf/asset-results", {}, lake)[0] == 409


def test_old_generation_without_projection_remains_readable(lake, tmp_path):
    from security_lakehouse.io import write_json

    legacy = tmp_path / "legacy"
    assessment = read_json(lake / "gold/ccf_assessment.json")
    write_json(legacy / "gold/ccf_assessment.json", assessment)
    assert api_v1.handle_get("/api/v1/ccf/assessment", {}, legacy)[1]["data"]["asset_result_count"] == 8
    assert api_v1.handle_get("/api/v1/ccf/asset-results", {"limit": ["1"]}, legacy)[1]["meta"]["count"] == 8


def test_huge_offset_is_an_empty_page(lake):
    offset = 10**30
    status, body = api_v1.handle_get("/api/v1/ccf/asset-results", {"offset": [str(offset)]}, lake)
    assert status == 200
    assert body["data"] == []
    assert body["meta"]["offset"] == offset


def test_publication_between_page_entry_and_query_stays_pinned(lake, tmp_path, monkeypatch):
    from security_lakehouse import ccf_queries
    from security_lakehouse.generations import generation_identity

    before = generation_identity(lake)
    raw = tmp_path / "replacement.jsonl"
    write_jsonl(raw, [{**event(), "safeguard_ids": ["SG-IDENTITY-001"]}])
    original = ccf_queries.read_page

    def interleaved(*args, **kwargs):
        run_pipeline(raw, lake)
        return original(*args, **kwargs)

    monkeypatch.setattr(ccf_queries, "read_page", interleaved)
    status, body = api_v1.handle_get("/api/v1/ccf/asset-results", {}, lake)
    assert status == 200
    assert body["meta"]["count"] == 8
    assert body["meta"]["generation"] == before
    assert api_v1.handle_get("/api/v1/ccf/assessment", {}, lake)[1]["data"]["asset_result_count"] == 1

"""Generation-keyed read caches: equivalence, invalidation, isolation, and bounds."""

from __future__ import annotations

import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from security_lakehouse import api_v1, assessment, graph, io, pipeline, read_cache
from security_lakehouse.catalog import (
    control_catalog_view,
    framework_registry_view,
    load_control_catalog,
    load_framework_registry,
)
from security_lakehouse.evidence_freshness import build_evidence_freshness, freshness_status_interval
from security_lakehouse.ingestion_status import build_ingestion_status
from security_lakehouse.io import read_jsonl, write_jsonl

RAW = Path(__file__).resolve().parents[1] / "data/raw/security_events.jsonl"
MOMENT = datetime(2026, 5, 21, 9, 30, tzinfo=UTC)


@pytest.fixture
def lake(tmp_path: Path) -> Path:
    root = tmp_path / "lake"
    pipeline.run_pipeline(RAW, root)
    return root


@pytest.fixture
def clock(monkeypatch):
    state = {"now": MOMENT}
    monkeypatch.setattr(assessment, "_utcnow", lambda: state["now"])
    return state


def _settle_files(monkeypatch) -> None:
    """Treat every file as older than the racy-timestamp window, so its key is its stat."""
    real = io.time.time_ns
    monkeypatch.setattr(io.time, "time_ns", lambda: real() + 60 * 10**9)


@pytest.fixture
def window_builds(monkeypatch):
    _settle_files(monkeypatch)
    calls: list[datetime] = []
    original = assessment._PostureWindow.build.__func__

    def counted(cls, lake, freshness_days, max_violations, evaluated_at):
        calls.append(evaluated_at)
        return original(cls, lake, freshness_days, max_violations, evaluated_at)

    monkeypatch.setattr(assessment._PostureWindow, "build", classmethod(counted))
    return calls


def _get(lake: Path, path: str, **params: str) -> dict:
    status, body = api_v1.handle_get(path, {key: [value] for key, value in params.items()}, lake)
    assert status == 200, body
    return body


def _rewrite_raw(tmp_path: Path, mutate) -> Path:
    rows = read_jsonl(RAW)
    mutate(rows)
    changed = tmp_path / "changed.jsonl"
    write_jsonl(changed, rows)
    return changed


def test_live_posture_matches_a_fresh_build_and_is_reused(lake, clock, window_builds):
    first = assessment.build_current_posture(lake)
    clock["now"] = MOMENT + timedelta(seconds=7, microseconds=3)
    second = assessment.build_current_posture(lake)

    assert first == assessment.build_current_posture(lake, now=MOMENT)
    assert second == assessment.build_current_posture(lake, now=clock["now"])
    assert second["evaluated_at"] != first["evaluated_at"]
    assert second["assessment_hash"] == assessment._assessment_hash(second)
    assert len(window_builds) == 3  # one live window plus the two explicit-time builds


def test_live_posture_preserves_the_uncached_key_order(lake, clock):
    cached = assessment.build_current_posture(lake)
    fresh = assessment.build_current_posture(lake, now=MOMENT)
    assert json.dumps(cached) == json.dumps(fresh)


def test_freshness_status_change_rebuilds_the_window(lake, clock, window_builds):
    events = read_jsonl(lake / "silver/normalized_events.jsonl")
    since, until = freshness_status_interval(build_evidence_freshness(events, now=MOMENT), MOMENT)
    assert until is not None, "fixture needs a pending freshness transition"
    statuses_before = assessment.build_current_posture(lake)["evidence_freshness"]["sources"]

    for moment in (until - timedelta(microseconds=1), until, until + timedelta(minutes=1)):
        clock["now"] = moment
        assert assessment.build_current_posture(lake) == assessment.build_current_posture(lake, now=moment)
    clock["now"] = until
    assert assessment.build_current_posture(lake)["evidence_freshness"]["sources"] != statuses_before
    live_builds = [moment for moment in window_builds if moment in {MOMENT, until}]
    assert live_builds.count(MOMENT) == 1 and until in live_builds

    if since is not None:
        clock["now"] = since - timedelta(microseconds=1)
        assert assessment.build_current_posture(lake) == assessment.build_current_posture(lake, now=clock["now"])


def test_every_caller_gets_an_independent_copy(lake, clock):
    first = assessment.build_current_posture(lake)
    pristine = json.loads(json.dumps(first))
    first["posture"]["score"] = -1
    first["violations"][0]["severity"] = "tampered"
    first["violations"].clear()
    first["frameworks"][0]["score"] = -1
    first["evidence_freshness"]["sources"].clear()
    assert assessment.build_current_posture(lake) == pristine

    page = _get(lake, "/api/v1/violations", limit="2")
    page["data"][0]["severity"] = "tampered"
    assert _get(lake, "/api/v1/violations", limit="2")["data"][0]["severity"] != "tampered"

    graph_page = _get(lake, "/api/v1/graph", limit="5")
    graph_page["data"]["nodes"][0]["label"] = "tampered"
    assert _get(lake, "/api/v1/graph", limit="5")["data"]["nodes"][0]["label"] != "tampered"
    full = graph.build_compliance_graph(lake)
    full["nodes"].clear()
    assert graph.build_compliance_graph(lake)["nodes"]


def test_new_generation_invalidates_posture_violations_graph_and_status(tmp_path, lake, clock):
    before_posture = assessment.build_current_posture(lake)
    before_violations = _get(lake, "/api/v1/violations", limit="1000")
    before_graph = graph.build_compliance_graph(lake)
    before_status = build_ingestion_status(lake)

    def drop_open_events(rows):
        rows[:] = [row for row in rows if row["status"] != "open"][:4]
        rows[0]["source"] = "brand-new-source"

    pipeline.run_pipeline(_rewrite_raw(tmp_path, drop_open_events), lake)

    after_posture = assessment.build_current_posture(lake)
    assert after_posture["generation"] != before_posture["generation"]
    assert after_posture == assessment.build_current_posture(lake, now=MOMENT)
    after_violations = _get(lake, "/api/v1/violations", limit="1000")
    assert after_violations["meta"]["count"] < before_violations["meta"]["count"]
    assert after_violations["data"] == _uncached_violation_rows(lake)
    assert graph.build_compliance_graph(lake) == graph._build_compliance_graph(lake)
    assert graph.build_compliance_graph(lake) != before_graph
    after_status = build_ingestion_status(lake)
    assert "brand-new-source" in {row["source"] for row in after_status["sources"]}
    assert after_status["summary"]["evidence_count"] == 4 != before_status["summary"]["evidence_count"]


def _uncached_violation_rows(lake: Path) -> list[dict]:
    frameworks = {row["control_id"]: row["framework"] for row in read_jsonl(lake / "gold/control_posture.jsonl")}
    rows = assessment.build_current_posture(lake, now=MOMENT)["violations"]
    return [{**row, "framework": frameworks.get(row["control_id"], "unknown")} for row in rows]


def test_triage_decision_leaves_posture_and_violations_equal_to_a_fresh_build(lake, clock):
    violations = _get(lake, "/api/v1/violations", limit="1000")["data"]
    target = violations[0]["violation_id"]
    status, _body = api_v1.handle_post(
        f"/api/v1/violations/{target}/triage", {"state": "dismissed", "actor": "analyst"}, lake
    )
    assert status == 201

    assert assessment.build_current_posture(lake) == assessment.build_current_posture(lake, now=MOMENT)
    assert _get(lake, "/api/v1/violations", limit="1000")["data"] == _uncached_violation_rows(lake)
    tracking = _get(lake, f"/api/v1/violations/{target}/tracking")["data"]
    assert tracking["current_state"] == "dismissed"


def test_connector_run_is_visible_in_ingestion_status_immediately(lake):
    from security_lakehouse.connector_state import append_run_event

    build_ingestion_status(lake)
    append_run_event(lake, connector_id="okta-identity", kind="sync", result="error", error="token expired")
    status = build_ingestion_status(lake)
    assert status["latest_runs"][0]["connector_id"] == "okta-identity"
    assert status["latest_runs"][0]["result"] == "error"


def test_retention_of_old_generations_keeps_reads_correct(tmp_path, lake, clock):
    from security_lakehouse.generation_retention import archive_generations

    pipeline.run_pipeline(_rewrite_raw(tmp_path, lambda rows: rows.pop()), lake)
    pipeline.run_pipeline(_rewrite_raw(tmp_path, lambda rows: rows.pop(0)), lake)
    assessment.build_current_posture(lake)
    graph.build_compliance_graph(lake)
    old = sorted((lake / "generations").iterdir(), key=lambda path: path.stat().st_mtime)[0]
    os.utime(old, (0, 0))
    report = archive_generations(lake, older_than_days=1, keep_latest=1, archive_to=tmp_path / "archive")
    assert old.name in report["archived"]

    assert assessment.build_current_posture(lake) == assessment.build_current_posture(lake, now=MOMENT)
    assert graph.build_compliance_graph(lake) == graph._build_compliance_graph(lake)
    assert _get(lake, "/api/v1/violations", limit="1000")["data"] == _uncached_violation_rows(lake)


def _legacy_lake(root: Path, events: list[dict]) -> Path:
    write_jsonl(root / "silver/normalized_events.jsonl", events)
    write_jsonl(
        root / "gold/control_posture.jsonl",
        [{"control_id": "SOC2-CC6.1", "framework": "SOC 2", "status": "fail", "risk_score": 80}],
    )
    write_jsonl(root / "gold/control_tests.jsonl", [{"control_id": "SOC2-CC6.1", "result": "fail"}])
    write_jsonl(root / "gold/asset_risk.jsonl", [{"asset_id": "asset-1", "asset_name": "Primary"}])
    return root


def _event(event_id: str, *, severity: str = "high", source: str = "okta") -> dict:
    return {
        "event_id": event_id,
        "event_time": "2026-05-20T13:01:00Z",
        "event_type": "identity.mfa",
        "control_ids": ["SOC2-CC6.1"],
        "asset_id": "asset-1",
        "asset_owner": "it",
        "environment": "prod",
        "source": source,
        "severity": severity,
        "severity_score": 70,
        "status": "open",
        "evidence_ref": f"s3://evidence/{event_id}.json",
        "raw_sha256": "0" * 64,
    }


@pytest.mark.parametrize("settled", [False, True])
def test_rewritten_legacy_artifacts_invalidate(tmp_path, clock, monkeypatch, settled):
    lake = _legacy_lake(tmp_path / "legacy", [_event("evt-1")])
    if settled:
        _settle_files(monkeypatch)
    assert assessment.build_current_posture(lake)["posture"]["open_violation_count"] == 1
    assert _get(lake, "/api/v1/violations")["meta"]["count"] == 1

    write_jsonl(lake / "silver/normalized_events.jsonl", [_event("evt-1"), _event("evt-2", severity="critical")])

    posture = assessment.build_current_posture(lake)
    assert posture["posture"]["open_violation_count"] == 2
    assert posture == assessment.build_current_posture(lake, now=MOMENT)
    assert _get(lake, "/api/v1/violations")["meta"]["count"] == 2


def test_tenant_lakes_never_share_cached_reads(tmp_path, clock):
    first = _legacy_lake(tmp_path / "tenant-a" / "lake", [_event("evt-a", source="tenant-a-source")])
    second = _legacy_lake(tmp_path / "tenant-b" / "lake", [_event("evt-b", source="tenant-b-source")] * 1)
    for _ in range(2):
        for lake, own, other in ((first, "evt-a", "evt-b"), (second, "evt-b", "evt-a")):
            posture = assessment.build_current_posture(lake)
            assert {row["event_id"] for row in posture["violations"]} == {own}
            ids = {row["event_id"] for row in _get(lake, "/api/v1/violations")["data"]}
            assert ids == {own} and other not in ids
            sources = {row["source"] for row in build_ingestion_status(lake)["sources"]}
            assert sources == {f"tenant-{own[-1]}-source"}
            nodes = {node["id"] for node in graph.build_compliance_graph(lake)["nodes"]}
            assert "asset:asset-1" in nodes
    roots = {key[0] for key in assessment._POSTURE_WINDOWS._entries}
    assert {str(first.resolve()), str(second.resolve())} <= roots


def test_identical_tenant_content_still_gets_separate_entries(tmp_path, clock):
    first = _legacy_lake(tmp_path / "a", [_event("evt-1")])
    second = _legacy_lake(tmp_path / "b", [_event("evt-1")])
    assessment.build_current_posture(first)
    assessment.build_current_posture(second)
    write_jsonl(second / "silver/normalized_events.jsonl", [])
    assert assessment.build_current_posture(first)["posture"]["open_violation_count"] == 1
    assert assessment.build_current_posture(second)["posture"]["open_violation_count"] == 0


def test_derived_cache_is_bounded_per_root_and_overall(tmp_path):
    cache: read_cache.DerivedCache[int] = read_cache.DerivedCache(max_entries=3, per_root=2)
    roots = [tmp_path / name for name in "abc"]
    for root in roots:
        root.mkdir()
    for slot in range(3):
        cache.get(roots[0], slot, 1, lambda slot=slot: slot)
    assert sorted(key[1] for key in cache._entries) == [1, 2]
    cache.get(roots[0], 2, 2, lambda: 20)
    assert cache.get(roots[0], 2, 2, lambda: -1) == 20
    assert len(cache) == 2
    cache.get(roots[1], "x", 1, lambda: 1)
    cache.get(roots[2], "x", 1, lambda: 1)
    assert len(cache) == 3
    assert {key[0] for key in cache._entries} == {str(roots[0]), str(roots[1]), str(roots[2])}


def test_derived_cache_rejected_entries_rebuild(tmp_path):
    cache: read_cache.DerivedCache[int] = read_cache.DerivedCache(max_entries=4)
    assert cache.get(tmp_path, "s", 1, lambda: 1) == 1
    assert cache.get(tmp_path, "s", 1, lambda: 2, accept=lambda value: value > 1) == 2
    assert cache.get(tmp_path, "s", 1, lambda: 3) == 2


def test_concurrent_misses_build_once_without_blocking_other_tenants(tmp_path):
    cache: read_cache.DerivedCache[str] = read_cache.DerivedCache(max_entries=8)
    first_root, second_root = tmp_path / "a", tmp_path / "b"
    first_root.mkdir()
    second_root.mkdir()
    entered, release = threading.Event(), threading.Event()
    builds: list[str] = []

    def slow() -> str:
        builds.append("a")
        entered.set()
        assert release.wait(5)
        return "a"

    with ThreadPoolExecutor(max_workers=3) as executor:
        first = executor.submit(cache.get, first_root, "s", 1, slow)
        assert entered.wait(2)
        second = executor.submit(cache.get, first_root, "s", 1, slow)
        other = executor.submit(cache.get, second_root, "s", 1, lambda: "b")
        assert other.result(timeout=2) == "b"
        release.set()
        assert first.result(timeout=2) == second.result(timeout=2) == "a"
    assert builds == ["a"]


def test_failed_build_is_not_cached(tmp_path):
    cache: read_cache.DerivedCache[int] = read_cache.DerivedCache(max_entries=4)

    def boom() -> int:
        raise ValueError("bad row")

    with pytest.raises(ValueError):
        cache.get(tmp_path, "s", 1, boom)
    assert cache.get(tmp_path, "s", 1, lambda: 5) == 5


@pytest.mark.parametrize(
    ("route", "relative"),
    [
        ("/api/v1/assets", "gold/asset_risk.jsonl"),
        ("/api/v1/evidence/freshness", "gold/evidence_freshness.jsonl"),
        ("/api/v1/control-tests", "gold/control_tests.jsonl"),
    ],
)
def test_streamed_collection_pages_match_the_materialized_contract(lake, route, relative):
    rows = read_jsonl(lake / relative)
    resource = api_v1.STREAMED_COLLECTIONS[route][0]
    assert rows
    for params in (
        {},
        {"limit": "2"},
        {"limit": "2", "offset": "3"},
        {"limit": "1000", "offset": str(len(rows) - 1)},
        {"offset": str(len(rows) + 5)},
        {"cursor": api_v1.encode_cursor(1), "limit": "3"},
    ):
        body = _get(lake, route, **params)
        expected = api_v1.collection_response(resource, rows, {key: [value] for key, value in params.items()})
        assert body["data"] == expected["data"]
        assert {key: value for key, value in body["meta"].items() if key != "generation"} == expected["meta"]
    first_key = next(iter(rows[0]))
    sorted_body = _get(lake, route, sort=f"-{first_key}", limit="3")
    assert (
        sorted_body["data"]
        == api_v1.collection_response(resource, rows, {"sort": [f"-{first_key}"], "limit": ["3"]})["data"]
    )


def test_streamed_collection_fails_closed_on_an_invalid_row_outside_the_page(tmp_path):
    lake = _legacy_lake(tmp_path / "lake", [_event("evt-1")])
    path = lake / "gold/asset_risk.jsonl"
    path.write_text('{"asset_id":"a"}\n\n{"asset_id":"b","risk":NaN}\n')
    status, body = api_v1.handle_get("/api/v1/assets", {"limit": ["1"]}, lake)
    assert status == 400
    assert body["errors"][0]["code"] == "bad_request"


def test_jsonl_page_matches_text_mode_rows(tmp_path):
    path = tmp_path / "rows.jsonl"
    path.write_bytes(b'{"n":1}\r\n\n  {"n":2}  \n{"n":"\\u00e9"}\n{"n":4}')
    assert io.jsonl_page(path, 0, 10) == (4, read_jsonl(path))
    assert io.jsonl_page(path, 2, 3) == (4, [{"n": "\u00e9"}])
    assert io.jsonl_page(path, 7, 9) == (4, [])
    bare = tmp_path / "bare.jsonl"
    bare.write_bytes(b'{"n":1}\r{"n":2}\n')
    assert io.jsonl_page(bare, 1, 2) == (2, [{"n": 2}])
    assert io.jsonl_page(tmp_path / "missing.jsonl", 0, 1, missing_ok=True) == (0, [])


def test_graph_pages_reuse_one_build_and_rebuild_the_full_graph(lake, monkeypatch):
    builds = []
    original = graph._build_compliance_graph

    def counted(path):
        builds.append(path)
        return original(path)

    monkeypatch.setattr(graph, "_build_compliance_graph", counted)
    _settle_files(monkeypatch)
    graph._GRAPHS.clear()
    nodes, edges, cursor = [], [], None
    while True:
        params = {"limit": "7"} | ({"cursor": cursor} if cursor else {})
        body = _get(lake, "/api/v1/graph", **params)
        nodes += body["data"]["nodes"]
        edges += body["data"]["edges"]
        cursor = body["meta"]["next_cursor"]
        if not cursor:
            break
    expected = original(lake)
    assert nodes == expected["nodes"] and edges == expected["edges"]
    assert len(builds) == 1


def test_coverage_pages_match_an_uncached_analysis(lake):
    body = _get(lake, "/api/v1/graph/coverage", limit="1000")
    expected = graph.analyze_coverage(lake, detail_limit=None)
    assert body["data"]["summary"] == expected["summary"]
    assert body["data"]["assets"] == expected["assets"][:1000]


def test_catalog_views_are_shared_read_only_and_match_the_loaders():
    controls = control_catalog_view()
    assert controls is control_catalog_view()
    assert {key: _thaw(value) for key, value in controls.items()} == load_control_catalog()
    assert {key: _thaw(value) for key, value in framework_registry_view().items()} == load_framework_registry()
    control_id = next(iter(controls))
    with pytest.raises(TypeError):
        controls[control_id]["title"] = "tampered"  # type: ignore[index]
    with pytest.raises(TypeError):
        controls["new"] = {}  # type: ignore[index]


def _thaw(value):
    if hasattr(value, "items"):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def test_ingestion_status_matches_an_uncached_build(lake, monkeypatch):
    from security_lakehouse import ingestion_metrics, ingestion_status, lake_scale

    def lake_derived(payload):
        keys = ("state", "summary", "sources", "pipeline", "integrity", "eval_accuracy", "recommended_actions")
        return {key: payload[key] for key in keys} | {"manifest": payload["scale"]["manifest"]}

    cached = build_ingestion_status(lake)
    cached_again = build_ingestion_status(lake)
    for cache in (ingestion_status._DERIVED, ingestion_metrics._DERIVED, lake_scale._ROW_COUNTS):
        cache.clear()
    fresh = build_ingestion_status(lake)
    assert lake_derived(cached) == lake_derived(cached_again) == lake_derived(fresh)
    assert cached["summary"]["evidence_count"] == len(read_jsonl(lake / "silver/normalized_events.jsonl"))


def test_explicit_naive_time_keeps_existing_posture_contract(tmp_path):
    lake = _legacy_lake(tmp_path / "lake", [_event("evt-1")])
    moment = datetime(2026, 5, 21, 9, 30)
    result = assessment.build_current_posture(lake, now=moment)
    assert result == assessment.build_current_posture(lake, now=moment.astimezone(UTC))

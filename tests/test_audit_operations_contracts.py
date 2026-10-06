"""Boundary and performance regressions for operational console workflows."""

import argparse
import csv
import io
import json

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from security_lakehouse import catalog, cli, tenancy
from security_lakehouse.auth.sessions import SESSION_COOKIE
from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
from security_lakehouse.server_app import _KnownCredentials, _rate_limit_key, create_app
from test_api_v1 import _seed_lake


def test_flat_share_remains_revocable_after_second_tenant(tmp_path):
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        first = create_tenant(session, slug="first", name="First")
        user = create_user(session, tenant_id=first.id, email="owner@example.test", role="security_admin")
        _, token = create_api_key(session, tenant_id=first.id, user_id=user.id)
    client = TestClient(app)
    headers = {"Authorization": "Bearer " + token}
    response = client.post("/api/v1/trust-shares", headers=headers, json={"scope": "posture_full", "role": "auditor"})
    assert response.status_code == 201
    share = response.json()["data"]
    with session_scope(app.state.sessionmaker) as session:
        create_tenant(session, slug="second", name="Second")
    revoke = client.post(f"/api/v1/trust-shares/{share['share_id']}/revoke", headers=headers, json={})
    assert revoke.status_code == 201
    assert client.get("/api/public/trust/" + share["token"]).status_code == 404


def test_request_audit_is_written_to_authenticated_tenant(tmp_path):
    from test_tenant_isolation import _provision_tenant

    app = create_app(tmp_path)
    tenant, token = _provision_tenant(app, "a")
    _provision_tenant(app, "b")
    assert TestClient(app).get("/api/v1/controls", headers={"Authorization": "Bearer " + token}).status_code == 200
    assert (tmp_path / "tenants" / tenant / "gold/request_audit.jsonl").is_file()


@pytest.mark.parametrize("tenant", ["../escape", "/tmp/escape", "..", "a/b"])
def test_tenant_path_rejects_non_identifiers(tmp_path, tenant):
    with pytest.raises(ValueError):
        tenancy.tenant_lake(tmp_path, tenant, bound_tenant=None)


def test_known_browser_sessions_get_distinct_rate_buckets():
    import hashlib

    known = _KnownCredentials()
    keys = []
    for value in ("signed-one", "signed-two"):
        known.add(hashlib.sha256(("session:" + value).encode()).hexdigest()[:32])
        request = Request(
            {"type": "http", "headers": [(b"cookie", f"{SESSION_COOKIE}={value}".encode())], "client": ("host", 123)}
        )
        keys.append(_rate_limit_key(request, known))
    assert keys[0] != keys[1]


def test_auditor_view_narrows_server_write_authority(tmp_path):
    _seed_lake(tmp_path)
    client = TestClient(create_app(tmp_path, require_auth=False))
    response = client.post(
        "/api/v1/trust-shares", headers={"X-Trust-Role": "auditor"}, json={"scope": "posture_full", "role": "auditor"}
    )
    assert response.status_code == 403


@pytest.mark.parametrize("command", ["status", "snapshot"])
def test_cli_missing_lake_fails_without_creating_it(tmp_path, command):
    lake = tmp_path / "typo"
    assert cli.main(["assessment", command, "--lake", str(lake)]) == 1
    assert not lake.exists()


def test_review_csv_neutralizes_formula_cells(tmp_path, monkeypatch, capsys):
    from security_lakehouse import mapping_review

    monkeypatch.setattr(
        mapping_review, "list_decisions", lambda lake: [{"rationale": '=HYPERLINK("https://example.test")'}]
    )
    cli._frameworks_review_export(argparse.Namespace(lake=tmp_path, format="csv", out=None))
    row = next(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    assert row["rationale"].startswith("'=")


def test_catalog_cache_returns_copies_and_refreshes_on_replace(tmp_path, monkeypatch):
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps({"controls": [{"control_id": "A", "title": "First"}]}))
    calls = []
    original = catalog.json.loads
    monkeypatch.setattr(catalog.json, "loads", lambda *a, **k: (calls.append(1), original(*a, **k))[1])
    first = catalog.load_control_catalog(path)
    first["A"]["title"] = "Mutated"
    assert catalog.load_control_catalog(path)["A"]["title"] == "First"
    assert len(calls) == 1
    path.write_text(json.dumps({"controls": [{"control_id": "A", "title": "Second"}]}))
    assert catalog.load_control_catalog(path)["A"]["title"] == "Second"


def test_policy_coverage_reads_templates_once(monkeypatch):
    from security_lakehouse.services import policy_documents as policies

    calls = []
    monkeypatch.setattr(policies, "load_control_catalog", lambda: {"A": {}, "B": {}})
    monkeypatch.setattr(policies.pd, "published_control_ids", lambda *a, **k: {})
    monkeypatch.setattr(policies, "list_policy_templates", lambda: (calls.append(1), [])[1])
    assert policies.control_coverage(None, "tenant") == []
    assert len(calls) == 1


def test_connector_history_cache_bounds_reads_and_detects_rewrites(tmp_path, monkeypatch):
    from security_lakehouse import connector_state as state
    from security_lakehouse.io import write_jsonl

    gold = tmp_path / "gold"
    gold.mkdir()
    path = gold / state.RUNS_FILE
    write_jsonl(
        path, [{"connector_id": "aws-posture", "kind": "sync", "result": "ok", "occurred_at": "2026-01-01T00:00:00Z"}]
    )
    calls = []
    original = state._read_jsonl
    monkeypatch.setattr(state, "_read_jsonl", lambda path: (calls.append(path.name), original(path))[1])
    assert state.latest_run(tmp_path, "aws-posture")["result"] == "ok"
    state.latest_run(tmp_path, "aws-posture")["result"] = "bad"
    assert state.latest_run(tmp_path, "aws-posture")["result"] == "ok"
    assert calls.count(state.RUNS_FILE) == 1
    path.write_text("corrupt\n")
    with pytest.raises(ValueError):
        state.latest_run(tmp_path, "aws-posture")


def test_proposed_mapping_does_not_assert_requirement_pass():
    from security_lakehouse.safeguards import requirement_status

    payload = {"safeguards": [{"safeguard_id": "S", "satisfies": [{"control_id": "C", "review_status": "proposed"}]}]}
    assert requirement_status("C", {"S": "pass"}, payload) == "unmapped"


def test_policy_lint_rejects_non_object_catalog(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("[]")
    assert cli.main(["policy", "lint", "--catalog", str(path)]) == 1


def test_framework_summary_counts_unique_evidence(tmp_path):
    from security_lakehouse.framework_detail import build_framework_detail
    from security_lakehouse.io import write_jsonl

    _seed_lake(tmp_path)
    write_jsonl(
        tmp_path / "silver/normalized_events.jsonl",
        [{"event_id": "one", "control_ids": ["SOC2-CC6.1", "SOC2-CC6.2"], "source": "fixture"}],
    )
    detail = build_framework_detail("soc2", tmp_path)
    assert detail["summary"]["evidence_count"] == 1
    assert detail["sources"][0]["event_count"] == 1


def test_coverage_does_not_cross_assign_assets_by_evidence_type(tmp_path):
    from security_lakehouse.graph import analyze_coverage
    from security_lakehouse.io import write_jsonl

    write_jsonl(
        tmp_path / "silver/normalized_events.jsonl",
        [
            {"event_id": "one", "event_type": "identity", "asset_id": "a", "control_ids": ["SOC2-CC6.1"]},
            {"event_id": "two", "event_type": "identity", "asset_id": "b", "control_ids": ["SOC2-CC6.2"]},
        ],
    )
    data = analyze_coverage(tmp_path)
    a = next(a for a in data["assets"] if a["asset_id"] == "asset:a")
    assert [c["id"] for c in a["controls"]] == ["control:SOC2-CC6.1"]


def test_graph_coverage_bounds_details_preserving_totals(tmp_path):
    from security_lakehouse.graph import analyze_coverage
    from security_lakehouse.io import write_jsonl

    write_jsonl(
        tmp_path / "silver/normalized_events.jsonl",
        [
            {"event_id": str(i), "event_type": "identity", "asset_id": str(i), "control_ids": ["SOC2-CC6.1"]}
            for i in range(600)
        ],
    )
    data = analyze_coverage(tmp_path)
    assert data["summary"]["total_assets"] == 600
    assert len(data["assets"]) <= 200
    assert data["details_truncated"] is True


def test_sse_tabs_share_computation_and_auditor_redaction(tmp_path, monkeypatch):
    import asyncio

    from security_lakehouse import server_app

    calls = []
    monkeypatch.setattr(
        server_app.api_v1,
        "handle_get",
        lambda *a, **k: (calls.append(1), (200, {"data": {"asset_owner": "private-owner"}}))[1],
    )

    class Connected:
        async def is_disconnected(self):
            return False

    async def read_two():
        first = server_app.platform_event_stream(tmp_path, Connected())
        second = server_app.platform_event_stream(tmp_path, Connected(), role="auditor")
        try:
            await anext(first)
            assert "private-owner" not in str(await anext(second))
        finally:
            await first.aclose()
            await second.aclose()

    asyncio.run(read_two())
    assert len(calls) == 1


def test_retention_archives_only_old_unreferenced_generations(tmp_path):
    import os

    from security_lakehouse.generation_retention import archive_generations
    from security_lakehouse.generations import active_generation
    from security_lakehouse.pipeline import run_pipeline
    from test_generations import RAW

    lake = tmp_path / "lake"
    run_pipeline(RAW, lake)
    old = active_generation(lake)
    os.utime(old, (1, 1))
    run_pipeline(RAW, lake)
    active = active_generation(lake)
    report = archive_generations(lake, older_than_days=1, keep_latest=1)
    assert report["candidates"] == [old.name]
    assert old.exists()
    result = archive_generations(lake, older_than_days=1, keep_latest=1, archive_to=tmp_path / "archive")
    assert result["archived"] == [old.name]
    assert not old.exists()
    assert (tmp_path / "archive" / old.name / "generation.json").is_file()
    assert active_generation(lake) == active


def test_control_and_oscal_exports_carry_input_provenance(tmp_path):
    from pathlib import Path

    from security_lakehouse.io import canonical_sha256, read_jsonl
    from security_lakehouse.oscal import build_assessment_results
    from security_lakehouse.pipeline import CONTROL_EVALUATION_VERSION, run_pipeline

    run_pipeline(Path(__file__).resolve().parents[1] / "data/raw/security_events.jsonl", tmp_path)
    events = read_jsonl(tmp_path / "silver/normalized_events.jsonl", base_dir=tmp_path)
    controls = read_jsonl(tmp_path / "gold/control_posture.jsonl", base_dir=tmp_path)
    exported = build_assessment_results(tmp_path)
    observations = exported["assessment-results"]["results"][0]["observations"]
    for control in controls:
        inputs = sorted(
            (
                {"event_id": e["event_id"], "raw_sha256": e["raw_sha256"]}
                for e in events
                if control["control_id"] in e["control_ids"]
            ),
            key=lambda e: (e["event_id"], e["raw_sha256"]),
        )
        assert control["evaluation_version"] == CONTROL_EVALUATION_VERSION
        assert control["input_event_set_sha256"] == canonical_sha256(inputs)
        observation = next(o for o in observations if o["title"] == control["control_id"] + " evaluation")
        assert len(observation["relevant-evidence"]) == len(inputs)
        for evidence, source in zip(observation["relevant-evidence"], inputs, strict=True):
            assert source["raw_sha256"] in evidence["description"]


@pytest.mark.parametrize("protection", ["reader", "snapshot"])
def test_retention_preserves_readers_and_snapshot_inputs(tmp_path, protection):
    import contextlib
    import os

    from security_lakehouse.assessment import write_assessment_snapshot
    from security_lakehouse.generation_retention import archive_generations
    from security_lakehouse.generations import active_generation, pin_generation
    from security_lakehouse.pipeline import run_pipeline
    from test_generations import RAW

    lake = tmp_path / "lake"
    run_pipeline(RAW, lake)
    old = active_generation(lake)
    os.utime(old, (1, 1))
    if protection == "snapshot":
        write_assessment_snapshot(lake)
    with pin_generation(lake) if protection == "reader" else contextlib.nullcontext():
        run_pipeline(RAW, lake)
        assert archive_generations(lake, older_than_days=1, keep_latest=1)["candidates"] == []
        assert old.exists()


def test_server_does_not_publish_embedded_offline_evidence(tmp_path):
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    response = TestClient(app).get("/console", follow_redirects=False)
    assert response.status_code in {200, 307}
    assert "SOC2-CC6.1" not in response.text
    assert (tmp_path / "console.html").read_bytes() == b"<!doctype html>"


def test_violation_framework_filter_is_resolved_and_unknown_fields_fail(tmp_path):
    _seed_lake(tmp_path)
    client = TestClient(create_app(tmp_path, require_auth=False))
    response = client.get("/api/v1/violations", params={"framework": "SOC 2"})
    assert response.status_code == 200
    assert response.json()["data"]
    assert all(row["framework"] == "SOC 2" for row in response.json()["data"])
    assert client.get("/api/v1/violations", params={"framwork": "SOC 2"}).status_code == 400


@pytest.mark.parametrize("payload", [{"options": -1}, {"state": "unexpected-state"}])
def test_invalid_connector_configuration_is_a_client_error(tmp_path, payload):
    client = TestClient(create_app(tmp_path, require_auth=False), raise_server_exceptions=False)
    response = client.post("/api/v1/connectors/github-security/configure", json=payload)
    assert response.status_code in {400, 422}

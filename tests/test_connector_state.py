"""Connector configuration + probe + framework provenance tests."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from security_lakehouse import connector_state
from security_lakehouse.connector_state import (
    _access_fingerprint,
    _missing_required_config,
    append_config_event,
    build_catalog_view,
    configure_payload_error,
    latest_config,
    latest_run,
    list_runs,
    run_discovery,
    run_probe,
)
from security_lakehouse.framework_provenance import build_framework_view
from security_lakehouse.server import _Handler

# --- pure-Python connector_state ------------------------------------------------


def test_configure_records_state_and_redacts_credentials(tmp_path: Path) -> None:
    record = append_config_event(
        tmp_path,
        connector_id="github-security",
        state="enabled",
        actor="alice",
        credentials={"token": "source_connector_secret", "username": "alice"},
        options={"org": "acme"},
    )
    assert record["state"] == "enabled"
    # credentials are redacted (token → fingerprint), username left alone
    assert record["credentials"]["token"].startswith("***")
    assert record["credentials"]["username"] == "alice"
    # fingerprint deterministic
    again = append_config_event(
        tmp_path,
        connector_id="github-security",
        state="enabled",
        actor="alice",
        credentials={"token": "source_connector_secret", "username": "alice"},
        options={"org": "acme"},
    )
    assert again["credential_fingerprint"] == record["credential_fingerprint"]
    assert record["credential_fingerprint"] != "source_connector_secret"


def test_configure_strips_raw_from_persisted_options(tmp_path: Path) -> None:
    append_config_event(
        tmp_path,
        connector_id="github-security",
        state="enabled",
        actor="alice",
        credentials={"token": "secret-token-value", "username": "alice"},
        options={"org": "acme", "raw": {"token": "secret-token-value"}},
    )
    persisted = (tmp_path / "gold" / "connector_config.jsonl").read_text(encoding="utf-8")
    assert '"raw"' not in persisted
    assert "secret-token-value" not in persisted


def test_staged_probe_does_not_persist_raw_credentials_in_runs_jsonl(tmp_path: Path) -> None:
    append_config_event(
        tmp_path,
        connector_id="github-security",
        state="disabled",
        actor="alice",
        credentials={"token": "probe-secret-token", "username": "alice"},
        options={"org": "acme"},
    )
    run_probe(
        tmp_path,
        connector_id="github-security",
        credentials={"token": "probe-secret-token", "username": "alice"},
        options={"org": "acme"},
    )
    persisted = (tmp_path / "gold" / "connector_runs.jsonl").read_text(encoding="utf-8")
    assert "probe-secret-token" not in persisted


def test_access_fingerprint_changes_with_secret_rotation() -> None:
    first = _access_fingerprint({"token": "abc"}, {"org": "x"})
    same = _access_fingerprint({"token": "abc"}, {"org": "x"})
    rotated = _access_fingerprint({"token": "different"}, {"org": "x"})

    assert first == same
    assert first != rotated


def test_access_fingerprint_ignores_scheduler_options_but_not_scope() -> None:
    first = _access_fingerprint({"token": "abc"}, {"org": "x", "repo": "acme/app"})
    with_schedule = _access_fingerprint(
        {"token": "abc"},
        {
            "org": "x",
            "repo": "acme/app",
            "sync_schedule": "every 15m",
            "fixture_dir": "/tmp/fixture",
            "token_env": "GH_READ_TOKEN",
            "materialize": False,
        },
    )
    different_scope = _access_fingerprint({"token": "abc"}, {"org": "x", "repo": "acme/other"})

    assert first == with_schedule
    assert first != different_scope


def test_latest_config_returns_most_recent(tmp_path: Path) -> None:
    append_config_event(tmp_path, connector_id="github-security", state="disabled", actor="a")
    append_config_event(tmp_path, connector_id="github-security", state="enabled", actor="a")
    assert latest_config(tmp_path, "github-security")["state"] == "enabled"


def test_probe_requires_enabled_connector(tmp_path: Path) -> None:
    skipped = run_probe(tmp_path, connector_id="github-security")
    assert skipped["result"] == "skipped"
    assert "not enabled" in skipped["error"]
    append_config_event(tmp_path, connector_id="github-security", state="enabled", actor="a")
    ok = run_probe(tmp_path, connector_id="github-security")
    assert ok["result"] == "ok"
    # The probe validates configuration; it does not collect or fabricate a count.
    assert ok["evidence_count"] is None


def test_probe_without_adapter_is_skipped_not_fabricated(tmp_path: Path) -> None:
    # A connector with no collection adapter must report contract-validated only,
    # never a synthetic evidence_count implying live collection.
    append_config_event(tmp_path, connector_id="identity-provider", state="enabled", actor="a")
    rec = run_probe(tmp_path, connector_id="identity-provider")
    assert rec["result"] == "skipped"
    assert rec["evidence_count"] is None
    assert "no collection adapter" in rec["error"]
    assert rec["metadata"]["probe_mode"] == "contract_only"


def test_probe_validates_staged_payload_without_enabling(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_probe(*, credentials: dict, options: dict) -> dict:
        return {"ok": True, "table": "security.normalized_events", "row_count": 1, "error": None}

    monkeypatch.setattr("security_lakehouse.connector_state.probe_clickhouse_access", fake_probe)

    rec = run_probe(
        tmp_path,
        connector_id="clickhouse-telemetry-lake",
        credentials={
            "host": "https://cluster.example.clickhouse.cloud:8443",
            "credential_ref": "GRC_LAKE_CLICKHOUSE_TOKEN",
        },
        options={},
    )
    assert rec["result"] == "ok"
    assert rec["evidence_count"] == 1
    assert rec["metadata"]["probe_mode"] == "live"
    assert latest_config(tmp_path, "clickhouse-telemetry-lake") is None


def test_probe_rejects_incomplete_staged_payload(tmp_path: Path) -> None:
    rec = run_probe(
        tmp_path,
        connector_id="clickhouse-telemetry-lake",
        credentials={"host": "https://cluster.example.clickhouse.cloud:8443"},
        options={},
    )
    assert rec["result"] == "error"
    assert "missing required connector configuration" in rec["error"]
    assert "credential_ref" in rec["error"]
    assert latest_config(tmp_path, "clickhouse-telemetry-lake") is None


def test_runnable_probe_marks_config_only_mode(tmp_path: Path) -> None:
    rec = run_probe(
        tmp_path,
        connector_id="github-security",
        credentials={"credential_ref": "GITHUB_TOKEN"},
        options={"repo": "acme/platform"},
    )
    assert rec["result"] == "ok"
    assert rec["metadata"]["probe_mode"] == "config_only"


def test_snowflake_probe_reads_selected_scope_before_enable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_probe_snowflake_access(*, credentials: dict, options: dict) -> dict:
        assert credentials["account"] == "org-account"
        assert options["database"] == "GRC_LAKE_SECURITY_LAKE"
        return {
            "ok": True,
            "context": {"role": "GRC_LAKE_READER", "warehouse": "GRC_LAKE_READ_WH"},
            "views": [
                {"purpose": "audit_events", "view": "GRC_LAKE_AUDIT_EVENTS", "ok": True, "row_count": 2},
                {"purpose": "control_posture", "view": "GRC_LAKE_CONTROL_POSTURE", "ok": True, "row_count": 1},
                {"purpose": "asset_risk", "view": "GRC_LAKE_ASSET_RISK", "ok": True, "row_count": 1},
                {"purpose": "evidence_bundles", "view": "GRC_LAKE_EVIDENCE_BUNDLES", "ok": True, "row_count": 2},
            ],
        }

    monkeypatch.setattr("security_lakehouse.connector_state.probe_snowflake_access", fake_probe_snowflake_access)

    rec = run_probe(
        tmp_path,
        connector_id="snowflake-evidence-lake",
        credentials={"account": "org-account", "user": "trustops_reader", "credential_ref": "externalbrowser"},
        options={
            "warehouse": "GRC_LAKE_READ_WH",
            "database": "GRC_LAKE_SECURITY_LAKE",
            "schema": "EVIDENCE",
            "audit_events": "GRC_LAKE_AUDIT_EVENTS",
            "control_posture": "GRC_LAKE_CONTROL_POSTURE",
            "asset_risk": "GRC_LAKE_ASSET_RISK",
            "evidence_bundles": "GRC_LAKE_EVIDENCE_BUNDLES",
        },
    )

    assert rec["result"] == "ok"
    assert rec["evidence_count"] == 4
    assert rec["metadata"]["probe_mode"] == "live"
    assert rec["metadata"]["context"]["role"] == "GRC_LAKE_READER"
    assert rec["metadata"]["views"][0]["row_count"] == 2
    assert rec["access_fingerprint"]
    assert latest_config(tmp_path, "snowflake-evidence-lake") is None


def test_snowflake_probe_blocks_missing_views(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_probe_snowflake_access(*, credentials: dict, options: dict) -> dict:
        return {
            "ok": False,
            "context": {"role": "GRC_LAKE_READER", "warehouse": "GRC_LAKE_READ_WH"},
            "views": [
                {"purpose": "audit_events", "view": "GRC_LAKE_AUDIT_EVENTS", "ok": True, "row_count": 2},
                {
                    "purpose": "control_posture",
                    "view": "GRC_LAKE_CONTROL_POSTURE",
                    "ok": False,
                    "row_count": None,
                    "error": "object not found or not granted to the active role",
                },
            ],
        }

    monkeypatch.setattr("security_lakehouse.connector_state.probe_snowflake_access", fake_probe_snowflake_access)

    rec = run_probe(
        tmp_path,
        connector_id="snowflake-evidence-lake",
        credentials={"account": "org-account", "user": "trustops_reader", "credential_ref": "externalbrowser"},
        options={
            "warehouse": "GRC_LAKE_READ_WH",
            "database": "GRC_LAKE_SECURITY_LAKE",
            "schema": "EVIDENCE",
            "audit_events": "GRC_LAKE_AUDIT_EVENTS",
            "control_posture": "GRC_LAKE_CONTROL_POSTURE",
            "asset_risk": "GRC_LAKE_ASSET_RISK",
            "evidence_bundles": "GRC_LAKE_EVIDENCE_BUNDLES",
        },
    )

    assert rec["result"] == "error"
    assert "GRC_LAKE_CONTROL_POSTURE" in rec["error"]
    assert rec["metadata"]["views"][1]["error"] == "object not found or not granted to the active role"
    assert latest_config(tmp_path, "snowflake-evidence-lake") is None


def test_snowflake_probe_records_sanitized_error_not_raw_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A probe ValueError must not flow to the HTTP boundary verbatim (CodeQL
    # py/stack-trace-exposure): the run record carries the exception category,
    # not the raw message, which could contain a path or connection detail.
    def boom(*, credentials: dict, options: dict) -> dict:
        raise ValueError("connection to host 10.0.0.5:443 failed: /etc/secret/key unreadable")

    monkeypatch.setattr("security_lakehouse.connector_state.probe_snowflake_access", boom)

    rec = run_probe(
        tmp_path,
        connector_id="snowflake-evidence-lake",
        credentials={"account": "org-account", "user": "trustops_reader", "credential_ref": "externalbrowser"},
        options={
            "warehouse": "GRC_LAKE_READ_WH",
            "database": "GRC_LAKE_SECURITY_LAKE",
            "schema": "EVIDENCE",
            "audit_events": "GRC_LAKE_AUDIT_EVENTS",
            "control_posture": "GRC_LAKE_CONTROL_POSTURE",
            "asset_risk": "GRC_LAKE_ASSET_RISK",
            "evidence_bundles": "GRC_LAKE_EVIDENCE_BUNDLES",
        },
    )

    assert rec["result"] == "error"
    assert rec["error"] == "ValueError"
    assert "10.0.0.5" not in rec["error"]
    assert "/etc/secret/key" not in rec["error"]


def test_discovery_returns_selectable_snowflake_scope_without_enable(tmp_path: Path) -> None:
    rec = run_discovery(
        tmp_path,
        connector_id="snowflake-evidence-lake",
        credentials={
            "account": "org-account",
            "user": "trustops_reader",
            "credential_ref": "GRC_LAKE_SNOWFLAKE_OAUTH",
        },
        options={
            "warehouse": "GRC_LAKE_READ_WH",
            "database": "GRC_LAKE_SECURITY_LAKE",
            "schema": "EVIDENCE",
        },
    )

    assert rec["kind"] == "discover"
    assert rec["result"] == "ok"
    assert rec["evidence_count"] == 7
    assert rec["metadata"]["selection_mode"] == "curated_views"
    assert rec["metadata"]["requires_selection"] == []
    selectors = rec["metadata"]["selectors"]
    assert {"kind": "database", "name": "GRC_LAKE_SECURITY_LAKE", "required": True, "selected": True} in selectors
    assert {"kind": "view", "name": "GRC_LAKE_AUDIT_EVENTS", "required": True, "purpose": "audit_events"} in selectors
    assert latest_config(tmp_path, "snowflake-evidence-lake") is None
    persisted = list_runs(tmp_path, "snowflake-evidence-lake", limit=1)[0]
    assert persisted["metadata"]["selection_mode"] == "curated_views"


def test_discovery_uses_live_snowflake_scope_when_credentials_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_discover_snowflake_scope(*, credentials: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
        assert credentials["account"] == "org-account"
        assert credentials["private_key_ref"] == "SNOWFLAKE_PRIVATE_KEY_FILE"
        assert options == {"database": "GRC_LAKE_SECURITY_LAKE"}
        return {
            "ok": True,
            "selection_mode": "live_snowflake_scope",
            "selectors": [
                {"kind": "warehouse", "name": "GRC_LAKE_READ_WH", "required": True, "selected": True},
                {"kind": "database", "name": "GRC_LAKE_SECURITY_LAKE", "required": True, "selected": True},
                {"kind": "schema", "name": "EVIDENCE", "required": True, "selected": True},
                {
                    "kind": "view",
                    "name": "GRC_LAKE_AUDIT_EVENTS",
                    "required": True,
                    "purpose": "audit_events",
                    "selected": True,
                },
            ],
            "candidates": {
                "warehouses": ["GRC_LAKE_READ_WH"],
                "databases": ["GRC_LAKE_SECURITY_LAKE"],
                "schemas": ["EVIDENCE"],
                "views": ["GRC_LAKE_AUDIT_EVENTS"],
            },
            "recommended_options": {
                "warehouse": "GRC_LAKE_READ_WH",
                "database": "GRC_LAKE_SECURITY_LAKE",
                "schema": "EVIDENCE",
                "audit_events": "GRC_LAKE_AUDIT_EVENTS",
            },
        }

    monkeypatch.setattr(connector_state, "discover_snowflake_scope", fake_discover_snowflake_scope)

    rec = run_discovery(
        tmp_path,
        connector_id="snowflake-evidence-lake",
        credentials={
            "account": "org-account",
            "user": "GRC_LAKE_INGEST_SVC",
            "private_key_ref": "SNOWFLAKE_PRIVATE_KEY_FILE",
        },
        options={"database": "GRC_LAKE_SECURITY_LAKE"},
    )

    assert rec["result"] == "ok"
    assert rec["metadata"]["selection_mode"] == "live_snowflake_scope"
    assert rec["metadata"]["candidates"]["views"] == ["GRC_LAKE_AUDIT_EVENTS"]
    assert latest_config(tmp_path, "snowflake-evidence-lake") is None


def test_discovery_recommends_concrete_snowflake_scope_without_placeholders(tmp_path: Path) -> None:
    rec = run_discovery(
        tmp_path,
        connector_id="snowflake-evidence-lake",
        credentials={
            "account": "org-account",
            "user": "trustops_reader",
            "credential_ref": "GRC_LAKE_SNOWFLAKE_OAUTH",
        },
        options={},
    )

    assert rec["result"] == "ok"
    assert rec["metadata"]["requires_selection"] == ["warehouse", "database", "schema"]
    assert rec["metadata"]["recommended_options"] == {
        "warehouse": "GRC_LAKE_READ_WH",
        "database": "GRC_LAKE_SECURITY_LAKE",
        "schema": "EVIDENCE",
        "audit_events": "GRC_LAKE_AUDIT_EVENTS",
        "control_posture": "GRC_LAKE_CONTROL_POSTURE",
        "asset_risk": "GRC_LAKE_ASSET_RISK",
        "evidence_bundles": "GRC_LAKE_EVIDENCE_BUNDLES",
    }
    assert "<" not in json.dumps(rec["metadata"]["recommended_options"])


def test_discovery_validates_scope_credentials_without_password_terms(tmp_path: Path) -> None:
    rec = run_discovery(
        tmp_path,
        connector_id="snowflake-evidence-lake",
        credentials={"account": "org-account"},
        options={},
    )

    assert rec["kind"] == "discover"
    assert rec["result"] == "error"
    assert "missing required connector discovery configuration" in rec["error"]
    assert "user" in rec["error"]
    assert "credential_ref" in rec["error"]
    assert "password" not in rec["error"]


def test_snowflake_public_config_requires_secret_references() -> None:
    error = configure_payload_error(
        connector_id="snowflake-evidence-lake",
        state="enabled",
        credentials={
            "account": "org-account",
            "user": "GRC_LAKE_INGEST_SVC",
            "private_key": "raw-key-material",
        },
        options={
            "warehouse": "GRC_LAKE_READ_WH",
            "database": "GRC_LAKE_SECURITY_LAKE",
            "schema": "EVIDENCE",
            "audit_events": "GRC_LAKE_AUDIT_EVENTS",
            "control_posture": "GRC_LAKE_CONTROL_POSTURE",
            "asset_risk": "GRC_LAKE_ASSET_RISK",
            "evidence_bundles": "GRC_LAKE_EVIDENCE_BUNDLES",
        },
    )

    assert error
    assert "credential_ref" in error
    assert "private_key" not in error


def test_snowflake_discovery_requires_secret_references(tmp_path: Path) -> None:
    rec = run_discovery(
        tmp_path,
        connector_id="snowflake-evidence-lake",
        credentials={
            "account": "org-account",
            "user": "GRC_LAKE_INGEST_SVC",
            "oauth_token": "raw-oauth-token",
        },
        options={},
    )

    assert rec["result"] == "error"
    assert "credential_ref" in rec["error"]
    assert "oauth_token" not in rec["error"]


def test_discovery_reuses_enabled_config_without_retyping_credentials(tmp_path: Path) -> None:
    append_config_event(
        tmp_path,
        connector_id="aws-posture",
        state="enabled",
        actor="alice",
        credentials={"account_id": "123456789012"},
        options={"region": "us-west-2"},
    )

    rec = run_discovery(tmp_path, connector_id="aws-posture")

    assert rec["kind"] == "discover"
    assert rec["result"] == "ok"
    assert rec["metadata"]["selection_mode"] == "account"
    assert rec["metadata"]["selectors"][0]["name"] == "123456789012"


def test_discovery_returns_cloud_scope_candidates(tmp_path: Path) -> None:
    aws = run_discovery(
        tmp_path,
        connector_id="aws-posture",
        credentials={"account_id": "123456789012"},
        options={"region": "us-west-2"},
    )
    azure = run_discovery(
        tmp_path,
        connector_id="azure-posture",
        credentials={"subscription_id": "00000000-0000-0000-0000-000000000000"},
        options={},
    )

    assert aws["result"] == "ok"
    assert aws["metadata"]["selectors"][0] == {
        "kind": "account",
        "name": "123456789012",
        "required": True,
        "selected": True,
    }
    assert aws["metadata"]["recommended_options"] == {"region": "us-west-2"}
    assert azure["result"] == "ok"
    assert azure["metadata"]["selectors"][0]["kind"] == "subscription"


def test_keyless_cloud_connectors_require_only_scope_identifiers() -> None:
    assert _missing_required_config(
        "aws-posture",
        "aws_sso_or_read_only_role",
        {},
        {},
    ) == ["account_id"]
    assert (
        _missing_required_config(
            "aws-posture",
            "aws_sso_or_read_only_role",
            {"account_id": "123456789012"},
            {},
        )
        == []
    )
    assert _missing_required_config(
        "azure-posture",
        "azure_default_credential_reader",
        {},
        {},
    ) == ["subscription_id"]
    assert (
        _missing_required_config(
            "azure-posture",
            "azure_default_credential_reader",
            {"subscription_id": "00000000-0000-0000-0000-000000000000"},
            {},
        )
        == []
    )


def test_probe_unknown_connector_returns_error(tmp_path: Path) -> None:
    rec = run_probe(tmp_path, connector_id="not-a-real-connector")
    assert rec["result"] == "error"
    assert "unknown connector_id" in rec["error"]


def test_build_catalog_view_joins_config_and_runs(tmp_path: Path) -> None:
    append_config_event(tmp_path, connector_id="github-security", state="enabled", actor="a")
    run_probe(tmp_path, connector_id="github-security")
    view = build_catalog_view(tmp_path)
    by_id = {c["connector_id"]: c for c in view}
    assert by_id["github-security"]["state"] == "enabled"
    assert by_id["github-security"]["last_probe"]["result"] == "ok"
    # connectors that have not been configured fall back to disabled
    assert by_id["snowflake-evidence-lake"]["state"] == "disabled"


def test_list_runs_returns_newest_first(tmp_path: Path) -> None:
    append_config_event(tmp_path, connector_id="github-security", state="enabled", actor="a")
    a = run_probe(tmp_path, connector_id="github-security")
    b = run_probe(tmp_path, connector_id="github-security")
    rows = list_runs(tmp_path, "github-security")
    assert len(rows) == 2
    assert rows[0]["occurred_at"] >= rows[1]["occurred_at"]
    assert latest_run(tmp_path, "github-security", kind="probe")["occurred_at"] == max(
        a["occurred_at"], b["occurred_at"]
    )


# --- framework provenance -------------------------------------------------------


def test_framework_view_computes_freshness_state() -> None:
    view = build_framework_view()
    assert len(view) >= 1
    for framework in view:
        # Freshness must be one of the known states; current registry has
        # pulled_at=null so every framework is "never_pulled".
        assert framework["freshness_state"] in {"fresh", "stale", "expired", "never_pulled"}
        # Each framework reports its control count + mapping coverage.
        assert "control_count" in framework
        assert "mapping_coverage_pct" in framework


def test_framework_view_marks_pulled_recently_as_fresh(tmp_path: Path) -> None:
    registry = {
        "frameworks": [
            {
                "framework_id": "demo",
                "name": "Demo",
                "version": "1.0",
                "official_source_url": "https://example.com/demo",
                "official_source_name": "Demo Source",
                "implementation_status": "implemented",
                "effective_date": "2026-01-01",
                "superseded_by": None,
                "pulled_at": ((datetime.now(UTC) - timedelta(days=1)).isoformat().replace("+00:00", "Z")),
                "source_sha256": "abc",
                "sync_cadence_days": 30,
            }
        ]
    }
    catalog = {
        "catalog_version": "test",
        "scope": "test",
        "controls": [
            {
                "control_id": "DEMO-1",
                "framework_id": "demo",
                "framework": "Demo",
                "title": "t",
                "risk_domain": "x",
                "owner": "team",
                "evidence_requirement": "e",
                "evaluation_rule": "r",
                "frequency": "continuous",
                "implementation_status": "implemented",
                "official_source_ref": "demo",
            }
        ],
    }
    reg_path = tmp_path / "registry.json"
    cat_path = tmp_path / "catalog.json"
    reg_path.write_text(json.dumps(registry), encoding="utf-8")
    cat_path.write_text(json.dumps(catalog), encoding="utf-8")
    view = build_framework_view(reg_path, cat_path)
    assert view[0]["freshness_state"] == "fresh"
    assert view[0]["control_count"] == 1
    assert view[0]["mapping_coverage_pct"] == 100.0


# --- HTTP integration -----------------------------------------------------------


def _spin_handler(lake: Path) -> ThreadingHTTPServer:
    (lake / "gold").mkdir(parents=True, exist_ok=True)
    (lake / "silver").mkdir(parents=True, exist_ok=True)
    (lake / "console.html").write_bytes(b"<!doctype html>")

    class Handler(_Handler):
        lake_dir = lake
        dashboard_path = lake / "console.html"
        web_dist = None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _request(
    server: ThreadingHTTPServer,
    method: str,
    path: str,
    *,
    body: dict | None = None,
    role: str | None = None,
) -> tuple[int, dict]:
    host, port = server.server_address
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(  # noqa: S310 (local test url)
        f"http://{host}:{port}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    if role:
        req.add_header("X-Trust-Role", role)
    try:
        with urllib.request.urlopen(req) as resp:
            return int(resp.status), json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return int(exc.code), json.loads(exc.read().decode("utf-8"))


def test_connector_endpoints_round_trip(tmp_path: Path) -> None:
    server = _spin_handler(tmp_path)
    try:
        status, body = _request(server, "GET", "/api/connectors")
        assert status == HTTPStatus.OK
        assert body["count"] >= 1

        status, body = _request(
            server,
            "POST",
            "/api/connectors/github-security/probe",
            body={"credentials": {"token": "abc"}, "options": {"repo": "x/repo"}},
        )
        assert status == HTTPStatus.CREATED
        assert body["run"]["result"] == "ok"
        assert body["run"]["access_fingerprint"]

        status, body = _request(
            server,
            "POST",
            "/api/connectors/github-security/configure",
            body={"state": "enabled", "credentials": {"token": "abc"}, "options": {"repo": "x/repo"}},
        )
        assert status == HTTPStatus.CREATED
        assert body["event"]["state"] == "enabled"
        assert body["event"]["credentials"]["token"].startswith("***")

        status, body = _request(server, "POST", "/api/connectors/github-security/probe", body={})
        assert status == HTTPStatus.CREATED
        assert body["run"]["result"] == "ok"

        status, body = _request(server, "GET", "/api/connectors/github-security/runs")
        assert status == HTTPStatus.OK
        assert len(body["runs"]) == 2

        status, body = _request(server, "GET", "/api/frameworks")
        assert status == HTTPStatus.OK
        assert body["count"] >= 1
    finally:
        server.shutdown()


def test_connector_configure_unknown_id_returns_400(tmp_path: Path) -> None:
    server = _spin_handler(tmp_path)
    try:
        status, body = _request(
            server,
            "POST",
            "/api/connectors/does-not-exist/configure",
            body={"state": "enabled"},
        )
        assert status == HTTPStatus.BAD_REQUEST
        assert "unknown connector_id" in body["reason"]
    finally:
        server.shutdown()


def test_connector_configure_rejects_empty_enable(tmp_path: Path) -> None:
    server = _spin_handler(tmp_path)
    try:
        status, body = _request(
            server,
            "POST",
            "/api/connectors/clickhouse-telemetry-lake/configure",
            body={"state": "enabled", "credentials": {}, "options": {}},
        )
        assert status == HTTPStatus.BAD_REQUEST
        assert "missing required connector configuration" in body["reason"]
        assert "host" in body["reason"]
        assert "credential_ref" in body["reason"]
        assert "password" not in body["reason"]
        assert "database" not in body["reason"]
        assert "events_table" not in body["reason"]
        assert "ClickHouse" not in body["reason"]
    finally:
        server.shutdown()


def test_connector_configure_requires_matching_ok_probe(tmp_path: Path) -> None:
    server = _spin_handler(tmp_path)
    try:
        status, body = _request(
            server,
            "POST",
            "/api/connectors/github-security/configure",
            body={"state": "enabled", "credentials": {"token": "abc"}, "options": {"repo": "x/repo"}},
        )
        assert status == HTTPStatus.BAD_REQUEST
        assert "Test connection" in body["reason"]

        status, body = _request(
            server,
            "POST",
            "/api/connectors/github-security/probe",
            body={"credentials": {"token": "abc"}, "options": {"repo": "x/repo"}},
        )
        assert status == HTTPStatus.CREATED
        assert body["run"]["result"] == "ok"

        status, body = _request(
            server,
            "POST",
            "/api/connectors/github-security/configure",
            body={"state": "enabled", "credentials": {"token": "different"}, "options": {"repo": "x/repo"}},
        )
        assert status == HTTPStatus.BAD_REQUEST
        assert "exact credentials" in body["reason"]
    finally:
        server.shutdown()


def test_scoped_user_contract_requires_token_not_password() -> None:
    # Pins the public fallback used for future scoped-user catalog entries.
    missing = _missing_required_config(
        "future-scoped-source",
        "scoped_user",
        {},
        {},
    )
    assert missing == ["host", "token"]


def test_object_storage_enable_requires_live_probe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_probe(*, credentials: dict, options: dict) -> dict:
        return {
            "ok": True,
            "bucket": options["bucket"],
            "prefix": options["prefix"],
            "object_count": 2,
            "error": None,
        }

    monkeypatch.setattr("security_lakehouse.connector_state.probe_s3_access", fake_probe)

    server = _spin_handler(tmp_path)
    try:
        status, body = _request(
            server,
            "POST",
            "/api/connectors/object-storage-evidence/probe",
            body={
                "credentials": {"role_arn": "arn:aws:iam::123456789012:role/GrcLakeEvidenceRead"},
                "options": {"bucket": "trustops-evidence", "prefix": "bundles/"},
            },
        )
        assert status == HTTPStatus.CREATED
        assert body["run"]["result"] == "ok"
        assert body["run"]["access_fingerprint"]

        status, body = _request(
            server,
            "POST",
            "/api/connectors/object-storage-evidence/configure",
            body={
                "state": "enabled",
                "credentials": {"role_arn": "arn:aws:iam::123456789012:role/GrcLakeEvidenceRead"},
                "options": {"bucket": "trustops-evidence", "prefix": "bundles/"},
            },
        )
        assert status == HTTPStatus.CREATED
        assert body["event"]["state"] == "enabled"
    finally:
        server.shutdown()


def test_clickhouse_enable_requires_live_probe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_probe(*, credentials: dict, options: dict) -> dict:
        return {"ok": True, "table": "security.normalized_events", "row_count": 1, "error": None}

    monkeypatch.setattr("security_lakehouse.connector_state.probe_clickhouse_access", fake_probe)

    server = _spin_handler(tmp_path)
    try:
        status, body = _request(
            server,
            "POST",
            "/api/connectors/clickhouse-telemetry-lake/probe",
            body={
                "credentials": {
                    "host": "https://cluster.example.clickhouse.cloud:8443",
                    "credential_ref": "GRC_LAKE_CLICKHOUSE_TOKEN",
                },
                "options": {},
            },
        )
        assert status == HTTPStatus.CREATED
        assert body["run"]["result"] == "ok"
        assert body["run"]["access_fingerprint"]

        status, body = _request(
            server,
            "POST",
            "/api/connectors/clickhouse-telemetry-lake/configure",
            body={
                "state": "enabled",
                "credentials": {
                    "host": "https://cluster.example.clickhouse.cloud:8443",
                    "credential_ref": "GRC_LAKE_CLICKHOUSE_TOKEN",
                },
                "options": {},
            },
        )
        assert status == HTTPStatus.CREATED
        assert body["event"]["state"] == "enabled"
    finally:
        server.shutdown()


def test_connector_probe_accepts_staged_payload_without_enable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_probe(*, credentials: dict, options: dict) -> dict:
        return {
            "ok": True,
            "bucket": options["bucket"],
            "prefix": options["prefix"],
            "object_count": 1,
            "error": None,
        }

    monkeypatch.setattr("security_lakehouse.connector_state.probe_s3_access", fake_probe)

    server = _spin_handler(tmp_path)
    try:
        status, body = _request(
            server,
            "POST",
            "/api/connectors/object-storage-evidence/probe",
            body={
                "credentials": {"role_arn": "arn:aws:iam::123456789012:role/GrcLakeEvidenceRead"},
                "options": {"bucket": "trustops-evidence", "prefix": "bundles/"},
            },
        )
        assert status == HTTPStatus.CREATED
        assert body["run"]["result"] == "ok"
        assert body["run"]["evidence_count"] == 1
        assert body["run"]["metadata"]["probe_mode"] == "live"

        status, body = _request(server, "GET", "/api/connectors")
        assert status == HTTPStatus.OK
        by_id = {item["connector_id"]: item for item in body["connectors"]}
        assert by_id["object-storage-evidence"]["state"] == "disabled"
        assert by_id["object-storage-evidence"]["credential_fingerprint"] is None
    finally:
        server.shutdown()


def test_connector_discover_route_returns_scope_candidates(tmp_path: Path) -> None:
    server = _spin_handler(tmp_path)
    try:
        status, body = _request(
            server,
            "POST",
            "/api/connectors/aws-posture/discover",
            body={
                "credentials": {"account_id": "123456789012"},
                "options": {"region": "us-west-2"},
            },
        )
        assert status == HTTPStatus.CREATED
        assert body["run"]["kind"] == "discover"
        assert body["run"]["result"] == "ok"
        assert body["run"]["metadata"]["selection_mode"] == "account"
        assert body["run"]["metadata"]["selectors"][0]["name"] == "123456789012"

        status, body = _request(server, "GET", "/api/connectors/aws-posture/runs")
        assert status == HTTPStatus.OK
        assert body["runs"][0]["kind"] == "discover"
        assert body["runs"][0]["metadata"]["selection_mode"] == "account"
    finally:
        server.shutdown()


def test_connector_discover_route_reuses_enabled_config(tmp_path: Path) -> None:
    server = _spin_handler(tmp_path)
    try:
        append_config_event(
            tmp_path,
            connector_id="aws-posture",
            state="enabled",
            actor="alice",
            credentials={"account_id": "123456789012"},
            options={"region": "us-west-2"},
        )

        status, body = _request(server, "POST", "/api/connectors/aws-posture/discover", body={})

        assert status == HTTPStatus.CREATED
        assert body["run"]["kind"] == "discover"
        assert body["run"]["result"] == "ok"
        assert body["run"]["metadata"]["selectors"][0]["name"] == "123456789012"
    finally:
        server.shutdown()


def test_connector_post_blocked_in_auditor_mode(tmp_path: Path) -> None:
    server = _spin_handler(tmp_path)
    try:
        status, body = _request(
            server,
            "POST",
            "/api/connectors/github-security/configure",
            body={"state": "enabled"},
            role="auditor",
        )
        assert status == HTTPStatus.FORBIDDEN
        assert body["error"] == "forbidden"

        status, body = _request(
            server,
            "POST",
            "/api/connectors/github-security/probe",
            body={},
            role="auditor",
        )
        assert status == HTTPStatus.FORBIDDEN
    finally:
        server.shutdown()


def test_google_workspace_accepts_refresh_material_without_access_token() -> None:
    # The runner mints access tokens from the refresh triple, so an operator
    # running unattended sync never has a static access token to reference.
    assert (
        _missing_required_config(
            "google-workspace-identity",
            "google_oauth_token",
            {
                "customer_id": "C01234567",
                "refresh_token_ref": "GOOGLE_WORKSPACE_REFRESH_TOKEN",
                "client_id": "123-abc.apps.googleusercontent.com",
                "client_secret_ref": "GOOGLE_WORKSPACE_OAUTH_CLIENT_SECRET",
            },
            {},
        )
        == []
    )


def test_google_workspace_static_access_token_still_accepted() -> None:
    assert (
        _missing_required_config(
            "google-workspace-identity",
            "google_oauth_token",
            {"customer_id": "C01234567", "credential_ref": "GOOGLE_WORKSPACE_ACCESS_TOKEN"},
            {},
        )
        == []
    )


def test_google_workspace_partial_refresh_material_names_the_gap() -> None:
    # A half-configured triple would build no token source in the runner, so the
    # error points at the specific fields rather than the access-token path.
    missing = _missing_required_config(
        "google-workspace-identity",
        "google_oauth_token",
        {"customer_id": "C01234567", "refresh_token_ref": "GOOGLE_WORKSPACE_REFRESH_TOKEN"},
        {},
    )
    assert missing == ["client_id", "client_secret_ref"]


def test_google_workspace_without_any_credential_reports_credential_ref() -> None:
    assert _missing_required_config(
        "google-workspace-identity",
        "google_oauth_token",
        {"customer_id": "C01234567"},
        {},
    ) == ["credential_ref"]


def test_google_workspace_probe_accepts_refresh_only_config(tmp_path: Path) -> None:
    rec = run_probe(
        tmp_path,
        connector_id="google-workspace-identity",
        credentials={
            "customer_id": "C01234567",
            "refresh_token_ref": "GOOGLE_WORKSPACE_REFRESH_TOKEN",
            "client_id": "123-abc.apps.googleusercontent.com",
            "client_secret_ref": "GOOGLE_WORKSPACE_OAUTH_CLIENT_SECRET",
        },
        options={},
    )
    assert rec["result"] == "ok"
    assert rec["metadata"]["probe_mode"] == "config_only"


def test_oauth_client_credentials_fallback_matches_the_console_form() -> None:
    from security_lakehouse.connector_state import _missing_required_config

    assert (
        _missing_required_config(
            "identity-provider", "oauth_client_credentials", {"client_id": "a", "client_secret_ref": "B"}, {}
        )
        == []
    )
    assert _missing_required_config("identity-provider", "oauth_client_credentials", {}, {}) == [
        "client_id",
        "client_secret_ref",
    ]
    assert _missing_required_config("vendor-x", "vendor_oauth", {"client_id": "a", "client_secret_ref": "B"}, {}) == [
        "refresh_token_ref"
    ]


@pytest.mark.parametrize(
    ("connector_id", "credentials", "missing"),
    [
        ("jamf-devices", {}, "base_url, client_id, client_secret_ref"),
        ("jamf-devices", {"base_url": "https://acme.jamfcloud.com", "client_id": "c"}, "client_secret_ref"),
        ("crowdstrike-falcon", {"client_id": "c"}, "cloud, client_secret_ref"),
        ("kubernetes-cluster", {"context": "prod"}, "cluster_name"),
        ("knowbe4-training", {}, "region, credential_ref"),
    ],
)
def test_preview_endpoint_connectors_name_missing_enablement_fields(
    connector_id: str, credentials: dict[str, Any], missing: str
) -> None:
    error = configure_payload_error(connector_id=connector_id, state="enabled", credentials=credentials, options={})
    assert error == f"missing required connector configuration: {missing}"


@pytest.mark.parametrize(
    ("connector_id", "credentials"),
    [
        (
            "jamf-devices",
            {"base_url": "https://acme.jamfcloud.com", "client_id": "c", "client_secret_ref": "JAMF_CLIENT_SECRET"},
        ),
        ("crowdstrike-falcon", {"cloud": "eu-1", "client_id": "c", "client_secret_ref": "CROWDSTRIKE_CLIENT_SECRET"}),
        ("kubernetes-cluster", {"cluster_name": "prod-eks"}),
        ("knowbe4-training", {"region": "eu", "credential_ref": "KNOWBE4_API_TOKEN"}),
    ],
)
def test_preview_endpoint_connectors_accept_complete_configuration(
    connector_id: str, credentials: dict[str, Any]
) -> None:
    assert (
        configure_payload_error(connector_id=connector_id, state="enabled", credentials=credentials, options={}) is None
    )

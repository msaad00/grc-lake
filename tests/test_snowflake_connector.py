"""Snowflake evidence-lake connector tests."""

from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from security_lakehouse import connector_runner, connector_state
from security_lakehouse.connectors_snowflake import (
    SnowflakeClient,
    SnowflakeFixtureClient,
    _probe_query_params,
    collect_snowflake_evidence,
    probe_snowflake_access,
)
from security_lakehouse.io import read_jsonl
from security_lakehouse.validation import validate_raw_events

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "snowflake"


def test_collect_snowflake_fixture_evidence_validates() -> None:
    rows = collect_snowflake_evidence(
        SnowflakeFixtureClient(FIXTURE_DIR, account="acme_snowflake"),
        collected_at=datetime(2026, 5, 20, 12, 0, tzinfo=UTC),
    )

    assert len(rows) == 8
    assert validate_raw_events(rows) == []
    assert {row["source"] for row in rows} == {"snowflake"}
    assert {row["event_type"] for row in rows} == {
        "snowflake.asset.risk",
        "snowflake.audit.event",
        "snowflake.control.posture",
        "snowflake.evidence.bundle",
    }
    assert any(row["status"] == "open" and row["severity"] == "high" for row in rows)
    assert any(row["entity"]["asset_id"] == "snowflake:warehouse:trustops_wh" for row in rows)


def test_asset_risk_row_without_score_or_status_is_observed() -> None:
    class _Client:
        account = "acme_snowflake"

        def audit_events(self) -> list[dict[str, Any]]:
            return []

        def control_posture(self) -> list[dict[str, Any]]:
            return []

        def asset_risk(self) -> list[dict[str, Any]]:
            return [{"asset_id": "snowflake:warehouse:unscored", "risk_score": None}]

        def evidence_bundles(self) -> list[dict[str, Any]]:
            return []

    rows = collect_snowflake_evidence(_Client(), collected_at=datetime(2026, 5, 20, 12, 0, tzinfo=UTC))

    assert len(rows) == 1
    assert rows[0]["status"] == "observed"
    assert validate_raw_events(rows) == []


def test_snowflake_sync_writes_raw_evidence_and_materializes(tmp_path: Path) -> None:
    connector_state.append_config_event(
        tmp_path,
        connector_id="snowflake-evidence-lake",
        state="enabled",
        actor="alice",
    )

    result = connector_runner.run_connector_sync(
        tmp_path,
        connector_id="snowflake-evidence-lake",
        fixture_dir=FIXTURE_DIR,
    )

    assert result.result == "ok"
    assert result.evidence_count == 8
    raw_rows = read_jsonl(tmp_path / connector_runner.CONNECTOR_RAW_FILE)
    assert len(raw_rows) == 8
    assert validate_raw_events(raw_rows) == []
    assert (tmp_path / "silver" / "normalized_events.jsonl").is_file()
    assert (tmp_path / "gold" / "control_posture.jsonl").is_file()
    assert (tmp_path / "gold" / "asset_risk.jsonl").is_file()
    run = connector_state.latest_run(tmp_path, "snowflake-evidence-lake", kind="sync")
    assert run is not None
    assert run["result"] == "ok"
    assert run["evidence_count"] == 8


def test_snowflake_live_select_normalizes_driver_values() -> None:
    client = object.__new__(SnowflakeClient)
    client.query_params = {"account": "acme"}
    client.views = {"audit_events": "GRC_LAKE_AUDIT_EVENTS"}
    client._connector = _FakeSnowflakeConnector(
        rows=[
            (
                Decimal("42"),
                Decimal("0.95"),
                datetime(2026, 6, 25, 12, 30, tzinfo=UTC),
                date(2026, 6, 25),
            )
        ],
        description=[("COUNT_VALUE",), ("CONFIDENCE",), ("CREATED_AT",), ("CREATED_ON",)],
    )

    rows = client._select_view("audit_events")

    assert rows == [
        {
            "count_value": 42,
            "confidence": 0.95,
            "created_at": "2026-06-25T12:30:00Z",
            "created_on": "2026-06-25",
        }
    ]


def test_snowflake_live_discovery_recommends_visible_scope() -> None:
    client = object.__new__(SnowflakeClient)
    client.query_params = {
        "account": "acme",
        "warehouse": "GRC_LAKE_READ_WH",
        "database": "GRC_LAKE_SECURITY_LAKE",
        "schema": "EVIDENCE",
    }
    client.views = {
        "audit_events": "GRC_LAKE_AUDIT_EVENTS",
        "control_posture": "GRC_LAKE_CONTROL_POSTURE",
        "asset_risk": "GRC_LAKE_ASSET_RISK",
        "evidence_bundles": "GRC_LAKE_EVIDENCE_BUNDLES",
    }
    client._connector = _FakeSnowflakeDiscoveryConnector()

    result = client.discover_scope()

    assert result["ok"] is True
    assert result["selection_mode"] == "live_snowflake_scope"
    assert result["candidates"] == {
        "warehouses": ["GRC_LAKE_READ_WH"],
        "databases": ["GRC_LAKE_SECURITY_LAKE"],
        "schemas": ["EVIDENCE"],
        "views": [
            "GRC_LAKE_ASSET_RISK",
            "GRC_LAKE_AUDIT_EVENTS",
            "GRC_LAKE_CONTROL_POSTURE",
            "GRC_LAKE_EVIDENCE_BUNDLES",
        ],
    }
    assert result["recommended_options"] == {
        "warehouse": "GRC_LAKE_READ_WH",
        "database": "GRC_LAKE_SECURITY_LAKE",
        "schema": "EVIDENCE",
        "audit_events": "GRC_LAKE_AUDIT_EVENTS",
        "control_posture": "GRC_LAKE_CONTROL_POSTURE",
        "asset_risk": "GRC_LAKE_ASSET_RISK",
        "evidence_bundles": "GRC_LAKE_EVIDENCE_BUNDLES",
    }


def test_snowflake_live_requires_account_and_user_for_sso_or_oauth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connector_state.append_config_event(
        tmp_path,
        connector_id="snowflake-evidence-lake",
        state="enabled",
        actor="alice",
    )
    for name in (
        "SNOWFLAKE_ACCOUNT",
        "SNOWFLAKE_USER",
        "SNOWFLAKE_OAUTH_TOKEN",
        "SNOWFLAKE_PRIVATE_KEY_FILE",
        "SNOWFLAKE_AUTHENTICATOR",
    ):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(connector_runner.ConnectorSyncError, match="SNOWFLAKE_ACCOUNT"):
        connector_runner.run_connector_sync(tmp_path, connector_id="snowflake-evidence-lake", materialize=False)


def test_snowflake_live_defaults_to_externalbrowser_without_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connector_state.append_config_event(
        tmp_path,
        connector_id="snowflake-evidence-lake",
        state="enabled",
        actor="alice",
    )
    captured: dict[str, object] = {}

    class FakeSnowflakeClient:
        def __init__(self, *, query_params: dict[str, object], views: dict[str, str]) -> None:
            captured["query_params"] = query_params
            captured["views"] = views

    monkeypatch.setattr(connector_runner, "SnowflakeClient", FakeSnowflakeClient)
    monkeypatch.setattr(connector_runner, "collect_snowflake_evidence", lambda client, account=None: [])
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acme-trustops")
    monkeypatch.setenv("SNOWFLAKE_USER", "trustops.reader@example.com")
    monkeypatch.delenv("SNOWFLAKE_OAUTH_TOKEN", raising=False)
    monkeypatch.delenv("SNOWFLAKE_AUTHENTICATOR", raising=False)

    result = connector_runner.run_connector_sync(tmp_path, connector_id="snowflake-evidence-lake", materialize=False)

    assert result.result == "ok"
    assert captured["query_params"] == {
        "account": "acme-trustops",
        "user": "trustops.reader@example.com",
        "authenticator": "externalbrowser",
        "token": None,
        "warehouse": None,
        "database": None,
        "schema": None,
        "role": None,
    }


def test_snowflake_live_uses_oauth_when_token_env_is_present(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    connector_state.append_config_event(
        tmp_path,
        connector_id="snowflake-evidence-lake",
        state="enabled",
        actor="alice",
    )
    captured: dict[str, object] = {}

    class FakeSnowflakeClient:
        def __init__(self, *, query_params: dict[str, object], views: dict[str, str]) -> None:
            captured["query_params"] = query_params

    monkeypatch.setattr(connector_runner, "SnowflakeClient", FakeSnowflakeClient)
    monkeypatch.setattr(connector_runner, "collect_snowflake_evidence", lambda client, account=None: [])
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acme-trustops")
    monkeypatch.setenv("SNOWFLAKE_USER", "trustops.reader@example.com")
    monkeypatch.setenv("SNOWFLAKE_OAUTH_TOKEN", "read-only-oauth-token")

    result = connector_runner.run_connector_sync(tmp_path, connector_id="snowflake-evidence-lake", materialize=False)

    assert result.result == "ok"
    assert captured["query_params"]["authenticator"] == "oauth"
    assert captured["query_params"]["token"] == "read-only-oauth-token"


def test_snowflake_live_uses_key_pair_file_for_service_user(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    connector_state.append_config_event(
        tmp_path,
        connector_id="snowflake-evidence-lake",
        state="enabled",
        actor="alice",
    )
    captured: dict[str, object] = {}

    class FakeSnowflakeClient:
        def __init__(self, *, query_params: dict[str, object], views: dict[str, str]) -> None:
            captured["query_params"] = query_params

    monkeypatch.setattr(connector_runner, "SnowflakeClient", FakeSnowflakeClient)
    monkeypatch.setattr(connector_runner, "collect_snowflake_evidence", lambda client, account=None: [])
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acme-trustops")
    monkeypatch.setenv("SNOWFLAKE_USER", "GRC_LAKE_INGEST_SVC")
    monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_FILE", "/run/secrets/trustops_snowflake_key.p8")
    monkeypatch.delenv("SNOWFLAKE_OAUTH_TOKEN", raising=False)
    monkeypatch.delenv("SNOWFLAKE_AUTHENTICATOR", raising=False)

    result = connector_runner.run_connector_sync(tmp_path, connector_id="snowflake-evidence-lake", materialize=False)

    assert result.result == "ok"
    assert captured["query_params"]["authenticator"] == "SNOWFLAKE_JWT"
    assert captured["query_params"]["private_key_file"] == "/run/secrets/trustops_snowflake_key.p8"
    assert captured["query_params"]["token"] is None


def test_snowflake_sync_uses_configured_scope_and_private_key_ref(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connector_state.append_config_event(
        tmp_path,
        connector_id="snowflake-evidence-lake",
        state="enabled",
        actor="alice",
        credentials={
            "account": "MJFAYEE-YS65534",
            "user": "GRC_LAKE_INGEST_SVC",
            "private_key_ref": "SNOWFLAKE_PRIVATE_KEY_FILE",
        },
        options={
            "warehouse": "GRC_LAKE_READ_WH",
            "database": "GRC_LAKE_SECURITY_LAKE",
            "schema": "EVIDENCE",
            "role": "GRC_LAKE_READER",
            "audit_events": "GRC_LAKE_AUDIT_EVENTS",
            "control_posture": "GRC_LAKE_CONTROL_POSTURE",
            "asset_risk": "GRC_LAKE_ASSET_RISK",
            "evidence_bundles": "GRC_LAKE_EVIDENCE_BUNDLES",
        },
    )
    captured: dict[str, object] = {}

    class FakeSnowflakeClient:
        def __init__(self, *, query_params: dict[str, object], views: dict[str, str]) -> None:
            captured["query_params"] = query_params
            captured["views"] = views

    monkeypatch.setattr(connector_runner, "SnowflakeClient", FakeSnowflakeClient)
    monkeypatch.setattr(connector_runner, "collect_snowflake_evidence", lambda client, account=None: [])
    monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_FILE", "/run/secrets/trustops_snowflake_key.p8")
    for name in (
        "SNOWFLAKE_ACCOUNT",
        "SNOWFLAKE_USER",
        "SNOWFLAKE_WAREHOUSE",
        "SNOWFLAKE_DATABASE",
        "SNOWFLAKE_SCHEMA",
        "SNOWFLAKE_ROLE",
        "SNOWFLAKE_OAUTH_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)

    result = connector_runner.run_connector_sync(tmp_path, connector_id="snowflake-evidence-lake", materialize=False)

    assert result.result == "ok"
    assert captured["query_params"] == {
        "account": "MJFAYEE-YS65534",
        "user": "GRC_LAKE_INGEST_SVC",
        "authenticator": "SNOWFLAKE_JWT",
        "token": None,
        "warehouse": "GRC_LAKE_READ_WH",
        "database": "GRC_LAKE_SECURITY_LAKE",
        "schema": "EVIDENCE",
        "role": "GRC_LAKE_READER",
        "private_key_file": "/run/secrets/trustops_snowflake_key.p8",
        "private_key_file_pwd": None,
    }
    assert captured["views"] == {
        "audit_events": "GRC_LAKE_AUDIT_EVENTS",
        "control_posture": "GRC_LAKE_CONTROL_POSTURE",
        "asset_risk": "GRC_LAKE_ASSET_RISK",
        "evidence_bundles": "GRC_LAKE_EVIDENCE_BUNDLES",
    }


def test_snowflake_probe_resolves_oauth_ref_from_environment() -> None:
    params = _probe_query_params(
        credentials={
            "account": "acme-trustops",
            "user": "trustops.reader@example.com",
            "credential_ref": "SNOWFLAKE_OAUTH_TOKEN",
        },
        options={
            "warehouse": "GRC_LAKE_READ_WH",
            "database": "GRC_LAKE_SECURITY_LAKE",
            "schema": "EVIDENCE",
            "role": "GRC_LAKE_READER",
        },
        env={"SNOWFLAKE_OAUTH_TOKEN": "read-only-oauth-token"},
    )

    assert params == {
        "account": "acme-trustops",
        "user": "trustops.reader@example.com",
        "authenticator": "oauth",
        "token": "read-only-oauth-token",
        "warehouse": "GRC_LAKE_READ_WH",
        "database": "GRC_LAKE_SECURITY_LAKE",
        "schema": "EVIDENCE",
        "role": "GRC_LAKE_READER",
    }


def test_snowflake_probe_resolves_private_key_ref_from_environment() -> None:
    params = _probe_query_params(
        credentials={
            "account": "acme-trustops",
            "user": "GRC_LAKE_INGEST_SVC",
            "private_key_ref": "SNOWFLAKE_PRIVATE_KEY_FILE",
            "private_key_file_pwd_ref": "SNOWFLAKE_PRIVATE_KEY_FILE_PWD",
        },
        options={
            "warehouse": "GRC_LAKE_READ_WH",
            "database": "GRC_LAKE_SECURITY_LAKE",
            "schema": "EVIDENCE",
            "role": "GRC_LAKE_READER",
        },
        env={
            "SNOWFLAKE_PRIVATE_KEY_FILE": "/run/secrets/trustops_snowflake_key.p8",
            "SNOWFLAKE_PRIVATE_KEY_FILE_PWD": "key-password",
        },
    )

    assert params == {
        "account": "acme-trustops",
        "user": "GRC_LAKE_INGEST_SVC",
        "authenticator": "SNOWFLAKE_JWT",
        "token": None,
        "warehouse": "GRC_LAKE_READ_WH",
        "database": "GRC_LAKE_SECURITY_LAKE",
        "schema": "EVIDENCE",
        "role": "GRC_LAKE_READER",
        "private_key_file": "/run/secrets/trustops_snowflake_key.p8",
        "private_key_file_pwd": "key-password",
    }


def test_snowflake_probe_rejects_missing_private_key_ref_without_connection() -> None:
    with pytest.raises(ValueError, match="SNOWFLAKE_PRIVATE_KEY_FILE"):
        probe_snowflake_access(
            credentials={
                "account": "acme-trustops",
                "user": "GRC_LAKE_INGEST_SVC",
                "private_key_ref": "SNOWFLAKE_PRIVATE_KEY_FILE",
            },
            options={
                "warehouse": "GRC_LAKE_READ_WH",
                "database": "GRC_LAKE_SECURITY_LAKE",
                "schema": "EVIDENCE",
            },
            env={},
        )


def test_snowflake_probe_rejects_missing_oauth_ref_without_connection() -> None:
    with pytest.raises(ValueError, match="SNOWFLAKE_OAUTH_TOKEN"):
        probe_snowflake_access(
            credentials={
                "account": "acme-trustops",
                "user": "trustops.reader@example.com",
                "credential_ref": "SNOWFLAKE_OAUTH_TOKEN",
            },
            options={
                "warehouse": "GRC_LAKE_READ_WH",
                "database": "GRC_LAKE_SECURITY_LAKE",
                "schema": "EVIDENCE",
            },
            env={},
        )


class _FakeSnowflakeConnector:
    def __init__(self, *, rows: list[tuple[Any, ...]], description: list[tuple[str]]) -> None:
        self._rows = rows
        self._description = description

    def connect(self, **_params: object) -> _FakeSnowflakeConnection:
        return _FakeSnowflakeConnection(self._rows, self._description)


class _FakeSnowflakeDiscoveryConnector:
    def connect(self, **_params: object) -> _FakeSnowflakeConnection:
        return _FakeSnowflakeDiscoveryConnection()


class _FakeSnowflakeConnection:
    def __init__(self, rows: list[tuple[Any, ...]], description: list[tuple[str]]) -> None:
        self._rows = rows
        self._description = description

    def __enter__(self) -> _FakeSnowflakeConnection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self) -> _FakeSnowflakeCursor:
        return _FakeSnowflakeCursor(self._rows, self._description)


class _FakeSnowflakeDiscoveryConnection:
    def __enter__(self) -> _FakeSnowflakeDiscoveryConnection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self) -> _FakeSnowflakeDiscoveryCursor:
        return _FakeSnowflakeDiscoveryCursor()


class _FakeSnowflakeCursor:
    def __init__(self, rows: list[tuple[Any, ...]], description: list[tuple[str]]) -> None:
        self._rows = rows
        self.description = description

    def execute(self, _query: str) -> None:
        return None

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self._rows

    def close(self) -> None:
        return None


class _FakeSnowflakeDiscoveryCursor:
    description: list[tuple[str]]

    def __init__(self) -> None:
        self._rows: list[tuple[Any, ...]] = []
        self.description = []

    def execute(self, query: str) -> None:
        normalized = query.upper()
        if normalized.startswith("SELECT CURRENT_ROLE"):
            self.description = [("CURRENT_ROLE",), ("CURRENT_WAREHOUSE",), ("CURRENT_DATABASE",), ("CURRENT_SCHEMA",)]
            self._rows = [("GRC_LAKE_READER", "GRC_LAKE_READ_WH", "GRC_LAKE_SECURITY_LAKE", "EVIDENCE")]
        elif normalized == "SHOW WAREHOUSES":
            self.description = [("created_on",), ("name",)]
            self._rows = [(None, "GRC_LAKE_READ_WH")]
        elif normalized == "SHOW DATABASES":
            self.description = [("created_on",), ("name",)]
            self._rows = [(None, "GRC_LAKE_SECURITY_LAKE")]
        elif normalized.startswith("SHOW SCHEMAS"):
            self.description = [("created_on",), ("name",)]
            self._rows = [(None, "EVIDENCE")]
        elif normalized.startswith("SHOW VIEWS"):
            self.description = [("created_on",), ("name",)]
            self._rows = [
                (None, "GRC_LAKE_CONTROL_POSTURE"),
                (None, "GRC_LAKE_AUDIT_EVENTS"),
                (None, "GRC_LAKE_EVIDENCE_BUNDLES"),
                (None, "GRC_LAKE_ASSET_RISK"),
            ]
        else:  # pragma: no cover - protects fake cursor contract
            raise AssertionError(f"unexpected query {query}")

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self._rows

    def close(self) -> None:
        return None

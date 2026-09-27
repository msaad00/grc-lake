"""The mapping layer wired into the Snowflake, Databricks, and ClickHouse readers."""

from __future__ import annotations

import io
import json
import sys
import types
import urllib.parse
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

import security_lakehouse.connector_runner as connector_runner
from security_lakehouse import netguard
from security_lakehouse.connector_state import append_config_event, configure_payload_error
from security_lakehouse.connectors_clickhouse import ClickHouseClient, ClickHouseFixtureClient
from security_lakehouse.connectors_databricks import DatabricksClient, DatabricksFixtureClient
from security_lakehouse.connectors_snowflake import SnowflakeClient, SnowflakeFixtureClient
from security_lakehouse.ingestion.watermark import read_watermark
from security_lakehouse.io import read_jsonl
from security_lakehouse.lake_mapping import parse_mapping
from security_lakehouse.validation import validate_raw_events

HOST = "dbc-a1b2345c-d6e7.cloud.databricks.com"
SPEC = {
    "spec_version": 1,
    "name": "okta_auth",
    "source": {"table": "okta_events"},
    "filters": [{"column": "event_type", "op": "eq", "value": "user.session.start"}],
    "fields": {
        "id": {"column": "uuid"},
        "observed_at": {"column": "published", "format": "timestamp"},
        "asset_id": {"column": "actor.id"},
        "severity": {"column": "outcome", "map": {"FAILURE": "medium"}, "default": "info"},
        "controls": {"const": ["SOC2-CC6.1"]},
    },
}
ROWS = [
    {
        "uuid": "e1",
        "published": "2026-09-20T10:00:00Z",
        "event_type": "user.session.start",
        "actor": {"id": "00u1"},
        "outcome": "SUCCESS",
    },
    {
        "uuid": "e2",
        "published": "2026-09-21T10:00:00Z",
        "event_type": "user.session.start",
        "actor": {"id": "00u2"},
        "outcome": "FAILURE",
    },
    {
        "uuid": "e3",
        "published": "2026-09-21T11:00:00Z",
        "event_type": "user.lifecycle.create",
        "actor": {"id": "00u3"},
        "outcome": "SUCCESS",
    },
]


@pytest.fixture
def fixture_dir(tmp_path: Path) -> Path:
    target = tmp_path / "fixtures"
    target.mkdir()
    (target / "okta_events.json").write_text(json.dumps(ROWS), encoding="utf-8")
    return target


# --- fixture clients -----------------------------------------------------------


@pytest.mark.parametrize(
    "client_factory",
    [
        lambda d: SnowflakeFixtureClient(d),
        lambda d: DatabricksFixtureClient(d, host=HOST),
        lambda d: ClickHouseFixtureClient(d),
    ],
)
def test_fixture_clients_serve_mapping_rows(client_factory: Any, fixture_dir: Path) -> None:
    client = client_factory(fixture_dir)
    rows = client.fetch_mapping_rows(parse_mapping(SPEC), since=None, limit=100)
    assert [row["uuid"] for row in rows] == ["e1", "e2", "e3"]


# --- live clients: parameter binding -------------------------------------------


class _FakeCursor:
    def __init__(self, log: list[Any]) -> None:
        self.log = log
        self.description = [("UUID",), ("PUBLISHED",), ("EVENT_TYPE",), ("ACTOR",), ("OUTCOME",)]

    def execute(self, sql: str, params: Any = None) -> None:
        self.log.append((sql, params))

    def fetchall(self) -> list[tuple[Any, ...]]:
        return [
            (
                "e2",
                datetime(2026, 9, 21, 10, tzinfo=UTC),
                "user.session.start",
                json.dumps({"id": "00u2"}),
                "FAILURE",
            )
        ]

    def close(self) -> None:
        pass


def _fake_snowflake(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    log: list[Any] = []

    class _Conn:
        def __enter__(self) -> _Conn:
            return self

        def __exit__(self, *_: object) -> None:
            pass

        def cursor(self) -> _FakeCursor:
            return _FakeCursor(log)

    connector = types.ModuleType("snowflake.connector")
    connector.connect = lambda **_: _Conn()  # type: ignore[attr-defined]
    package = types.ModuleType("snowflake")
    package.connector = connector  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "snowflake", package)
    monkeypatch.setitem(sys.modules, "snowflake.connector", connector)
    return log


def test_snowflake_live_binds_values_and_decodes_variant_columns(monkeypatch: pytest.MonkeyPatch) -> None:
    log = _fake_snowflake(monkeypatch)
    client = SnowflakeClient(query_params={"account": "acme"})
    rows = client.fetch_mapping_rows(parse_mapping(SPEC), since="2026-09-21T00:00:00Z", limit=500)
    [(sql, params)] = log
    assert "%(p0)s" in sql and "%(since)s" in sql and sql.endswith("LIMIT 500")
    assert params == {"p0": "user.session.start", "since": "2026-09-21T00:00:00Z"}
    assert "user.session.start" not in sql
    assert rows[0]["published"] == "2026-09-21T10:00:00Z"
    assert rows[0]["uuid"] == "e2"


class _FakeResponse(io.BytesIO):
    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def test_databricks_live_sends_named_parameters(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Any] = []

    def fake_open_public(request: Any, *, timeout: float, label: str) -> _FakeResponse:
        seen.append(request)
        path = urllib.parse.urlparse(request.full_url).path
        if path == "/oidc/v1/token":
            return _FakeResponse(json.dumps({"access_token": "tok"}).encode())
        payload = {
            "statement_id": "s1",
            "status": {"state": "SUCCEEDED"},
            "manifest": {"schema": {"columns": [{"name": "uuid"}, {"name": "published"}, {"name": "actor"}]}},
            "result": {"data_array": [["e2", "2026-09-21T10:00:00Z", '{"id":"00u2"}']]},
        }
        return _FakeResponse(json.dumps(payload).encode())

    monkeypatch.setattr(netguard, "open_public", fake_open_public)
    client = DatabricksClient(HOST, client_id="c", client_secret="s", warehouse_id="wh1", catalog="main", schema="sec")
    rows = client.fetch_mapping_rows(parse_mapping(SPEC), since="2026-09-21T00:00:00Z", limit=10)
    body = json.loads(seen[-1].data)
    assert "FROM `main`.`sec`.`okta_events`" in body["statement"]
    assert ":p0" in body["statement"] and ":since" in body["statement"]
    assert body["parameters"] == [
        {"name": "p0", "value": "user.session.start", "type": "STRING"},
        {"name": "since", "value": "2026-09-21T00:00:00Z", "type": "STRING"},
    ]
    assert rows == [{"uuid": "e2", "published": "2026-09-21T10:00:00Z", "actor": '{"id":"00u2"}'}]


def test_clickhouse_live_sends_typed_http_parameters(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Any] = []

    def fake_open_public(request: Any, *, timeout: float, label: str) -> _FakeResponse:
        seen.append(request)
        line = {"uuid": "e2", "published": "2026-09-21 10:00:00", "actor": {"id": "00u2"}, "n": "18446744073709551615"}
        return _FakeResponse((json.dumps(line) + "\n").encode())

    monkeypatch.setattr(netguard, "open_public", fake_open_public)
    client = ClickHouseClient("https://ch.example.com:8443", user="reader", database="security")
    rows = client.fetch_mapping_rows(parse_mapping(SPEC), since="2026-09-21T00:00:00Z", limit=10)
    [request] = seen
    query = urllib.parse.parse_qs(urllib.parse.urlparse(request.full_url).query)
    assert query["readonly"] == ["1"]
    assert query["param_p0"] == ["user.session.start"]
    assert query["param_since"] == ["2026-09-21T00:00:00Z"]
    sql = request.data.decode()
    assert "FROM security.okta_events" in sql and "{p0:String}" in sql and "user.session.start" not in sql
    assert rows[0]["uuid"] == "e2"


# --- runner --------------------------------------------------------------------


def _enable(lake: Path, connector_id: str, options: dict[str, Any], credentials: dict[str, Any] | None = None) -> None:
    append_config_event(
        lake, connector_id=connector_id, state="enabled", actor="t", credentials=credentials, options=options
    )


@pytest.mark.parametrize(
    ("connector_id", "credentials"),
    [
        ("snowflake-evidence-lake", {"account": "acme"}),
        ("databricks-evidence-lake", {"host": HOST}),
        ("clickhouse-telemetry-lake", {}),
    ],
)
def test_sync_with_a_mapping_ingests_mapped_rows_incrementally(
    tmp_path: Path, fixture_dir: Path, connector_id: str, credentials: dict[str, Any]
) -> None:
    lake = tmp_path / "lake"
    _enable(lake, connector_id, {"mapping": SPEC}, credentials)
    first = connector_runner.run_connector_sync(
        lake, connector_id=connector_id, fixture_dir=fixture_dir, materialize=False
    )
    raw = read_jsonl(lake / connector_runner.CONNECTOR_RAW_FILE)
    assert first.evidence_count == 2  # the lifecycle row is filtered out
    assert validate_raw_events(raw) == []
    assert {row["attributes"]["mapping"] for row in raw} == {"okta_auth"}
    assert {row["severity"] for row in raw} == {"info", "medium"}
    # mapped sources are event logs: the watermark advances even for snapshot-shaped connectors
    assert first.watermark_cursor == "2026-09-21T10:00:00Z"
    assert read_watermark(lake, connector_id) == "2026-09-21T10:00:00Z"

    rows = [*ROWS, {**ROWS[1], "uuid": "e4", "published": "2026-09-22T09:00:00Z", "actor": {"id": "00u4"}}]
    (fixture_dir / "okta_events.json").write_text(json.dumps(rows), encoding="utf-8")
    second = connector_runner.run_connector_sync(
        lake, connector_id=connector_id, fixture_dir=fixture_dir, materialize=False
    )
    assert second.evidence_count == 2  # e2 (re-read at the inclusive bound) + e4
    raw = read_jsonl(lake / connector_runner.CONNECTOR_RAW_FILE)
    assert sorted(row["attributes"]["source_id"] for row in raw) == ["e1", "e2", "e4"]


def test_sync_without_a_mapping_keeps_the_trustops_view_contract(tmp_path: Path) -> None:
    lake = tmp_path / "lake"
    _enable(lake, "snowflake-evidence-lake", {}, {"account": "acme"})
    result = connector_runner.run_connector_sync(
        lake,
        connector_id="snowflake-evidence-lake",
        fixture_dir=Path(__file__).parent / "fixtures" / "snowflake",
        materialize=False,
    )
    raw = read_jsonl(lake / connector_runner.CONNECTOR_RAW_FILE)
    assert result.evidence_count > 0
    assert result.watermark_cursor is None
    assert all("mapping" not in row["attributes"] for row in raw)
    assert {row["event_type"] for row in raw} >= {"snowflake.audit.event", "snowflake.control.posture"}


def test_sync_fails_closed_when_no_fetched_row_maps(tmp_path: Path, fixture_dir: Path) -> None:
    broken = json.loads(json.dumps(SPEC))
    broken["fields"]["observed_at"] = {"column": "uuid", "format": "timestamp"}
    lake = tmp_path / "lake"
    _enable(lake, "snowflake-evidence-lake", {"mapping": broken}, {"account": "acme"})
    with pytest.raises(connector_runner.ConnectorSyncError, match="none of 2 fetched rows"):
        connector_runner.run_connector_sync(
            lake, connector_id="snowflake-evidence-lake", fixture_dir=fixture_dir, materialize=False
        )


def test_configure_rejects_an_invalid_mapping_before_it_is_stored() -> None:
    bad = {**SPEC, "fields": {**SPEC["fields"], "id": {"column": "uuid; drop"}}}
    error = configure_payload_error(
        connector_id="clickhouse-telemetry-lake",
        state="enabled",
        credentials={"host": "https://ch.example.com", "credential_ref": "CLICKHOUSE_PASSWORD"},
        options={"mapping": bad},
    )
    assert error is not None and "fields.id.column" in error


def test_decimal_and_datetime_driver_values_are_json_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    from security_lakehouse.lake_mapping import json_safe_row

    row = json_safe_row({"N": Decimal("3"), "T": datetime(2026, 1, 1, tzinfo=UTC), "F": Decimal("1.5")})
    assert row == {"n": 3, "t": "2026-01-01T00:00:00Z", "f": 1.5}

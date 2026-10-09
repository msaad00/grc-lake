"""ClickHouse telemetry-lake connector tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from security_lakehouse import connector_runner, connector_state
from security_lakehouse.connectors_clickhouse import (
    ClickHouseClient,
    ClickHouseFixtureClient,
    collect_clickhouse_evidence,
    discover_clickhouse_scope,
    probe_clickhouse_access,
)
from security_lakehouse.ingestion.watermark import read_watermark, write_watermark
from security_lakehouse.io import read_jsonl
from security_lakehouse.validation import validate_raw_events

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "clickhouse-telemetry-lake"


def test_collect_clickhouse_fixture_evidence_validates() -> None:
    rows = collect_clickhouse_evidence(
        ClickHouseFixtureClient(FIXTURE_DIR),
        collected_at=datetime(2026, 6, 1, 12, 0, tzinfo=UTC),
    )

    assert len(rows) == 3
    assert validate_raw_events(rows) == []
    assert {row["source"] for row in rows} == {"clickhouse"}
    assert {row["event_type"] for row in rows} == {
        "runtime.detection",
        "runtime.policy.violation",
        "telemetry.metric",
    }
    assert any(row["status"] == "open" and row["severity"] == "high" for row in rows)


def test_clickhouse_fixture_client_incremental_since() -> None:
    client = ClickHouseFixtureClient(FIXTURE_DIR)
    rows = collect_clickhouse_evidence(client, since="2026-06-01T11:00:00.000Z")
    assert len(rows) == 2
    assert all(row["event_id"] != "ch-evt-001" for row in rows)


def test_clickhouse_sync_writes_raw_evidence_and_materializes(tmp_path: Path) -> None:
    connector_state.append_config_event(
        tmp_path,
        connector_id="clickhouse-telemetry-lake",
        state="enabled",
        actor="alice",
    )

    result = connector_runner.run_connector_sync(
        tmp_path,
        connector_id="clickhouse-telemetry-lake",
        fixture_dir=FIXTURE_DIR,
    )

    assert result.result == "ok"
    assert result.evidence_count == 3
    assert result.watermark_cursor == "2026-06-01T12:15:00Z"
    raw_rows = read_jsonl(tmp_path / connector_runner.CONNECTOR_RAW_FILE)
    assert len(raw_rows) == 3
    assert validate_raw_events(raw_rows) == []
    assert (tmp_path / "silver" / "normalized_events.jsonl").is_file()
    run = connector_state.latest_run(tmp_path, "clickhouse-telemetry-lake", kind="sync")
    assert run is not None
    assert run["result"] == "ok"
    assert run["evidence_count"] == 3


def test_clickhouse_sync_resumes_from_watermark(tmp_path: Path) -> None:
    connector_state.append_config_event(
        tmp_path,
        connector_id="clickhouse-telemetry-lake",
        state="enabled",
        actor="alice",
    )
    write_watermark(tmp_path, "clickhouse-telemetry-lake", "2026-06-01T11:00:00.000Z")

    result = connector_runner.run_connector_sync(
        tmp_path,
        connector_id="clickhouse-telemetry-lake",
        fixture_dir=FIXTURE_DIR,
    )

    assert result.evidence_count == 2
    assert result.watermark_cursor == "2026-06-01T12:15:00Z"
    raw_rows = read_jsonl(tmp_path / connector_runner.CONNECTOR_RAW_FILE)
    assert len(raw_rows) == 2
    assert read_watermark(tmp_path, "clickhouse-telemetry-lake") == "2026-06-01T12:15:00Z"


def test_clickhouse_live_query_parses_json_each_row() -> None:
    body = "\n".join(
        [
            json.dumps({"event_id": "live-1", "event_time": "2026-06-01T10:00:00Z"}),
            json.dumps({"event_id": "live-2", "event_time": "2026-06-01T11:00:00Z"}),
        ]
    )
    response = MagicMock()
    response.read.return_value = body.encode("utf-8")
    response.__enter__.return_value = response

    with patch("security_lakehouse.netguard.open_public", return_value=response):
        rows = ClickHouseClient("https://ch.example:8443", user="reader", password="secret").normalized_events()

    assert len(rows) == 2
    assert rows[0]["event_id"] == "live-1"


def _keyset_clickhouse_server(dataset: list[dict[str, Any]], captured: list[str]):
    """A fake ClickHouse HTTP endpoint that honors the client's keyset cursor.

    Reads the composite ``(event_time, event_id)`` boundary from the HTTP query
    parameters (``param_cursor_id``) and ``LIMIT`` from the SQL, returning the
    next slice — so the test exercises the real page loop, not a fixed sequence.
    """
    import re
    import urllib.parse

    def handler(request: object, **_kwargs: object) -> object:
        sql = request.data.decode("utf-8")  # type: ignore[attr-defined]
        captured.append(sql)
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query)  # type: ignore[attr-defined]
        limit = int(re.search(r"LIMIT (\d+)", sql).group(1))  # type: ignore[union-attr]
        cursor = (params.get("param_cursor_id") or [None])[0]
        start = 0
        if cursor is not None:
            start = next(i for i, row in enumerate(dataset) if row["event_id"] == cursor) + 1
        page = dataset[start : start + limit]
        response = MagicMock()
        response.read.return_value = "\n".join(json.dumps(row) for row in page).encode("utf-8")
        response.__enter__.return_value = response
        return response

    return handler


def test_clickhouse_keyset_paginates_across_pages() -> None:
    """A result larger than one page is fetched to completion via keyset paging,
    stopping when a short page arrives."""
    dataset = [{"event_id": f"e{i}", "event_time": f"2026-06-01T10:0{i}:00Z"} for i in range(5)]
    captured: list[str] = []

    with patch("security_lakehouse.netguard.open_public", side_effect=_keyset_clickhouse_server(dataset, captured)):
        rows = ClickHouseClient("https://ch.example:8443", user="r", password="s").normalized_events(page_size=2)

    assert [row["event_id"] for row in rows] == ["e0", "e1", "e2", "e3", "e4"]
    assert len(captured) == 3  # 2 + 2 + 1 (short page stops the loop)
    assert "event_id > {cursor_id:String}" in captured[1]  # page 2 continued from the composite cursor, not an offset
    assert "LIMIT 2" in captured[0]


def test_clickhouse_keyset_survives_duplicate_timestamps() -> None:
    """Rows sharing an event_time straddling a page boundary must all be returned,
    and the loop must terminate — the reason the cursor is (event_time, event_id),
    not event_time alone."""
    dataset = [{"event_id": eid, "event_time": "2026-06-01T10:00:00Z"} for eid in ("a", "b", "c")]
    captured: list[str] = []

    with patch("security_lakehouse.netguard.open_public", side_effect=_keyset_clickhouse_server(dataset, captured)):
        rows = ClickHouseClient("https://ch.example:8443", user="r", password="s").normalized_events(page_size=2)

    assert [row["event_id"] for row in rows] == ["a", "b", "c"]  # none dropped at the boundary
    assert len(captured) == 2  # a,b then c — terminates, no infinite loop


def _capturing_clickhouse(pages: list[list[dict[str, Any]]], requests: list[Any]):
    def handler(request: Any, **_kwargs: object) -> object:
        requests.append(request)
        page = pages.pop(0) if pages else []
        response = MagicMock()
        response.read.return_value = "\n".join(json.dumps(row) for row in page).encode("utf-8")
        response.__enter__.return_value = response
        return response

    return handler


def test_clickhouse_cursor_values_are_bound_as_query_parameters_not_spliced_into_sql() -> None:
    """A source-controlled cursor value must never reach the SQL text.

    ClickHouse treats a backslash as an escape inside string literals, so doubling
    single quotes alone lets ``abc\\' OR 1=1 --`` break out of the literal. The
    cursor (and the watermark) are sent as typed HTTP query parameters instead.
    """
    import urllib.parse

    hostile_id = "abc\\' OR 1=1 --"
    hostile_time = "2026-06-01 10:00:00\\' OR 1=1 --"
    first_page = [
        {"event_id": "a", "event_time": "2026-06-01T09:00:00Z"},
        {"event_id": hostile_id, "event_time": hostile_time},
    ]
    requests: list[Any] = []
    with patch(
        "security_lakehouse.netguard.open_public", side_effect=_capturing_clickhouse([first_page, []], requests)
    ):
        ClickHouseClient("https://ch.example:8443", user="r", password="s").normalized_events(
            since="2026-01-01\\' OR 1=1 --", page_size=2
        )

    assert len(requests) == 2
    for request in requests:
        sql = request.data.decode("utf-8")
        assert "OR 1=1" not in sql
        assert "{since:String}" in sql
    second_sql = requests[1].data.decode("utf-8")
    assert "{cursor_time:String}" in second_sql and "{cursor_id:String}" in second_sql
    params = urllib.parse.parse_qs(urllib.parse.urlsplit(requests[1].full_url).query)
    # ClickHouse decodes parameter values in its escaped (TSV) format, so a raw
    # backslash would be consumed as an escape and the cursor would not match
    # the row it came from; it must arrive doubled.
    assert params["param_cursor_id"] == ["abc\\\\' OR 1=1 --"]
    assert params["param_cursor_time"] == ["2026-06-01 10:00:00\\\\' OR 1=1 --"]
    assert params["param_since"] == ["2026-01-01\\\\' OR 1=1 --"]


@pytest.mark.parametrize(
    ("raw", "encoded"),
    [
        ("plain", "plain"),
        ("a\\b", "a\\\\b"),
        ("tab\there", "tab\\there"),
        ("line\nbreak\r", "line\\nbreak\\r"),
        ("nul\x00", "nul\\0"),
        ("quote'", "quote'"),
    ],
)
def test_clickhouse_query_parameter_values_use_escaped_format(raw: str, encoded: str) -> None:
    from security_lakehouse.connectors_clickhouse import escape_query_parameter

    assert escape_query_parameter(raw) == encoded


def test_clickhouse_queries_run_with_readonly_setting() -> None:
    import urllib.parse

    requests: list[Any] = []
    with patch("security_lakehouse.netguard.open_public", side_effect=_capturing_clickhouse([[]], requests)):
        ClickHouseClient("https://ch.example:8443", user="r", password="s", database="security").show_tables()

    params = urllib.parse.parse_qs(urllib.parse.urlsplit(requests[0].full_url).query)
    assert params["readonly"] == ["1"]
    assert params["database"] == ["security"]


def test_clickhouse_retries_on_transient_gateway_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A read-only SELECT is safe to retry on a 502/503 — a single blip must not fail the sync."""
    import urllib.error

    monkeypatch.setattr("security_lakehouse.ingestion.backoff.time.sleep", lambda *_: None)
    response = MagicMock()
    response.read.return_value = json.dumps({"event_id": "e1", "event_time": "2026-06-01T10:00:00Z"}).encode("utf-8")
    response.__enter__.return_value = response
    sequence: list[object] = [
        urllib.error.HTTPError("https://ch.example:8443", 502, "bad gateway", {}, None),
        response,
    ]

    def flaky(*_args: object, **_kwargs: object) -> object:
        item = sequence.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    with patch("security_lakehouse.netguard.open_public", side_effect=flaky):
        rows = ClickHouseClient("https://ch.example:8443", user="reader", password="secret").normalized_events()

    assert [row["event_id"] for row in rows] == ["e1"]
    assert sequence == []


def test_clickhouse_probe_and_discovery_with_env_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRC_LAKE_CLICKHOUSE_TOKEN", "secret-token")

    with patch.object(
        ClickHouseClient,
        "probe",
        return_value={"ok": True, "table": "security.normalized_events", "row_count": 4, "error": None},
    ):
        probe = probe_clickhouse_access(
            credentials={
                "host": "https://ch.example:8443",
                "credential_ref": "GRC_LAKE_CLICKHOUSE_TOKEN",
            },
            options={},
        )
    assert probe["ok"] is True
    assert probe["row_count"] == 4

    with patch.object(
        ClickHouseClient,
        "discover_scope",
        return_value={
            "ok": True,
            "selection_mode": "visible_tables",
            "selectors": [{"kind": "table", "name": "normalized_events"}],
            "recommended_options": {"database": "security", "table": "normalized_events"},
        },
    ):
        scope = discover_clickhouse_scope(
            credentials={
                "host": "https://ch.example:8443",
                "credential_ref": "GRC_LAKE_CLICKHOUSE_TOKEN",
            },
            options={},
        )
    assert scope["ok"] is True
    assert scope["recommended_options"]["table"] == "normalized_events"


def test_clickhouse_probe_requires_host() -> None:
    with pytest.raises(ValueError, match="requires host"):
        probe_clickhouse_access(credentials={}, options={})


class _FakeClickHouseDiscoveryClient:
    def show_tables(self) -> list[str]:
        return ["normalized_events", "control_posture"]

    def discover_scope(self) -> dict[str, Any]:
        tables = self.show_tables()
        return {
            "ok": True,
            "selection_mode": "visible_tables",
            "selectors": [
                {"kind": "database", "name": "security", "required": True, "selected": True},
                *[
                    {
                        "kind": "table",
                        "name": name,
                        "required": name == "normalized_events",
                        "selected": name == "normalized_events",
                    }
                    for name in tables
                ],
            ],
            "recommended_options": {"database": "security", "table": "normalized_events"},
        }


def test_clickhouse_fixture_discovery_lists_tables() -> None:
    scope = ClickHouseFixtureClient(FIXTURE_DIR).discover_scope()
    assert scope["ok"] is True
    assert any(item["name"] == "normalized_events" for item in scope["selectors"])

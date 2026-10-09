"""Runtime gateway connector tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from security_lakehouse import connector_runner, connector_state
from security_lakehouse.connectors_runtime import (
    RuntimeGatewayClient,
    RuntimeGatewayFixtureClient,
    collect_runtime_gateway_evidence,
    discover_runtime_gateway_scope,
    probe_runtime_gateway_access,
)
from security_lakehouse.ingestion.watermark import read_watermark, write_watermark
from security_lakehouse.io import read_jsonl
from security_lakehouse.validation import validate_raw_events

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "runtime-gateway"


def test_collect_runtime_fixture_evidence_validates() -> None:
    rows = collect_runtime_gateway_evidence(
        RuntimeGatewayFixtureClient(FIXTURE_DIR),
        collected_at=datetime(2026, 6, 1, 12, 0, tzinfo=UTC),
    )

    assert len(rows) == 2
    assert validate_raw_events(rows) == []
    assert {row["source"] for row in rows} == {"runtime-gateway"}
    blocked = [row for row in rows if row["attributes"]["source_status"] == "blocked"]
    assert len(blocked) == 1
    assert blocked[0]["status"] == "observed"
    assert blocked[0]["attributes"]["tool"] == "sql.query"


def test_runtime_fixture_client_incremental_since() -> None:
    client = RuntimeGatewayFixtureClient(FIXTURE_DIR)
    rows = collect_runtime_gateway_evidence(client, since="2026-05-20T18:00:00Z")
    assert len(rows) == 1
    assert rows[0]["event_id"] == "runtime-evt-011"


def test_runtime_sync_writes_raw_evidence_and_materializes(tmp_path: Path) -> None:
    connector_state.append_config_event(
        tmp_path,
        connector_id="runtime-gateway",
        state="enabled",
        actor="alice",
    )

    result = connector_runner.run_connector_sync(
        tmp_path,
        connector_id="runtime-gateway",
        fixture_dir=FIXTURE_DIR,
    )

    assert result.result == "ok"
    assert result.evidence_count == 2
    assert result.watermark_cursor == "2026-05-20T18:05:00Z"
    raw_rows = read_jsonl(tmp_path / connector_runner.CONNECTOR_RAW_FILE)
    assert len(raw_rows) == 2
    assert validate_raw_events(raw_rows) == []
    assert (tmp_path / "silver" / "normalized_events.jsonl").is_file()
    run = connector_state.latest_run(tmp_path, "runtime-gateway", kind="sync")
    assert run is not None
    assert run["result"] == "ok"
    assert run["evidence_count"] == 2


def test_runtime_sync_resumes_from_watermark(tmp_path: Path) -> None:
    connector_state.append_config_event(
        tmp_path,
        connector_id="runtime-gateway",
        state="enabled",
        actor="alice",
    )
    write_watermark(tmp_path, "runtime-gateway", "2026-05-20T18:00:00Z")

    result = connector_runner.run_connector_sync(
        tmp_path,
        connector_id="runtime-gateway",
        fixture_dir=FIXTURE_DIR,
    )

    assert result.evidence_count == 1
    assert result.watermark_cursor == "2026-05-20T18:05:00Z"
    raw_rows = read_jsonl(tmp_path / connector_runner.CONNECTOR_RAW_FILE)
    assert len(raw_rows) == 1
    assert read_watermark(tmp_path, "runtime-gateway") == "2026-05-20T18:05:00Z"


def test_runtime_live_query_parses_json_list() -> None:
    body = json.dumps(
        [
            {
                "event_id": "live-1",
                "event_time": "2026-06-01T10:00:00Z",
                "event_type": "runtime.tool_call",
                "status": "blocked",
            }
        ]
    )
    response = MagicMock()
    response.read.return_value = body.encode("utf-8")
    response.__enter__.return_value = response

    with patch("security_lakehouse.netguard.open_public", return_value=response):
        rows = RuntimeGatewayClient("https://runtime.example", token="secret").events()

    assert len(rows) == 1
    assert rows[0]["event_id"] == "live-1"


def test_runtime_follows_next_cursor_across_pages() -> None:
    """The gateway export's next_cursor envelope is followed to completion,
    carrying the since window and stopping when no cursor is returned."""
    pages = {
        "": {"events": [{"event_id": "e1", "event_time": "2026-06-01T10:00:00Z"}], "next_cursor": "N2"},
        "N2": {"events": [{"event_id": "e2", "event_time": "2026-06-01T11:00:00Z"}]},
    }
    seen: list[str] = []

    def fake_open_public(request: object, **_kwargs: object) -> object:
        url = request.full_url  # type: ignore[attr-defined]
        cursor = url.split("cursor=", 1)[1].split("&", 1)[0] if "cursor=" in url else ""
        seen.append(cursor)
        response = MagicMock()
        response.read.return_value = json.dumps(pages[cursor]).encode("utf-8")
        response.__enter__.return_value = response
        return response

    with patch("security_lakehouse.netguard.open_public", side_effect=fake_open_public):
        rows = RuntimeGatewayClient("https://runtime.example", token="secret").events(since="2026-06-01T00:00:00Z")

    assert [row["event_id"] for row in rows] == ["e1", "e2"]
    assert seen == ["", "N2"]


def test_runtime_bare_list_response_is_a_single_page() -> None:
    body = json.dumps([{"event_id": "only", "event_time": "2026-06-01T10:00:00Z"}]).encode("utf-8")
    response = MagicMock()
    response.read.return_value = body
    response.__enter__.return_value = response
    calls = {"n": 0}

    def once(*_args: object, **_kwargs: object) -> object:
        calls["n"] += 1
        return response

    with patch("security_lakehouse.netguard.open_public", side_effect=once):
        rows = RuntimeGatewayClient("https://runtime.example", token="secret").events()

    assert [row["event_id"] for row in rows] == ["only"]
    assert calls["n"] == 1


def test_runtime_retries_on_transient_5xx_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    """A transient 503 must be retried, not fail the whole export."""
    import urllib.error

    monkeypatch.setattr("security_lakehouse.ingestion.backoff.time.sleep", lambda *_: None)
    response = MagicMock()
    response.read.return_value = json.dumps([{"event_id": "e1", "event_time": "2026-06-01T10:00:00Z"}]).encode("utf-8")
    response.__enter__.return_value = response
    sequence: list[object] = [
        urllib.error.HTTPError("https://runtime.example", 503, "unavailable", {}, None),
        response,
    ]

    def flaky(*_args: object, **_kwargs: object) -> object:
        item = sequence.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    with patch("security_lakehouse.netguard.open_public", side_effect=flaky):
        rows = RuntimeGatewayClient("https://runtime.example", token="secret").events()

    assert [row["event_id"] for row in rows] == ["e1"]
    assert sequence == []


def test_runtime_probe_and_discovery_with_env_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRC_LAKE_RUNTIME_GATEWAY_TOKEN", "secret-token")

    with patch.object(
        RuntimeGatewayClient,
        "probe",
        return_value={"ok": True, "stream": "runtime-events", "event_count": 3, "error": None},
    ):
        probe = probe_runtime_gateway_access(
            credentials={
                "host": "https://runtime.example",
                "credential_ref": "GRC_LAKE_RUNTIME_GATEWAY_TOKEN",
            },
            options={"stream": "runtime-events"},
        )
    assert probe["ok"] is True
    assert probe["event_count"] == 3

    with patch.object(
        RuntimeGatewayClient,
        "discover_scope",
        return_value={
            "ok": True,
            "selection_mode": "visible_streams",
            "selectors": [{"kind": "stream", "name": "runtime-events"}],
            "recommended_options": {"stream": "runtime-events"},
        },
    ):
        scope = discover_runtime_gateway_scope(
            credentials={
                "host": "https://runtime.example",
                "credential_ref": "GRC_LAKE_RUNTIME_GATEWAY_TOKEN",
            },
            options={},
        )
    assert scope["ok"] is True
    assert scope["recommended_options"]["stream"] == "runtime-events"


def test_runtime_probe_requires_host() -> None:
    with pytest.raises(ValueError, match="requires host"):
        probe_runtime_gateway_access(credentials={}, options={})


def test_runtime_fixture_discovery_lists_streams() -> None:
    scope = RuntimeGatewayFixtureClient(FIXTURE_DIR).discover_scope()
    assert scope["ok"] is True
    assert any(item["name"] == "runtime-events" for item in scope["selectors"])

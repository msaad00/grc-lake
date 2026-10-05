"""Request-scoped connector history must not rescan once per catalog entry."""

from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from security_lakehouse import connector_state
from security_lakehouse.ingestion_status import build_ingestion_status
from security_lakehouse.io import write_jsonl


def seed_runs(lake, count=75):
    rows = [
        {
            "connector_id": "github-security",
            "kind": "sync",
            "result": "ok" if i == 0 else "error",
            "occurred_at": (datetime(2026, 1, 1, tzinfo=UTC) + timedelta(minutes=i)).isoformat(),
        }
        for i in range(count)
    ]
    write_jsonl(lake / "gold" / connector_state.RUNS_FILE, rows)
    write_jsonl(
        lake / "gold" / connector_state.CONFIG_FILE,
        [
            {
                "connector_id": "github-security",
                "state": "enabled",
                "occurred_at": "2026-01-01T00:00:00Z",
                "options": {"sync_schedule": "every 15m"},
            }
        ],
    )
    return rows


@pytest.mark.parametrize("view", [connector_state.build_catalog_view, build_ingestion_status])
def test_each_history_file_is_read_once_per_view(tmp_path, monkeypatch, view):
    seed_runs(tmp_path)
    reads = Counter()
    original = Path.open

    def counted(path, *args, **kwargs):
        if path.name in (connector_state.CONFIG_FILE, connector_state.RUNS_FILE) and (not args or args[0] == "r"):
            reads[path.name] += 1
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", counted)
    view(tmp_path)
    assert reads[connector_state.RUNS_FILE] == 1
    assert reads[connector_state.CONFIG_FILE] == 1


def test_success_before_fifty_failed_attempts_is_not_lost(tmp_path):
    rows = seed_runs(tmp_path)
    assert connector_state.latest_successful_run(tmp_path, "github-security") == rows[0]
    item = next(row for row in connector_state.build_catalog_view(tmp_path) if row["connector_id"] == "github-security")
    assert item["last_successful_sync"] == rows[0]
    assert item["last_sync"] == rows[-1]


def test_history_snapshot_is_scoped_by_lake_and_request(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a_rows = seed_runs(a)
    b_rows = seed_runs(b, count=2)

    @connector_state.connector_state_reader
    def read_both():
        first = connector_state.latest_run(a, "github-security")
        assert first == a_rows[-1]
        first["result"] = "caller mutation"
        assert connector_state.latest_run(b, "github-security") == b_rows[-1]
        assert connector_state.latest_run(a, "github-security") == a_rows[-1]

    read_both()
    newer = {**a_rows[-1], "occurred_at": "2026-10-05T00:00:00Z", "result": "ok"}
    write_jsonl(a / "gold" / connector_state.RUNS_FILE, [newer])
    assert connector_state.latest_run(a, "github-security") == newer
    assert connector_state.latest_run(b, "github-security") == b_rows[-1]


def test_writer_invalidates_same_request_snapshot(tmp_path):
    seed_runs(tmp_path)

    @connector_state.connector_state_reader
    def read_then_write():
        assert connector_state.latest_run(tmp_path, "github-security")["result"] == "error"
        new = connector_state.append_run_event(tmp_path, connector_id="github-security", kind="sync", result="ok")
        assert connector_state.latest_run(tmp_path, "github-security") == new

    read_then_write()


@pytest.mark.parametrize(
    "payload", ["{broken", "null", '{"connector_id":"x","result":NaN}', '{"connector_id":"x","connector_id":"y"}']
)
def test_corrupt_connector_history_is_not_silently_discarded(tmp_path, payload):
    path = tmp_path / "gold" / connector_state.RUNS_FILE
    path.parent.mkdir()
    path.write_text(payload + "\n")
    before = path.read_bytes()
    with pytest.raises(ValueError):
        connector_state.build_catalog_view(tmp_path)
    assert path.read_bytes() == before


def test_nonfinite_run_metadata_is_rejected_before_append(tmp_path):
    seed_runs(tmp_path)
    path = tmp_path / "gold" / connector_state.RUNS_FILE
    before = path.read_bytes()
    with pytest.raises(ValueError):
        connector_state.append_run_event(
            tmp_path, connector_id="github-security", kind="sync", result="ok", metadata={"count": float("nan")}
        )
    assert path.read_bytes() == before


def test_corrupt_history_returns_sanitized_v1_error(tmp_path):
    from security_lakehouse import api_v1

    path = tmp_path / "gold" / connector_state.RUNS_FILE
    path.parent.mkdir()
    path.write_text('{"connector_id":"secret-provider", "result":NaN}\n')
    original = path.read_bytes()
    status, body = api_v1.handle_get("/api/v1/connectors", {}, tmp_path)
    assert status == 503
    assert body["errors"][0] == {"code": "invalid_stored_data", "detail": "stored data failed validation"}
    assert path.read_bytes() == original


def test_config_only_lookup_does_not_read_run_history(tmp_path, monkeypatch):
    seed_runs(tmp_path)
    original = connector_state._read_jsonl

    def config_only(path):
        assert path.name == connector_state.CONFIG_FILE
        return original(path)

    monkeypatch.setattr(connector_state, "_read_jsonl", config_only)
    assert connector_state.latest_config(tmp_path, "github-security")["state"] == "enabled"

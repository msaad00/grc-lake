"""The bulk DuckDB mart loaders must produce the same mart as row-by-row inserts."""

from __future__ import annotations

import random
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from security_lakehouse import pipeline
from security_lakehouse.fixtures import find_fixture
from security_lakehouse.golden_fixture import GOLDEN_COMPANY
from security_lakehouse.io import write_jsonl_from_iterable

duckdb = pytest.importorskip("duckdb")


def _executemany_loader(connection: Any, table: str, rows: list[tuple[Any, ...]]) -> None:
    if rows:
        placeholders = ", ".join("?" * len(pipeline._DUCKDB_TABLES[table]))
        connection.executemany(f"INSERT INTO {table} VALUES ({placeholders})", rows)


def _capture_mart_inputs(monkeypatch: pytest.MonkeyPatch, raw_path: Path, lake: Path) -> dict[str, Any]:
    captured: dict[str, Any] = {}
    original = pipeline._write_duckdb_mart_if_available

    def capture(*args: Any, **kwargs: Any) -> bool:
        captured["args"] = args[1:]
        captured["kwargs"] = kwargs
        return original(*args, **kwargs)

    monkeypatch.setattr(pipeline, "_write_duckdb_mart_if_available", capture)
    pipeline.run_pipeline(raw_path, lake)
    monkeypatch.undo()
    return captured


def _write_with(monkeypatch: pytest.MonkeyPatch, loader: Any, path: Path, inputs: dict[str, Any]) -> Path:
    monkeypatch.setattr(pipeline, "_duckdb_loader", lambda: loader)
    assert pipeline._write_duckdb_mart_if_available(path, *inputs["args"], **inputs["kwargs"])
    monkeypatch.undo()
    return path


def _snapshot(path: Path) -> dict[str, Any]:
    with duckdb.connect(str(path), read_only=True) as conn:
        objects = conn.execute(
            "SELECT table_name, table_type FROM information_schema.tables ORDER BY table_name"
        ).fetchall()
        columns = conn.execute(
            "SELECT table_name, column_name, data_type, ordinal_position, is_nullable "
            "FROM information_schema.columns ORDER BY table_name, ordinal_position"
        ).fetchall()
        contents = {}
        for name, kind in objects:
            order = " ORDER BY rowid" if kind == "BASE TABLE" else " ORDER BY ALL"
            contents[name] = conn.execute(f"SELECT * FROM {name}{order}").fetchall()
    return {"objects": objects, "columns": columns, "contents": contents}


def _assert_loaders_match(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, raw_path: Path) -> dict[str, Any]:
    inputs = _capture_mart_inputs(monkeypatch, raw_path, tmp_path / "lake")
    reference = _snapshot(_write_with(monkeypatch, _executemany_loader, tmp_path / "rows.duckdb", inputs))
    loaders = [pipeline._duckdb_load_json]
    if pipeline.importlib.util.find_spec("pyarrow") is not None:
        loaders.append(pipeline._duckdb_load_arrow)
    for loader in loaders:
        candidate = _snapshot(_write_with(monkeypatch, loader, tmp_path / f"{loader.__name__}.duckdb", inputs))
        assert candidate["objects"] == reference["objects"]
        assert candidate["columns"] == reference["columns"]
        for name, rows in reference["contents"].items():
            assert candidate["contents"][name] == rows, (loader.__name__, name)
    return reference


def test_bulk_loaders_match_row_inserts_on_golden_fixture(monkeypatch, tmp_path):
    fixture = find_fixture(GOLDEN_COMPANY)
    assert fixture is not None
    reference = _assert_loaders_match(monkeypatch, tmp_path, fixture.raw_path)
    assert len(reference["contents"]["normalized_events"]) == fixture.event_count
    assert reference["contents"]["control_tests"]
    assert reference["contents"]["evidence_freshness"]
    assert reference["contents"]["daily_control_results"]


def test_bulk_loaders_match_row_inserts_on_generated_lake(monkeypatch, tmp_path):
    from security_lakehouse.catalog import load_control_catalog
    from security_lakehouse.scale_synthesis import synthesize_audit_event

    control_ids = sorted(load_control_catalog())[:120]
    rng = random.Random(7)
    base = datetime(2026, 9, 30, tzinfo=UTC)
    events = []
    for index in range(1500):
        event = synthesize_audit_event(
            index=index,
            tenant_id="bulk",
            control_ids=control_ids,
            controls_per_event=3,
            open_ratio=0.2,
            base_time=base,
            rng=rng,
        )
        event["entity"]["asset_id"] = f"scale:asset:{index % 300:04d}"
        event["entity"]["owner"] = rng.choice(["o'brien", 'quote"team', "back\\slash", "漢字-team", "emoji-😀"])
        events.append(event)
    raw = tmp_path / "raw.jsonl"
    write_jsonl_from_iterable(raw, iter(events))
    reference = _assert_loaders_match(monkeypatch, tmp_path, raw)
    assert len(reference["contents"]["normalized_events"]) == 1500
    owners = {row[7] for row in reference["contents"]["normalized_events"]}
    assert "emoji-😀" in owners and 'quote"team' in owners


def test_bulk_loaders_create_typed_empty_tables(tmp_path):
    for loader in (pipeline._duckdb_load_json, _executemany_loader):
        path = tmp_path / f"{getattr(loader, '__name__', 'x')}.duckdb"
        with duckdb.connect(str(path)) as conn:
            pipeline._create_duckdb_tables(conn)
            loader(conn, "normalized_events", [])
            assert conn.execute("SELECT count(*) FROM normalized_events").fetchone() == (0,)


def test_bulk_loader_uses_json_without_optional_arrow(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline.importlib.util, "find_spec", lambda name: None)
    loader = pipeline._duckdb_loader()
    assert loader is pipeline._duckdb_load_json
    with duckdb.connect(str(tmp_path / "fallback.duckdb")) as conn:
        pipeline._create_duckdb_tables(conn)
        loader(conn, "metrics", [("quoted", "O'Brien 漢字"), ("null", None)])
        assert conn.execute("SELECT * FROM metrics ORDER BY rowid").fetchall() == [
            ("quoted", "O'Brien 漢字"),
            ("null", None),
        ]

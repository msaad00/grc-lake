"""Embedded DuckDB sink: self-bootstrapping, idempotent medallion load.

DuckDB is the zero-server lake option, so unlike the warehouse sinks these tests
run against a real (in-process) DuckDB connection rather than an injected fake —
the embedded path is the whole point.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

duckdb = pytest.importorskip("duckdb")

from security_lakehouse.sinks import land_if_configured  # noqa: E402
from security_lakehouse.sinks.duckdb_sink import DuckDBSink, DuckDBSinkConfig  # noqa: E402


def _seed_lake(tmp_path: Path) -> Path:
    (tmp_path / "silver").mkdir()
    (tmp_path / "gold").mkdir()
    (tmp_path / "silver" / "normalized_events.jsonl").write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {
                    "event_id": "aws-1",
                    "tenant_id": "t",
                    "event_time": "2026-06-01T00:00:00Z",
                    "source": "aws",
                    "severity_score": 80,
                    "control_ids": ["SOC2-CC6.1", "CIS-AWS-1.10"],
                },
                {
                    "event_id": "azure-1",
                    "tenant_id": "t",
                    "event_time": "2026-06-02T00:00:00Z",
                    "source": "azure",
                    "control_ids": [],
                },
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "gold" / "control_posture.jsonl").write_text(
        json.dumps({"control_id": "SOC2-CC6.1", "framework": "SOC 2", "status": "fail", "risk_score": 82.5}) + "\n",
        encoding="utf-8",
    )
    (tmp_path / "gold" / "asset_risk.jsonl").write_text(
        json.dumps({"asset_id": "aws:account:1", "asset_type": "account_config", "risk_score": 82}) + "\n",
        encoding="utf-8",
    )
    return tmp_path


def test_config_requires_path() -> None:
    assert DuckDBSinkConfig.from_env({}) is None
    assert DuckDBSinkConfig.from_env({"TRUSTOPS_DUCKDB_PATH": "/x/lake.duckdb"}).database == "/x/lake.duckdb"


def test_load_creates_tables_and_lands_rows(tmp_path: Path) -> None:
    lake = _seed_lake(tmp_path)
    db = tmp_path / "lake.duckdb"
    landed = DuckDBSink(DuckDBSinkConfig(database=str(db))).load(lake)
    assert landed == {"normalized_events": 2, "control_posture": 1, "asset_risk": 1}

    conn = duckdb.connect(str(db))
    try:
        assert conn.execute("SELECT count(*) FROM normalized_events").fetchone()[0] == 2
        # The array column round-trips as a real list.
        ids = conn.execute("SELECT control_ids FROM normalized_events WHERE event_id = 'aws-1'").fetchone()[0]
        assert ids == ["SOC2-CC6.1", "CIS-AWS-1.10"]
        # The default tenant_id is applied to gold rows that omit it.
        tenant = conn.execute("SELECT tenant_id FROM control_posture").fetchone()[0]
        assert tenant == "customer-managed"
    finally:
        conn.close()


def test_load_is_idempotent(tmp_path: Path) -> None:
    lake = _seed_lake(tmp_path)
    db = tmp_path / "lake.duckdb"
    sink = DuckDBSink(DuckDBSinkConfig(database=str(db)))
    sink.load(lake)
    sink.load(lake)  # second run upserts in place
    conn = duckdb.connect(str(db))
    try:
        assert conn.execute("SELECT count(*) FROM normalized_events").fetchone()[0] == 2
        assert conn.execute("SELECT count(*) FROM control_posture").fetchone()[0] == 1
    finally:
        conn.close()


def test_land_if_configured_targets_duckdb(tmp_path: Path) -> None:
    lake = _seed_lake(tmp_path)
    db = tmp_path / "lake.duckdb"
    landed = land_if_configured(lake, {"TRUSTOPS_DUCKDB_PATH": str(db)})
    assert landed is not None
    assert landed["duckdb"]["normalized_events"] == 2


def test_in_memory_database_is_supported(tmp_path: Path) -> None:
    conn = duckdb.connect(":memory:")
    sink = DuckDBSink(DuckDBSinkConfig(database=":memory:"), connection=conn)
    # Explicit empty artifacts represent an empty current projection.
    for relative in ("silver/normalized_events.jsonl", "gold/control_posture.jsonl", "gold/asset_risk.jsonl"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")
    landed = sink.load(tmp_path)
    assert landed == {"normalized_events": 0, "control_posture": 0, "asset_risk": 0}
    conn.close()


def test_gold_views_query_in_place(tmp_path: Path) -> None:
    lake = _seed_lake(tmp_path)
    db = tmp_path / "lake.duckdb"
    DuckDBSink(DuckDBSinkConfig(database=str(db))).load(lake)

    conn = duckdb.connect(str(db))
    try:
        # auditor_control_evidence joins the failing SOC2-CC6.1 control to the
        # aws-1 event that carries it in its control_ids array.
        rows = conn.execute(
            "SELECT control_id, source FROM auditor_control_evidence WHERE control_id = 'SOC2-CC6.1'"
        ).fetchall()
        assert rows == [("SOC2-CC6.1", "aws")]

        # executive_risk_summary aggregates per framework (1 SOC 2 control, failing).
        summary = conn.execute("SELECT framework, controls, failing_controls FROM executive_risk_summary").fetchall()
        assert summary == [("SOC 2", 1, 1)]
    finally:
        conn.close()


def test_views_survive_reload(tmp_path: Path) -> None:
    lake = _seed_lake(tmp_path)
    db = tmp_path / "lake.duckdb"
    sink = DuckDBSink(DuckDBSinkConfig(database=str(db)))
    sink.load(lake)
    sink.load(lake)  # CREATE OR REPLACE VIEW stays valid across reloads
    conn = duckdb.connect(str(db))
    try:
        assert conn.execute("SELECT count(*) FROM executive_risk_summary").fetchone()[0] == 1
    finally:
        conn.close()

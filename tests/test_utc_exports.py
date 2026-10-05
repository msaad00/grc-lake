"""DuckDB projections store UTC wall time independently of connection timezone."""

from datetime import datetime

import pytest

from security_lakehouse.io import read_jsonl, write_jsonl
from security_lakehouse.pipeline import _write_duckdb_mart_if_available
from security_lakehouse.sinks.duckdb_sink import DuckDBSink, DuckDBSinkConfig
from test_duckdb_sink import _seed_lake
from test_evidence_freshness import _event


def test_native_duckdb_mart_keeps_offset_instant(tmp_path):
    duckdb = pytest.importorskip("duckdb")
    value = "2026-01-02T02:00:00+14:00"
    row = _event(event_time=value, evidence_collected_at=value)
    path = tmp_path / "mart.duckdb"
    assert _write_duckdb_mart_if_available(path, [row], [], [], [], [], {})
    with duckdb.connect(str(path)) as connection:
        assert connection.execute("SELECT event_time, evidence_collected_at FROM normalized_events").fetchone() == (
            datetime(2026, 1, 1, 12),
            datetime(2026, 1, 1, 12),
        )


@pytest.mark.parametrize("zone", ["UTC", "America/New_York", "Pacific/Kiritimati"])
def test_duckdb_sink_is_independent_of_connection_timezone(tmp_path, zone):
    duckdb = pytest.importorskip("duckdb")
    lake = _seed_lake(tmp_path)
    path = lake / "silver/normalized_events.jsonl"
    rows = read_jsonl(path)
    rows[0]["event_time"] = "2026-01-02T02:00:00+14:00"
    rows[0]["evidence_collected_at"] = "2026-01-01T07:00:00-05:00"
    write_jsonl(path, rows)
    with duckdb.connect(":memory:") as connection:
        connection.execute(f"SET TimeZone='{zone}'")
        DuckDBSink(DuckDBSinkConfig(database=":memory:"), connection=connection).load(lake)
        result = connection.execute(
            "SELECT event_time, evidence_collected_at FROM normalized_events WHERE event_id='aws-1'"
        ).fetchone()
        assert result == (datetime(2026, 1, 1, 12), datetime(2026, 1, 1, 12))

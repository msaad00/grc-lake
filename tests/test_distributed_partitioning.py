"""Partitioned evidence retains verified rows and prunes unrelated partitions."""

import json
from pathlib import Path

import pytest

from security_lakehouse.distributed.partitioning import export_partitions, select_partitions
from security_lakehouse.pipeline import run_pipeline


def test_source_date_partitions_preserve_evidence_and_prune(tmp_path):
    import pyarrow.parquet as pq

    source = Path(__file__).resolve().parents[1] / "data/raw/security_events.jsonl"
    lake = tmp_path / "lake"
    run_pipeline(source, lake, tenant_id="tenant-a")
    result = export_partitions(lake, tmp_path / "partitions", tenant_id="tenant-a", batch_size=3)
    all_rows = []
    for part in result["partitions"]:
        rows = pq.ParquetFile(tmp_path / "partitions" / part["path"]).read().to_pylist()
        assert len(rows) == part["row_count"]
        assert all(row["source"] == part["source"] for row in rows)
        assert all(row["event_time"][:10] == part["date"] for row in rows)
        all_rows.extend(rows)
    expected = [json.loads(line) for line in (lake / "silver/normalized_events.jsonl").read_text().splitlines()]
    assert {r["event_id"] for r in all_rows} == {r["event_id"] for r in expected}
    import duckdb

    with duckdb.connect() as connection:
        scanned = connection.execute(
            "SELECT DISTINCT source FROM read_parquet(?, hive_partitioning=true)",
            [str(tmp_path / "partitions/**/*.parquet")],
        ).fetchall()
    assert {value[0] for value in scanned} == {row["source"] for row in expected}
    first = result["partitions"][0]
    selected = select_partitions(
        result, tenant_id="tenant-a", source=first["source"], start_date=first["date"], end_date=first["date"]
    )
    assert selected and all(p["source"] == first["source"] and p["date"] == first["date"] for p in selected)
    assert not select_partitions(result, tenant_id="tenant-a", source="absent")
    with pytest.raises(ValueError, match="tenant"):
        select_partitions(result, tenant_id="other")


def test_tampered_evidence_does_not_publish_partitions(tmp_path):
    lake = tmp_path / "lake"
    source = Path(__file__).resolve().parents[1] / "data/raw/security_events.jsonl"
    run_pipeline(source, lake, tenant_id="tenant-a")
    (lake / "silver/normalized_events.jsonl").write_text("{}\n")
    with pytest.raises(ValueError):
        export_partitions(lake, tmp_path / "partitions", tenant_id="tenant-a")
    assert not (tmp_path / "partitions").exists()

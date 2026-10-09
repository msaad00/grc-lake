"""Verified tenant/source/UTC event-date Parquet partitions with bounded batches."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from datetime import UTC, date, datetime
from pathlib import Path

from security_lakehouse.distributed.config import identifier
from security_lakehouse.generations import publication_lock
from security_lakehouse.io import file_sha256
from security_lakehouse.parquet_export import _sync, export_parquet


def export_partitions(lake, output, *, tenant_id: str, batch_size: int = 8192, file_limit: int = 100_000) -> dict:
    """Convert an independently verified export; never overwrite an existing bundle.

    Partition metadata contains the original source value. Storage keys use its
    digest so arbitrary connector strings cannot become filesystem paths.
    """
    import pyarrow as pa
    import pyarrow.parquet as pq

    identifier(tenant_id)
    if type(file_limit) is not int or file_limit < 1:
        raise ValueError("partition file limit must be positive")
    target = Path(output).absolute()
    target = target.parent.resolve() / target.name
    source_lake = Path(lake).resolve()
    if target == source_lake or target.is_relative_to(source_lake):
        raise ValueError("partition destination must be outside the source lake")
    if os.path.lexists(target):
        raise FileExistsError("partition destination exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".partitions-", dir=target.parent) as temporary:
        root = Path(temporary)
        original = export_parquet(lake, root / "verified", tenant_id=tenant_id, batch_size=batch_size)
        staged = root / "result"
        staged.mkdir(mode=0o700)
        reader = pq.ParquetFile(root / "verified/evidence.parquet")
        parts: list[dict] = []
        count = 0
        for batch in reader.iter_batches(batch_size=batch_size):
            groups: dict[tuple[str, str], list[dict]] = {}
            for row in batch.to_pylist():
                event_time = datetime.fromisoformat(row["event_time"].replace("Z", "+00:00"))
                if event_time.tzinfo is None:
                    raise ValueError("partitioned evidence requires timezone-aware event timestamps")
                day = event_time.astimezone(UTC).date().isoformat()
                groups.setdefault((row["source"], day), []).append(row)
            for (source, day), rows in sorted(groups.items()):
                if len(parts) >= file_limit:
                    raise ValueError("partition file limit exceeded")
                digest = hashlib.sha256(source.encode()).hexdigest()
                relative = f"tenant={tenant_id}/source_hash={digest}/date={day}/part-{len(parts):08d}.parquet"
                path = staged / relative
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                pq.write_table(pa.Table.from_pylist(rows, schema=reader.schema_arrow), path, compression="zstd")
                path.chmod(0o600)
                parts.append(
                    {
                        "path": relative,
                        "source": source,
                        "date": day,
                        "row_count": len(rows),
                        "size": path.stat().st_size,
                        "sha256": file_sha256(path),
                    }
                )
                count += len(rows)
        if count != original["row_count"]:
            raise ValueError("partition row count differs from verified evidence")
        manifest = {
            "schema": "grc-lake.partitions.v1",
            "tenant_id": tenant_id,
            "generation": original["generation"],
            "row_count": count,
            "columns": original["columns"],
            "source_sha256": original["source_sha256"],
            "partition_by": ["tenant", "source", "date"],
            "date_basis": "event_time_utc",
            "partitions": parts,
        }
        (staged / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
        (staged / "manifest.json").chmod(0o600)
        for artifact in staged.rglob("*"):
            _sync(artifact)
        _sync(staged)
        with publication_lock(target.parent):
            if os.path.lexists(target):
                raise FileExistsError("partition destination exists")
            staged.rename(target)
            _sync(target.parent)
        return manifest


def select_partitions(
    manifest: dict,
    *,
    tenant_id: str,
    source: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
) -> list[dict]:
    """Prune before downloading Parquet objects; bounds are inclusive UTC dates."""
    if manifest.get("schema") != "grc-lake.partitions.v1" or manifest.get("tenant_id") != tenant_id:
        raise ValueError("partition manifest schema or tenant differs from request")
    for boundary in (start_date, end_date):
        if boundary is not None and date.fromisoformat(boundary).isoformat() != boundary:
            raise ValueError("partition date must use YYYY-MM-DD")
    if start_date and end_date and start_date > end_date:
        raise ValueError("start date must not follow end date")
    return [
        part
        for part in manifest["partitions"]
        if (source is None or part["source"] == source)
        and (start_date is None or part["date"] >= start_date)
        and (end_date is None or part["date"] <= end_date)
    ]


def prepare(lake: Path, tenant_id: str) -> dict | None:
    """Refresh only when the authoritative assessment generation changes."""
    from security_lakehouse.generations import active_generation, generation_identity

    if active_generation(lake) is None:
        return None
    identity = generation_identity(lake)
    target = lake / "_distributed/analytics"
    if (target / "manifest.json").exists():
        saved = json.loads((target / "manifest.json").read_text())
        if saved.get("generation") == identity:
            return saved
    with tempfile.TemporaryDirectory(prefix="partitions-", dir=lake.parent) as temporary:
        staged = Path(temporary) / "bundle"
        result = export_partitions(lake, staged, tenant_id=tenant_id)
        if target.exists():
            shutil.rmtree(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        staged.rename(target)
        return result

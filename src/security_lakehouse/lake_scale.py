"""Lake scale policy: incremental materialize, split schedules, warehouse tier."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from security_lakehouse.io import read_json, write_json

WAREHOUSE_ROW_THRESHOLD = 100_000
DEFAULT_SYNC_SCHEDULE = "every 15m"
DEFAULT_EVAL_SCHEDULE = "every 6h"
LAKE_SCALE_FILE = ("gold", "lake_scale.json")


def warehouse_sink_configured(env: Mapping[str, str] | None = None) -> bool:
    """Return True when any evidence sink env is configured."""
    runtime = os.environ if env is None else env
    from security_lakehouse.sinks import ClickHouseSinkConfig, DuckDBSinkConfig, SnowflakeSinkConfig

    return any(
        (
            SnowflakeSinkConfig.from_env(runtime) is not None,
            ClickHouseSinkConfig.from_env(runtime) is not None,
            DuckDBSinkConfig.from_env(runtime) is not None,
        )
    )


def silver_row_count(lake: Path) -> int:
    """Return silver cardinality from manifest when available, else stream-count."""
    from security_lakehouse.io import count_jsonl

    manifest_path = lake / "manifest.json"
    if manifest_path.is_file():
        manifest = read_json(manifest_path, base_dir=lake)
        counts = manifest.get("row_counts") or {}
        if isinstance(counts.get("silver"), (int, float)):
            return int(counts["silver"])
    return count_jsonl(lake / "silver" / "normalized_events.jsonl", missing_ok=True, base_dir=lake)


def raw_row_count(raw_path: Path) -> int:
    from security_lakehouse.io import count_jsonl

    return count_jsonl(raw_path, missing_ok=True)


def apply_split_schedule_defaults(options: dict[str, Any] | None) -> dict[str, Any]:
    """When ``sync_schedule`` is set, default to split ingest/eval behavior."""
    opts = dict(options or {})
    sync = str(opts.get("sync_schedule") or "").strip()
    if not sync:
        return opts
    if not str(opts.get("eval_schedule") or "").strip():
        opts["eval_schedule"] = DEFAULT_EVAL_SCHEDULE
    if "split_ingest_eval" not in opts:
        opts["split_ingest_eval"] = True
    if opts.get("split_ingest_eval") and "materialize" not in opts:
        opts["materialize"] = False
    return opts


def connector_materialize_on_sync(options: dict[str, Any] | None) -> bool:
    """Whether a scheduled connector sync should run local materialize."""
    opts = options or {}
    if opts.get("split_ingest_eval"):
        return bool(opts.get("materialize", False))
    return bool(opts.get("materialize", True))


def lake_eval_schedule(lake_dir: str | Path) -> str | None:
    """Return the lake-wide eval schedule from enabled connector options."""
    from security_lakehouse.connector_state import build_catalog_view

    has_sync = False
    for row in build_catalog_view(lake_dir):
        if row.get("state") != "enabled":
            continue
        opts = row.get("configured_options") or {}
        sched = str(opts.get("eval_schedule") or "").strip()
        if sched:
            return sched
        if str(opts.get("sync_schedule") or "").strip():
            has_sync = True
    return DEFAULT_EVAL_SCHEDULE if has_sync else None


def resolve_materialize_strategy(
    lake: str | Path,
    raw_path: str | Path,
    *,
    env: Mapping[str, str] | None = None,
    force_local: bool = False,
) -> dict[str, Any]:
    """Choose local full, incremental, or warehouse evaluation for this lake."""
    lake_path = Path(lake)
    raw = Path(raw_path)
    runtime = os.environ if env is None else env
    silver = silver_row_count(lake_path)
    raw_count = raw_row_count(raw) if raw.is_file() else silver
    event_count = max(silver, raw_count)
    sink = warehouse_sink_configured(runtime)

    if force_local:
        mode = "local_incremental" if _incremental_ready(lake_path) else "local_full"
    elif event_count >= WAREHOUSE_ROW_THRESHOLD:
        mode = "warehouse" if sink else "warehouse_required"
    elif _incremental_ready(lake_path):
        mode = "local_incremental"
    else:
        mode = "local_full"

    return {
        "mode": mode,
        "execution_backend": "local_python",
        "event_count": event_count,
        "silver_count": silver,
        "warehouse_row_threshold": WAREHOUSE_ROW_THRESHOLD,
        "warehouse_sink_configured": sink,
        "recommendation": _recommendation(mode, sink),
    }


def write_lake_scale_state(lake: str | Path, strategy: dict[str, Any]) -> Path:
    """Persist the active scale tier for API/UI/agents."""
    lake_path = Path(lake)
    output = lake_path.joinpath(*LAKE_SCALE_FILE)
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "trustops.lake_scale.v1",
        **strategy,
    }
    write_json(output, payload)
    return output


def _incremental_ready(lake: Path) -> bool:
    return (lake / "manifest.json").is_file() and (lake / "silver" / "normalized_events.jsonl").is_file()


def _recommendation(mode: str, sink: bool) -> str:
    if mode == "warehouse_required":
        return (
            "Configure a Snowflake, ClickHouse, or DuckDB evidence sink; "
            "local full rebuild is disabled above 100k events."
        )
    if mode == "warehouse":
        return "Local evaluation followed by warehouse export; the sink does not remove local memory limits."
    if mode == "local_incremental":
        return "Incremental materialize processes only changed raw evidence since the last manifest."
    return "Full local pipeline rebuild."


class LakeEvalError(RuntimeError):
    """Raised when evaluation cannot proceed at the current lake scale tier."""


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, separators=(",", ":")) + "\n")

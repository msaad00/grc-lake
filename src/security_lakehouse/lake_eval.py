"""Lake-wide evaluation runs (decoupled from connector ingest syncs)."""

from __future__ import annotations

import os
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse.connector_runner import CONNECTOR_RAW_FILE
from security_lakehouse.ingestion_metrics import build_eval_accuracy
from security_lakehouse.lake_scale import (
    LakeEvalError,
    append_jsonl,
    resolve_materialize_strategy,
    write_lake_scale_state,
)
from security_lakehouse.models import PipelineResult, utc_iso
from security_lakehouse.pipeline import normalize_raw_events
from security_lakehouse.sinks import land_if_configured

EVAL_RUNS_FILE = ("gold", "eval_runs.jsonl")


def list_eval_runs(lake_dir: str | Path, *, limit: int = 25) -> list[dict[str, Any]]:
    """Return recent lake evaluation runs newest-first."""
    from security_lakehouse.io import read_jsonl

    lake = Path(lake_dir)
    rows = read_jsonl(lake.joinpath(*EVAL_RUNS_FILE), missing_ok=True, base_dir=lake)
    capped = max(1, min(limit, 1000))
    return list(reversed(rows[-capped:]))


@dataclass(frozen=True)
class LakeEvalResult:
    result: str
    mode: str
    duration_ms: int
    pipeline: PipelineResult | None
    strategy: dict[str, Any]
    error: str | None = None


def run_lake_eval(
    lake_dir: str | Path,
    *,
    mapping_path: str | Path | None = None,
    tenant_id: str = "default",
    env: Mapping[str, str] | None = None,
    actor: str = "system",
) -> LakeEvalResult:
    """Materialize and evaluate the lake using the scale-appropriate path."""
    lake = Path(lake_dir)
    raw_path = lake / CONNECTOR_RAW_FILE
    runtime = env or os.environ
    start = time.perf_counter()
    strategy = resolve_materialize_strategy(lake, raw_path, env=runtime)
    mode = str(strategy["mode"])
    pipeline: PipelineResult | None = None
    error: str | None = None
    result = "ok"

    try:
        if mode == "warehouse_required":
            raise LakeEvalError(str(strategy["recommendation"]))
        if mode == "warehouse":
            pipeline = _run_warehouse_eval(
                lake,
                raw_path,
                mapping_path=mapping_path,
                tenant_id=tenant_id,
                env=runtime,
            )
        elif mode == "local_incremental":
            pipeline = normalize_raw_events(
                raw_path,
                lake,
                mapping_path=mapping_path,
                tenant_id=tenant_id,
                incremental=True,
            )
        else:
            pipeline = normalize_raw_events(raw_path, lake, mapping_path=mapping_path, tenant_id=tenant_id)
        write_lake_scale_state(lake, strategy)
    except LakeEvalError as exc:
        result = "error"
        error = str(exc)
        write_lake_scale_state(lake, {**strategy, "last_error": error})
    except Exception:  # noqa: BLE001 - eval runs record sanitized errors
        result = "error"
        error = "evaluation failed"
        write_lake_scale_state(lake, {**strategy, "last_error": error})

    duration_ms = max(0, int((time.perf_counter() - start) * 1000))
    accuracy = build_eval_accuracy(lake) if result == "ok" else {}
    record = {
        "kind": "eval",
        "actor": actor,
        "result": result,
        "mode": mode,
        "duration_ms": duration_ms,
        "event_count": strategy.get("event_count"),
        "silver_count": strategy.get("silver_count"),
        "error": error,
        "occurred_at": utc_iso(datetime.now(UTC)),
        "control_tests_total": accuracy.get("total_tests"),
        "control_tests_passing": accuracy.get("passing"),
        "control_tests_failing": accuracy.get("failing"),
        "pass_rate": accuracy.get("pass_rate"),
    }
    append_jsonl(lake.joinpath(*EVAL_RUNS_FILE), record)
    return LakeEvalResult(
        result=result,
        mode=mode,
        duration_ms=duration_ms,
        pipeline=pipeline,
        strategy=strategy,
        error=error,
    )


def _run_warehouse_eval(
    lake: Path,
    raw_path: Path,
    *,
    mapping_path: str | Path | None,
    tenant_id: str,
    env: Mapping[str, str],
) -> PipelineResult:
    """Project to warehouse and keep a capped local posture slice when possible."""
    if _incremental_ready(lake):
        result = normalize_raw_events(
            raw_path,
            lake,
            mapping_path=mapping_path,
            tenant_id=tenant_id,
            incremental=True,
        )
    elif raw_path.is_file():
        result = normalize_raw_events(raw_path, lake, mapping_path=mapping_path, tenant_id=tenant_id)
    else:
        raise LakeEvalError("no raw evidence to evaluate")
    landed = land_if_configured(lake, env)
    if landed is None:
        raise LakeEvalError("warehouse sink is not configured")
    return result


def _incremental_ready(lake: Path) -> bool:
    return (lake / "manifest.json").is_file() and (lake / "silver" / "normalized_events.jsonl").is_file()

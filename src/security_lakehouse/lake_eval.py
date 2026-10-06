"""Lake-wide evaluation runs (decoupled from connector ingest syncs)."""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse.connector_runner import CONNECTOR_RAW_FILE
from security_lakehouse.execution_mode import in_server_mode
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
    local_result: str = "not_run"
    export_result: str = "not_configured"

    def to_dict(self) -> dict[str, Any]:
        """One result contract for CLI, API, and other callers."""
        return asdict(self)


def run_lake_eval(
    lake_dir: str | Path,
    *,
    mapping_path: str | Path | None = None,
    tenant_id: str | None = None,
    env: Mapping[str, str] | None = None,
    actor: str = "system",
) -> LakeEvalResult:
    """Evaluate locally, then optionally export the committed generation."""
    lake = Path(lake_dir)
    raw_path = lake / CONNECTOR_RAW_FILE
    runtime = {} if in_server_mode() else (os.environ if env is None else env)
    start = time.perf_counter()
    strategy = resolve_materialize_strategy(lake, raw_path, env=runtime)
    mode = str(strategy["mode"])
    pipeline: PipelineResult | None = None
    error: str | None = None
    result = "ok"
    local_result = "not_run"
    export_result = "not_run" if mode == "warehouse" else "not_configured"

    try:
        if mode == "warehouse_required":
            raise LakeEvalError(str(strategy["recommendation"]))
        local_result = "error"
        pipeline = normalize_raw_events(
            raw_path,
            lake,
            mapping_path=mapping_path,
            tenant_id=tenant_id,
            incremental=mode == "local_incremental" or (mode == "warehouse" and _incremental_ready(lake)),
        )
        local_result = "ok"
        if mode == "warehouse":
            export_result = "error"
            # Export the committed generation, never mutable compatibility links.
            if land_if_configured(Path(pipeline.output_dir), runtime) is None:
                raise LakeEvalError("warehouse sink is not configured")
            export_result = "ok"
        write_lake_scale_state(lake, strategy)
    except LakeEvalError as exc:
        result = "error"
        error = str(exc)
        write_lake_scale_state(lake, {**strategy, "last_error": error})
    except Exception:  # noqa: BLE001 - eval runs record sanitized errors
        logging.getLogger(__name__).exception("Lake evaluation failed; see the private operator log for the cause")
        result = "error"
        error = (
            "local assessment published; warehouse export failed"
            if export_result == "error"
            else "local assessment published; run bookkeeping failed"
            if local_result == "ok"
            else "evaluation failed"
        )
        write_lake_scale_state(lake, {**strategy, "last_error": error})

    duration_ms = max(0, int((time.perf_counter() - start) * 1000))
    accuracy = build_eval_accuracy(lake) if result == "ok" else {}
    record = {
        "kind": "eval",
        "actor": actor,
        "result": result,
        "local_result": local_result,
        "export_result": export_result,
        "generation_id": Path(pipeline.output_dir).name if pipeline else None,
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
        local_result=local_result,
        export_result=export_result,
    )


def _incremental_ready(lake: Path) -> bool:
    return (lake / "manifest.json").is_file() and (lake / "silver" / "normalized_events.jsonl").is_file()

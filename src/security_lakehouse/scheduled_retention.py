"""Scheduled retention: the CLI archival functions, fired by the scheduler.

Off unless ``TRUSTOPS_RETENTION_SCHEDULE`` is set. Without
``TRUSTOPS_RETENTION_ARCHIVE_DIR`` a scheduled run only previews candidates,
exactly like the CLI without ``--archive-to``; nothing is ever deleted without
first being copied, verified, and flushed to that archive. All protections
(active generation, pinned readers, snapshot/workpaper/receipt references,
the latest ``keep_latest`` generations, idempotency receipts) are the ones
enforced inside :func:`archive_generations` and
:func:`archive_operational_history`.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from security_lakehouse.generation_retention import archive_generations
from security_lakehouse.io import append_jsonl
from security_lakehouse.operation_jobs import root_key
from security_lakehouse.operational_retention import archive_operational_history

SCHEDULE_ENV = "TRUSTOPS_RETENTION_SCHEDULE"
ARCHIVE_ENV = "TRUSTOPS_RETENTION_ARCHIVE_DIR"
OLDER_THAN_DAYS_ENV = "TRUSTOPS_RETENTION_OLDER_THAN_DAYS"
KEEP_LATEST_ENV = "TRUSTOPS_RETENTION_KEEP_LATEST"
DEFAULT_OLDER_THAN_DAYS = 90
DEFAULT_KEEP_LATEST = 3
RUNS_FILE = "retention_runs.jsonl"
GENERATIONS = "generations"
OPERATIONAL = "operational"

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class RetentionPolicy:
    schedule: str
    period: timedelta
    older_than_days: int
    keep_latest: int
    archive_dir: Path | None

    @property
    def mode(self) -> str:
        return "preview" if self.archive_dir is None else "archive"


def _positive_int(raw: str, name: str, default: int) -> int:
    raw = raw.strip()
    if not raw:
        return default
    if not raw.isdigit() or int(raw) < 1:
        raise ValueError(f"{name} must be a positive integer")
    return int(raw)


def retention_policy(env: Mapping[str, str] | None = None) -> RetentionPolicy | None:
    """Return the configured policy, ``None`` when disabled; raise when misconfigured."""
    from security_lakehouse.scheduler import parse_schedule

    source = os.environ if env is None else env
    schedule = source.get(SCHEDULE_ENV, "").strip()
    if not schedule:
        return None
    period = parse_schedule(schedule)
    if period is None:
        raise ValueError(f"{SCHEDULE_ENV} is not a supported schedule")
    archive_raw = source.get(ARCHIVE_ENV, "").strip()
    archive_dir = Path(archive_raw) if archive_raw else None
    if archive_dir is not None and not archive_dir.is_absolute():
        raise ValueError(f"{ARCHIVE_ENV} must be an absolute path")
    return RetentionPolicy(
        schedule=schedule,
        period=period,
        older_than_days=_positive_int(
            source.get(OLDER_THAN_DAYS_ENV, ""), OLDER_THAN_DAYS_ENV, DEFAULT_OLDER_THAN_DAYS
        ),
        keep_latest=_positive_int(source.get(KEEP_LATEST_ENV, ""), KEEP_LATEST_ENV, DEFAULT_KEEP_LATEST),
        archive_dir=archive_dir,
    )


def _deployment_root(lake: Path) -> Path:
    return lake.parent.parent if lake.parent.name == "tenants" else lake


def _archive_for(policy: RetentionPolicy, lake: Path, kind: str) -> Path | None:
    if policy.archive_dir is None:
        return None
    archive = policy.archive_dir.resolve()
    root = _deployment_root(lake)
    # A tenant lake's own check cannot see sibling tenants; refuse the whole root.
    if archive == root or root in archive.parents:
        raise ValueError("retention archive must be outside the lake root")
    if kind == GENERATIONS:
        return archive / GENERATIONS / root_key(lake)
    return archive / OPERATIONAL


def run_retention(lake_dir: str | Path, kind: str, policy: RetentionPolicy, *, fired_at: datetime) -> dict[str, Any]:
    """Run one retention kind and append its outcome to ``gold/retention_runs.jsonl``."""
    lake = Path(lake_dir).resolve()
    record: dict[str, Any] = {
        "target_kind": "retention",
        "target_id": kind,
        "schedule": policy.schedule,
        "fired_at": fired_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "mode": policy.mode,
        "older_than_days": policy.older_than_days,
        "result": "ok",
        "report": None,
        "error": None,
    }
    if kind == GENERATIONS:
        record["keep_latest"] = policy.keep_latest
    try:
        archive = _archive_for(policy, lake, kind)
        if kind == GENERATIONS:
            report = archive_generations(
                lake, older_than_days=policy.older_than_days, keep_latest=policy.keep_latest, archive_to=archive
            )
        else:
            report = archive_operational_history(lake, older_than_days=policy.older_than_days, archive_to=archive)
        record["report"] = report
    except Exception as exc:  # noqa: BLE001 - results must not expose exception details
        # Retention's own ValueErrors are fixed operator guidance (no secrets).
        _log.error(
            "scheduled %s retention failed: %s", kind, exc if isinstance(exc, ValueError) else type(exc).__name__
        )
        record.update(result="error", error="internal error")
    append_jsonl(lake / "gold" / RUNS_FILE, {**record, "actor": "scheduler"})
    return record


__all__ = [
    "ARCHIVE_ENV",
    "GENERATIONS",
    "KEEP_LATEST_ENV",
    "OLDER_THAN_DAYS_ENV",
    "OPERATIONAL",
    "RUNS_FILE",
    "SCHEDULE_ENV",
    "RetentionPolicy",
    "archive_generations",
    "archive_operational_history",
    "retention_policy",
    "run_retention",
]

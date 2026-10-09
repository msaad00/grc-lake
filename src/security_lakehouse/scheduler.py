"""Cron scheduler for workflows and connector syncs.

A workflow whose triggers include ``trigger.cron`` (with a ``schedule`` param)
becomes eligible for periodic execution. The scheduler ticks once per call,
attempts each due workflow once per interval, and persists the attempt timestamp
before execution to ``gold/scheduler_state.jsonl`` so successive ticks don't double-fire.

An enabled connector becomes eligible for periodic sync when its connector
configuration options include ``sync_schedule``. When ``split_ingest_eval`` is
true (the default whenever ``sync_schedule`` is set), syncs ingest raw evidence
only and a separate lake-wide ``eval_schedule`` (default ``every 6h``) runs
``run_lake_eval`` to materialize and evaluate.

Retention (``lake retention`` / ``lake operational-retention``) becomes
eligible when ``GRC_LAKE_RETENTION_SCHEDULE`` is set; see
:mod:`security_lakehouse.scheduled_retention`. Generation retention runs per
lake; operational retention runs once per deployment root because job rows and
request-audit logs belong to the root, never to one tenant.

Two execution surfaces:
  * ``grc-lake scheduler tick --lake build/lakehouse`` runs the
    tick once and exits (intended for system cron / k8s CronJob).
  * ``grc-lake scheduler run --lake build/lakehouse`` runs a
    long-lived daemon ticking every N seconds.

Schedule grammar (intentionally small):
  * ``@hourly``       — one hour after the last attempt
  * ``@daily``        — 24 hours after the last attempt
  * ``every Nm``      — every N minutes (positive integer)
  * ``every Nh``      — every N hours (positive integer)

This keeps the in-process scheduler portable; production deployments that
need full crontab grammar should call ``scheduler tick`` from a real cron.
"""

from __future__ import annotations

import fcntl
import logging
import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from security_lakehouse.assessment import SnapshotWrittenHook
from security_lakehouse.connector_runner import run_connector_sync
from security_lakehouse.connector_state import build_catalog_view
from security_lakehouse.execution_mode import in_server_mode, server_execution, server_tenant_id
from security_lakehouse.io import append_jsonl, read_jsonl
from security_lakehouse.lake_eval import run_lake_eval
from security_lakehouse.lake_scale import connector_materialize_on_sync, lake_eval_schedule
from security_lakehouse.schedule_expr import parse_schedule
from security_lakehouse.scheduled_retention import (
    GENERATIONS,
    OPERATIONAL,
    RetentionPolicy,
    retention_policy,
    run_retention,
)
from security_lakehouse.strict_json import InvalidJSON
from security_lakehouse.timeutil import utc_iso_z, utc_now
from security_lakehouse.workflows import list_workflows, run_workflow

STATE_FILE = "scheduler_state.jsonl"
LOCK_FILE = ".scheduler.lock"
DEFAULT_TICK_SECONDS = 60


def _gold(lake_dir: str | Path) -> Path:
    return Path(lake_dir) / "gold"


@dataclass(frozen=True)
class ScheduledWorkflow:
    workflow_id: str
    schedule: str
    period: timedelta


@dataclass(frozen=True)
class ScheduledConnector:
    connector_id: str
    schedule: str
    period: timedelta
    repo: str | None
    fixture_dir: str | None
    token_env: str
    materialize: bool


def _scheduled_from_workflows(workflows: list[dict[str, Any]]) -> list[ScheduledWorkflow]:
    out: list[ScheduledWorkflow] = []
    for workflow in workflows:
        for node in workflow.get("nodes", []) or []:
            if str(node.get("node_type") or "") != "trigger.cron":
                continue
            schedule = str((node.get("params") or {}).get("schedule") or "")
            period = parse_schedule(schedule)
            if period is None:
                continue
            out.append(
                ScheduledWorkflow(
                    workflow_id=str(workflow.get("workflow_id") or ""),
                    schedule=schedule,
                    period=period,
                )
            )
            break  # one trigger.cron per workflow is enough
    return out


@dataclass(frozen=True)
class ScheduledLakeEval:
    schedule: str
    period: timedelta


def _scheduled_lake_eval(lake_dir: str | Path) -> ScheduledLakeEval | None:
    schedule = lake_eval_schedule(lake_dir)
    if not schedule:
        return None
    period = parse_schedule(schedule)
    if period is None:
        return None
    return ScheduledLakeEval(schedule=schedule, period=period)


def eval_schedule_status(lake_dir: str | Path, *, now: datetime | None = None) -> dict[str, Any]:
    """Return attempt cadence; last_fired_at does not imply successful evaluation."""
    lake_eval = _scheduled_lake_eval(lake_dir)
    if lake_eval is None:
        return {
            "last_fired_at": None,
            "next_eval_at": None,
            "eval_overdue": False,
        }
    state = _read_state(lake_dir)
    last_fired = state.get(_state_key("lake_eval", "default"))
    moment = now or utc_now()
    if last_fired is None:
        return {
            "last_fired_at": None,
            "next_eval_at": utc_iso_z(moment),
            "eval_overdue": True,
        }
    next_due = last_fired + lake_eval.period
    return {
        "last_fired_at": utc_iso_z(last_fired),
        "next_eval_at": utc_iso_z(next_due),
        "eval_overdue": moment >= next_due,
    }


def _scheduled_from_connectors(lake_dir: str | Path) -> list[ScheduledConnector]:
    out: list[ScheduledConnector] = []
    for connector in build_catalog_view(lake_dir):
        if connector.get("state") != "enabled":
            continue
        options = connector.get("configured_options") or {}
        schedule = str(options.get("sync_schedule") or options.get("schedule") or "")
        period = parse_schedule(schedule)
        if period is None:
            continue
        out.append(
            ScheduledConnector(
                connector_id=str(connector.get("connector_id") or ""),
                schedule=schedule,
                period=period,
                repo=options.get("repo"),
                fixture_dir=options.get("fixture_dir"),
                token_env=str(options.get("token_env") or "__provider_default__"),
                materialize=connector_materialize_on_sync(options),
            )
        )
    return out


def _state_key(target_kind: str, target_id: str) -> str:
    return f"{target_kind}:{target_id}"


def _read_state(lake_dir: str | Path) -> dict[str, datetime]:
    path = _gold(lake_dir) / STATE_FILE
    from security_lakehouse.distributed.schedules import read_state

    latest: dict[str, datetime] = read_state()
    if not path.is_file():
        return latest
    try:
        rows = read_jsonl(path)
    except (ValueError, UnicodeError) as exc:
        raise InvalidJSON("invalid scheduler state; operator reconciliation required") from exc
    for row in rows:
        target_kind = row.get("target_kind", "workflow")
        target_id = row.get("target_id", row.get("workflow_id"))
        last = row.get("last_fired_at")
        if (
            target_kind not in ("workflow", "connector", "lake_eval", "retention")
            or not isinstance(target_id, str)
            or not target_id
            or not isinstance(last, str)
        ):
            raise InvalidJSON("invalid scheduler state; operator reconciliation required")
        try:
            parsed = datetime.fromisoformat(last.replace("Z", "+00:00"))
        except ValueError as exc:
            raise InvalidJSON("invalid scheduler state; operator reconciliation required") from exc
        # astimezone() would read a naive value as server-local time.
        parsed = parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
        key = _state_key(target_kind, target_id)
        existing = latest.get(key)
        if existing is None or parsed > existing:
            latest[key] = parsed
    return latest


def _write_state(lake_dir: str | Path, *, target_kind: str, target_id: str, fired_at: datetime, result: str) -> None:
    gold = _gold(lake_dir)
    gold.mkdir(parents=True, exist_ok=True)
    record = {
        "target_kind": target_kind,
        "target_id": target_id,
        "last_fired_at": utc_iso_z(fired_at),
        "result": result,
    }
    if target_kind == "workflow":
        record["workflow_id"] = target_id
    if target_kind == "connector":
        record["connector_id"] = target_id
    from security_lakehouse.distributed.schedules import record_attempt

    record_attempt(target_kind, target_id, fired_at)
    append_jsonl(gold / STATE_FILE, record)


def _lock_path(lake_dir: str | Path) -> Path:
    return _gold(lake_dir) / LOCK_FILE


@contextmanager
def _try_scheduler_lock(lake_dir: str | Path) -> Iterator[bool]:
    lock_path = _lock_path(lake_dir)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w", encoding="utf-8") as lock_fd:
        try:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)


_INVALID_RETENTION = {
    "target_kind": "retention",
    "target_id": "configuration",
    "result": "error",
    "error": "invalid retention configuration",
}


def _retention_policy_or_error() -> tuple[RetentionPolicy | None, list[dict[str, Any]]]:
    try:
        return retention_policy(), []
    except ValueError as exc:
        logging.getLogger(__name__).error("retention disabled: %s", exc)
        return None, [dict(_INVALID_RETENTION)]


def _retention_kinds(lake_dir: str | Path) -> tuple[str, ...]:
    # A tenant-scoped tick must never compact the deployment's shared job table.
    return (GENERATIONS,) if server_tenant_id(lake_dir) is not None else (GENERATIONS, OPERATIONAL)


def _fire_retention(
    lake_dir: str | Path,
    state: dict[str, datetime],
    moment: datetime,
    kinds: tuple[str, ...],
) -> list[dict[str, Any]]:
    """Caller holds the lake's scheduler lock; attempts are recorded before running."""
    policy, errors = _retention_policy_or_error()
    if policy is None:
        return errors
    results: list[dict[str, Any]] = []
    for kind in kinds:
        last_fired = state.get(_state_key("retention", kind))
        if last_fired is not None and moment < last_fired + policy.period:
            continue
        _write_state(lake_dir, target_kind="retention", target_id=kind, fired_at=moment, result="started")
        record = run_retention(lake_dir, kind, policy, fired_at=moment)
        results.append(record)
        _write_state(lake_dir, target_kind="retention", target_id=kind, fired_at=moment, result=record["result"])
    return results


def _tick_root_retention(root: Path, *, now: datetime | None) -> list[dict[str, Any]]:
    policy, errors = _retention_policy_or_error()
    if policy is None:
        return errors
    try:
        with _try_scheduler_lock(root) as locked:
            if not locked:
                return [{"target_kind": "retention", "target_id": OPERATIONAL, "skipped_locked": True, "fired": []}]
            if (_gold(root) / "scheduler_recovery_pending.json").exists():
                raise InvalidJSON("scheduler recovery is incomplete; run scheduler repair-history")
            moment = (now or utc_now()).astimezone(UTC)
            return _fire_retention(root, _read_state(root), moment, (OPERATIONAL,))
    except Exception:  # noqa: BLE001 - scheduler results must not expose exception details
        return [{"target_kind": "retention", "target_id": OPERATIONAL, "result": "error", "error": "internal error"}]


def tick(
    lake_dir: str | Path,
    *,
    now: datetime | None = None,
    runner: Any | None = None,
    connector_runner: Any | None = None,
    on_snapshot_written: SnapshotWrittenHook | None = None,
    all_tenants: bool = False,
) -> list[dict[str, Any]]:
    """Fire every due workflow and connector once.

    Returns one record per attempted run. ``runner`` remains the workflow
    runner override used by tests; ``connector_runner`` is the equivalent
    override for scheduled connector syncs. ``on_snapshot_written`` reaches
    every fired workflow's ``action.snapshot`` node (if any) via
    :func:`security_lakehouse.workflows.run_workflow` -- this is how a
    cron-scheduled snapshot dispatches webhook events, not only an
    API-triggered one. It is applied only to the real ``run_workflow``, never
    to a test-supplied ``runner`` override (whose narrower signature tests
    already rely on).

    The read-state -> record-attempt -> fire -> record-outcome critical section is guarded by a
    non-blocking advisory file lock (``gold/.scheduler.lock``) so two
    concurrent ticks (cron overlap, ``concurrencyPolicy: Allow``, daemon plus
    a manual API tick) cannot both observe the same ``last_fired`` and
    double-fire. A tick that cannot acquire the lock is a no-op and returns a
    single ``{"skipped_locked": True}`` record instead of firing.
    """
    from security_lakehouse.distributed.config import ClusterConfig
    from security_lakehouse.distributed.context import binding

    if ClusterConfig.from_env() is not None and binding.get() is None:
        from security_lakehouse.distributed.schedules import tick_cluster

        return tick_cluster(Path(lake_dir), tick_tenant=tick, snapshot_hook_factory=_hosted_snapshot_hook, now=now)
    if all_tenants and server_tenant_id(lake_dir) is not None:
        raise ValueError("all-tenants scheduling requires an unbound lake root")
    if all_tenants or (in_server_mode() and server_tenant_id(lake_dir) is None):
        if on_snapshot_written is not None:
            raise ValueError("hosted root ticks require tenant-local snapshot hooks")
        return _tick_hosted_root(lake_dir, now=now, runner=runner, connector_runner=connector_runner)
    lock_path = _lock_path(lake_dir)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = lock_path.open("w", encoding="utf-8")
    try:
        try:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return [{"target_kind": None, "skipped_locked": True, "fired": []}]
        try:
            return _tick_locked(
                lake_dir,
                now=now,
                runner=runner,
                connector_runner=connector_runner,
                on_snapshot_written=on_snapshot_written,
            )
        finally:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
    finally:
        lock_fd.close()


def _hosted_snapshot_hook(factory: Any, tenant_id: str) -> SnapshotWrittenHook:
    from security_lakehouse.db.base import session_scope
    from security_lakehouse.services.webhooks import dispatch_snapshot_events

    def hook(
        snapshot_path: Path,
        assessment: dict[str, Any],
        new_violations: list[dict[str, Any]],
        newly_failing_controls: list[str],
    ) -> None:
        with session_scope(factory) as session:
            dispatch_snapshot_events(
                session,
                tenant_id,
                snapshot_path=snapshot_path,
                assessment=assessment,
                new_violations=new_violations,
                newly_failing_controls=newly_failing_controls,
            )

    return hook


def _tick_hosted_root(
    lake_dir: str | Path,
    *,
    now: datetime | None,
    runner: Any,
    connector_runner: Any,
) -> list[dict[str, Any]]:
    """Enumerate registered tenant lakes; never treat arbitrary directories as tenants."""
    from security_lakehouse.db.base import create_engine_for, session_factory
    from security_lakehouse.db.repository import list_tenant_ids
    from security_lakehouse.tenancy import resolve_bound_tenant, tenant_lake

    root = Path(lake_dir).resolve()
    engine = create_engine_for(root)
    factory = session_factory(engine)
    results: list[dict[str, Any]] = []
    try:
        with factory() as session:
            tenant_ids = list_tenant_ids(session)
        bound = resolve_bound_tenant(root, require_auth=True, tenant_ids=tenant_ids)
        for tenant_id in tenant_ids:
            try:
                if re.fullmatch(r"[A-Za-z0-9_-]+", tenant_id) is None:
                    raise ValueError("invalid tenant path")
                lake = tenant_lake(root, tenant_id, bound_tenant=bound)
                # A directory symlink can cross tenants even while staying under root.
                if lake.resolve() != lake or not lake.is_relative_to(root):
                    raise ValueError("invalid tenant path")
                if not lake.exists():
                    continue
                with server_execution(tenant_id):
                    fired = tick(
                        lake,
                        now=now,
                        runner=runner,
                        connector_runner=connector_runner,
                        on_snapshot_written=_hosted_snapshot_hook(factory, tenant_id),
                    )
                results.extend({**row, "tenant_id": tenant_id} for row in fired)
            except Exception:  # noqa: BLE001 - isolate tenant failures and sanitize provider details
                results.append(
                    {"tenant_id": tenant_id, "target_kind": "tenant", "result": "error", "error": "internal error"}
                )
    finally:
        engine.dispose()
    results.extend(_tick_root_retention(root, now=now))
    return results


def _tick_locked(
    lake_dir: str | Path,
    *,
    now: datetime | None = None,
    runner: Any | None = None,
    connector_runner: Any | None = None,
    on_snapshot_written: SnapshotWrittenHook | None = None,
) -> list[dict[str, Any]]:
    if (_gold(lake_dir) / "scheduler_recovery_pending.json").exists():
        raise InvalidJSON("scheduler recovery is incomplete; run scheduler repair-history")
    moment = (now or utc_now()).astimezone(UTC)
    scheduled = _scheduled_from_workflows(list_workflows(lake_dir))
    state = _read_state(lake_dir)
    results: list[dict[str, Any]] = []
    for entry in scheduled:
        last_fired = state.get(_state_key("workflow", entry.workflow_id))
        due_at = (last_fired + entry.period) if last_fired else moment
        if last_fired is not None and moment < due_at:
            continue
        _write_state(lake_dir, target_kind="workflow", target_id=entry.workflow_id, fired_at=moment, result="started")
        try:
            if runner is None:
                run = run_workflow(
                    lake_dir, workflow_id=entry.workflow_id, actor="scheduler", on_snapshot_written=on_snapshot_written
                )
            else:
                run = runner(lake_dir, workflow_id=entry.workflow_id, actor="scheduler")
            outcome = run.get("result") if isinstance(run, dict) else "ok"
            results.append(
                {
                    "target_kind": "workflow",
                    "workflow_id": entry.workflow_id,
                    "schedule": entry.schedule,
                    "fired_at": utc_iso_z(moment),
                    "result": outcome,
                    "error": None,
                }
            )
        except Exception:  # noqa: BLE001 - scheduler results must not expose exception details
            results.append(
                {
                    "target_kind": "workflow",
                    "workflow_id": entry.workflow_id,
                    "schedule": entry.schedule,
                    "fired_at": utc_iso_z(moment),
                    "result": "error",
                    "error": "internal error",
                }
            )
        _write_state(
            lake_dir,
            target_kind="workflow",
            target_id=entry.workflow_id,
            fired_at=moment,
            result=str(results[-1]["result"]),
        )
    sync_runner = connector_runner or run_connector_sync
    for connector_entry in _scheduled_from_connectors(lake_dir):
        last_fired = state.get(_state_key("connector", connector_entry.connector_id))
        due_at = (last_fired + connector_entry.period) if last_fired else moment
        if last_fired is not None and moment < due_at:
            continue
        _write_state(
            lake_dir, target_kind="connector", target_id=connector_entry.connector_id, fired_at=moment, result="started"
        )
        try:
            sync_run = sync_runner(
                lake_dir,
                connector_id=connector_entry.connector_id,
                actor="scheduler",
                repo=connector_entry.repo,
                fixture_dir=connector_entry.fixture_dir,
                token_env=connector_entry.token_env,
                materialize=connector_entry.materialize,
            )
            outcome = getattr(sync_run, "result", None) or (
                sync_run.get("result") if isinstance(sync_run, dict) else "ok"
            )
            evidence_count = getattr(sync_run, "evidence_count", None)
            if evidence_count is None and isinstance(sync_run, dict):
                evidence_count = sync_run.get("evidence_count")
            results.append(
                {
                    "target_kind": "connector",
                    "connector_id": connector_entry.connector_id,
                    "schedule": connector_entry.schedule,
                    "fired_at": utc_iso_z(moment),
                    "result": outcome,
                    "evidence_count": evidence_count,
                    "error": None,
                }
            )
        except Exception:  # noqa: BLE001 - scheduler results must not expose exception details
            results.append(
                {
                    "target_kind": "connector",
                    "connector_id": connector_entry.connector_id,
                    "schedule": connector_entry.schedule,
                    "fired_at": utc_iso_z(moment),
                    "result": "error",
                    "evidence_count": None,
                    "error": "internal error",
                }
            )
        _write_state(
            lake_dir,
            target_kind="connector",
            target_id=connector_entry.connector_id,
            fired_at=moment,
            result=str(results[-1]["result"]),
        )
    lake_eval = _scheduled_lake_eval(lake_dir)
    if lake_eval is not None:
        last_fired = state.get(_state_key("lake_eval", "default"))
        due_at = (last_fired + lake_eval.period) if last_fired else moment
        if last_fired is None or moment >= due_at:
            _write_state(lake_dir, target_kind="lake_eval", target_id="default", fired_at=moment, result="started")
            try:
                eval_result = run_lake_eval(lake_dir, actor="scheduler")
                results.append(
                    {
                        "target_kind": "lake_eval",
                        "schedule": lake_eval.schedule,
                        "fired_at": utc_iso_z(moment),
                        "result": eval_result.result,
                        "mode": eval_result.mode,
                        "local_result": eval_result.local_result,
                        "export_result": eval_result.export_result,
                        "error": eval_result.error,
                    }
                )
            except Exception:  # noqa: BLE001 - scheduler results must not expose exception details
                results.append(
                    {
                        "target_kind": "lake_eval",
                        "schedule": lake_eval.schedule,
                        "fired_at": utc_iso_z(moment),
                        "result": "error",
                        "error": "internal error",
                    }
                )
            _write_state(
                lake_dir,
                target_kind="lake_eval",
                target_id="default",
                fired_at=moment,
                result=str(results[-1]["result"]),
            )
    results.extend(_fire_retention(lake_dir, state, moment, _retention_kinds(lake_dir)))
    return results


def run_forever(
    lake_dir: str | Path,
    *,
    tick_seconds: int = DEFAULT_TICK_SECONDS,
    iterations: int | None = None,
    sleeper: Any | None = None,
    all_tenants: bool = False,
) -> int:
    """Daemon loop. ``iterations`` caps the loop for tests."""
    count = 0
    sleep = sleeper or time.sleep
    while iterations is None or count < iterations:
        try:
            tick(lake_dir, all_tenants=all_tenants)
        except Exception:  # noqa: BLE001 - daemon loop must survive any tick failure; logged
            # No exception text: connector errors may contain credentials or identifiers.
            logging.getLogger(__name__).error("scheduler tick failed; inspect runtime state before reconciliation")
        sleep(tick_seconds)
        count += 1
    return count


def repair_history(lake_dir: str | Path, *, now: datetime | None = None) -> dict[str, Any]:
    """Explicitly recover only unterminated runtime tails; never evidence ledgers.

    Original bytes are quarantined before mutation. A durable marker blocks all
    ticks until recovery finishes. Every scheduled target is deferred one full
    interval because a torn attempt record cannot establish whether it executed.
    """
    import hashlib
    import os

    from security_lakehouse import strict_json
    from security_lakehouse.io import write_json, write_jsonl
    from security_lakehouse.ledger import chain_lock

    gold = _gold(lake_dir)
    gold.mkdir(parents=True, exist_ok=True)
    runs = gold / "connector_runs.jsonl"
    marker = gold / "scheduler_recovery_pending.json"
    with _lock_path(lake_dir).open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        with chain_lock(runs):
            repairs = []
            for path in (gold / STATE_FILE, runs):
                if path.is_symlink():
                    raise ValueError("runtime recovery refuses symlinks")
                if not path.exists():
                    continue
                raw = path.read_bytes()
                lines = raw.splitlines(keepends=True)
                rows = []
                torn = False
                for index, line in enumerate(lines):
                    if not line.strip():
                        continue
                    try:
                        row = strict_json.loads(line.decode("utf-8"))
                        if not isinstance(row, dict):
                            raise ValueError("runtime row must be an object")
                        rows.append(row)
                    except (ValueError, UnicodeError) as exc:
                        if index != len(lines) - 1 or line.endswith(b"\n"):
                            raise ValueError("only an unterminated final runtime record can be repaired") from exc
                        torn = True
                if torn or (raw and not raw.endswith(b"\n")):
                    repairs.append((path, raw, rows))
            if not repairs and not marker.exists():
                return {"repaired": [], "deferred_targets": 0}
            write_json(marker, {"status": "recovery_pending"})
            directory = os.open(gold, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            archive = gold / "recovery"
            archive.mkdir(mode=0o700, exist_ok=True)
            archive.chmod(0o700)
            directory = os.open(gold, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            for path, raw, rows in repairs:
                backup = archive / f"{path.name}.{hashlib.sha256(raw).hexdigest()}.original"
                fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600) if not backup.exists() else None
                if fd is not None:
                    with os.fdopen(fd, "wb") as handle:
                        handle.write(raw)
                        handle.flush()
                        os.fsync(handle.fileno())
                elif backup.read_bytes() != raw:
                    raise ValueError("runtime recovery archive does not match")
                directory = os.open(archive, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
                write_jsonl(path, rows)
            _read_state(lake_dir)  # malformed complete state stays blocked for reconciliation
            targets = [("workflow", entry.workflow_id) for entry in _scheduled_from_workflows(list_workflows(lake_dir))]
            targets += [("connector", entry.connector_id) for entry in _scheduled_from_connectors(lake_dir)]
            if _scheduled_lake_eval(lake_dir):
                targets.append(("lake_eval", "default"))
            try:
                if retention_policy() is not None:
                    targets += [("retention", kind) for kind in _retention_kinds(lake_dir)]
            except ValueError:
                pass  # an invalid policy never runs, so there is no attempt to defer
            moment = now or utc_now()
            for kind, target in targets:
                _write_state(lake_dir, target_kind=kind, target_id=target, fired_at=moment, result="recovery_deferred")
            marker.unlink()
            directory = os.open(gold, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            return {"repaired": [path.name for path, _, _ in repairs], "deferred_targets": len(targets)}

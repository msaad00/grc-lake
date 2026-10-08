"""Durable acceptance and single-claim execution of bounded HTTP operations.

An expired running claim is interrupted, never automatically retried: its side
effects may have completed before the worker stopped. Queued work survives restart.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import multiprocessing
import re
import signal
import threading
import time
import uuid
from collections.abc import Callable, Collection
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import case, func, select, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from security_lakehouse.auth.rbac import Identity
from security_lakehouse.db.models import OperationJob
from security_lakehouse.ledger import chain_lock
from security_lakehouse.tenancy import root_key

_LOG = logging.getLogger(__name__)
LEASE_SECONDS = 90
RESULT_LIMIT = 1024 * 1024
DEFAULT_WORKERS = 2
MAX_WORKERS = 16
_RENEW_RETRY_MIN_SECONDS = 0.05
_RENEW_RETRY_MAX_SECONDS = 2.0
_WRITE_RETRY_SECONDS = 10.0


def _write_with_retry(factory: sessionmaker, write: Callable[[Session], object], *, job_id: str) -> None:
    """Run one fenced write transaction, retrying transient database errors briefly.

    After the budget the error propagates unchanged, so recovery still marks
    the job once its lease expires.
    """
    deadline = time.monotonic() + _WRITE_RETRY_SECONDS
    delay = _RENEW_RETRY_MIN_SECONDS
    while True:
        try:
            with factory.begin() as session:
                write(session)
            return
        except OperationalError as exc:
            if time.monotonic() + delay >= deadline:
                raise
            _LOG.warning("operation %s state write deferred: %s", job_id, exc.orig or exc)
            time.sleep(delay)
            delay = min(delay * 2, _RENEW_RETRY_MAX_SECONDS)


def supported(path: str) -> bool:
    return path in {"/api/v1/ingestion/eval", "/api/v1/scheduler/tick", "/api/v1/snapshots"} or bool(
        re.fullmatch(r"/api/v1/connectors/[A-Za-z0-9_-]+/sync", path)
    )


def serialize(row: OperationJob, *, include_result: bool = True) -> dict[str, Any]:
    def stamp(value: float | None) -> str | None:
        return datetime.fromtimestamp(value, UTC).isoformat() if value is not None else None

    result = json.loads(row.result_json) if row.result_json else None
    archived = isinstance(result, dict) and result.get("schema_version") == "trustops.operation_archive.v1"
    return {
        "result_archived": archived,
        "id": row.id,
        "kind": "operation",
        "label": {
            "/api/v1/ingestion/eval": "Lake evaluation",
            "/api/v1/scheduler/tick": "Scheduled collections",
            "/api/v1/snapshots": "Assessment snapshot",
        }.get(row.path, "Connector sync: " + row.path.split("/")[-2]),
        "status": row.status,
        "created_at": stamp(row.created_at),
        "started_at": stamp(row.started_at) or stamp(row.created_at),
        "finished_at": stamp(row.finished_at),
        "status_url": f"/api/v1/operations/{row.id}",
        "http_status": row.http_status,
        **({"response": None if archived else result} if include_result else {}),
    }


class JobConflict(ValueError):
    """A repeated key refers to different work."""


class JobQueue:
    def __init__(self, factory: sessionmaker, root: Path):
        self.factory = factory
        self.root = root.resolve()
        self.root_key = root_key(root)

    def enqueue(self, identity: Identity, path: str, payload: dict[str, Any], key: str) -> dict[str, Any]:
        # Serialize count-and-insert across API processes sharing the writer lake.
        tenant_key = hashlib.sha256(identity.tenant_id.encode()).hexdigest()
        with chain_lock(self.root / "server/operation_admission" / tenant_key):
            return self._enqueue(identity, path, payload, key)

    def _enqueue(self, identity: Identity, path: str, payload: dict[str, Any], key: str) -> dict[str, Any]:
        if not supported(path):
            raise ValueError("operation does not support asynchronous execution")
        if not key or len(key) > 200:
            raise ValueError("Idempotency-Key must contain 1 to 200 characters")
        # These operations only accept selectors, never credentials or local paths.
        allowed = {"actor", "idempotency_key"}
        if path == "/api/v1/snapshots":
            allowed.add("reason")
        elif path.endswith("/sync"):
            allowed.add("materialize")
        if payload.keys() - allowed:
            raise ValueError("unsupported asynchronous operation fields")
        if "materialize" in payload and not isinstance(payload["materialize"], bool):
            raise ValueError("materialize must be a boolean")
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(raw.encode()) > 8192:
            raise ValueError("operation payload exceeds 8 KiB")
        semantic = json.dumps(
            {k: v for k, v in payload.items() if k not in {"actor", "idempotency_key"}},
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        digest = hashlib.sha256((path + "\n" + semantic).encode()).hexdigest()
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        with self.factory() as session:
            query = select(OperationJob).where(
                OperationJob.root_key == self.root_key,
                OperationJob.tenant_id == identity.tenant_id,
                OperationJob.user_id == identity.user_id,
                OperationJob.idempotency_key == key_hash,
            )
            existing = session.scalar(query)
            if existing is None:
                pending = session.scalar(
                    select(func.count())
                    .select_from(OperationJob)
                    .where(
                        OperationJob.root_key == self.root_key,
                        OperationJob.tenant_id == identity.tenant_id,
                        OperationJob.status.in_(["queued", "running", "cancelling"]),
                    )
                )
                if pending and pending >= 100:
                    raise JobConflict("too many pending operations; wait for existing work")
                existing = OperationJob(
                    root_key=self.root_key,
                    tenant_id=identity.tenant_id,
                    user_id=identity.user_id,
                    api_key_id=identity.api_key_id,
                    session_id=identity.session_id,
                    auth_method=identity.auth_method,
                    idempotency_key=key_hash,
                    request_hash=digest,
                    path=path,
                    payload_json=raw,
                    status="queued",
                    created_at=time.time(),
                )
                session.add(existing)
                try:
                    session.commit()
                except IntegrityError:
                    session.rollback()
                    existing = session.scalar(query)
                    if existing is None:
                        raise
            if existing.request_hash != digest:
                raise JobConflict("Idempotency-Key already identifies a different request")
            return serialize(existing)

    def get(self, tenant_id: str, job_id: str, *, viewer: Identity | None = None) -> dict[str, Any] | None:
        with self.factory() as session:
            row = session.scalar(
                select(OperationJob).where(
                    OperationJob.id == job_id,
                    OperationJob.root_key == self.root_key,
                    OperationJob.tenant_id == tenant_id,
                )
            )
            return serialize(row, include_result=viewer is None or self.can_manage(row, viewer)) if row else None

    @staticmethod
    def can_manage(row: OperationJob, identity: Identity) -> bool:
        from security_lakehouse.api_v1 import required_post_scope

        return (
            row.tenant_id == identity.tenant_id
            and (row.user_id == identity.user_id or identity.role in {"admin", "security_admin"})
            and identity.has_scope(required_post_scope(row.path))
        )

    def cancel(self, identity: Identity, job_id: str) -> dict[str, Any] | None:
        with self.factory.begin() as session:
            row = session.scalar(
                select(OperationJob).where(
                    OperationJob.id == job_id,
                    OperationJob.root_key == self.root_key,
                    OperationJob.tenant_id == identity.tenant_id,
                )
            )
            if row is None:
                return None
            if not self.can_manage(row, identity):
                raise PermissionError(
                    "requires operation ownership or administrator authority and its current write scope"
                )
            if row.status in {"queued", "running"}:
                # Choose from the current database state: a claim may have won
                # since the authorization read. Completed outcomes are excluded.
                session.execute(
                    update(OperationJob)
                    .where(
                        OperationJob.id == row.id,
                        OperationJob.status.in_(["queued", "running"]),
                    )
                    .values(
                        status=case((OperationJob.status == "queued", "cancelled"), else_="cancelling"),
                        finished_at=case((OperationJob.status == "queued", time.time()), else_=None),
                    )
                )
                session.expire(row)
            if row.status not in {"cancelled", "cancelling", "interrupted"}:
                raise JobConflict("operation already finished; cancellation cannot undo its effects")
            return serialize(row)

    def list(
        self, tenant_id: str, limit: int = 50, offset: int = 0, *, viewer: Identity | None = None
    ) -> list[dict[str, Any]]:
        with self.factory() as session:
            rows = session.scalars(
                select(OperationJob)
                .where(
                    OperationJob.root_key == self.root_key,
                    OperationJob.tenant_id == tenant_id,
                )
                .order_by(OperationJob.created_at.desc(), OperationJob.id)
                .limit(min(500, max(1, limit)))
                .offset(max(0, offset))
            )
            return [
                {
                    **serialize(row, include_result=False),
                    "can_cancel": viewer is not None
                    and row.status in {"queued", "running"}
                    and self.can_manage(row, viewer),
                }
                for row in rows
            ]

    def execution_lock(self, row: OperationJob):
        return chain_lock(self.root / "server/operation_execution" / row.id, blocking=False)

    def owns_claim(self, row: OperationJob) -> bool:
        with self.factory() as session:
            return (
                session.scalar(
                    select(OperationJob.id).where(
                        OperationJob.id == row.id,
                        OperationJob.root_key == self.root_key,
                        OperationJob.status == "running",
                        OperationJob.worker_token == row.worker_token,
                    )
                )
                is not None
            )

    def recover(self) -> None:
        with self.factory() as session:
            stale = list(
                session.scalars(
                    select(OperationJob).where(
                        OperationJob.root_key == self.root_key,
                        OperationJob.status.in_(["running", "cancelling"]),
                        OperationJob.heartbeat_at < time.time() - LEASE_SECONDS,
                    )
                )
            )
            for row in stale:
                try:
                    with self.execution_lock(row):
                        session.execute(
                            update(OperationJob)
                            .where(
                                OperationJob.id == row.id,
                                OperationJob.status.in_(["running", "cancelling"]),
                                OperationJob.heartbeat_at < time.time() - LEASE_SECONDS,
                            )
                            .values(status="interrupted", finished_at=time.time())
                        )
                        session.commit()
                except BlockingIOError:
                    # A process still owns execution. Its independent deadline
                    # bounds its lifetime; never fence a live writer mid-action.
                    continue

    def claim(self, *, exclude_tenants: Collection[str] = ()) -> OperationJob | None:
        """Claim the oldest queued job of the least recently started tenant.

        ``exclude_tenants`` skips tenants that already have work in flight on
        the calling replica. The conditional UPDATE is the cross-replica fence.
        """
        self.recover()
        with self.factory() as session:
            turns = (
                select(OperationJob.tenant_id, func.max(OperationJob.started_at).label("last_started"))
                .where(OperationJob.root_key == self.root_key)
                .group_by(OperationJob.tenant_id)
                .subquery()
            )
            candidates = (
                select(OperationJob.id)
                .join(turns, turns.c.tenant_id == OperationJob.tenant_id)
                .where(
                    OperationJob.root_key == self.root_key,
                    OperationJob.status == "queued",
                )
            )
            if exclude_tenants:
                candidates = candidates.where(OperationJob.tenant_id.not_in(sorted(exclude_tenants)))
            job_id = session.scalar(
                candidates.order_by(
                    func.coalesce(turns.c.last_started, 0), OperationJob.created_at, OperationJob.id
                ).limit(1)
            )
            if job_id is None:
                return None
            token = str(uuid.uuid4())
            claimed = session.execute(
                update(OperationJob)
                .where(
                    OperationJob.id == job_id,
                    OperationJob.status == "queued",
                )
                .values(status="running", worker_token=token, started_at=time.time(), heartbeat_at=time.time())
            )
            session.commit()
            if claimed.rowcount != 1:
                return None
            row = session.get(OperationJob, job_id)
            session.expunge(row)
            return row

    def renew(self, row: OperationJob) -> bool:
        with self.factory.begin() as session:
            result = session.execute(
                update(OperationJob)
                .where(
                    OperationJob.id == row.id,
                    OperationJob.status == "running",
                    OperationJob.worker_token == row.worker_token,
                )
                .values(heartbeat_at=time.time())
            )

            return result.rowcount == 1

    def finish(self, row: OperationJob, code: int, response: dict[str, Any]) -> None:
        raw = json.dumps(response, allow_nan=False)
        state = "succeeded" if code < 400 else "failed"
        if len(raw.encode()) > RESULT_LIMIT:
            raw = "null"
            state = "interrupted"  # Work completed; inspect its domain history rather than replaying it.
        finished_at = time.time()

        def write(session: Session) -> None:
            session.execute(
                update(OperationJob)
                .where(
                    OperationJob.id == row.id,
                    OperationJob.status == "running",
                    OperationJob.worker_token == row.worker_token,
                )
                .values(status=state, http_status=code, result_json=raw, finished_at=finished_at)
            )
            session.execute(
                update(OperationJob)
                .where(
                    OperationJob.id == row.id,
                    OperationJob.status == "cancelling",
                    OperationJob.worker_token == row.worker_token,
                )
                .values(
                    status="interrupted",
                    finished_at=finished_at,
                    result_json=json.dumps(
                        {
                            "data": None,
                            "meta": {},
                            "errors": [
                                {
                                    "code": "cancelled",
                                    "detail": "Cancellation overlapped execution; inspect domain history before starting new work.",
                                }
                            ],
                        }
                    ),
                )
            )

        _write_with_retry(self.factory, write, job_id=row.id)


def _subprocess_entry(root: Path, row: OperationJob, execute, connection, timeout_seconds: float) -> None:
    from security_lakehouse.db.base import create_engine_for, session_factory

    # The kernel enforces this even while native code prevents Python signal
    # callbacks from running, or the parent watchdog has exited unexpectedly.
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.setitimer(signal.ITIMER_REAL, timeout_seconds)
    engine = create_engine_for(root)
    queue = JobQueue(session_factory(engine), root)
    try:
        with queue.execution_lock(row):
            if not queue.owns_claim(row):
                return
            connection.send(execute(root, row))
    except Exception:
        _LOG.exception("isolated operation %s failed", row.id)
        connection.send(
            (500, {"data": None, "errors": [{"detail": "operation failed; inspect operator logs"}], "meta": {}})
        )
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        connection.close()
        engine.dispose()


def _renewal_deadline(renewed_at: float) -> float:
    """Monotonic time after which a failed renewal can no longer keep the lease.

    The margin leaves room for one more database round trip before another
    replica's recovery may treat the lease as expired.
    """
    return renewed_at + LEASE_SECONDS - LEASE_SECONDS / 9


class JobWorker:
    def __init__(
        self,
        queue: JobQueue,
        execute: Callable[[OperationJob], tuple[int, dict[str, Any]]],
        *,
        subprocess_execute: Callable[[Path, OperationJob], tuple[int, dict[str, Any]]] | None = None,
        timeout_seconds: float = 900,
        concurrency: int = 1,
    ):
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 3600:
            raise ValueError("operation timeout must be between 0 and 3600 seconds")
        if isinstance(concurrency, bool) or not isinstance(concurrency, int) or not 1 <= concurrency <= MAX_WORKERS:
            raise ValueError(f"operation worker count must be an integer between 1 and {MAX_WORKERS}")
        self.queue = queue
        self.execute = execute
        self.subprocess_execute = subprocess_execute
        self.timeout_seconds = timeout_seconds
        self.concurrency = concurrency
        self.stop_event = threading.Event()
        # Claims within one replica are serialized so the in-flight tenant set
        # is current when the next claim excludes it.
        self._claim_lock = threading.Lock()
        self._in_flight: set[str] = set()
        self.threads = [
            threading.Thread(target=self.run, name=f"trustops-operations-{index}", daemon=True)
            for index in range(concurrency)
        ]

    def _try_renew(self, row: OperationJob) -> bool | None:
        """Renew the lease: True renewed, False claim lost, None transient database error.

        Renewal is a conditional UPDATE fenced on this worker's token, so a
        retry can never extend a lease another worker now holds.
        """
        try:
            return self.queue.renew(row)
        except OperationalError as exc:
            _LOG.warning("operation %s lease renewal deferred: %s", row.id, exc.orig or exc)
            return None

    def _isolated(self, row: OperationJob) -> None:
        context = multiprocessing.get_context("spawn")
        receiver, sender = context.Pipe(duplex=False)
        process = context.Process(
            target=_subprocess_entry,
            args=(self.queue.root, row, self.subprocess_execute, sender, self.timeout_seconds),
            daemon=True,
        )
        process.start()
        sender.close()
        deadline = time.monotonic() + self.timeout_seconds
        renewed_at = time.monotonic()
        next_renewal = renewed_at + min(LEASE_SECONDS / 3, 1)
        retry_delay = _RENEW_RETRY_MIN_SECONDS
        response = None
        reason = "outcome_unknown"
        try:
            while process.is_alive():
                if receiver.poll(0.1):
                    with suppress(EOFError):
                        response = receiver.recv()
                    break
                if self.stop_event.is_set():
                    reason = "worker_stopped"
                    break
                if time.monotonic() >= deadline:
                    reason = "execution_timeout"
                    break
                if time.monotonic() >= next_renewal:
                    attempted_at = time.monotonic()
                    renewed = self._try_renew(row)
                    if renewed is False:
                        reason = "claim_lost"
                        break
                    if renewed:
                        renewed_at = attempted_at
                        next_renewal = attempted_at + min(LEASE_SECONDS / 3, 1)
                        retry_delay = _RENEW_RETRY_MIN_SECONDS
                    elif time.monotonic() + retry_delay >= _renewal_deadline(renewed_at):
                        reason = "lease_renewal_failed"
                        break
                    else:
                        next_renewal = time.monotonic() + retry_delay
                        retry_delay = min(retry_delay * 2, _RENEW_RETRY_MAX_SECONDS)
            if response is None and receiver.poll():
                with suppress(EOFError):
                    response = receiver.recv()
        finally:
            if process.is_alive():
                process.terminate()
            process.join(5)
            if process.is_alive():
                process.kill()
                process.join()
            receiver.close()
        if response is not None and self.queue.owns_claim(row):
            self.queue.finish(row, *response)
        else:
            if process.exitcode == -signal.SIGALRM:
                reason = "execution_timeout"
            interrupted = (
                update(OperationJob)
                .where(
                    OperationJob.id == row.id,
                    OperationJob.status.in_(["running", "cancelling"]),
                    OperationJob.worker_token == row.worker_token,
                )
                .values(
                    status="interrupted",
                    finished_at=time.time(),
                    result_json=json.dumps(
                        {
                            "data": None,
                            "errors": [
                                {
                                    "code": reason,
                                    "detail": "Execution stopped; inspect domain history before starting new work.",
                                }
                            ],
                            "meta": {},
                        }
                    ),
                )
            )
            _write_with_retry(self.queue.factory, lambda session: session.execute(interrupted), job_id=row.id)

    def _claim(self) -> OperationJob | None:
        with self._claim_lock:
            row = self.queue.claim(exclude_tenants=frozenset(self._in_flight))
            if row is not None:
                self._in_flight.add(row.tenant_id)
            return row

    def run_once(self, *, isolated: bool = False) -> bool:
        row = self._claim()
        if row is None:
            return False
        try:
            self._execute(row, isolated=isolated)
        finally:
            with self._claim_lock:
                self._in_flight.discard(row.tenant_id)
        return True

    def _execute(self, row: OperationJob, *, isolated: bool) -> None:
        if isolated and self.subprocess_execute is not None:
            self._isolated(row)
            return
        done = threading.Event()

        def heartbeat() -> None:
            renewed_at = time.monotonic()
            wait = LEASE_SECONDS / 3
            retry_delay = _RENEW_RETRY_MIN_SECONDS
            while not done.wait(wait):
                attempted_at = time.monotonic()
                try:
                    renewed = self._try_renew(row)
                except Exception:
                    _LOG.exception("operation heartbeat failed")
                    renewed = None
                if renewed is False:
                    return
                if renewed:
                    renewed_at = attempted_at
                    wait = LEASE_SECONDS / 3
                    retry_delay = _RENEW_RETRY_MIN_SECONDS
                    continue
                if time.monotonic() + retry_delay >= _renewal_deadline(renewed_at):
                    # An in-process job cannot be stopped; stop renewing and let
                    # recovery fence it once its execution lock is released.
                    _LOG.error("operation %s lease renewal failed until the lease deadline", row.id)
                    return
                wait = retry_delay
                retry_delay = min(retry_delay * 2, _RENEW_RETRY_MAX_SECONDS)

        pulse = threading.Thread(target=heartbeat, daemon=True)
        pulse.start()
        try:
            with self.queue.execution_lock(row):
                if not self.queue.owns_claim(row):
                    return
                try:
                    code, response = self.execute(row)
                except Exception:
                    _LOG.exception("operation %s failed", row.id)
                    code, response = (
                        500,
                        {"data": None, "errors": [{"detail": "operation failed; inspect operator logs"}], "meta": {}},
                    )
                self.queue.finish(row, code, response)
        finally:
            done.set()
            pulse.join()

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                worked = self.run_once(isolated=True)
            except Exception:
                _LOG.exception("operation worker failed")
                worked = False
            if not worked:
                self.stop_event.wait(1)

    def start(self) -> None:
        for thread in self.threads:
            thread.start()

    def stop(self) -> None:
        """Signal every worker and wait up to 30 seconds in total for them."""
        self.stop_event.set()
        deadline = time.monotonic() + 30
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=max(0.0, deadline - time.monotonic()))

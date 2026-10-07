"""Durable acceptance and single-claim execution of bounded HTTP operations.

An expired running claim is interrupted, never automatically retried: its side
effects may have completed before the worker stopped. Queued work survives restart.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from security_lakehouse.auth.rbac import Identity
from security_lakehouse.db.models import OperationJob

_LOG = logging.getLogger(__name__)
LEASE_SECONDS = 90
RESULT_LIMIT = 1024 * 1024


def supported(path: str) -> bool:
    return path in {"/api/v1/ingestion/eval", "/api/v1/scheduler/tick", "/api/v1/snapshots"} or bool(
        re.fullmatch(r"/api/v1/connectors/[A-Za-z0-9_-]+/sync", path)
    )


def root_key(root: Path) -> str:
    return hashlib.sha256(str(root.resolve()).encode()).hexdigest()


def serialize(row: OperationJob, *, include_result: bool = True) -> dict[str, Any]:
    def stamp(value: float | None) -> str | None:
        return datetime.fromtimestamp(value, UTC).isoformat() if value is not None else None

    return {
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
        **({"response": json.loads(row.result_json) if row.result_json else None} if include_result else {}),
    }


class JobConflict(ValueError):
    """A repeated key refers to different work."""


class JobQueue:
    def __init__(self, factory: sessionmaker, root: Path):
        self.factory = factory
        self.root_key = root_key(root)

    def enqueue(self, identity: Identity, path: str, payload: dict[str, Any], key: str) -> dict[str, Any]:
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
                        OperationJob.status.in_(["queued", "running"]),
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

    def get(self, tenant_id: str, job_id: str) -> dict[str, Any] | None:
        with self.factory() as session:
            row = session.scalar(
                select(OperationJob).where(
                    OperationJob.id == job_id,
                    OperationJob.root_key == self.root_key,
                    OperationJob.tenant_id == tenant_id,
                )
            )
            return serialize(row) if row else None

    def list(self, tenant_id: str, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
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
            return [serialize(row, include_result=False) for row in rows]

    def recover(self) -> None:
        with self.factory.begin() as session:
            session.execute(
                update(OperationJob)
                .where(
                    OperationJob.root_key == self.root_key,
                    OperationJob.status == "running",
                    OperationJob.heartbeat_at < time.time() - LEASE_SECONDS,
                )
                .values(status="interrupted", finished_at=time.time())
            )

    def claim(self) -> OperationJob | None:
        self.recover()
        with self.factory() as session:
            job_id = session.scalar(
                select(OperationJob.id)
                .where(
                    OperationJob.root_key == self.root_key,
                    OperationJob.status == "queued",
                )
                .order_by(OperationJob.created_at, OperationJob.id)
                .limit(1)
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

    def renew(self, row: OperationJob) -> None:
        with self.factory.begin() as session:
            session.execute(
                update(OperationJob)
                .where(
                    OperationJob.id == row.id,
                    OperationJob.status == "running",
                    OperationJob.worker_token == row.worker_token,
                )
                .values(heartbeat_at=time.time())
            )

    def finish(self, row: OperationJob, code: int, response: dict[str, Any]) -> None:
        raw = json.dumps(response, allow_nan=False)
        state = "succeeded" if code < 400 else "failed"
        if len(raw.encode()) > RESULT_LIMIT:
            raw = "null"
            state = "interrupted"  # Work completed; inspect its domain history rather than replaying it.
        with self.factory.begin() as session:
            session.execute(
                update(OperationJob)
                .where(
                    OperationJob.id == row.id,
                    OperationJob.status == "running",
                    OperationJob.worker_token == row.worker_token,
                )
                .values(status=state, http_status=code, result_json=raw, finished_at=time.time())
            )


class JobWorker:
    def __init__(self, queue: JobQueue, execute: Callable[[OperationJob], tuple[int, dict[str, Any]]]):
        self.queue = queue
        self.execute = execute
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.run, name="trustops-operations", daemon=True)

    def run_once(self) -> bool:
        row = self.queue.claim()
        if row is None:
            return False
        done = threading.Event()

        def heartbeat() -> None:
            while not done.wait(LEASE_SECONDS / 3):
                try:
                    self.queue.renew(row)
                except Exception:
                    _LOG.exception("operation heartbeat failed")

        pulse = threading.Thread(target=heartbeat, daemon=True)
        pulse.start()
        try:
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
        return True

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                worked = self.run_once()
            except Exception:
                _LOG.exception("operation worker failed")
                worked = False
            if not worked:
                self.stop_event.wait(1)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=30)

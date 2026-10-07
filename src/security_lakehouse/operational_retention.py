"""Explicit archival of operational payloads; idempotency receipts are retained."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select, update

from security_lakehouse.db.base import create_engine_for, session_factory
from security_lakehouse.db.models import OperationJob
from security_lakehouse.ledger import chain_lock
from security_lakehouse.models import parse_event_time
from security_lakehouse.operation_jobs import root_key

ARCHIVE_MARKER = "trustops.operation_archive.v1"


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _durable_directory(directory: Path, synced: set[Path]) -> None:
    # Fsync ancestor entries even on resume: they may have been created just
    # before an interrupted archive. Reuse this set only within one invocation.
    for component in reversed((directory, *directory.parents)):
        if component in synced:
            continue
        if component.is_symlink():
            raise ValueError("archive symlinks are not allowed")
        component.mkdir(exist_ok=True, mode=0o700)
        _fsync_dir(component.parent)
        synced.add(component)


def _persist_archive(directory: Path, content: bytes, suffix: str, *, durable_dirs: set[Path]) -> str:
    """Exclusive, durable, content-addressed writes; existing bytes must match."""
    if any(parent.is_symlink() for parent in (directory, *directory.parents)):
        raise ValueError("archive symlinks are not allowed")
    _durable_directory(directory, durable_dirs)
    digest = hashlib.sha256(content).hexdigest()
    path = directory / (digest + suffix)
    if path.is_symlink():
        raise ValueError("archive symlinks are not allowed")
    if path.exists():
        if not path.is_file() or path.read_bytes() != content:
            raise ValueError("existing archive differs from original bytes")
    else:
        fd, temporary = tempfile.mkstemp(prefix=".job-archive-", dir=directory)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)
    _fsync_dir(directory)
    return digest


def _reject_request_symlinks(path: Path) -> None:
    if any(component.is_symlink() for component in (path, *path.parents)):
        raise ValueError("request audit symlinks are not allowed")


def _request_history(path: Path, cutoff: datetime, archive: Path | None, *, durable_dirs: set[Path]) -> tuple[int, int]:
    _reject_request_symlinks(path)
    if not path.exists():
        return 0, 0
    # Bound memory even for long-lived logs. Temporary files stay private and
    # the active file is replaced only after the archive is durable.
    with chain_lock(path), tempfile.TemporaryFile() as expired, tempfile.TemporaryFile() as kept:
        count = 0
        digest = hashlib.sha256()
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
            for raw in source:
                row = json.loads(raw)
                stamp = parse_event_time(row.get("occurred_at"))
                if stamp is None:
                    raise ValueError("request audit has an invalid timestamp; retention stopped")
                if stamp < cutoff:
                    expired.write(raw)
                    digest.update(raw)
                    count += 1
                else:
                    kept.write(raw)
        if not count or archive is None:
            return count, 0
        if any(parent.is_symlink() for parent in (archive, *archive.parents)):
            raise ValueError("archive symlinks are not allowed")
        _durable_directory(archive, durable_dirs)
        destination = archive / (digest.hexdigest() + ".jsonl")
        if destination.is_symlink():
            raise ValueError("archive symlinks are not allowed")
        expired.seek(0)
        if destination.exists():
            with destination.open("rb") as existing:
                for chunk in iter(lambda: expired.read(1024 * 1024), b""):
                    if existing.read(len(chunk)) != chunk:
                        raise ValueError("existing request archive differs from original bytes")
                if existing.read(1):
                    raise ValueError("existing request archive has extra bytes")
        else:
            fd, temporary = tempfile.mkstemp(prefix=".request-archive-", dir=archive)
            try:
                with os.fdopen(fd, "wb") as output:
                    for chunk in iter(lambda: expired.read(1024 * 1024), b""):
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
                os.link(temporary, destination)  # no replacement of an existing archive
            finally:
                Path(temporary).unlink(missing_ok=True)
        # Also covers recovery after an interruption between link and fsync.
        _fsync_dir(archive)
        fd, temporary = tempfile.mkstemp(prefix=".request-retention-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as output:
                kept.seek(0)
                for chunk in iter(lambda: kept.read(1024 * 1024), b""):
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            _fsync_dir(path.parent)
        finally:
            Path(temporary).unlink(missing_ok=True)
        return count, count


def archive_operational_history(
    lake: Path, *, older_than_days: int = 90, archive_to: Path | None = None
) -> dict[str, Any]:
    lake = lake.resolve()
    if not lake.is_dir() or older_than_days < 1:
        raise ValueError("retention requires an existing lake and a positive age")
    if archive_to is not None:
        if any(parent.is_symlink() for parent in (archive_to, *archive_to.parents)):
            raise ValueError("archive symlinks are not allowed")
        archive_to = archive_to.resolve()
        if archive_to == lake or lake in archive_to.parents:
            raise ValueError("archive must be outside the lake")
        archive_to = archive_to / root_key(lake)
    # Validate the whole source set before acquiring retention/source locks or
    # compacting jobs. An in-lake alias must not redirect another tenant's log.
    sources = [lake / "gold/request_audit.jsonl", lake / "server/security_audit/gold/request_audit.jsonl"]
    sources.extend(lake.glob("tenants/*/gold/request_audit.jsonl"))
    for path in sources:
        _reject_request_symlinks(path)
        if not path.resolve().is_relative_to(lake):
            raise ValueError("request audit must remain inside the lake")
    cutoff = datetime.now(UTC) - timedelta(days=older_than_days)
    report = dict(
        eligible_jobs=0,
        archived_jobs=0,
        eligible_request_rows=0,
        archived_request_rows=0,
        preview=archive_to is None,
        idempotency_receipts_retained=True,
    )
    durable_dirs: set[Path] = set()
    with chain_lock(lake / "server/operational-retention"):
        if (lake / "server/app.db").is_file() or os.environ.get("TRUSTOPS_DATABASE_URL"):
            engine = create_engine_for(lake)
            try:
                with session_factory(engine).begin() as session:
                    rows = session.scalars(
                        select(OperationJob)
                        .where(
                            OperationJob.root_key == root_key(lake),
                            OperationJob.status.in_(["succeeded", "failed", "interrupted", "cancelled"]),
                            OperationJob.finished_at < cutoff.timestamp(),
                        )
                        .execution_options(yield_per=100)
                    )
                    for row in rows:
                        response = json.loads(row.result_json) if row.result_json else None
                        if isinstance(response, dict) and response.get("schema_version") == ARCHIVE_MARKER:
                            continue
                        report["eligible_jobs"] += 1
                        if archive_to is None:
                            continue
                        content = json.dumps(
                            {
                                "schema_version": ARCHIVE_MARKER,
                                "job_id": row.id,
                                "tenant_id": row.tenant_id,
                                "user_id": row.user_id,
                                "path": row.path,
                                "status": row.status,
                                "created_at": row.created_at,
                                "finished_at": row.finished_at,
                                "request_hash": row.request_hash,
                                "idempotency_key": row.idempotency_key,
                                "payload_json": row.payload_json,
                                "result_json": row.result_json,
                            },
                            sort_keys=True,
                            allow_nan=False,
                        ).encode()
                        digest = _persist_archive(archive_to / "jobs", content, ".json", durable_dirs=durable_dirs)
                        result = session.execute(
                            update(OperationJob)
                            .where(
                                OperationJob.id == row.id,
                                OperationJob.status == row.status,
                                OperationJob.result_json == row.result_json,
                            )
                            .returning(OperationJob.id)
                            .values(
                                payload_json="{}",
                                result_json=json.dumps({"schema_version": ARCHIVE_MARKER, "sha256": digest}),
                            )
                        )
                        report["archived_jobs"] += int(result.scalar_one_or_none() is not None)
            finally:
                engine.dispose()
        for path in sources:
            namespace = hashlib.sha256(str(path.relative_to(lake)).encode()).hexdigest()
            eligible, archived = _request_history(
                path, cutoff, archive_to / "requests" / namespace if archive_to else None, durable_dirs=durable_dirs
            )
            report["eligible_request_rows"] += eligible
            report["archived_request_rows"] += archived
    return report

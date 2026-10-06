"""Operator-directed quarantine of uncommitted snapshots, never ledger repair."""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse.assessment import (
    SnapshotIntegrityError,
    _is_safe_snapshot_token,
    _ledger_path,
    _snapshot_chain_rows_unlocked,
)
from security_lakehouse.io import canonical_sha256, file_sha256, read_json, read_jsonl, write_json
from security_lakehouse.ledger import chain_lock

_SCHEMA = "trustops.snapshot_recovery.v1"


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _safe_path(path: Path) -> None:
    if path.is_symlink() or path.resolve() != path.absolute():
        raise ValueError("snapshot recovery refuses symlinks")


def _digest(path: Path) -> str:
    _safe_path(path)
    if not path.is_file():
        raise ValueError("snapshot recovery requires regular files")
    return file_sha256(path)


def _durable_json(path: Path, payload: dict[str, Any]) -> None:
    _safe_path(path)
    write_json(path, payload)
    _fsync_dir(path.parent)


def _move_to_archive(source: Path, target: Path) -> None:
    if target.exists():
        if _digest(source) != _digest(target):
            raise ValueError("snapshot recovery archive differs from source")
        with target.open("rb") as handle:
            os.fsync(handle.fileno())
        source.unlink()
    else:
        # Persist source contents before moving the directory entry.
        with source.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(source, target)
    _fsync_dir(target.parent)
    _fsync_dir(source.parent)


def _validate_pending(value: Any, committed: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"schema_version", "recovery_id", "started_at", "files"}:
        raise ValueError("invalid snapshot recovery journal")
    if value["schema_version"] != _SCHEMA or not isinstance(value["files"], list) or not value["files"]:
        raise ValueError("invalid snapshot recovery journal")
    names: set[str] = set()
    for row in value["files"]:
        if not isinstance(row, dict) or set(row) != {"snapshot", "sha256"}:
            raise ValueError("invalid snapshot recovery entry")
        name, digest = row["snapshot"], row["sha256"]
        if (
            not isinstance(name, str)
            or not _is_safe_snapshot_token(name)
            or not name.endswith(".json")
            or name in names | committed
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise ValueError("invalid or committed snapshot in recovery journal")
        names.add(name)
    if value["recovery_id"] != canonical_sha256(value["files"]):
        raise ValueError("snapshot recovery journal digest mismatch")
    return value


def reconcile_snapshots(lake_dir: str | Path, *, apply: bool = False) -> dict[str, Any]:
    """Preview or quarantine unledgered files under the snapshot writer lock.

    A fsynced intent journal precedes every move. Retrying a pending operation
    checks both source and archive hashes; it never overwrites committed history
    or accepts quarantined content as evidence. Hashing streams file bytes.
    """
    lake = Path(lake_dir).resolve()
    if not lake.is_dir():
        raise FileNotFoundError("assessment lake directory does not exist")
    snapshots = lake / "gold/snapshots"
    recovery = lake / "gold/snapshot_recovery"
    pending = recovery / "pending.json"
    ledger = _ledger_path(lake)
    for path in (snapshots, ledger, ledger.with_name(ledger.name + ".lock"), recovery, pending):
        _safe_path(path)
    if not snapshots.exists():
        if pending.exists():
            raise SnapshotIntegrityError("snapshot directory is missing during recovery")
        return {"applied": apply, "files": [], "archive": None, "integrity": {"ok": True, "length": 0, "issues": []}}
    with chain_lock(ledger):
        _, committed_integrity = _snapshot_chain_rows_unlocked(lake, metadata_only=True, allow_unledgered=True)
        if not committed_integrity["ok"]:
            raise SnapshotIntegrityError("committed snapshot history failed verification; quarantine refused")
        committed = {row["snapshot"] for row in read_jsonl(ledger, missing_ok=True)}
        orphans = sorted(path for path in snapshots.glob("*.json") if path.name not in committed)
        files = [{"snapshot": path.name, "sha256": _digest(path)} for path in orphans]
        if pending.exists():
            journal = _validate_pending(read_json(pending), committed)
        elif files:
            journal = {
                "schema_version": _SCHEMA,
                "recovery_id": canonical_sha256(files),
                "started_at": datetime.now(UTC).isoformat(),
                "files": files,
            }
        else:
            return {"applied": apply, "files": [], "archive": None, "integrity": committed_integrity}
        archive = recovery / journal["recovery_id"]
        originals = archive / "files"
        manifest = archive / "manifest.json"
        for path in (archive, originals, manifest):
            _safe_path(path)
        # Validate every pending entry before any mutation, including after a crash.
        for row in journal["files"]:
            source, target = snapshots / row["snapshot"], originals / row["snapshot"]
            for path in (source, target):
                _safe_path(path)
            if not source.exists() and not target.exists():
                raise SnapshotIntegrityError("snapshot recovery source and archive are both missing")
            for path in (source, target):
                if path.exists() and _digest(path) != row["sha256"]:
                    raise SnapshotIntegrityError("snapshot recovery content hash mismatch")
        result = {"applied": apply, "files": journal["files"], "archive": archive.relative_to(lake).as_posix()}
        if not apply:
            return {**result, "integrity": _snapshot_chain_rows_unlocked(lake, metadata_only=True)[1]}
        for directory in (recovery, archive, originals):
            directory.mkdir(mode=0o700, exist_ok=True)
            _fsync_dir(directory.parent)
        if not pending.exists():
            _durable_json(pending, journal)
        for row in journal["files"]:
            source, target = snapshots / row["snapshot"], originals / row["snapshot"]
            if source.exists():
                _move_to_archive(source, target)
            if _digest(target) != row["sha256"]:
                raise SnapshotIntegrityError("quarantined snapshot content hash mismatch")
            # A retry after rename must also persist both directory entries.
            _fsync_dir(originals)
            _fsync_dir(snapshots)
        integrity = _snapshot_chain_rows_unlocked(lake, metadata_only=True)[1]
        _durable_json(manifest, {**journal, "status": "completed", "completed_at": datetime.now(UTC).isoformat()})
        pending.unlink()
        _fsync_dir(recovery)
        return {**result, "integrity": integrity}

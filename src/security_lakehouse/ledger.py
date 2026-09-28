"""Append-only JSONL ledger helpers.

These helpers are intentionally small and storage-neutral: callers own their
domain schema, while the helper adds tamper-evident linkage and idempotent
replay semantics for append-only operational logs.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from security_lakehouse.io import append_jsonl, read_jsonl


def canonical_record_hash(record: dict[str, Any], *, hash_field: str = "record_hash") -> str:
    """Return the canonical sha256 for ``record`` excluding ``hash_field``."""
    payload = {key: value for key, value in record.items() if key != hash_field}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@contextlib.contextmanager
def chain_lock(path: str | Path):
    """Exclusive lock serializing read-then-append chain writers on ``path``.

    Uses an OS-level ``flock`` on a sibling lock file, so it serializes across
    threads, processes, and server workers -- not just within one process.
    Without this, two concurrent writers can both read the same chain tip and
    append with the same ``prev_hash``, forking the tamper-evident chain.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    lock_path = target.with_name(target.name + ".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def append_chained_jsonl(
    path: str | Path,
    record: dict[str, Any],
    *,
    idempotency_key: str | None = None,
    prev_field: str = "prev_hash",
    hash_field: str = "record_hash",
) -> dict[str, Any]:
    """Append ``record`` to ``path`` with hash-chain metadata.

    If ``idempotency_key`` already exists in the file, the existing record is
    returned and no duplicate is written. This supports retry-safe API,
    scheduler, CLI, and agent execution without minting conflicting audit rows.

    The read-decide-append sequence is serialized with :func:`chain_lock` so
    concurrent callers can never fork the chain by reading the same tip.
    """
    target = Path(path)
    key = str(idempotency_key or "").strip() or None
    with chain_lock(target):
        rows = read_jsonl(target, missing_ok=True)
        if key:
            for row in reversed(rows):
                if row.get("idempotency_key") == key:
                    return {**row, "idempotent_replay": True}

        prev_hash = None
        if rows:
            prev_hash = rows[-1].get(hash_field)
            if not isinstance(prev_hash, str) or not prev_hash:
                prev_hash = canonical_record_hash(rows[-1], hash_field=hash_field)

        chained = {**record, prev_field: prev_hash}
        if key:
            chained["idempotency_key"] = key
        chained[hash_field] = canonical_record_hash(chained, hash_field=hash_field)
        append_jsonl(target, chained)
        return chained


def append_chained_jsonl_batch(
    path: str | Path,
    build: Callable[[list[dict[str, Any]]], list[dict[str, Any]]],
    *,
    prev_field: str = "prev_hash",
    hash_field: str = "record_hash",
    on_appended: Callable[[int, str | None], None] | None = None,
) -> list[dict[str, Any]]:
    """Append the records ``build(existing_rows)`` returns, chained, under one lock.

    ``build`` sees the chain as it is while the lock is held, so records that
    reference earlier rows (for example "this supersedes decision X") are
    derived from the same state they are appended to, even with concurrent
    writers in other processes.

    The whole batch goes to disk in one ``O_APPEND`` write followed by
    ``fsync``, so a crash leaves either the full batch or, at worst, a torn
    trailing line that chain verification reports; never a silent partial
    batch. ``on_appended(length, tip_hash)`` runs after the write while the lock
    is still held, for callers that keep a sidecar over the chain tip.
    """
    from security_lakehouse.generations import assert_mutable

    target = Path(path)
    with chain_lock(target):
        rows = read_jsonl(target, missing_ok=True)
        prev_hash: str | None = None
        if rows:
            tip = rows[-1].get(hash_field)
            prev_hash = tip if isinstance(tip, str) and tip else canonical_record_hash(rows[-1], hash_field=hash_field)
        written: list[dict[str, Any]] = []
        for record in build(rows):
            chained = {**record, prev_field: prev_hash}
            chained[hash_field] = canonical_record_hash(chained, hash_field=hash_field)
            written.append(chained)
            prev_hash = chained[hash_field]
        if written:
            assert_mutable(target)
            blob = "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in written)
            _append_once(target, blob.encode("utf-8"))
        if on_appended is not None:
            on_appended(len(rows) + len(written), prev_hash)
        return written


def _append_once(target: Path, data: bytes) -> None:
    """Append ``data`` with a single write and fsync it before returning."""
    fd = os.open(target, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def verify_chained_jsonl(
    path: str | Path,
    *,
    prev_field: str = "prev_hash",
    hash_field: str = "record_hash",
) -> dict[str, Any]:
    """Verify a JSONL hash chain and return ``ok``, ``length`` and ``issues``."""
    target = Path(path)
    rows = read_jsonl(target, missing_ok=True)
    issues: list[str] = []
    expected_prev: str | None = None
    tip_hash: str | None = None
    for index, row in enumerate(rows):
        recorded_hash = row.get(hash_field)
        recomputed_hash = canonical_record_hash(row, hash_field=hash_field)
        if row.get(prev_field) != expected_prev:
            issues.append(f"entry {index}: {prev_field} breaks the chain")
        if not isinstance(recorded_hash, str) or not recorded_hash:
            issues.append(f"entry {index}: missing {hash_field}")
            tip_hash = recomputed_hash
            expected_prev = recomputed_hash
            continue
        if recorded_hash != recomputed_hash:
            issues.append(f"entry {index}: {hash_field} does not match content")
        tip_hash = recorded_hash
        expected_prev = recorded_hash
    return {"ok": not issues, "length": len(rows), "tip_hash": tip_hash, "issues": issues}

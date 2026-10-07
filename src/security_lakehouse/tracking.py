"""Violation triage persistence.

Stores the human/agent workflow on top of the immutable violation stream.
Records are append-only JSONL in ``gold/violation_tracking.jsonl`` so the
underlying assessment posture stays deterministic -- tracking augments, never
mutates, the source-of-truth evidence facts.

Schema (per record):
    {
        "tracking_id": str  (sha256(violation_id|timestamp|idempotency)[:16]),
        "violation_id": str,
        "actor": str,
        "state": "open" | "triaged" | "in_progress" | "resolved" | "dismissed",
        "assignee": str | None,
        "due_at": str | None  (ISO 8601),
        "note": str | None,
        "occurred_at": str  (ISO 8601 UTC),
        "prev_hash": str | None,
        "record_hash": str,
        "idempotency_key": str | None  (only when supplied),
    }
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse.io import read_jsonl
from security_lakehouse.ledger import append_chained_jsonl, verify_chained_jsonl
from security_lakehouse.models import instant_sort_key

ALLOWED_STATES = {"open", "triaged", "in_progress", "resolved", "dismissed"}


def tracking_path(lake_dir: str | Path) -> Path:
    """Return the JSONL file backing the triage log."""
    return Path(lake_dir) / "gold" / "violation_tracking.jsonl"


def append_event(
    lake_dir: str | Path,
    *,
    violation_id: str,
    actor: str,
    state: str,
    assignee: str | None = None,
    due_at: str | None = None,
    note: str | None = None,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    """Append a triage event for ``violation_id`` and return the record."""
    if state not in ALLOWED_STATES:
        raise ValueError(f"unknown state {state!r}; allowed: {sorted(ALLOWED_STATES)}")
    if not violation_id:
        raise ValueError("violation_id is required")
    occurred_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    nonce_material = f"{violation_id}|{occurred_at}|{idempotency_key or ''}"
    nonce = hashlib.sha256(nonce_material.encode("utf-8")).hexdigest()[:16]
    record: dict[str, Any] = {
        "tracking_id": nonce,
        "violation_id": violation_id,
        "actor": actor or "anonymous",
        "state": state,
        "assignee": assignee,
        "due_at": due_at,
        "note": note,
        "occurred_at": occurred_at,
    }
    return append_chained_jsonl(tracking_path(lake_dir), record, idempotency_key=idempotency_key)


def list_events(lake_dir: str | Path, *, violation_id: str | None = None) -> list[dict[str, Any]]:
    """Return all triage events, optionally filtered by ``violation_id``."""
    path = tracking_path(lake_dir)
    records: list[dict[str, Any]] = []
    for payload in read_jsonl(path, missing_ok=True):
        if violation_id and payload.get("violation_id") != violation_id:
            continue
        records.append(payload)
    return records


def latest_state(lake_dir: str | Path, *, violation_id: str) -> dict[str, Any] | None:
    """Return the most recent triage event for ``violation_id`` or None."""
    events = list_events(lake_dir, violation_id=violation_id)
    if not events:
        return None
    return max(events, key=lambda r: instant_sort_key(r.get("occurred_at")))


def verify_tracking_chain(lake_dir: str | Path) -> dict[str, Any]:
    """Verify the append-only tracking event hash chain."""
    return verify_chained_jsonl(tracking_path(lake_dir))

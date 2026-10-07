"""Append-only request audit events for server-mode auth boundaries."""

from __future__ import annotations

import threading
import time
import uuid
from collections import OrderedDict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse.auth.rbac import Identity
from security_lakehouse.io import append_jsonl
from security_lakehouse.ledger import chain_lock

REQUEST_AUDIT_FILE = "request_audit.jsonl"

MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class AnonymousAuditSampler:
    """Admit at most one anonymous audit row per key per window.

    Unauthenticated callers can send unlimited requests, so recording each one
    would let anyone grow the append-only audit file without bound. Keys are
    held in a bounded LRU map.
    """

    def __init__(self, *, window_seconds: float = 60.0, max_keys: int = 10_000) -> None:
        self._window = window_seconds
        self._max = max_keys
        self._last: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._last)

    def should_record(self, key: str, *, now: float | None = None) -> bool:
        moment = time.monotonic() if now is None else now
        with self._lock:
            last = self._last.get(key)
            if last is not None and moment - last < self._window:
                return False
            self._last[key] = moment
            self._last.move_to_end(key)
            while len(self._last) > self._max:
                self._last.popitem(last=False)
        return True


def should_audit_request(
    sampler: AnonymousAuditSampler,
    *,
    identity: Identity | None,
    method: str,
    status_code: int,
    client_host: str,
) -> bool:
    """Authenticated requests and successful anonymous mutations (signup, invite
    acceptance, SSO callbacks) are always audited; other anonymous traffic is
    sampled per client and decision."""
    if identity is not None:
        return True
    if method.upper() in MUTATING_METHODS and status_code < 400:
        return True
    decision = "allow" if status_code < 400 else "deny"
    return sampler.should_record(f"{client_host}|{decision}")


def _now() -> str:
    return datetime.now(UTC).isoformat()


def append_request_audit(
    lake_dir: str | Path,
    *,
    method: str,
    route: str,
    status_code: int,
    decision: str,
    correlation_id: str,
    identity: Identity | None = None,
) -> dict[str, Any]:
    """Persist a single request authorization decision.

    Each row gets a unique ``event_id``. ``correlation_id`` ties one HTTP
    request/response pair for tracing; it is **not** an idempotency key — client
    retries may append multiple rows with the same correlation id.
    """
    event = {
        "event_id": str(uuid.uuid4()),
        "category": "request",
        "actor": identity.email if identity else "anonymous",
        "actor_user_id": identity.user_id if identity else None,
        "tenant_id": identity.tenant_id if identity else None,
        "workspace_id": identity.workspace_id if identity else None,
        "role": identity.role if identity else None,
        "route": route,
        "method": method,
        "decision": decision,
        "status_code": status_code,
        "correlation_id": correlation_id,
        "occurred_at": _now(),
    }
    path = Path(lake_dir) / "gold" / REQUEST_AUDIT_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    with chain_lock(path):
        append_jsonl(path, event)
    return event

"""PostgreSQL locks for short admission transactions and job process ownership."""

import hashlib
from contextlib import contextmanager

from sqlalchemy import text


def key(namespace: str, identity: str) -> int:
    return int.from_bytes(hashlib.sha256(f"grc-lake:{namespace}:{identity}".encode()).digest()[:8], "big", signed=True)


def transaction_lock(session, namespace: str, identity: str) -> None:
    session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key(namespace, identity)})


@contextmanager
def process_lock(engine, namespace: str, identity: str):
    # An exclusively checked-out connection owns this session-level lock.
    # A connection loss releases it; publication has a separate monotonic fence.
    with engine.connect() as connection:
        value = key(namespace, identity)
        if not connection.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": value}):
            raise BlockingIOError("operation is executing on another replica")
        try:
            yield
        finally:
            try:
                connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": value})
            except Exception:  # noqa: BLE001 - fail closed at a distributed ownership boundary
                connection.invalidate()

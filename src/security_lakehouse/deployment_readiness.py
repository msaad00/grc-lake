"""Small deployment dependency probe, independent of assessment posture."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.engine import Engine


def ready(lake: Path, engine: Engine) -> bool:
    """Check persistent application state and writable lake storage, without tenant data."""
    try:
        if engine.dialect.name == "sqlite" and engine.url.database not in {None, "", ":memory:"}:
            # Fresh, existing-file connection detects removal/corruption even
            # when a pooled connection still holds an old inode. Never recreate.
            path = Path(engine.url.database).resolve()
            with closing(sqlite3.connect(f"{path.as_uri()}?mode=rw", uri=True, timeout=1)) as connection:
                connection.execute("PRAGMA query_only = ON")
                connection.execute("SELECT id FROM tenants LIMIT 0")
        else:
            with engine.connect() as connection:
                connection.execute(text("SELECT id FROM tenants LIMIT 0"))
        with tempfile.TemporaryFile(prefix=".readiness-", dir=lake) as probe:
            probe.write(b"ready")
            probe.flush()
            os.fsync(probe.fileno())
        return True
    except Exception:  # noqa: BLE001 - public probes never expose credentials or paths
        return False

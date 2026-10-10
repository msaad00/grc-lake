"""A failed distributed tenant tick is logged and records its exception class, never its message."""

from __future__ import annotations

import logging
from contextlib import contextmanager

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("alembic")


class _BrokenRuntime:
    def __init__(self, *args, **kwargs):
        pass

    @contextmanager
    def write(self, tenant):
        raise ConnectionError("postgresql://user:hunter2@db/grc refused")
        yield


def test_tenant_failure_is_logged_with_its_exception_class(tmp_path, monkeypatch, caplog):
    from sqlalchemy import text

    from security_lakehouse.db import migrate
    from security_lakehouse.db.base import create_engine_for
    from security_lakehouse.distributed import catalog, config, objects, schedules, workspace

    migrate.upgrade(tmp_path)
    engine = create_engine_for(tmp_path)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO tenants (id, slug, name) VALUES ('tenant-a', 'a', 'A')"))
    engine.dispose()
    monkeypatch.setattr(config.ClusterConfig, "from_env", classmethod(lambda cls: cls("cluster", "bucket")))
    monkeypatch.setattr(catalog, "Catalog", lambda *args, **kwargs: None)
    monkeypatch.setattr(objects, "ObjectStore", lambda *args, **kwargs: None)
    monkeypatch.setattr(workspace, "Runtime", _BrokenRuntime)

    with caplog.at_level(logging.ERROR, logger=schedules.__name__):
        rows = schedules.tick_cluster(tmp_path, tick_tenant=None, snapshot_hook_factory=lambda *args: None)

    assert rows == [
        {
            "tenant_id": "tenant-a",
            "result": "error",
            "error": "distributed scheduler failed",
            "error_type": "ConnectionError",
        }
    ]
    records = [record for record in caplog.records if record.name == schedules.__name__]
    assert len(records) == 1
    assert records[0].exc_info is not None
    assert "tenant-a" in records[0].getMessage()
    assert "ConnectionError" in records[0].getMessage()
    assert "hunter2" not in records[0].getMessage()

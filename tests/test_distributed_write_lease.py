"""Unchanged writes keep their revision but stay fenced; transient heartbeat failures are retried."""

import time

import pytest
from sqlalchemy import func, select, text

from security_lakehouse.db.base import session_factory
from security_lakehouse.db.models import DistributedRevision
from security_lakehouse.distributed import workspace as workspace_module
from security_lakehouse.distributed.catalog import Conflict
from security_lakehouse.distributed.objects import ObjectStore
from security_lakehouse.distributed.workspace import Runtime
from test_distributed_objects import MemoryObjects


def _revisions(catalog, tenant_id: str) -> int:
    with catalog.engine.connect() as conn:
        return conn.scalar(
            select(func.count()).select_from(DistributedRevision).where(DistributedRevision.tenant_id == tenant_id)
        )


@pytest.fixture
def runtime(catalog, tmp_path):
    return Runtime(catalog, ObjectStore(catalog.config, client=MemoryObjects()), tmp_path)


def test_unchanged_write_keeps_the_revision_and_commits_fenced_domain_writes(catalog, runtime):
    with catalog.engine.begin() as conn:
        conn.execute(text("CREATE TABLE unchanged_proof (id integer primary key)"))
    with runtime.write("tenant-a") as lake:
        (lake / "facts").write_text("published")
    assert catalog.head("tenant-a").version == 1
    revisions = _revisions(catalog, "tenant-a")

    with runtime.write("tenant-a"), session_factory(catalog.engine)() as session:
        session.execute(text("INSERT INTO unchanged_proof VALUES (1)"))
        session.commit()
    assert catalog.head("tenant-a").version == 1
    assert _revisions(catalog, "tenant-a") == revisions
    with catalog.engine.connect() as conn:
        assert conn.scalar(text("SELECT count(*) FROM unchanged_proof")) == 1

    with runtime.write("tenant-a") as lake:
        (lake / "facts").write_text("changed")
    assert catalog.head("tenant-a").version == 2


def test_unchanged_write_with_an_expired_fence_rolls_back(catalog, runtime):
    with catalog.engine.begin() as conn:
        conn.execute(text("CREATE TABLE fenced_proof (id integer primary key)"))
    with runtime.write("tenant-a") as lake:
        (lake / "facts").write_text("published")
    with pytest.raises(Conflict), runtime.write("tenant-a"):
        with session_factory(catalog.engine)() as session:
            session.execute(text("INSERT INTO fenced_proof VALUES (1)"))
            session.commit()
        with catalog.engine.begin() as other:
            other.execute(
                text("UPDATE distributed_tenant_heads SET lease_until = clock_timestamp() - interval '1 second'")
            )
    with catalog.engine.connect() as conn:
        assert conn.scalar(text("SELECT count(*) FROM fenced_proof")) == 0
    assert catalog.head("tenant-a").version == 1


def test_transient_heartbeat_failure_is_retried_within_the_lease(catalog, runtime, monkeypatch):
    monkeypatch.setattr(workspace_module, "HEARTBEAT_SECONDS", 0.05)
    monkeypatch.setattr(workspace_module, "HEARTBEAT_RETRY_SECONDS", 0.01)
    original = catalog.renew
    failures = []

    def flaky(lease, **kwargs):
        if len(failures) < 3:
            failures.append(lease)
            raise OSError("transient network error")
        return original(lease, **kwargs)

    monkeypatch.setattr(catalog, "renew", flaky)
    with runtime.write("tenant-a") as lake:
        time.sleep(0.4)
        (lake / "facts").write_text("published")
    assert len(failures) == 3
    assert catalog.head("tenant-a").version == 1


def test_rejected_renewal_is_lost_immediately(catalog, runtime, monkeypatch):
    monkeypatch.setattr(workspace_module, "HEARTBEAT_SECONDS", 0.05)
    monkeypatch.setattr(catalog, "renew", lambda lease, **kwargs: False)
    with pytest.raises(Conflict, match="renewal failed"), runtime.write("tenant-a") as lake:
        time.sleep(0.3)
        (lake / "facts").write_text("unpublished")
    assert catalog.head("tenant-a").version == 0


def test_heartbeat_failing_past_the_lease_window_is_lost(catalog, runtime, monkeypatch):
    monkeypatch.setattr(workspace_module, "LEASE_SECONDS", 1)
    monkeypatch.setattr(workspace_module, "HEARTBEAT_SECONDS", 0.05)
    monkeypatch.setattr(workspace_module, "HEARTBEAT_RETRY_SECONDS", 0.01)

    def down(lease, **kwargs):
        raise OSError("database unreachable")

    monkeypatch.setattr(catalog, "renew", down)
    with pytest.raises(Conflict), runtime.write("tenant-a") as lake:
        time.sleep(1.3)
        (lake / "facts").write_text("unpublished")
    assert catalog.head("tenant-a").version == 0

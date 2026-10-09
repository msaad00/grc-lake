"""Separate replica scratch directories, atomic database/file state, crash rollback."""

import pytest
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from security_lakehouse.db.base import session_factory
from security_lakehouse.distributed.catalog import Conflict
from security_lakehouse.distributed.context import binding
from security_lakehouse.distributed.objects import ObjectStore
from security_lakehouse.distributed.workspace import Runtime
from test_distributed_objects import MemoryObjects


def test_replicas_with_different_local_roots_read_the_same_committed_revision(catalog, tmp_path):
    store = ObjectStore(catalog.config, client=MemoryObjects())
    writer = Runtime(catalog, store, tmp_path / "writer-pod")
    reader = Runtime(catalog, store, tmp_path / "reader-pod")
    with writer.write("tenant-a") as lake:
        (lake / "facts.json").write_text('{"answer":42}')
        assert catalog.head("tenant-a").version == 0
    with reader.read("tenant-a") as lake:
        assert (lake / "facts.json").read_text() == '{"answer":42}'
    with reader.read("tenant-b") as lake:
        assert not (lake / "facts.json").exists()


def test_failure_rolls_back_domain_database_writes_and_never_publishes(catalog, tmp_path):
    runtime = Runtime(catalog, ObjectStore(catalog.config, client=MemoryObjects()), tmp_path)
    factory = session_factory(catalog.engine)
    with catalog.engine.begin() as conn:
        conn.execute(text("CREATE TABLE atomic_proof (id integer primary key)"))

    def failed_worker():
        with runtime.write("tenant-a") as lake:
            with factory() as session:
                session.execute(text("INSERT INTO atomic_proof VALUES (1)"))
                session.commit()
            (lake / "facts").write_text("must remain private")
            raise RuntimeError("lost worker")

    with pytest.raises(RuntimeError, match="lost worker"):
        failed_worker()
    with catalog.engine.connect() as conn:
        assert conn.scalar(text("SELECT count(*) FROM atomic_proof")) == 0
    assert catalog.head("tenant-a").version == 0


def test_postgres_connection_loss_fences_old_writer_even_if_it_keeps_computing(catalog, tmp_path):
    runtime = Runtime(catalog, ObjectStore(catalog.config, client=MemoryObjects()), tmp_path)
    with pytest.raises((SQLAlchemyError, Conflict)), runtime.write("tenant-a") as lake:
        connection = binding.get().connection
        pid = connection.scalar(text("SELECT pg_backend_pid()"))
        with catalog.engine.connect() as other:
            other.execute(text("SELECT pg_terminate_backend(:pid)"), {"pid": pid})
        (lake / "stale").write_text("unpublished")
    assert catalog.head("tenant-a").version == 0


def test_reader_local_writes_cannot_poison_cached_revision(catalog, tmp_path):
    runtime = Runtime(catalog, ObjectStore(catalog.config, client=MemoryObjects()), tmp_path)
    with runtime.write("tenant-a") as lake:
        (lake / "facts").write_text("published")
    with runtime.read("tenant-a") as lake:
        (lake / "facts").write_text("private projection")
    with runtime.read("tenant-a") as lake:
        assert (lake / "facts").read_text() == "published"
    assert not list(tmp_path.glob("reader-*"))


def test_waiting_worker_recovers_after_failed_owner_lease_expires(catalog, tmp_path):
    runtime = Runtime(catalog, ObjectStore(catalog.config, client=MemoryObjects()), tmp_path)
    stale = catalog.acquire("tenant-a", owner="failed-node", seconds=1)
    with runtime.write("tenant-a", wait_seconds=2) as lake:
        (lake / "recovered").write_text("new owner")
    assert catalog.head("tenant-a").version == 1
    with pytest.raises(Conflict):
        catalog.publish("tenant-a", expected=1, manifest={"files": {}}, lease=stale)

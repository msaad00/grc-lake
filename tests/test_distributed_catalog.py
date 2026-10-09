"""Real PostgreSQL fencing, independent replica roots and stable tenant shards."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import text

from security_lakehouse.distributed.catalog import Catalog, Conflict
from security_lakehouse.distributed.config import ClusterConfig


def test_shards_are_stable_and_configuration_cannot_remap_existing_data(catalog):
    expected = catalog.config.shard_for("tenant-a")
    assert 0 <= expected < 64
    assert ClusterConfig("test-cluster", "test-bucket", shards=64).shard_for("tenant-a") == expected
    with pytest.raises(Conflict, match="configuration"):
        Catalog(catalog.engine, ClusterConfig("test-cluster", "test-bucket", shards=32)).initialize()
    with pytest.raises(Conflict, match="configuration"):
        Catalog(catalog.engine, ClusterConfig("test-cluster", "another-bucket", shards=64)).initialize()
    with pytest.raises(Conflict, match="one cluster"):
        Catalog(catalog.engine, ClusterConfig("another-cluster", "test-bucket")).initialize()


def test_only_one_optimistic_publisher_can_replace_the_same_revision(catalog):
    revision = catalog.head("tenant-a")
    barrier = threading.Barrier(2)

    def publish(i):
        barrier.wait()
        try:
            return catalog.publish("tenant-a", expected=revision.version, manifest={"files": {}, "writer": i})
        except Conflict:
            return None

    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(publish, range(2)))
    assert sum(r is not None for r in results) == 1
    assert catalog.head("tenant-a").version == 1
    assert catalog.head("tenant-b").version == 0


def test_stale_fence_cannot_publish_after_new_owner(catalog):
    old = catalog.acquire("tenant-a", owner="worker-old", seconds=1)
    # Simulate expiry using the database clock, never a worker's clock.
    with catalog.engine.begin() as conn:
        conn.execute(text("UPDATE distributed_tenant_heads SET lease_until = CURRENT_TIMESTAMP - INTERVAL '1 second'"))
    new = catalog.acquire("tenant-a", owner="worker-new", seconds=60)
    assert new.fence > old.fence
    with pytest.raises(Conflict):
        catalog.publish("tenant-a", expected=0, manifest={"files": {}}, lease=old)
    catalog.publish("tenant-a", expected=0, manifest={"files": {}}, lease=new)
    assert catalog.head("tenant-a").version == 1


def test_lease_renewal_is_owner_fenced_and_tenants_can_write_concurrently(catalog):
    first = catalog.acquire("tenant-a", owner="a", seconds=60)
    second = catalog.acquire("tenant-b", owner="b", seconds=60)
    with pytest.raises(Conflict):
        catalog.acquire("tenant-a", owner="c", seconds=60)
    assert catalog.renew(first, seconds=60)
    catalog.release(first)
    assert not catalog.renew(first, seconds=60)
    catalog.publish("tenant-b", expected=0, manifest={"files": {}}, lease=second)


def test_revision_history_is_immutable_and_reader_pins_an_old_head(catalog):
    first = catalog.publish("tenant-a", expected=0, manifest={"files": {}, "marker": "first"})
    catalog.publish("tenant-a", expected=1, manifest={"files": {}, "marker": "second"})
    assert first.manifest["marker"] == "first"
    assert catalog.revision("tenant-a", 1).manifest["marker"] == "first"
    assert catalog.head("tenant-a").manifest["marker"] == "second"
    with pytest.raises(KeyError):
        catalog.revision("tenant-b", 1)


def _upgrade_in_process(url):
    from security_lakehouse.db.migrate import upgrade

    upgrade(".", url=url)


def test_concurrent_replica_startups_serialize_postgres_migrations(catalog):
    import multiprocessing

    from alembic import command

    from security_lakehouse.db.migrate import _config

    url = catalog.engine.url.render_as_string(hide_password=False)
    command.downgrade(_config(url), "base")
    context = multiprocessing.get_context("spawn")
    processes = [context.Process(target=_upgrade_in_process, args=(url,)) for _ in range(2)]
    try:
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=30)
            assert process.exitcode == 0
        command.check(_config(url))
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)

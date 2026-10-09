"""Fenced distributed scheduling; ambiguous attempts are not automatically replayed."""

from __future__ import annotations

from typing import cast

from security_lakehouse.distributed.config import ClusterConfig
from security_lakehouse.distributed.context import binding


def read_state() -> dict:
    workspace = binding.get()
    config = ClusterConfig.from_env()
    if workspace is None or config is None:
        return {}
    from sqlalchemy import Table, select

    from security_lakehouse.db.base import create_engine_for
    from security_lakehouse.db.models import DistributedScheduleState

    engine = workspace.connection.engine if workspace.connection is not None else create_engine_for(workspace.path)
    try:
        table = cast(Table, DistributedScheduleState.__table__)
        with engine.connect() as connection:
            return {
                f"{row.target_kind}:{row.target_id}": row.last_fired_at
                for row in connection.execute(
                    select(table).where(
                        table.c.cluster_id == config.cluster_id, table.c.tenant_id == workspace.tenant_id
                    )
                )
            }
    finally:
        if workspace.connection is None:
            engine.dispose()


def record_attempt(kind: str, target: str, fired_at) -> None:
    workspace = binding.get()
    config = ClusterConfig.from_env()
    if workspace is None or config is None:
        return
    from sqlalchemy import Table, func, select
    from sqlalchemy.dialects.postgresql import insert

    from security_lakehouse.distributed.catalog import Conflict

    if workspace.connection is None:
        raise Conflict("reader cannot record scheduler attempts")
    from security_lakehouse.db.models import DistributedScheduleState, DistributedTenantHead

    head = cast(Table, DistributedTenantHead.__table__)
    state = cast(Table, DistributedScheduleState.__table__)
    # Separate committed intent survives workspace/worker failure. The head lock
    # serializes this check with lease acquisition and publication.
    with workspace.connection.engine.begin() as connection:
        owner = connection.scalar(
            select(head.c.owner)
            .where(
                head.c.cluster_id == config.cluster_id,
                head.c.tenant_id == workspace.tenant_id,
                head.c.owner == workspace.owner,
                head.c.fence == workspace.fence,
                head.c.lease_until > func.clock_timestamp(),
            )
            .with_for_update()
        )
        if owner is None:
            raise Conflict("scheduler lost its writer fence")
        statement = insert(state).values(
            cluster_id=config.cluster_id,
            tenant_id=workspace.tenant_id,
            target_kind=kind,
            target_id=target,
            last_fired_at=fired_at,
        )
        connection.execute(
            statement.on_conflict_do_update(
                index_elements=[state.c.cluster_id, state.c.tenant_id, state.c.target_kind, state.c.target_id],
                set_={"last_fired_at": func.greatest(state.c.last_fired_at, fired_at)},
            )
        )


def tick_cluster(root, *, tick_tenant, snapshot_hook_factory, now=None, shards=None) -> list[dict]:
    from sqlalchemy import select

    from security_lakehouse.db.base import create_engine_for, session_factory
    from security_lakehouse.db.models import Tenant
    from security_lakehouse.distributed.catalog import Catalog, Conflict
    from security_lakehouse.distributed.objects import ObjectStore
    from security_lakehouse.distributed.workspace import Runtime
    from security_lakehouse.execution_mode import server_execution

    config = ClusterConfig.from_env()
    if config is None:
        raise ValueError("cluster scheduler requires distributed mode")
    engine = create_engine_for(root)
    factory = session_factory(engine)
    runtime = Runtime(Catalog(engine, config), ObjectStore(config), root / "distributed-scratch")
    results: list[dict] = []
    try:
        # Page identities instead of materializing all tenant state in RAM.
        after = ""
        while True:
            with engine.connect() as conn:
                tenants = list(conn.scalars(select(Tenant.id).where(Tenant.id > after).order_by(Tenant.id).limit(100)))
            if not tenants:
                break
            for tenant in tenants:
                if shards is not None and config.shard_for(tenant) not in shards:
                    continue
                try:
                    with runtime.write(tenant) as lake, server_execution(tenant):
                        rows = tick_tenant(lake, now=now, on_snapshot_written=snapshot_hook_factory(factory, tenant))
                    results.extend({**row, "tenant_id": tenant} for row in rows)
                except Conflict:
                    results.append({"tenant_id": tenant, "skipped_locked": True})
                except Exception:  # noqa: BLE001 - fail closed at a distributed ownership boundary
                    results.append({"tenant_id": tenant, "result": "error", "error": "distributed scheduler failed"})
            after = tenants[-1]
        return results
    finally:
        engine.dispose()

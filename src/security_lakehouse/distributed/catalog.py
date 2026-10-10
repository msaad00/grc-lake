"""PostgreSQL is the authority for publication and fencing, never a worker clock."""

from __future__ import annotations

import json
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import timedelta
from typing import cast

from sqlalchemy import Table, delete, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.engine import Connection, Engine

from security_lakehouse.db.models import (
    DistributedCluster,
    DistributedRevision,
    DistributedShareIndex,
    DistributedTenantHead,
)
from security_lakehouse.distributed.config import ClusterConfig, identifier


class Conflict(RuntimeError):
    """A revision, owner, or cluster configuration no longer matches."""


@dataclass(frozen=True)
class Head:
    tenant_id: str
    version: int
    manifest: dict


@dataclass(frozen=True)
class Lease:
    tenant_id: str
    owner: str
    fence: int


class Catalog:
    def __init__(self, engine: Engine, config: ClusterConfig):
        if engine.dialect.name != "postgresql":
            raise ValueError("distributed catalog requires PostgreSQL")
        self.engine = engine
        self.config = config

    def initialize(self) -> None:
        table = cast(Table, DistributedCluster.__table__)
        raw = json.dumps(
            {
                "bucket": self.config.bucket,
                "endpoint": self.config.endpoint,
                "region": self.config.region,
                "shards": self.config.shards,
                "layout": 1,
            },
            sort_keys=True,
        )
        with self.engine.begin() as conn:
            from security_lakehouse.distributed.locks import transaction_lock

            transaction_lock(conn, "cluster-registration", "database")
            identities = set(conn.scalars(select(table.c.id)))
            if identities - {self.config.cluster_id}:
                raise Conflict("a PostgreSQL application database belongs to one cluster")
            conn.execute(insert(table).values(id=self.config.cluster_id, config_json=raw).on_conflict_do_nothing())
            saved = conn.scalar(select(table.c.config_json).where(table.c.id == self.config.cluster_id))
            if saved != raw:
                raise Conflict("cluster storage configuration differs from its registered identity")

    def _where(self, table, tenant_id):
        identifier(tenant_id)
        return (table.c.cluster_id == self.config.cluster_id, table.c.tenant_id == tenant_id)

    def ensure_tenant(self, tenant_id: str) -> None:
        table = cast(Table, DistributedTenantHead.__table__)
        with self.engine.begin() as conn:
            conn.execute(
                insert(table)
                .values(
                    cluster_id=self.config.cluster_id,
                    tenant_id=identifier(tenant_id),
                    shard_id=self.config.shard_for(tenant_id),
                    version=0,
                    manifest_json='{"files":{}}',
                    fence=0,
                )
                .on_conflict_do_nothing()
            )

    def head(self, tenant_id: str) -> Head:
        table = cast(Table, DistributedTenantHead.__table__)
        with self.engine.connect() as conn:
            row = conn.execute(
                select(table.c.version, table.c.manifest_json).where(*self._where(table, tenant_id))
            ).first()
        return Head(tenant_id, row.version, json.loads(row.manifest_json)) if row else Head(tenant_id, 0, {"files": {}})

    def revision(self, tenant_id: str, version: int) -> Head:
        table = cast(Table, DistributedRevision.__table__)
        with self.engine.connect() as conn:
            raw = conn.scalar(
                select(table.c.manifest_json).where(*self._where(table, tenant_id), table.c.version == version)
            )
        if raw is None:
            raise KeyError("tenant revision not found")
        return Head(tenant_id, version, json.loads(raw))

    def acquire(self, tenant_id: str, *, owner: str, seconds: int = 90) -> Lease:
        identifier(owner)
        self._duration(seconds)
        self.ensure_tenant(tenant_id)
        table = cast(Table, DistributedTenantHead.__table__)
        with self.engine.begin() as conn:
            fence = conn.scalar(
                update(table)
                .where(
                    *self._where(table, tenant_id),
                    or_(table.c.owner.is_(None), table.c.lease_until <= func.clock_timestamp()),
                )
                .values(
                    owner=owner,
                    fence=table.c.fence + 1,
                    lease_until=func.clock_timestamp() + timedelta(seconds=seconds),
                )
                .returning(table.c.fence)
            )
        if fence is None:
            raise Conflict("tenant has an active writer")
        return Lease(tenant_id, owner, fence)

    @staticmethod
    def _duration(seconds):
        if type(seconds) is not int or not 1 <= seconds <= 3600:
            raise ValueError("lease duration must be between 1 and 3600 seconds")

    def _owns(self, table, lease):
        return (
            *self._where(table, lease.tenant_id),
            table.c.owner == lease.owner,
            table.c.fence == lease.fence,
            table.c.lease_until > func.clock_timestamp(),
        )

    def renew(self, lease: Lease, *, seconds: int = 90) -> bool:
        self._duration(seconds)
        table = cast(Table, DistributedTenantHead.__table__)
        with self.engine.begin() as conn:
            result = conn.execute(
                update(table)
                .where(*self._owns(table, lease))
                .values(lease_until=func.clock_timestamp() + timedelta(seconds=seconds))
            )
            return result.rowcount == 1

    def release(self, lease: Lease) -> None:
        table = cast(Table, DistributedTenantHead.__table__)
        with self.engine.begin() as conn:
            conn.execute(
                update(table)
                .where(*self._where(table, lease.tenant_id), table.c.owner == lease.owner, table.c.fence == lease.fence)
                .values(owner=None, lease_until=None)
            )

    def confirm(self, lease: Lease, *, expected: int, connection: Connection) -> None:
        """Fence ``connection``'s writes to ``lease`` at revision ``expected`` without publishing.

        The row lock holds until the transaction ends, so the check covers the commit.
        """
        table = cast(Table, DistributedTenantHead.__table__)
        held = connection.scalar(
            select(table.c.version).where(*self._owns(table, lease), table.c.version == expected).with_for_update()
        )
        if held is None:
            raise Conflict("publication rejected: stale revision or expired writer fence")

    def publish(
        self,
        tenant_id: str,
        *,
        expected: int,
        manifest: dict,
        lease: Lease | None = None,
        connection: Connection | None = None,
    ) -> Head:
        if lease is not None and lease.tenant_id != tenant_id:
            raise Conflict("lease belongs to another tenant")
        if connection is None:
            self.ensure_tenant(tenant_id)
        raw = json.dumps(manifest, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(raw.encode()) > 32 * 1024**2:
            raise ValueError("publication manifest exceeds 32 MiB")
        table = cast(Table, DistributedTenantHead.__table__)
        conditions = (
            self._owns(table, lease)
            if lease
            else (
                *self._where(table, tenant_id),
                or_(table.c.owner.is_(None), table.c.lease_until <= func.clock_timestamp()),
            )
        )
        with self.engine.begin() if connection is None else nullcontext(connection) as conn:
            result = conn.execute(
                update(table)
                .where(*conditions, table.c.version == expected)
                .values(version=expected + 1, manifest_json=raw)
                .returning(table.c.version)
            )
            if result.scalar_one_or_none() is None:
                raise Conflict("publication rejected: stale revision or expired writer fence")
            conn.execute(
                insert(cast(Table, DistributedRevision.__table__)).values(
                    cluster_id=self.config.cluster_id, tenant_id=tenant_id, version=expected + 1, manifest_json=raw
                )
            )
            shares = cast(Table, DistributedShareIndex.__table__)
            conn.execute(delete(shares).where(*self._where(shares, tenant_id)))
            for token_hash in manifest.get("shares", []):
                if len(token_hash) != 64 or any(c not in "0123456789abcdef" for c in token_hash):
                    raise ValueError("invalid share token digest")
                conn.execute(
                    insert(shares).values(
                        cluster_id=self.config.cluster_id, tenant_id=tenant_id, token_sha256=token_hash
                    )
                )
        return Head(tenant_id, expected + 1, json.loads(raw))

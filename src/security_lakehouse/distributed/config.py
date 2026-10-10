"""Stable storage identity and virtual shards; independent of worker count."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from security_lakehouse.runtime_environment import runtime_env


def identifier(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value):
        raise ValueError("invalid distributed storage identifier")
    return value


@dataclass(frozen=True)
class ClusterConfig:
    cluster_id: str
    bucket: str
    shards: int = 64
    endpoint: str | None = None
    region: str = "us-east-1"
    workspace_limit: int = 20 * 1024**3
    file_limit: int = 100_000
    read_cache_entries: int = 4
    read_cache_limit: int = 20 * 1024**3

    def __post_init__(self):
        identifier(self.cluster_id)
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", self.bucket):
            raise ValueError("invalid S3 bucket name")
        if type(self.shards) is not int or not 1 <= self.shards <= 4096:
            raise ValueError("virtual shard count must be between 1 and 4096")
        if self.workspace_limit < 1 or self.file_limit < 1:
            raise ValueError("workspace limits must be positive")
        if type(self.read_cache_entries) is not int or not 1 <= self.read_cache_entries <= 64:
            raise ValueError("read cache entries must be between 1 and 64")
        if self.read_cache_limit < self.workspace_limit:
            raise ValueError("read cache bytes must be at least the workspace limit")

    @property
    def root_key(self) -> str:
        return hashlib.sha256(("grc-lake-cluster:" + self.cluster_id).encode()).hexdigest()

    def shard_for(self, tenant_id: str) -> int:
        identifier(tenant_id)
        return int.from_bytes(hashlib.sha256(tenant_id.encode()).digest()[:8], "big") % self.shards

    def prefix_for(self, tenant_id: str) -> str:
        return f"clusters/{self.cluster_id}/shard={self.shard_for(tenant_id):04d}/tenant={identifier(tenant_id)}"

    @classmethod
    def from_env(cls) -> ClusterConfig | None:
        env = runtime_env()
        mode = env.get("GRC_LAKE_DEPLOYMENT_MODE", "local")
        if mode == "local":
            return None
        if mode != "distributed":
            raise ValueError("GRC_LAKE_DEPLOYMENT_MODE must be local or distributed")
        if env.get("GRC_LAKE_REPLICA_ROLE", "api") not in {"api", "reader", "worker", "scheduler"}:
            raise ValueError("invalid GRC_LAKE_REPLICA_ROLE")
        endpoint = env.get("GRC_LAKE_OBJECT_ENDPOINT")
        if endpoint:
            parsed = urlsplit(endpoint)
            if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError("object endpoint must be a service URL without credentials")
            if parsed.scheme != "https" and not (
                parsed.scheme == "http" and env.get("GRC_LAKE_OBJECT_ALLOW_HTTP") == "1"
            ):
                raise ValueError("object endpoint requires HTTPS; local testing may explicitly allow HTTP")
        from sqlalchemy.engine import make_url

        if make_url(env.get("GRC_LAKE_DATABASE_URL", "sqlite://")).get_backend_name() != "postgresql":
            raise ValueError("distributed mode requires PostgreSQL")
        return cls(
            cluster_id=env.get("GRC_LAKE_CLUSTER_ID", ""),
            bucket=env.get("GRC_LAKE_OBJECT_BUCKET", ""),
            shards=int(env.get("GRC_LAKE_VIRTUAL_SHARDS", "64")),
            endpoint=env.get("GRC_LAKE_OBJECT_ENDPOINT") or None,
            region=env.get("GRC_LAKE_OBJECT_REGION", "us-east-1"),
            workspace_limit=int(env.get("GRC_LAKE_WORKSPACE_BYTES", str(20 * 1024**3))),
            read_cache_entries=int(env.get("GRC_LAKE_READ_CACHE_ENTRIES", "4")),
            read_cache_limit=int(
                env.get("GRC_LAKE_READ_CACHE_BYTES", env.get("GRC_LAKE_WORKSPACE_BYTES", str(20 * 1024**3)))
            ),
        )

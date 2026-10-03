"""Pluggable evidence sinks: land the local medallion into an external lake.

A sink reads the local ``silver``/``gold`` artifacts a pipeline run produced and
loads them into a customer-owned lake — a warehouse (Snowflake, ClickHouse) or an
embedded file (DuckDB) — behind one shape. The local pipeline stays the source of
truth; a sink is an optional, idempotent projection of it into the customer's lake.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from security_lakehouse.execution_mode import in_server_mode
from security_lakehouse.sinks.clickhouse_sink import ClickHouseSink, ClickHouseSinkConfig
from security_lakehouse.sinks.duckdb_sink import DuckDBSink, DuckDBSinkConfig
from security_lakehouse.sinks.snowflake_sink import SnowflakeSink, SnowflakeSinkConfig

__all__ = [
    "ClickHouseSink",
    "ClickHouseSinkConfig",
    "DuckDBSink",
    "DuckDBSinkConfig",
    "SnowflakeSink",
    "SnowflakeSinkConfig",
    "land_if_configured",
]


def land_if_configured(lake_dir: str | Path, env: Mapping[str, str]) -> dict[str, dict[str, int]] | None:
    """Project the local medallion to every configured evidence lake.

    The lake is pluggable — Snowflake, ClickHouse, and/or an embedded DuckDB
    file — so a deployment can target any combination. Returns
    ``{sink_name: {table: rows}}`` for each configured sink, or ``None`` when none
    is configured (the common case — the local lake stays the source of truth).
    Lazy config means callers pay nothing unless ``SNOWFLAKE_*`` / ``CLICKHOUSE_*``
    / ``TRUSTOPS_DUCKDB_PATH`` is set.
    """
    if in_server_mode():
        raise ValueError("warehouse export requires tenant-scoped destination support; use an operator-owned local run")
    landed: dict[str, dict[str, int]] = {}
    snowflake = SnowflakeSinkConfig.from_env(env)
    if snowflake is not None:
        landed["snowflake"] = SnowflakeSink(snowflake).load(lake_dir)
    clickhouse = ClickHouseSinkConfig.from_env(env)
    if clickhouse is not None:
        landed["clickhouse"] = ClickHouseSink(clickhouse).load(lake_dir)
    duckdb = DuckDBSinkConfig.from_env(env)
    if duckdb is not None:
        landed["duckdb"] = DuckDBSink(duckdb).load(lake_dir)
    return landed or None

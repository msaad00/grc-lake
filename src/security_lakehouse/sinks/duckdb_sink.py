"""DuckDB evidence-lake sink: land the local medallion into an embedded file.

The zero-dependency, zero-server counterpart to the Snowflake and ClickHouse
sinks — same pluggable shape, but the "lake" is a single local DuckDB file. This
is the embedded option the architecture promises: a customer who does not want
to stand up a warehouse can still keep a queryable, idempotent medallion (the
same ``normalized_events`` / ``control_posture`` / ``asset_risk`` tables) in a
file they own, and run the gold analytics with plain SQL.

Properties:

* **Self-bootstrapping.** Unlike the warehouse sinks (which target a deployed
  ``schema.sql``), this sink creates its tables on first load, so there is no
  separate provisioning step for the embedded case.
* **Idempotent.** Each gold/silver table has a primary key and is loaded with
  ``INSERT OR REPLACE``, so a re-run upserts in place and never double-counts.
* **Native arrays + timestamps.** ``control_ids`` lands as a real ``VARCHAR[]``;
  ISO strings are coerced to ``TIMESTAMP``.

``duckdb`` imports lazily and the connection is injectable, so the load path is
unit-tested without the optional ``analytics`` extra installed at import time.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse.io import read_jsonl

DEFAULT_TENANT = "customer-managed"
ENV_PATH = "TRUSTOPS_DUCKDB_PATH"


@dataclass(frozen=True)
class DuckDBSinkConfig:
    """Embedded DuckDB target — just the path to the lake file.

    No host/user/password: the lake is a local file the customer owns. The path
    is read from ``TRUSTOPS_DUCKDB_PATH``; an in-memory ``:memory:`` value is
    accepted for ephemeral use.
    """

    database: str

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> DuckDBSinkConfig | None:
        """Build a config from env, or ``None`` when the embedded sink is unset."""
        path = env.get(ENV_PATH)
        if not path:
            return None
        return cls(database=path)


@dataclass(frozen=True)
class DuckTableSpec:
    """Maps one local lake artifact to one DuckDB table + its create DDL."""

    artifact: tuple[str, ...]
    table: str
    key: tuple[str, ...]
    columns: tuple[str, ...]
    ddl: str
    datetime_columns: tuple[str, ...] = ()
    array_columns: tuple[str, ...] = ()
    defaults: dict[str, Any] = field(default_factory=dict)


TABLE_SPECS: tuple[DuckTableSpec, ...] = (
    DuckTableSpec(
        artifact=("silver", "normalized_events.jsonl"),
        table="normalized_events",
        key=("event_id",),
        columns=(
            "event_id",
            "tenant_id",
            "event_time",
            "source",
            "event_type",
            "asset_id",
            "asset_type",
            "asset_owner",
            "environment",
            "severity",
            "severity_score",
            "status",
            "control_ids",
            "evidence_id",
            "evidence_ref",
            "evidence_collected_at",
            "raw_sha256",
        ),
        ddl=(
            "CREATE TABLE IF NOT EXISTS normalized_events ("
            "event_id VARCHAR PRIMARY KEY, tenant_id VARCHAR, event_time TIMESTAMP, source VARCHAR, "
            "event_type VARCHAR, asset_id VARCHAR, asset_type VARCHAR, asset_owner VARCHAR, environment VARCHAR, "
            "severity VARCHAR, severity_score DOUBLE, status VARCHAR, control_ids VARCHAR[], evidence_id VARCHAR, "
            "evidence_ref VARCHAR, evidence_collected_at TIMESTAMP, raw_sha256 VARCHAR)"
        ),
        datetime_columns=("event_time", "evidence_collected_at"),
        array_columns=("control_ids",),
    ),
    DuckTableSpec(
        artifact=("gold", "control_posture.jsonl"),
        table="control_posture",
        key=("tenant_id", "control_id"),
        columns=(
            "tenant_id",
            "control_id",
            "framework",
            "title",
            "risk_domain",
            "owner",
            "status",
            "risk_score",
            "event_count",
            "open_event_count",
            "evidence_count",
            "evidence_coverage",
            "latest_event_time",
        ),
        ddl=(
            "CREATE TABLE IF NOT EXISTS control_posture ("
            "tenant_id VARCHAR, control_id VARCHAR, framework VARCHAR, title VARCHAR, risk_domain VARCHAR, "
            "owner VARCHAR, status VARCHAR, risk_score DOUBLE, event_count BIGINT, open_event_count BIGINT, "
            "evidence_count BIGINT, evidence_coverage DOUBLE, latest_event_time TIMESTAMP, "
            "PRIMARY KEY (tenant_id, control_id))"
        ),
        datetime_columns=("latest_event_time",),
        defaults={"tenant_id": DEFAULT_TENANT},
    ),
    DuckTableSpec(
        artifact=("gold", "asset_risk.jsonl"),
        table="asset_risk",
        key=("tenant_id", "asset_id"),
        columns=(
            "tenant_id",
            "asset_id",
            "asset_type",
            "asset_owner",
            "environment",
            "risk_score",
            "critical_open",
            "high_open",
            "event_count",
            "latest_event_time",
        ),
        ddl=(
            "CREATE TABLE IF NOT EXISTS asset_risk ("
            "tenant_id VARCHAR, asset_id VARCHAR, asset_type VARCHAR, asset_owner VARCHAR, environment VARCHAR, "
            "risk_score DOUBLE, critical_open BIGINT, high_open BIGINT, event_count BIGINT, "
            "latest_event_time TIMESTAMP, PRIMARY KEY (tenant_id, asset_id))"
        ),
        datetime_columns=("latest_event_time",),
        defaults={"tenant_id": DEFAULT_TENANT},
    ),
)


# Gold "evaluate in place" views — the same auditor + executive surfaces the
# Snowflake schema ships, expressed in DuckDB SQL so the embedded lake is queried,
# not re-derived in Python. They read only the tables this sink lands, so they are
# always valid after a load. ``control_ids`` membership uses DuckDB's
# ``list_contains`` over the native ``VARCHAR[]`` column.
GOLD_VIEWS: tuple[str, ...] = (
    "CREATE OR REPLACE VIEW auditor_control_evidence AS "
    "SELECT c.framework, c.control_id, c.title, c.status AS control_status, c.risk_score, "
    "e.event_time, e.source, e.event_type, e.asset_id, e.severity, e.status AS event_status, "
    "e.evidence_ref, e.raw_sha256 "
    "FROM control_posture c JOIN normalized_events e ON list_contains(e.control_ids, c.control_id)",
    "CREATE OR REPLACE VIEW executive_risk_summary AS "
    "SELECT framework, count(*) AS controls, "
    "count(*) FILTER (WHERE status = 'fail') AS failing_controls, "
    "round(avg(risk_score), 2) AS avg_risk_score, "
    "round(avg(evidence_coverage), 4) AS avg_evidence_coverage "
    "FROM control_posture GROUP BY framework ORDER BY avg_risk_score DESC",
)


def _coerce_datetime(value: Any) -> datetime:
    """Parse an ISO-8601 string (``Z`` accepted) to a UTC-aware datetime."""
    if isinstance(value, datetime):
        return value
    text = str(value or "").strip()
    if not text:
        return datetime(1970, 1, 1, tzinfo=UTC)
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def rows_for_spec(spec: DuckTableSpec, lake_dir: str | Path) -> list[list[Any]]:
    """Project a local artifact onto a DuckDB table's ordered columns."""
    raw = read_jsonl(Path(lake_dir).joinpath(*spec.artifact), missing_ok=True)
    rows: list[list[Any]] = []
    for record in raw:
        row: list[Any] = []
        for col in spec.columns:
            value = record.get(col)
            if value is None and col in spec.defaults:
                value = spec.defaults[col]
            if col in spec.array_columns:
                value = [str(item) for item in (value or [])]
            elif col in spec.datetime_columns:
                value = _coerce_datetime(value)
            row.append(value)
        rows.append(row)
    return rows


class DuckDBSink:
    """Loads the local medallion into an embedded, customer-owned DuckDB file."""

    name = "duckdb"

    def __init__(self, config: DuckDBSinkConfig, *, connection: Any | None = None) -> None:
        self.config = config
        self._connection = connection

    def _connect(self) -> Any:
        if self._connection is not None:
            return self._connection
        import duckdb  # noqa: PLC0415

        if self.config.database not in {":memory:", ""}:
            Path(self.config.database).parent.mkdir(parents=True, exist_ok=True)
        return duckdb.connect(self.config.database)

    def load(self, lake_dir: str | Path) -> dict[str, int]:
        """Idempotently land every configured table; return rows landed per table."""
        conn = self._connect()
        landed: dict[str, int] = {}
        try:
            for spec in TABLE_SPECS:
                conn.execute(spec.ddl)
                rows = rows_for_spec(spec, lake_dir)
                if not rows:
                    landed[spec.table] = 0
                    continue
                placeholders = ", ".join("?" for _ in spec.columns)
                columns = ", ".join(spec.columns)
                conn.executemany(
                    f"INSERT OR REPLACE INTO {spec.table} ({columns}) VALUES ({placeholders})",
                    rows,
                )
                landed[spec.table] = len(rows)
            # Project the gold "evaluate in place" views so compliance can be
            # queried in the embedded lake without re-running the Python engine.
            for view_sql in GOLD_VIEWS:
                conn.execute(view_sql)
        finally:
            if self._connection is None:
                conn.close()
        return landed

"""ClickHouse evidence-lake sink: land the local medallion idempotently.

The ClickHouse counterpart to the Snowflake sink — same pluggable shape, so the
security data lake is a *choice* (cheap self-hostable ClickHouse vs Snowflake)
behind one interface. It targets the tables ``deploy/clickhouse/schema.sql``
defines (``security.normalized_events`` / ``control_posture`` / ``asset_risk``).

ClickHouse differences from the Snowflake path:

* **Native arrays.** ``control_ids`` inserts as a real ``Array(String)`` — no
  JSON round-trip.
* **Idempotent via delete-then-insert.** ClickHouse has no ``MERGE``; the gold
  tables are ``ReplacingMergeTree`` but dedup only happens at background merge.
  To make a re-run deterministic *now*, each table deletes the keys it is about
  to load (lightweight ``DELETE``) and re-inserts them — an upsert that is
  correct on every engine.
* **Typed columns.** ISO timestamps are coerced to ``datetime`` for the
  ``DateTime64`` columns the client expects.

``clickhouse_connect`` imports lazily and the client is injectable, so the load
path is unit-tested without a live ClickHouse.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse.connectors_clickhouse import safe_identifier
from security_lakehouse.io import read_jsonl

DEFAULT_DATABASE = "security"
DEFAULT_TENANT = "customer-managed"


@dataclass(frozen=True)
class ClickHouseSinkConfig:
    """ClickHouse connection identity.

    The password is read from the environment (``CLICKHOUSE_PASSWORD``) — a
    reference, never embedded in code or config. Prefer ``secure=True`` (TLS) and
    a scoped read/write user restricted to the ``security`` database.
    """

    host: str
    database: str = DEFAULT_DATABASE
    port: int | None = None
    user: str = "default"
    password: str = ""
    secure: bool = True

    def __post_init__(self) -> None:
        safe_identifier(self.database)

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> ClickHouseSinkConfig | None:
        host = env.get("CLICKHOUSE_HOST")
        if not host:
            return None
        port_raw = env.get("CLICKHOUSE_PORT")
        secure = str(env.get("CLICKHOUSE_SECURE", "true")).lower() not in {"0", "false", "no"}
        return cls(
            host=host,
            database=env.get("CLICKHOUSE_DATABASE") or DEFAULT_DATABASE,
            port=int(port_raw) if port_raw else None,
            user=env.get("CLICKHOUSE_USER") or "default",
            password=env.get("CLICKHOUSE_PASSWORD", ""),
            secure=secure,
        )


@dataclass(frozen=True)
class CHTableSpec:
    """Maps one local lake artifact to one ClickHouse table."""

    artifact: tuple[str, ...]
    table: str
    key: tuple[str, ...]
    columns: tuple[str, ...]
    datetime_columns: tuple[str, ...] = ()
    array_columns: tuple[str, ...] = ()
    defaults: dict[str, Any] = field(default_factory=dict)


TABLE_SPECS: tuple[CHTableSpec, ...] = (
    CHTableSpec(
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
        datetime_columns=("event_time", "evidence_collected_at"),
        array_columns=("control_ids",),
    ),
    CHTableSpec(
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
        datetime_columns=("latest_event_time",),
        defaults={"tenant_id": DEFAULT_TENANT},
    ),
    CHTableSpec(
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
        datetime_columns=("latest_event_time",),
        defaults={"tenant_id": DEFAULT_TENANT},
    ),
)


def _coerce_datetime(value: Any) -> datetime:
    """Parse an ISO-8601 string (``Z`` accepted) to a UTC-aware datetime."""
    if isinstance(value, datetime):
        return value
    text = str(value or "").strip()
    if not text:
        return datetime(1970, 1, 1, tzinfo=UTC)
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def rows_for_spec(spec: CHTableSpec, lake_dir: str | Path) -> list[list[Any]]:
    """Project a local artifact onto a ClickHouse table's ordered columns."""
    raw = read_jsonl(Path(lake_dir).joinpath(*spec.artifact), missing_ok=True)
    rows: list[list[Any]] = []
    for record in raw:
        row: list[Any] = []
        for col in spec.columns:
            value = record.get(col)
            if value is None and col in spec.defaults:
                value = spec.defaults[col]
            if col in spec.array_columns:
                value = list(value or [])
            elif col in spec.datetime_columns:
                value = _coerce_datetime(value)
            row.append(value)
        rows.append(row)
    return rows


def _quote(value: Any) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def delete_keys_sql(spec: CHTableSpec, database: str, rows: list[list[Any]]) -> str | None:
    """Build a lightweight DELETE for the keys a load is about to (re)insert."""
    if not rows:
        return None
    key_idx = [spec.columns.index(k) for k in spec.key]
    if len(spec.key) == 1:
        values = ", ".join(_quote(r[key_idx[0]]) for r in rows)
        predicate = f"{spec.key[0]} IN ({values})"
    else:
        cols = ", ".join(spec.key)
        tuples = ", ".join("(" + ", ".join(_quote(r[i]) for i in key_idx) + ")" for r in rows)
        predicate = f"({cols}) IN ({tuples})"
    return f"DELETE FROM {safe_identifier(database)}.{spec.table} WHERE {predicate}"


class ClickHouseSink:
    """Loads the local medallion into a customer-owned ClickHouse lake."""

    name = "clickhouse"

    def __init__(self, config: ClickHouseSinkConfig, *, client: Any | None = None) -> None:
        self.config = config
        self._client = client

    def _connect(self) -> Any:
        if self._client is not None:
            return self._client
        import clickhouse_connect  # noqa: PLC0415

        params: dict[str, Any] = {
            "host": self.config.host,
            "username": self.config.user,
            "password": self.config.password,
            "database": self.config.database,
            "secure": self.config.secure,
        }
        if self.config.port:
            params["port"] = self.config.port
        return clickhouse_connect.get_client(**params)

    def load(self, lake_dir: str | Path) -> dict[str, int]:
        """Idempotently land every configured table; return rows landed per table."""
        client = self._connect()
        landed: dict[str, int] = {}
        for spec in TABLE_SPECS:
            rows = rows_for_spec(spec, lake_dir)
            if not rows:
                landed[spec.table] = 0
                continue
            delete = delete_keys_sql(spec, self.config.database, rows)
            if delete:
                client.command(delete)
            client.insert(spec.table, rows, column_names=list(spec.columns), database=self.config.database)
            landed[spec.table] = len(rows)
        return landed

"""Snowflake evidence-lake sink: land the local medallion via stage + MERGE.

This is the write half of the Snowflake story (the connector is the read half).
A pipeline run produces local ``silver``/``gold`` artifacts; this sink projects
them into the customer's own Snowflake using the **same medallion tables** the
shipped ``deploy/snowflake/schema.sql`` defines, so evaluation can run in the
warehouse (the gold auditor/exec views).

Design properties:

* **Key-pair auth by reference.** Auth is RSA key-pair (no password). The private
  key is read from ``SNOWFLAKE_PRIVATE_KEY_FILE`` — a *path*, never key material
  in config or logs. The matching public key lives on the Snowflake service user.
* **Idempotent.** Each table loads through a transient staging table and a
  ``MERGE`` on its primary key, so re-running a sync upserts in place and never
  double-counts.
* **Pluggable load step.** ``write_pandas`` bulk-loads the small curated layers
  (silver/gold are one row per event/control/asset). High-volume raw streams
  belong on ``COPY``/Snowpipe from object storage — a different load step feeding
  the same MERGE.
* **Optional + lazy.** ``snowflake-connector-python`` and ``pandas`` import lazily
  so the base install never needs them; the connector module and writer are
  injectable for offline tests.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from security_lakehouse.io import read_jsonl
from security_lakehouse.runtime_environment import runtime_env

DEFAULT_DATABASE = "SECURITY_COMPLIANCE_LAKEHOUSE"
DEFAULT_TENANT = "customer-managed"


@dataclass(frozen=True)
class SnowflakeSinkConfig:
    """Non-secret Snowflake identity + the private-key *file path*.

    The key material itself is never held here — only the path to it, mounted
    from the runtime secret manager.
    """

    account: str
    user: str
    private_key_file: str
    role: str | None = None
    warehouse: str | None = None
    database: str = DEFAULT_DATABASE

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> SnowflakeSinkConfig | None:
        """Build a config from env, or None when the sink is not configured."""
        env = runtime_env(env)
        account = env.get("SNOWFLAKE_ACCOUNT")
        user = env.get("SNOWFLAKE_USER")
        key_file = env.get("SNOWFLAKE_PRIVATE_KEY_FILE")
        if not (account and user and key_file):
            return None
        return cls(
            account=account,
            user=user,
            private_key_file=key_file,
            role=env.get("SNOWFLAKE_ROLE"),
            warehouse=env.get("SNOWFLAKE_WAREHOUSE"),
            database=env.get("SNOWFLAKE_DATABASE") or DEFAULT_DATABASE,
        )


@dataclass(frozen=True)
class TableSpec:
    """Maps one local lake artifact to one Snowflake medallion table."""

    artifact: tuple[str, ...]
    schema: str
    table: str
    key: tuple[str, ...]
    columns: tuple[str, ...]
    variant: tuple[str, ...] = ()  # JSON-array columns -> PARSE_JSON on MERGE
    defaults: dict[str, Any] = field(default_factory=dict)


# The medallion tables this sink lands. Column lists match deploy/snowflake/schema.sql.
TABLE_SPECS: tuple[TableSpec, ...] = (
    TableSpec(
        artifact=("silver", "normalized_events.jsonl"),
        schema="SECURITY_SILVER",
        table="NORMALIZED_EVENTS",
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
        variant=("control_ids",),
    ),
    TableSpec(
        artifact=("gold", "control_posture.jsonl"),
        schema="SECURITY_GOLD",
        table="CONTROL_POSTURE",
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
        defaults={"tenant_id": DEFAULT_TENANT},
    ),
    TableSpec(
        artifact=("gold", "asset_risk.jsonl"),
        schema="SECURITY_GOLD",
        table="ASSET_RISK",
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
        defaults={"tenant_id": DEFAULT_TENANT},
    ),
)


def rows_for_spec(spec: TableSpec, lake_dir: str | Path) -> list[dict[str, Any]]:
    """Project a local artifact's records onto a table spec's columns.

    Array columns are JSON-encoded to a string for staging (re-parsed to a
    Snowflake ARRAY in the MERGE); missing values fall back to declared defaults.
    """
    raw = read_jsonl(Path(lake_dir).joinpath(*spec.artifact), missing_ok=True)
    projected: list[dict[str, Any]] = []
    for record in raw:
        row: dict[str, Any] = {}
        for col in spec.columns:
            if col in spec.variant:
                row[col] = json.dumps(record.get(col) or [])
            else:
                value = record.get(col)
                row[col] = spec.defaults.get(col) if value is None and col in spec.defaults else value
        projected.append(row)
    return projected


def merge_sql(spec: TableSpec) -> str:
    """Build the idempotent staging -> target MERGE for a table spec.

    The MATCHED branch is guarded by a change condition so the UPDATE only fires
    when a non-key column actually differs. We compare every projected non-key
    column with Snowflake's null-safe ``EQUAL_NULL`` (which also works on the
    VARIANT ``control_ids``) and update only when ``NOT (all columns equal)``.

    Why: re-loading identical data must be a true no-op. Skipping no-op updates
    means ``loaded_at`` is bumped only for rows that genuinely changed, so the
    set of freshly updated rows *is* the drift signal — what actually changed
    between syncs, not every matched row.
    """
    staging = f"STG_{spec.table}"
    select = ", ".join(f"PARSE_JSON({c}) AS {c}" if c in spec.variant else c for c in spec.columns)
    on = " AND ".join(f"t.{k} = s.{k}" for k in spec.key)
    non_key = [c for c in spec.columns if c not in spec.key]
    change_condition = " AND ".join(f"EQUAL_NULL(t.{c}, s.{c})" for c in non_key)
    update = ", ".join(f"{c} = s.{c}" for c in non_key)
    insert_cols = ", ".join(spec.columns)
    insert_vals = ", ".join(f"s.{c}" for c in spec.columns)
    return (
        f"MERGE INTO {spec.schema}.{spec.table} t "
        f"USING (SELECT {select} FROM {spec.schema}.{staging}) s ON {on} "
        f"WHEN MATCHED AND NOT ({change_condition}) THEN UPDATE SET {update} "
        f"WHEN NOT MATCHED THEN INSERT ({insert_cols}) VALUES ({insert_vals})"
    )


class SnowflakeSink:
    """Loads the local medallion into a customer-owned Snowflake lake."""

    name = "snowflake"

    def __init__(
        self,
        config: SnowflakeSinkConfig,
        *,
        connector: Any | None = None,
        writer: Any | None = None,
        private_key_der: bytes | None = None,
    ) -> None:
        self.config = config
        self._connector = connector  # snowflake.connector module (injectable for tests)
        self._writer = writer  # write_pandas callable (injectable for tests)
        self._private_key_der = private_key_der

    def _key_der(self) -> bytes:
        if self._private_key_der is not None:
            return self._private_key_der
        from cryptography.hazmat.primitives import serialization

        data = Path(self.config.private_key_file).read_bytes()
        private_key = serialization.load_pem_private_key(data, password=None)
        return private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def _connect(self) -> Any:
        connector = self._connector
        if connector is None:
            import snowflake.connector as snowflake_connector

            connector = snowflake_connector

        params: dict[str, Any] = {
            "account": self.config.account,
            "user": self.config.user,
            "private_key": self._key_der(),
            "database": self.config.database,
        }
        if self.config.role:
            params["role"] = self.config.role
        if self.config.warehouse:
            params["warehouse"] = self.config.warehouse
        return connector.connect(**params)

    def _write_pandas(self) -> Any:
        if self._writer is not None:
            return self._writer
        from snowflake.connector.pandas_tools import write_pandas

        return write_pandas

    def cortex_complete(self, model: str, prompt: str) -> str:
        """Run inference inside Snowflake via ``SNOWFLAKE.CORTEX.COMPLETE``.

        The prompt is the only thing that crosses into Snowflake and the response
        is generated in-warehouse, so evidence never leaves the customer's lake
        to reach a third-party model endpoint. Returns the raw completion text.
        """
        conn = self._connect()
        try:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT SNOWFLAKE.CORTEX.COMPLETE(%(model)s, %(prompt)s)",
                    {"model": model, "prompt": prompt},
                )
                row = cursor.fetchone()
            finally:
                cursor.close()
        finally:
            conn.close()
        if not row or row[0] is None:
            raise RuntimeError("Cortex COMPLETE returned no content")
        return str(row[0])

    def load(self, lake_dir: str | Path) -> dict[str, int]:
        """Land every configured medallion table; return rows landed per table."""
        import pandas as pd

        write_pandas = self._write_pandas()
        landed: dict[str, int] = {}
        conn = self._connect()
        try:
            cursor = conn.cursor()
            try:
                for spec in TABLE_SPECS:
                    rows = rows_for_spec(spec, lake_dir)
                    if not rows:
                        landed[spec.table] = 0
                        continue
                    frame = pd.DataFrame(rows, columns=list(spec.columns))
                    write_pandas(
                        conn,
                        frame,
                        f"STG_{spec.table}",
                        schema=spec.schema,
                        auto_create_table=True,
                        overwrite=True,
                        quote_identifiers=False,
                    )
                    cursor.execute(merge_sql(spec))
                    landed[spec.table] = len(rows)
            finally:
                cursor.close()
        finally:
            conn.close()
        return landed

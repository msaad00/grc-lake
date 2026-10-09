"""Snowflake sink: column mapping, idempotent MERGE SQL, and load orchestration.

The snowflake connector + write_pandas are injected, so the load path is exercised
end to end without a live warehouse.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_lakehouse.sinks.snowflake_sink import (
    TABLE_SPECS,
    SnowflakeSink,
    SnowflakeSinkConfig,
    merge_sql,
    rows_for_spec,
)


def _spec(table: str):
    return next(s for s in TABLE_SPECS if s.table == table)


def test_config_from_env_requires_account_user_and_key_path() -> None:
    assert SnowflakeSinkConfig.from_env({}) is None
    assert SnowflakeSinkConfig.from_env({"SNOWFLAKE_ACCOUNT": "a", "SNOWFLAKE_USER": "u"}) is None

    cfg = SnowflakeSinkConfig.from_env(
        {
            "SNOWFLAKE_ACCOUNT": "ORG-ACCT",
            "SNOWFLAKE_USER": "GRC_LAKE_INGEST_SVC",
            "SNOWFLAKE_PRIVATE_KEY_FILE": "/secrets/key.p8",
            "SNOWFLAKE_ROLE": "GRC_LAKE_LOADER",
            "SNOWFLAKE_WAREHOUSE": "GRC_LAKE_LOAD_WH",
        }
    )
    assert cfg is not None
    assert cfg.account == "ORG-ACCT" and cfg.role == "GRC_LAKE_LOADER"
    assert cfg.database == "SECURITY_COMPLIANCE_LAKEHOUSE"  # default


def test_rows_for_spec_applies_defaults_and_json_encodes_arrays(tmp_path: Path) -> None:
    (tmp_path / "gold").mkdir()
    (tmp_path / "gold" / "control_posture.jsonl").write_text(
        json.dumps({"control_id": "SOC2-CC6.1", "framework": "SOC 2", "status": "fail"}) + "\n",
        encoding="utf-8",
    )
    rows = rows_for_spec(_spec("CONTROL_POSTURE"), tmp_path)
    assert rows[0]["tenant_id"] == "customer-managed"  # default injected
    assert rows[0]["control_id"] == "SOC2-CC6.1"

    (tmp_path / "silver").mkdir()
    (tmp_path / "silver" / "normalized_events.jsonl").write_text(
        json.dumps({"event_id": "e1", "control_ids": ["SOC2-CC6.1", "ISO27001-A.5.15"]}) + "\n",
        encoding="utf-8",
    )
    srows = rows_for_spec(_spec("NORMALIZED_EVENTS"), tmp_path)
    # Array column is JSON-encoded to a string for staging.
    assert srows[0]["control_ids"] == json.dumps(["SOC2-CC6.1", "ISO27001-A.5.15"])


def test_merge_sql_is_idempotent_upsert_keyed_on_primary_key() -> None:
    sql = merge_sql(_spec("CONTROL_POSTURE"))
    assert "MERGE INTO SECURITY_GOLD.CONTROL_POSTURE t" in sql
    assert "ON t.tenant_id = s.tenant_id AND t.control_id = s.control_id" in sql
    # The MATCHED branch is now change-guarded so no-op reloads do not update.
    assert "WHEN MATCHED AND NOT (" in sql
    assert "THEN UPDATE SET" in sql
    assert "WHEN NOT MATCHED THEN INSERT" in sql

    # Array column is reconstructed as a Snowflake ARRAY via PARSE_JSON.
    silver_sql = merge_sql(_spec("NORMALIZED_EVENTS"))
    assert "PARSE_JSON(control_ids) AS control_ids" in silver_sql


def _change_condition(sql: str) -> str:
    """Isolate the text inside ``WHEN MATCHED AND NOT ( ... )``."""
    head = "WHEN MATCHED AND NOT ("
    start = sql.index(head) + len(head)
    end = sql.index(") THEN UPDATE SET", start)
    return sql[start:end]


def test_merge_sql_change_condition_covers_non_key_columns_only() -> None:
    # Composite key: both key columns are excluded; a non-key column is included.
    sql = merge_sql(_spec("CONTROL_POSTURE"))
    cond = _change_condition(sql)
    assert "EQUAL_NULL(t.status, s.status)" in cond
    assert "EQUAL_NULL(t.risk_score, s.risk_score)" in cond
    # Key columns must never appear in the change condition.
    assert "t.tenant_id" not in cond
    assert "t.control_id" not in cond


def test_merge_sql_change_condition_single_key_includes_variant_column() -> None:
    # Single key (event_id): excluded from the condition; status compared; the
    # VARIANT control_ids column is compared with EQUAL_NULL like any other.
    sql = merge_sql(_spec("NORMALIZED_EVENTS"))
    cond = _change_condition(sql)
    assert "EQUAL_NULL(t.status, s.status)" in cond
    assert "EQUAL_NULL(t.control_ids, s.control_ids)" in cond
    assert "t.event_id" not in cond


class _FakeCursor:
    def __init__(self) -> None:
        self.executed: list[str] = []

    def execute(self, sql: str) -> None:
        self.executed.append(sql)

    def close(self) -> None:
        pass


class _FakeConn:
    def __init__(self) -> None:
        self._cursor = _FakeCursor()
        self.closed = False

    def cursor(self) -> _FakeCursor:
        return self._cursor

    def close(self) -> None:
        self.closed = True


class _FakeConnector:
    def __init__(self) -> None:
        self.connect_kwargs: dict | None = None
        self.conn = _FakeConn()

    def connect(self, **kwargs: object) -> _FakeConn:
        self.connect_kwargs = kwargs
        return self.conn


def _seed_lake(tmp_path: Path) -> Path:
    (tmp_path / "silver").mkdir()
    (tmp_path / "gold").mkdir()
    (tmp_path / "silver" / "normalized_events.jsonl").write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {"event_id": "aws-1", "source": "aws", "control_ids": ["SOC2-CC6.1"], "tenant_id": "t"},
                {"event_id": "azure-1", "source": "azure", "control_ids": ["ISO27001-A.5.15"], "tenant_id": "t"},
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "gold" / "control_posture.jsonl").write_text(
        json.dumps({"control_id": "SOC2-CC6.1", "framework": "SOC 2", "status": "fail"}) + "\n",
        encoding="utf-8",
    )
    (tmp_path / "gold" / "asset_risk.jsonl").write_text(
        json.dumps({"asset_id": "aws:account:1", "asset_type": "account_config", "risk_score": 82}) + "\n",
        encoding="utf-8",
    )
    return tmp_path


def test_load_writes_staging_and_merges_each_table() -> None:
    pytest.importorskip("pandas")
    import tempfile

    lake = _seed_lake(Path(tempfile.mkdtemp()))
    connector = _FakeConnector()
    writes: list[tuple[str, str, int]] = []

    def fake_write_pandas(conn, df, table_name, *, schema, **kwargs):  # noqa: ANN001, ANN003
        writes.append((schema, table_name, len(df)))
        return True, 1, len(df), []

    cfg = SnowflakeSinkConfig(
        account="ORG-ACCT",
        user="GRC_LAKE_INGEST_SVC",
        private_key_file="/unused",
        role="GRC_LAKE_LOADER",
        warehouse="GRC_LAKE_LOAD_WH",
    )
    sink = SnowflakeSink(cfg, connector=connector, writer=fake_write_pandas, private_key_der=b"der")

    landed = sink.load(lake)

    # Connected with key-pair (no password) and the scoped role.
    assert connector.connect_kwargs["user"] == "GRC_LAKE_INGEST_SVC"
    assert connector.connect_kwargs["role"] == "GRC_LAKE_LOADER"
    assert "password" not in connector.connect_kwargs
    assert connector.connect_kwargs["private_key"] == b"der"

    # Each table staged then MERGEd; rows landed reported.
    assert landed == {"NORMALIZED_EVENTS": 2, "CONTROL_POSTURE": 1, "ASSET_RISK": 1}
    assert ("SECURITY_SILVER", "STG_NORMALIZED_EVENTS", 2) in writes
    assert ("SECURITY_GOLD", "STG_CONTROL_POSTURE", 1) in writes
    merges = [s for s in connector.conn._cursor.executed if s.startswith("MERGE INTO")]
    assert len(merges) == 3
    assert connector.conn.closed is True


def test_land_if_configured_is_noop_without_env() -> None:
    import security_lakehouse.sinks as sinks

    assert sinks.land_if_configured("/lake", {}) is None


def test_land_if_configured_invokes_sink_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    import security_lakehouse.sinks as sinks

    seen: dict[str, object] = {}

    class _FakeSink:
        def __init__(self, config: object) -> None:
            seen["config"] = config

        def load(self, lake_dir: object) -> dict[str, int]:
            seen["lake"] = lake_dir
            return {"NORMALIZED_EVENTS": 5}

    monkeypatch.setattr(sinks, "SnowflakeSink", _FakeSink)
    env = {"SNOWFLAKE_ACCOUNT": "a", "SNOWFLAKE_USER": "u", "SNOWFLAKE_PRIVATE_KEY_FILE": "/k"}
    assert sinks.land_if_configured("/lake", env) == {"snowflake": {"NORMALIZED_EVENTS": 5}}
    assert seen["lake"] == "/lake"


def test_sync_sink_failure_is_swallowed(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    # A sink failure must never fail evidence collection — the local lake is the
    # source of truth, the sink is an optional projection.
    import security_lakehouse.connector_runner as connector_runner

    def boom(*_args: object, **_kwargs: object) -> dict[str, int]:
        raise RuntimeError("warehouse down")

    monkeypatch.setattr(connector_runner, "land_if_configured", boom)
    connector_runner._land_to_sink(Path("/lake"))  # must not raise
    assert "sink load failed" in capsys.readouterr().err


def test_snowflake_source_sync_does_not_infer_snowflake_sink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import security_lakehouse.connector_runner as connector_runner

    seen: dict[str, str] = {}

    def fake_land(_lake: Path, env: dict[str, str]) -> None:
        seen.update(env)
        return None

    monkeypatch.setattr(connector_runner, "land_if_configured", fake_land)
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "source-account")
    monkeypatch.setenv("SNOWFLAKE_USER", "GRC_LAKE_INGEST_SVC")
    monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_FILE", "/run/secrets/key.p8")
    monkeypatch.setenv("GRC_LAKE_DUCKDB_PATH", "/tmp/trustops.duckdb")

    connector_runner._land_to_sink(Path("/lake"), connector_id="snowflake-evidence-lake")

    assert "SNOWFLAKE_ACCOUNT" not in seen
    assert "SNOWFLAKE_USER" not in seen
    assert "SNOWFLAKE_PRIVATE_KEY_FILE" not in seen
    assert seen["GRC_LAKE_DUCKDB_PATH"] == "/tmp/trustops.duckdb"

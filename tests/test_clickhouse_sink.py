"""ClickHouse sink: typed column mapping, delete-then-insert idempotency, load.

The clickhouse_connect client is injected, so the load path runs without a live
ClickHouse.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from security_lakehouse.sinks.clickhouse_sink import (
    TABLE_SPECS,
    ClickHouseSink,
    ClickHouseSinkConfig,
    delete_keys_sql,
    rows_for_spec,
)


def _spec(table: str):
    return next(s for s in TABLE_SPECS if s.table == table)


def test_config_from_env_requires_host_and_defaults_to_secure() -> None:
    assert ClickHouseSinkConfig.from_env({}) is None

    cfg = ClickHouseSinkConfig.from_env(
        {"CLICKHOUSE_HOST": "ch.example.com", "CLICKHOUSE_USER": "trustops_loader", "CLICKHOUSE_PASSWORD": "x"}
    )
    assert cfg is not None
    assert cfg.host == "ch.example.com" and cfg.user == "trustops_loader"
    assert cfg.database == "security"  # default
    assert cfg.secure is True  # TLS by default

    insecure = ClickHouseSinkConfig.from_env({"CLICKHOUSE_HOST": "h", "CLICKHOUSE_SECURE": "false"})
    assert insecure is not None and insecure.secure is False


@pytest.mark.parametrize("database", ["security; DROP TABLE x", "sec-urity", "1security", "security.events", ""])
def test_config_rejects_unsafe_database_identifier(database: str) -> None:
    with pytest.raises(ValueError, match="unsafe ClickHouse identifier"):
        ClickHouseSinkConfig.from_env({"CLICKHOUSE_HOST": "h", "CLICKHOUSE_DATABASE": database or " "})
    with pytest.raises(ValueError, match="unsafe ClickHouse identifier"):
        ClickHouseSinkConfig(host="h", database=database)


def test_delete_keys_sql_rejects_unsafe_database() -> None:
    with pytest.raises(ValueError, match="unsafe ClickHouse identifier"):
        delete_keys_sql(_spec("normalized_events"), "security; DROP TABLE x", [["e1"] * 20])


def test_rows_for_spec_keeps_arrays_native_and_coerces_datetimes(tmp_path: Path) -> None:
    (tmp_path / "silver").mkdir()
    (tmp_path / "silver" / "normalized_events.jsonl").write_text(
        json.dumps(
            {
                "event_id": "e1",
                "control_ids": ["SOC2-CC6.1", "ISO27001-A.5.15"],
                "event_time": "2026-06-27T06:56:14.978184Z",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    spec = _spec("normalized_events")
    rows = rows_for_spec(spec, tmp_path)
    row = rows[0]
    control_ids = row[spec.columns.index("control_ids")]
    event_time = row[spec.columns.index("event_time")]
    # Array stays a native list (no JSON round-trip), timestamp becomes a datetime.
    assert control_ids == ["SOC2-CC6.1", "ISO27001-A.5.15"]
    assert isinstance(event_time, datetime)


def test_rows_for_spec_applies_tenant_default(tmp_path: Path) -> None:
    (tmp_path / "gold").mkdir()
    (tmp_path / "gold" / "control_posture.jsonl").write_text(
        json.dumps({"control_id": "SOC2-CC6.1", "latest_event_time": "2026-06-27T06:56:14Z"}) + "\n",
        encoding="utf-8",
    )
    spec = _spec("control_posture")
    rows = rows_for_spec(spec, tmp_path)
    assert rows[0][spec.columns.index("tenant_id")] == "customer-managed"


def test_delete_keys_sql_single_and_composite_keys() -> None:
    ev = _spec("normalized_events")
    sql = delete_keys_sql(ev, "security", [["e1"] + [None] * (len(ev.columns) - 1)])
    assert sql == "DELETE FROM security.normalized_events WHERE event_id IN ('e1')"

    cp = _spec("control_posture")
    row = [None] * len(cp.columns)
    row[cp.columns.index("tenant_id")] = "t"
    row[cp.columns.index("control_id")] = "SOC2-CC6.1"
    sql = delete_keys_sql(cp, "security", [row])
    assert sql == "DELETE FROM security.control_posture WHERE (tenant_id, control_id) IN (('t', 'SOC2-CC6.1'))"


def test_delete_keys_sql_escapes_quotes() -> None:
    ev = _spec("normalized_events")
    sql = delete_keys_sql(ev, "security", [["o'brien"] + [None] * (len(ev.columns) - 1)])
    assert "o\\'brien" in sql


class _FakeClient:
    def __init__(self) -> None:
        self.commands: list[str] = []
        self.inserts: list[tuple[str, int]] = []

    def command(self, sql: str) -> None:
        self.commands.append(sql)

    def insert(self, table: str, data: list, *, column_names: list, database: str) -> None:  # noqa: ANN001
        self.inserts.append((f"{database}.{table}", len(data)))


def _seed_lake(tmp_path: Path) -> Path:
    (tmp_path / "silver").mkdir()
    (tmp_path / "gold").mkdir()
    (tmp_path / "silver" / "normalized_events.jsonl").write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {"event_id": "aws-1", "control_ids": ["SOC2-CC6.1"], "event_time": "2026-06-27T06:56:14Z"},
                {"event_id": "azure-1", "control_ids": [], "event_time": "2026-06-27T06:56:14Z"},
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "gold" / "control_posture.jsonl").write_text(
        json.dumps({"control_id": "SOC2-CC6.1", "latest_event_time": "2026-06-27T06:56:14Z"}) + "\n",
        encoding="utf-8",
    )
    (tmp_path / "gold" / "asset_risk.jsonl").write_text(
        json.dumps({"asset_id": "aws:account:1", "latest_event_time": "2026-06-27T06:56:14Z"}) + "\n",
        encoding="utf-8",
    )
    return tmp_path


def test_load_deletes_then_inserts_each_table(tmp_path: Path) -> None:
    lake = _seed_lake(tmp_path)
    client = _FakeClient()
    cfg = ClickHouseSinkConfig(host="ch", user="trustops_loader", password="x", database="security")
    sink = ClickHouseSink(cfg, client=client)

    landed = sink.load(lake)

    assert landed == {"normalized_events": 2, "control_posture": 1, "asset_risk": 1}
    # Every table did a delete-then-insert (idempotent upsert).
    assert all(c.startswith("DELETE FROM security.") for c in client.commands)
    assert len(client.commands) == 3
    assert ("security.normalized_events", 2) in client.inserts
    assert ("security.control_posture", 1) in client.inserts


def test_load_is_noop_safe_on_empty_lake(tmp_path: Path) -> None:
    client = _FakeClient()
    sink = ClickHouseSink(ClickHouseSinkConfig(host="ch"), client=client)
    landed = sink.load(tmp_path)
    assert landed == {"normalized_events": 0, "control_posture": 0, "asset_risk": 0}
    assert client.commands == [] and client.inserts == []


def test_land_if_configured_routes_to_clickhouse(monkeypatch: pytest.MonkeyPatch) -> None:
    import security_lakehouse.sinks as sinks

    class _FakeCHSink:
        def __init__(self, config: object) -> None:
            self._config = config

        def load(self, lake_dir: object) -> dict[str, int]:
            return {"control_posture": 3}

    monkeypatch.setattr(sinks, "ClickHouseSink", _FakeCHSink)
    out = sinks.land_if_configured("/lake", {"CLICKHOUSE_HOST": "ch.example.com"})
    assert out == {"clickhouse": {"control_posture": 3}}

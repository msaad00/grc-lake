"""Declarative lake mapping: spec validation, row mapping, and safe SQL compilation."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from security_lakehouse import lake_mapping
from security_lakehouse.lake_mapping import (
    MappingError,
    compile_select,
    load_mapping_file,
    map_rows,
    parse_mapping,
    resolve_mappings,
)
from security_lakehouse.validation import validate_raw_events

COLLECTED = datetime(2026, 9, 1, tzinfo=UTC)


def _spec(**overrides: Any) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "spec_version": 1,
        "name": "okta_auth",
        "source": {"table": "security.okta_events"},
        "fields": {
            "id": {"column": "uuid"},
            "observed_at": {"column": "published", "format": "timestamp"},
            "source": {"const": "okta"},
            "event_type": {"column": "event_type", "prefix": "okta."},
            "asset_id": {"coalesce": [{"column": "target.id"}, {"const": "okta:org"}]},
            "asset_type": {"const": "identity"},
            "owner": {"column": "actor.alternate_id"},
            "severity": {"column": "outcome.result", "map": {"FAILURE": "medium"}, "default": "info"},
            "status": {"column": "outcome.result", "map": {"SUCCESS": "pass", "FAILURE": "open"}},
            "controls": {"const": ["SOC2-CC6.1"]},
        },
        "attributes": {"actor": {"column": "actor.alternate_id"}, "ip": {"column": "client.ip"}},
    }
    for key, value in overrides.items():
        spec[key] = value
    return spec


ROW = {
    "uuid": "evt-1",
    "published": "2026-08-30T10:00:00Z",
    "event_type": "user.session.start",
    "target": {"id": "00u1"},
    "actor": {"alternate_id": "alice@example.com"},
    "outcome": {"result": "FAILURE"},
    "client": {"ip": "203.0.113.9"},
}


def test_valid_spec_maps_a_row_to_a_valid_raw_event() -> None:
    spec = parse_mapping(_spec())
    result = map_rows(spec, [ROW], collected_at=COLLECTED, tenant_id="acme")
    assert result.errors == []
    [event] = result.events
    assert validate_raw_events([event]) == []
    assert event["tenant_id"] == "acme"
    assert event["event_time"] == "2026-08-30T10:00:00Z"
    assert event["source"] == "okta"
    assert event["event_type"] == "okta.user.session.start"
    assert event["entity"]["asset_id"] == "00u1"
    assert event["entity"]["asset_type"] == "identity"
    assert event["entity"]["asset_owner"] == "alice@example.com"
    assert event["severity"] == "medium"
    assert event["status"] == "open"
    assert event["controls"] == ["SOC2-CC6.1"]
    assert event["attributes"]["actor"] == "alice@example.com"
    assert event["attributes"]["ip"] == "203.0.113.9"
    assert event["attributes"]["mapping"] == "okta_auth"
    assert event["attributes"]["source_table"] == "security.okta_events"
    # raw hash covers the whole source row, canonically serialized
    assert len(event["attributes"]["raw_sha256"]) == 64
    assert event["evidence"]["evidence_collected_at"] == "2026-09-01T00:00:00Z"


def test_event_id_is_stable_and_scoped_to_mapping_and_source() -> None:
    spec = parse_mapping(_spec())
    first = map_rows(spec, [ROW], collected_at=COLLECTED).events[0]["event_id"]
    again = map_rows(spec, [dict(ROW, client={"ip": "198.51.100.1"})], collected_at=COLLECTED).events[0]["event_id"]
    other = map_rows(parse_mapping(_spec(name="okta_other")), [ROW], collected_at=COLLECTED).events[0]["event_id"]
    assert first == again
    assert first != other
    assert first.startswith("okta-okta_auth-")


def test_raw_hash_changes_when_source_row_changes() -> None:
    spec = parse_mapping(_spec())
    a = map_rows(spec, [ROW]).events[0]["attributes"]["raw_sha256"]
    b = map_rows(spec, [dict(ROW, client={"ip": "198.51.100.1"})]).events[0]["attributes"]["raw_sha256"]
    assert a != b


def test_composite_id_uses_every_column() -> None:
    fields = dict(_spec()["fields"], id={"columns": ["uuid", "target.id"]})
    spec = parse_mapping(_spec(fields=fields))
    a = map_rows(spec, [ROW]).events[0]["event_id"]
    b = map_rows(spec, [dict(ROW, target={"id": "00u2"})]).events[0]["event_id"]
    assert a != b


def test_epoch_ms_observed_time_and_json_string_structs() -> None:
    fields = dict(_spec()["fields"], observed_at={"column": "time", "format": "epoch_ms"})
    spec = parse_mapping(_spec(fields=fields))
    # Snowflake VARIANT / Databricks STRUCT columns arrive as JSON text.
    row = dict(ROW, time=1756548000000, actor=json.dumps({"alternate_id": "bob@example.com"}))
    [event] = map_rows(spec, [row]).events
    assert event["event_time"] == "2025-08-30T10:00:00Z"
    assert event["entity"]["asset_owner"] == "bob@example.com"


def test_array_index_paths_and_case_insensitive_top_level_columns() -> None:
    fields = dict(_spec()["fields"], asset_id={"column": "resources[0].uid"})
    spec = parse_mapping(_spec(fields=fields))
    row = {k.upper(): v for k, v in ROW.items()}
    row["RESOURCES"] = [{"uid": "arn:aws:s3:::bucket"}]
    [event] = map_rows(spec, [row]).events
    assert event["entity"]["asset_id"] == "arn:aws:s3:::bucket"


def test_rows_missing_id_or_time_are_reported_not_fabricated() -> None:
    spec = parse_mapping(_spec())
    result = map_rows(spec, [ROW, {**ROW, "uuid": None}, {**ROW, "published": "not-a-time"}])
    assert len(result.events) == 1
    assert [error["row"] for error in result.errors] == [2, 3]
    assert "fields.id" in result.errors[0]["error"]
    assert "fields.observed_at" in result.errors[1]["error"]


def test_filters_are_applied_to_rows() -> None:
    spec = parse_mapping(_spec(filters=[{"column": "event_type", "op": "in", "value": ["user.session.start"]}]))
    result = map_rows(spec, [ROW, dict(ROW, uuid="evt-2", event_type="user.lifecycle.create")])
    assert [e["attributes"]["mapping"] for e in result.events] == ["okta_auth"]
    assert result.filtered == 1


def test_since_bound_is_applied_to_rows_with_lookback() -> None:
    spec = parse_mapping(_spec(source={"table": "security.okta_events", "lookback_minutes": 60}))
    old = dict(ROW, uuid="old", published="2026-08-30T08:00:00Z")
    inside_lookback = dict(ROW, uuid="late", published="2026-08-30T09:30:00Z")
    result = map_rows(spec, [old, inside_lookback, ROW], since="2026-08-30T10:00:00Z")
    assert sorted(e["attributes"]["source_id"] for e in result.events) == ["evt-1", "late"]


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda s: s.pop("fields"), "fields: required"),
        (lambda s: s.update(spec_version=2), "spec_version: must be 1"),
        (lambda s: s.update(name="bad name!"), "name:"),
        (lambda s: s.update(unknown=1), "unknown: unexpected key"),
        (lambda s: s["source"].update(table="security.okta; DROP TABLE x"), "source.table:"),
        (lambda s: s["source"].update(table="a.b.c.d"), "source.table:"),
        (lambda s: s["fields"].pop("id"), "fields.id: required"),
        (lambda s: s["fields"].pop("asset_id"), "fields.asset_id: required"),
        (lambda s: s["fields"].update(id={"column": "uuid || 'x'"}), "fields.id.column:"),
        (lambda s: s["fields"].update(id={"sql": "1"}), "fields.id.sql: unexpected key"),
        (lambda s: s["fields"].update(severity={"column": "x", "map": {"a": "urgent"}}), "fields.severity.map.a:"),
        (lambda s: s["fields"].update(status={"const": "done"}), "fields.status.const:"),
        (lambda s: s["fields"].update(observed_at={"column": "t", "format": "weird"}), "fields.observed_at.format:"),
        (lambda s: s["fields"].update(observed_at={"const": "2026-01-01"}), "fields.observed_at: must be"),
        (lambda s: s["fields"].update(asset_id={"column": "a", "const": "b"}), "fields.asset_id: exactly one of"),
        (lambda s: s.update(filters=[{"column": "a", "op": "like", "value": "%"}]), "filters[0].op:"),
        (lambda s: s.update(filters=[{"column": "a", "op": "eq", "value": {"x": 1}}]), "filters[0].value:"),
        (lambda s: s.update(filters=[{"column": "a.b", "op": "eq", "value": 1}]), "filters[0].column:"),
        (lambda s: s.update(attributes={"bad key": {"column": "a"}}), "attributes.bad key:"),
        (lambda s: s["source"].update(lookback_minutes=-1), "source.lookback_minutes:"),
    ],
)
def test_invalid_specs_fail_with_path_scoped_errors(mutate: Any, expected: str) -> None:
    spec = _spec()
    mutate(spec)
    with pytest.raises(MappingError) as info:
        parse_mapping(spec)
    assert any(expected in message for message in info.value.errors), info.value.errors


def test_all_errors_are_reported_together() -> None:
    spec = _spec(spec_version=9, name="")
    spec["fields"].pop("id")
    with pytest.raises(MappingError) as info:
        parse_mapping(spec)
    assert len(info.value.errors) >= 3
    assert "spec_version" in str(info.value)


# --- SQL compilation --------------------------------------------------------------


def test_snowflake_compile_selects_top_level_columns_and_binds_values() -> None:
    spec = parse_mapping(_spec(filters=[{"column": "event_type", "op": "in", "value": ["a", "b"]}]))
    query = compile_select(spec, "snowflake", since="2026-08-30T10:00:00Z", limit=10)
    assert query.sql.startswith("SELECT ")
    for column in ("uuid", "published", "event_type", "target", "actor", "outcome", "client"):
        assert column in query.sql
    assert "FROM security.okta_events" in query.sql
    assert "event_type IN (%(p0)s, %(p1)s)" in query.sql
    assert "published >= TO_TIMESTAMP_TZ(%(since)s)" in query.sql
    assert query.sql.endswith("ORDER BY published LIMIT 10")
    assert query.params == {"p0": "a", "p1": "b", "since": "2026-08-30T10:00:00Z"}
    # values never appear in the SQL text
    assert "'a'" not in query.sql and "2026-08-30" not in query.sql


def test_databricks_compile_uses_backticks_and_named_markers() -> None:
    spec = parse_mapping(_spec(filters=[{"column": "class_uid", "op": "eq", "value": 3002}]))
    query = compile_select(spec, "databricks", since="2026-08-30T10:00:00Z", default_namespace=("main", "sec"))
    assert "FROM `security`.`okta_events`" in query.sql
    assert "`class_uid` = :p0" in query.sql
    assert "`published` >= CAST(:since AS TIMESTAMP)" in query.sql
    assert query.databricks_parameters() == [
        {"name": "p0", "value": "3002", "type": "BIGINT"},
        {"name": "since", "value": "2026-08-30T10:00:00Z", "type": "STRING"},
    ]


def test_databricks_single_part_table_is_qualified_with_catalog_and_schema() -> None:
    spec = parse_mapping(_spec(source={"table": "okta_events"}))
    query = compile_select(spec, "databricks", default_namespace=("main", "sec"))
    assert "FROM `main`.`sec`.`okta_events`" in query.sql


def test_clickhouse_compile_uses_typed_placeholders() -> None:
    fields = dict(_spec()["fields"], observed_at={"column": "time", "format": "epoch_ms"})
    spec = parse_mapping(_spec(fields=fields, filters=[{"column": "class_uid", "op": "ne", "value": 1}]))
    query = compile_select(spec, "clickhouse", since="2026-08-30T10:00:00Z", default_namespace=("security",))
    assert "FROM security.okta_events" in query.sql
    assert "class_uid != {p0:Int64}" in query.sql
    assert "time >= {since:Int64}" in query.sql
    assert query.params == {"p0": 1, "since": 1788084000000}
    assert query.sql.endswith("FORMAT JSONEachRow")


def test_bigquery_compile_allows_project_hyphen_and_uses_at_params() -> None:
    spec = parse_mapping(_spec(source={"table": "my-proj.security.okta_events"}))
    query = compile_select(spec, "bigquery", since="2026-08-30T10:00:00Z", limit=5)
    assert "FROM `my-proj`.`security`.`okta_events`" in query.sql
    assert "`published` >= @since" in query.sql
    assert query.bigquery_parameters() == [("since", "TIMESTAMP", datetime(2026, 8, 30, 10, tzinfo=UTC))]


def test_hyphenated_table_is_rejected_outside_bigquery_project_position() -> None:
    spec = parse_mapping(_spec(source={"table": "my-proj.security.okta_events"}))
    with pytest.raises(MappingError):
        compile_select(spec, "snowflake")
    with pytest.raises(MappingError):
        compile_select(parse_mapping(_spec(source={"table": "sec.okta-events"})), "bigquery")


def test_incremental_false_never_binds_a_watermark() -> None:
    spec = parse_mapping(_spec(source={"table": "security.okta_events", "incremental": False}))
    query = compile_select(spec, "snowflake", since="2026-08-30T10:00:00Z")
    assert "since" not in query.params
    assert "WHERE" not in query.sql


def test_lookback_is_subtracted_from_the_bound_parameter() -> None:
    spec = parse_mapping(_spec(source={"table": "security.okta_events", "lookback_minutes": 30}))
    query = compile_select(spec, "snowflake", since="2026-08-30T10:00:00Z")
    assert query.params["since"] == "2026-08-30T09:30:00Z"


def test_malicious_since_is_bound_not_spliced() -> None:
    spec = parse_mapping(_spec())
    with pytest.raises(ValueError):
        compile_select(spec, "snowflake", since="2026-01-01'; DROP TABLE x; --")


# --- resolution ------------------------------------------------------------------


def test_resolve_accepts_inline_and_list_forms() -> None:
    inline = resolve_mappings({"mapping": _spec()})
    assert [m.name for m in inline] == ["okta_auth"]
    both = resolve_mappings({"mappings": [_spec(), _spec(name="okta_other")]})
    assert [m.name for m in both] == ["okta_auth", "okta_other"]
    assert resolve_mappings({}) == []


def test_resolve_rejects_file_paths_from_connector_options() -> None:
    with pytest.raises(MappingError):
        resolve_mappings({"mapping": "/etc/passwd"})


def test_resolve_rejects_unknown_preset_and_duplicate_names() -> None:
    with pytest.raises(MappingError, match="unknown preset"):
        resolve_mappings({"mapping": {"preset": "ocsf/nope", "source": {"table": "t"}}})
    with pytest.raises(MappingError, match="duplicate mapping name"):
        resolve_mappings({"mappings": [_spec(), _spec()]})


def test_load_mapping_file_reads_json_and_yaml(tmp_path: Path) -> None:
    path = tmp_path / "m.json"
    path.write_text(json.dumps(_spec()), encoding="utf-8")
    assert load_mapping_file(path).name == "okta_auth"
    yaml = pytest.importorskip("yaml")
    ypath = tmp_path / "m.yaml"
    ypath.write_text(yaml.safe_dump(_spec()), encoding="utf-8")
    assert load_mapping_file(ypath).name == "okta_auth"


def test_load_mapping_file_rejects_oversized_specs(tmp_path: Path) -> None:
    path = tmp_path / "big.json"
    path.write_text(" " * (lake_mapping.MAX_SPEC_BYTES + 1), encoding="utf-8")
    with pytest.raises(MappingError, match="larger than"):
        load_mapping_file(path)


def test_write_mode_is_append_when_every_mapping_is_incremental() -> None:
    assert lake_mapping.write_mode_for_options({"mapping": _spec()}) == "append"
    snapshot = _spec(source={"table": "t", "incremental": False})
    assert lake_mapping.write_mode_for_options({"mapping": snapshot}) == "snapshot"
    assert lake_mapping.write_mode_for_options({}) is None

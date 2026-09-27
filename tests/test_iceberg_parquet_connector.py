"""Iceberg / Parquet lake reader (preview): real local Iceberg + Parquet scans, no cloud."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import security_lakehouse.connector_runner as connector_runner
from security_lakehouse import connectors_iceberg as ice
from security_lakehouse.connector_state import append_config_event, configure_payload_error
from security_lakehouse.connectors import load_connector_catalog, validate_connector_catalog
from security_lakehouse.io import read_jsonl
from security_lakehouse.lake_mapping import resolve_mapping_ref
from security_lakehouse.validation import validate_raw_events

pa = pytest.importorskip("pyarrow")
OCSF = Path(__file__).parent / "fixtures" / "ocsf"

SCHEMA = pa.schema(
    [
        ("time", pa.int64()),
        ("time_dt", pa.timestamp("us", tz="UTC")),
        ("class_uid", pa.int32()),
        ("severity_id", pa.int32()),
        ("status", pa.string()),
        (
            "metadata",
            pa.struct(
                [("uid", pa.string()), ("version", pa.string()), ("product", pa.struct([("name", pa.string())]))]
            ),
        ),
        ("api", pa.struct([("operation", pa.string()), ("service", pa.struct([("name", pa.string())]))])),
        ("resources", pa.list_(pa.struct([("uid", pa.string()), ("type", pa.string())]))),
        ("cloud", pa.struct([("region", pa.string()), ("account", pa.struct([("uid", pa.string())]))])),
    ]
)


def _row(uid: str, day: int, class_uid: int = 6003, op: str = "PutBucketPolicy") -> dict[str, Any]:
    when = datetime(2026, 9, day, 12, tzinfo=UTC)
    return {
        "time": int(when.timestamp() * 1000),
        "time_dt": when,
        "class_uid": class_uid,
        "severity_id": 1,
        "status": "Success",
        "metadata": {"uid": uid, "version": "1.1.0", "product": {"name": "CloudTrail"}},
        "api": {"operation": op, "service": {"name": "s3.amazonaws.com"}},
        "resources": [{"uid": f"arn:aws:s3:::bucket-{uid}", "type": "AWS::S3::Bucket"}],
        "cloud": {"region": "us-east-1", "account": {"uid": "111122223333"}},
    }


ROWS = [_row("a", 20), _row("b", 22), _row("c", 23, class_uid=3002), _row("d", 21)]


@pytest.fixture
def sql_catalog(tmp_path: Path) -> Any:
    pytest.importorskip("pyiceberg")
    from pyiceberg.catalog.sql import SqlCatalog

    catalog = SqlCatalog("test", uri=f"sqlite:///{tmp_path}/catalog.db", warehouse=f"file://{tmp_path}/warehouse")
    catalog.create_namespace("sec")
    table = catalog.create_table("sec.cloud_trail_mgmt", schema=SCHEMA)
    table.append(pa.Table.from_pylist(ROWS, schema=SCHEMA))
    return catalog


def _api_spec(table: str = "sec.cloud_trail_mgmt", **source: Any) -> Any:
    return resolve_mapping_ref({"preset": "ocsf/api_activity", "source": {"table": table, **source}})


# --- Iceberg ---------------------------------------------------------------------


def test_iceberg_reader_pushes_filters_and_watermark_and_orders_rows(sql_catalog: Any) -> None:
    reader = ice.IcebergCatalogReader(sql_catalog)
    spec = _api_spec(lookback_minutes=0)
    rows = reader.fetch_mapping_rows(spec, since="2026-09-21T00:00:00Z", limit=10)
    # class 3002 is filtered by class_uid, day 20 by the watermark; order is by time_dt
    assert [row["metadata"]["uid"] for row in rows] == ["d", "b"]
    assert rows[0]["time_dt"] == "2026-09-21T12:00:00Z"


def test_iceberg_reader_limit_keeps_the_oldest_rows(sql_catalog: Any) -> None:
    rows = ice.IcebergCatalogReader(sql_catalog).fetch_mapping_rows(_api_spec(), since=None, limit=2)
    assert [row["metadata"]["uid"] for row in rows] == ["a", "d"]


def test_iceberg_reader_tolerates_columns_the_table_lacks(sql_catalog: Any) -> None:
    # api_activity also reads actor and src_endpoint, which this table does not have
    spec = _api_spec()
    assert "actor" in spec.top_level_columns()
    rows = ice.IcebergCatalogReader(sql_catalog).fetch_mapping_rows(spec, since=None, limit=10)
    assert "actor" not in rows[0]


def test_iceberg_reader_requires_the_watermark_column(sql_catalog: Any) -> None:
    spec = resolve_mapping_ref(
        {
            "preset": "ocsf/api_activity",
            "source": {"table": "sec.cloud_trail_mgmt"},
            "fields": {"observed_at": {"column": "event_time", "format": "timestamp"}},
        }
    )
    with pytest.raises(ValueError, match="event_time"):
        ice.IcebergCatalogReader(sql_catalog).fetch_mapping_rows(spec, since=None, limit=10)


def test_iceberg_reader_applies_the_initial_window_on_the_first_sync(sql_catalog: Any) -> None:
    reader = ice.IcebergCatalogReader(sql_catalog, initial_window_days=2, now=lambda: datetime(2026, 9, 23, tzinfo=UTC))
    rows = reader.fetch_mapping_rows(_api_spec(), since=None, limit=10)
    assert [row["metadata"]["uid"] for row in rows] == ["d", "b"]


def test_iceberg_sync_end_to_end_through_the_mapping_layer(sql_catalog: Any) -> None:
    events = ice.collect_iceberg_evidence(
        ice.IcebergCatalogReader(sql_catalog), [_api_spec()], since=None, collected_at=datetime(2026, 9, 24, tzinfo=UTC)
    )
    assert validate_raw_events(events) == []
    assert sorted(event["attributes"]["api_operation"] for event in events) == ["PutBucketPolicy"] * 3
    assert {event["source"] for event in events} == {"CloudTrail"}


# --- Parquet -------------------------------------------------------------------------


def _write_partitioned(root: Path) -> Path:
    import pyarrow.dataset as ds

    dataset_root = root / "ocsf_api"
    table = pa.Table.from_pylist(
        [dict(r, region="us-east-1") for r in ROWS], schema=SCHEMA.append(pa.field("region", pa.string()))
    )
    ds.write_dataset(table, dataset_root, format="parquet", partitioning=["region"], partitioning_flavor="hive")
    return dataset_root


def test_parquet_reader_reads_a_local_hive_dataset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dataset_root = _write_partitioned(tmp_path)
    monkeypatch.setenv(ice.LOCAL_ROOT_ENV, str(tmp_path))
    spec = resolve_mapping_ref(
        {
            "preset": "ocsf/api_activity",
            "source": {"table": "ocsf_api", "lookback_minutes": 0},
            "fields": {"observed_at": {"column": "time", "format": "epoch_ms"}},
            # the Hive partition column is filterable like any other column
            "filters": [
                {"column": "class_uid", "op": "eq", "value": 6003},
                {"column": "region", "op": "eq", "value": "us-east-1"},
            ],
        }
    )
    reader = ice.ParquetDatasetReader({"ocsf_api": str(dataset_root)})
    rows = reader.fetch_mapping_rows(spec, since="2026-09-21T00:00:00Z", limit=10)
    assert [row["metadata"]["uid"] for row in rows] == ["d", "b"]
    assert rows[0]["region"] == "us-east-1"
    other_region = resolve_mapping_ref(
        {
            "preset": "ocsf/api_activity",
            "source": {"table": "ocsf_api"},
            "filters": [{"column": "region", "op": "eq", "value": "eu-west-1"}],
        }
    )
    assert reader.fetch_mapping_rows(other_region, since=None, limit=10) == []


def test_parquet_local_paths_need_an_explicit_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dataset_root = _write_partitioned(tmp_path)
    monkeypatch.delenv(ice.LOCAL_ROOT_ENV, raising=False)
    with pytest.raises(ValueError, match=ice.LOCAL_ROOT_ENV):
        ice.ParquetDatasetReader({"ocsf_api": str(dataset_root)})
    monkeypatch.setenv(ice.LOCAL_ROOT_ENV, str(tmp_path / "elsewhere"))
    with pytest.raises(ValueError, match="outside"):
        ice.ParquetDatasetReader({"ocsf_api": str(dataset_root)})
    with pytest.raises(ValueError, match="outside"):
        ice.ParquetDatasetReader({"ocsf_api": str(tmp_path / "elsewhere" / ".." / "ocsf_api")})


@pytest.mark.parametrize(
    "uri",
    [
        "http://example.com/data",
        "gs://bucket/x",
        "s3://Bad_Bucket/x",
        "s3://ok-bucket/../x",
        "file:///etc",
        "relative/dir",
    ],
)
def test_parquet_rejects_unsupported_or_unsafe_locations(
    uri: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(ice.LOCAL_ROOT_ENV, str(tmp_path))
    with pytest.raises(ValueError):
        ice.ParquetDatasetReader({"t": uri})


def test_parquet_reader_without_a_path_for_the_table_fails_clearly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ice.LOCAL_ROOT_ENV, str(tmp_path))
    reader = ice.ParquetDatasetReader({"other": str(tmp_path)})
    with pytest.raises(ValueError, match="no Parquet path"):
        reader.fetch_mapping_rows(_api_spec("ocsf_api"), since=None, limit=1)


# --- catalogs --------------------------------------------------------------------------


def test_rest_catalog_uri_must_be_public_https(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTOPS_ICEBERG_TOKEN", "tok")
    with pytest.raises(ValueError, match="SSRF|non-public"):
        ice.build_reader({"catalog_type": "rest", "uri": "https://10.0.0.8/api/catalog", "warehouse": "w"}, {}, env={})
    with pytest.raises(ValueError):
        ice.build_reader({"catalog_type": "rest", "uri": "http://catalog.example.com", "warehouse": "w"}, {}, env={})


def test_glue_catalog_uses_assumed_role_and_pins_file_io(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("pyiceberg")
    calls: dict[str, Any] = {}

    class FakeSTS:
        def assume_role(self, **kwargs: Any) -> dict[str, Any]:
            calls["assume_role"] = kwargs
            return {"Credentials": {"AccessKeyId": "AK", "SecretAccessKey": "SK", "SessionToken": "ST"}}

    class FakeSession:
        def __init__(self, **kwargs: Any) -> None:
            calls.setdefault("sessions", []).append(kwargs)

        def client(self, name: str, **kwargs: Any) -> Any:
            return FakeSTS() if name == "sts" else object()

    import boto3

    monkeypatch.setattr(boto3, "Session", FakeSession)
    catalog = ice.glue_catalog(
        region="us-east-1", role_arn="arn:aws:iam::111122223333:role/trustops-lake-reader", external_id="ext-1"
    )
    assert calls["assume_role"]["RoleArn"].endswith("role/trustops-lake-reader")
    assert calls["assume_role"]["ExternalId"] == "ext-1"
    assert catalog.properties["s3.access-key-id"] == "AK"
    assert catalog.properties["s3.region"] == "us-east-1"
    io = catalog._load_file_io({"s3.endpoint": "https://attacker.example", "py-io-impl": "evil.Module"})
    assert type(io).__name__ == "PyArrowFileIO"
    assert "s3.endpoint" not in io.properties


@pytest.mark.parametrize(
    ("credentials", "message"),
    [
        ({"catalog_type": "glue", "region": "us-east-1", "role_arn": "not-an-arn"}, "role_arn"),
        ({"catalog_type": "glue", "region": "moon-1"}, "region"),
        ({"catalog_type": "glue", "region": "us-east-1", "catalog_id": "12"}, "catalog_id"),
        ({"catalog_type": "nope"}, "catalog_type"),
    ],
)
def test_build_reader_validates_identity_fields(credentials: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        ice.build_reader(credentials, {}, env={})


# --- Security Lake defaults ---------------------------------------------------------------


def test_glue_without_mappings_defaults_to_security_lake_ocsf_presets() -> None:
    specs = ice.resolve_iceberg_mappings({"catalog_type": "glue", "region": "eu-west-2"}, {})
    tables = {spec.source_table for spec in specs}
    assert tables == {
        "amazon_security_lake_glue_db_eu_west_2.amazon_security_lake_table_eu_west_2_cloud_trail_mgmt_2_0",
        "amazon_security_lake_glue_db_eu_west_2.amazon_security_lake_table_eu_west_2_sh_findings_2_0",
    }
    assert {spec.preset for spec in specs} == {
        "ocsf/authentication",
        "ocsf/account_change",
        "ocsf/api_activity",
        "ocsf/detection_finding",
        "ocsf/vulnerability_finding",
        "ocsf/compliance_finding",
    }
    only = ice.resolve_iceberg_mappings(
        {"catalog_type": "glue", "region": "eu-west-2"}, {"security_lake_sources": ["sh_findings"]}
    )
    assert {spec.preset for spec in only} == {
        "ocsf/detection_finding",
        "ocsf/vulnerability_finding",
        "ocsf/compliance_finding",
    }
    from_console = ice.resolve_iceberg_mappings(
        {"catalog_type": "glue", "region": "eu-west-2"}, {"security_lake_sources": " sh_findings , cloud_trail_mgmt"}
    )
    assert len(from_console) == 6
    with pytest.raises(ValueError, match="security_lake_sources"):
        ice.resolve_iceberg_mappings({"catalog_type": "glue", "region": "eu-west-2"}, {"security_lake_sources": ["x"]})


def test_explicit_mappings_win_and_non_glue_needs_one() -> None:
    explicit = {"mapping": {"preset": "ocsf/api_activity", "source": {"table": "sec.ct"}}}
    specs = ice.resolve_iceberg_mappings({"catalog_type": "glue", "region": "us-east-1"}, explicit)
    assert [spec.source_table for spec in specs] == ["sec.ct"]
    with pytest.raises(ValueError, match="options.mapping"):
        ice.resolve_iceberg_mappings({"catalog_type": "parquet", "path": "s3://b/p"}, {})


# --- catalog, registry, runner -------------------------------------------------------------


def test_catalog_row_is_valid_preview_and_registered() -> None:
    assert validate_connector_catalog() == []
    row = load_connector_catalog()[ice.CONNECTOR_ID]
    assert row["collection_mode"] == "existing_lake_read"
    assert row["data_shape"] == "event_log"
    assert row["release_stage"] == "preview"
    assert ice.CONNECTOR_ID in connector_runner.REGISTRY


@pytest.mark.parametrize(
    ("credentials", "options", "missing"),
    [
        ({}, {}, "catalog_type"),
        ({"catalog_type": "glue"}, {}, "region"),
        (
            {"catalog_type": "rest", "uri": "https://c.example.com"},
            {"mapping": {"preset": "ocsf/api_activity"}},
            "warehouse",
        ),
        ({"catalog_type": "rest", "uri": "https://c.example.com", "warehouse": "w"}, {}, "mapping"),
        ({"catalog_type": "parquet"}, {"mapping": {"preset": "ocsf/api_activity", "source": {"table": "t"}}}, "path"),
    ],
)
def test_enablement_reports_missing_fields(credentials: dict[str, Any], options: dict[str, Any], missing: str) -> None:
    error = configure_payload_error(
        connector_id=ice.CONNECTOR_ID, state="enabled", credentials=credentials, options=options
    )
    assert error is not None and missing in error


def test_glue_security_lake_enablement_needs_only_the_region() -> None:
    assert (
        configure_payload_error(
            connector_id=ice.CONNECTOR_ID,
            state="enabled",
            credentials={"catalog_type": "glue", "region": "us-east-1"},
            options={},
        )
        is None
    )


def test_fixture_sync_through_the_runner_uses_security_lake_defaults(tmp_path: Path) -> None:
    fixtures = tmp_path / "fx"
    fixtures.mkdir()
    region_db = "amazon_security_lake_glue_db_us_east_1"
    for source in ("cloud_trail_mgmt", "sh_findings"):
        table = f"{region_db}.amazon_security_lake_table_us_east_1_{source}_2_0"
        rows = json.loads((OCSF / f"{source}_2_0.json").read_text(encoding="utf-8"))
        (fixtures / f"{table}.json").write_text(json.dumps(rows), encoding="utf-8")
    lake = tmp_path / "lake"
    append_config_event(
        lake,
        connector_id=ice.CONNECTOR_ID,
        state="enabled",
        actor="t",
        credentials={"catalog_type": "glue", "region": "us-east-1"},
    )
    result = connector_runner.run_connector_sync(
        lake, connector_id=ice.CONNECTOR_ID, fixture_dir=fixtures, materialize=False
    )
    raw = read_jsonl(lake / connector_runner.CONNECTOR_RAW_FILE)
    assert result.evidence_count == 7
    assert validate_raw_events(raw) == []
    assert {row["event_type"] for row in raw} == {
        "ocsf.authentication",
        "ocsf.account_change",
        "ocsf.api_activity",
        "ocsf.detection_finding",
        "ocsf.vulnerability_finding",
        "ocsf.compliance_finding",
    }
    assert result.watermark_cursor == "2026-09-21T14:07:00Z"

"""Remote Iceberg catalogs and table metadata cannot steer storage I/O.

A REST catalog's config/table responses and a Glue table's parameters are
controlled by whoever runs the catalog. They must not be able to point the
reader at an internal endpoint (SSRF), a proxy, a signer, a custom FileIO or
retry class, or a local file on the GRC Lake host.
"""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("pyiceberg")

from pyiceberg.io.pyarrow import PyArrowFileIO

from security_lakehouse import connectors_iceberg as ice
from security_lakehouse import iceberg_export
from security_lakehouse.execution_mode import COMMERCIAL_HOSTED_ENV, server_execution

HOSTILE_PROPERTIES = {
    "s3.endpoint": "http://169.254.169.254",
    "s3.proxy-uri": "http://10.0.0.5:3128",
    "s3.signer": "S3V4RestSigner",
    "s3.signer.uri": "http://10.0.0.5",
    "s3.retry-strategy-impl": "os.system",
    "s3.role-arn": "arn:aws:iam::111122223333:role/server",
    "s3.anonymous": "true",
    "s3.resolve-region": "true",
    "client.role-arn": "arn:aws:iam::111122223333:role/server",
    "py-io-impl": "evil.FileIO",
    "gcs.service.host": "http://10.0.0.5",
    "hdfs.host": "10.0.0.5",
    "DEFAULT_SCHEME": "file",
    "adls.account-key": "x",
}
VENDED = {
    "s3.access-key-id": "AK",
    "s3.secret-access-key": "SK",
    "s3.session-token": "ST",
    "s3.region": "us-east-1",
    "client.region": "us-east-1",
}


def test_storage_properties_keep_only_vended_credentials() -> None:
    filtered = iceberg_export.storage_properties({**HOSTILE_PROPERTIES, **VENDED})
    assert filtered == VENDED


@pytest.fixture(autouse=True)
def _no_hosted_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(COMMERCIAL_HOSTED_ENV, raising=False)


LOCAL_LOCATIONS = ["file:///etc/passwd", "/etc/passwd", "relative/metadata.json"]
REMOTE_NON_OBJECT_STORE = [
    "http://169.254.169.254/latest/meta-data",
    "https://attacker.example/x.parquet",
    "hdfs://10.0.0.5/x",
    "gs://bucket/x",
    "abfss://c@acct.dfs.core.windows.net/x",
    "oss://bucket/x",
]


@pytest.mark.parametrize("location", REMOTE_NON_OBJECT_STORE)
def test_guarded_file_io_rejects_non_object_store_schemes_in_every_mode(location: str) -> None:
    for io in (iceberg_export.guarded_file_io(VENDED), _server_io(VENDED)):
        with pytest.raises(iceberg_export.IcebergPublicationError, match="storage location"):
            io.new_input(location)
        with pytest.raises(iceberg_export.IcebergPublicationError, match="storage location"):
            io.new_output(location)


@pytest.mark.parametrize("location", LOCAL_LOCATIONS)
def test_guarded_file_io_refuses_local_files_in_server_mode(location: str) -> None:
    io = _server_io(VENDED)
    with pytest.raises(iceberg_export.IcebergPublicationError, match="storage location"):
        io.new_input(location)
    with pytest.raises(iceberg_export.IcebergPublicationError, match="storage location"):
        io.new_output(location)


def test_guarded_file_io_allows_a_local_file_warehouse_in_local_mode(tmp_path: Any) -> None:
    target = tmp_path / "metadata.json"
    target.write_text("{}", encoding="utf-8")
    io = iceberg_export.guarded_file_io(VENDED)
    with io.new_input(target.as_uri()).open() as stream:
        content = stream.read()
    assert content == b"{}"
    exists = io.new_input(str(target)).exists()
    assert exists


def test_server_mode_is_fixed_when_the_file_io_is_built() -> None:
    """Scans read data files on executor threads that lack the request context."""
    io = _server_io(VENDED)
    with pytest.raises(iceberg_export.IcebergPublicationError, match="storage location"):
        io.new_input("file:///etc/passwd")  # read outside server_execution


def _server_io(properties: dict[str, str]) -> Any:
    with server_execution("tenant-a"):
        return iceberg_export.guarded_file_io(properties)


def test_guarded_file_io_allows_s3_and_opted_in_warehouse_scheme() -> None:
    io = iceberg_export.guarded_file_io(VENDED)
    assert isinstance(io, PyArrowFileIO)
    assert io.new_input("s3://bucket/warehouse/metadata/v1.json").location.startswith("s3://")
    assert io.new_input("s3a://bucket/x").location.startswith("s3a://")
    gcs_io = iceberg_export.guarded_file_io(
        {"gcs.oauth2.token": "t", "gcs.oauth2.token-expires-at": "4102444800000"}, extra_schemes=("gs",)
    )
    assert gcs_io.new_input("gs://bucket/x").location == "gs://bucket/x"


def test_guarded_file_io_ignores_hostile_properties() -> None:
    io = iceberg_export.guarded_file_io({**HOSTILE_PROPERTIES, **VENDED})
    assert "s3.endpoint" not in io.properties
    assert "s3.retry-strategy-impl" not in io.properties


def test_warehouse_scheme_opt_in_is_limited_to_object_stores() -> None:
    assert iceberg_export.warehouse_schemes("gs://bucket/wh") == ("gs", "gcs")
    assert iceberg_export.warehouse_schemes("s3://bucket/wh") == ()
    assert iceberg_export.warehouse_schemes("file:///tmp/wh") == ()
    assert iceberg_export.warehouse_schemes("my-catalog") == ()


def test_rest_catalog_filters_config_and_table_properties(rest_stub: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    url, state = rest_stub
    monkeypatch.setenv("GRC_LAKE_TEST_BEARER", "synthetic-ephemeral-bearer")
    state["overrides"] = dict(HOSTILE_PROPERTIES)
    catalog = iceberg_export.rest_catalog(
        url, warehouse="fixture", token_env="GRC_LAKE_TEST_BEARER", allow_http_localhost=True
    )
    try:
        with server_execution("tenant-a"):
            io = catalog._load_file_io({**HOSTILE_PROPERTIES, **VENDED}, location="s3://bucket/t")
        assert isinstance(io, PyArrowFileIO)
        assert dict(io.properties) == VENDED
        with pytest.raises(iceberg_export.IcebergPublicationError, match="storage location"):
            io.new_input("file:///etc/passwd")
    finally:
        catalog.close()


def test_glue_catalog_file_io_rejects_local_metadata_locations(monkeypatch: pytest.MonkeyPatch) -> None:
    import boto3

    class FakeSession:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def client(self, name: str, **kwargs: Any) -> Any:
            return object()

    monkeypatch.setattr(boto3, "Session", FakeSession)
    catalog = ice.glue_catalog(region="us-east-1")
    with server_execution("tenant-a"):
        io = catalog._load_file_io(HOSTILE_PROPERTIES, location="file:///etc/passwd")
    assert "s3.endpoint" not in io.properties
    with pytest.raises(iceberg_export.IcebergPublicationError, match="storage location"):
        io.new_input("file:///var/lib/trustops/tenants/other/metadata.json")
    with pytest.raises(iceberg_export.IcebergPublicationError, match="storage location"):
        io.new_input("/etc/passwd")


def test_loopback_test_catalog_may_use_a_local_file_warehouse(rest_stub: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Local catalog testing (loopback opt-in) can use a local FILE warehouse; server mode cannot."""
    url, _state = rest_stub
    monkeypatch.setenv("GRC_LAKE_TEST_BEARER", "synthetic-ephemeral-bearer")
    catalog = iceberg_export.rest_catalog(
        url, warehouse="fixture", token_env="GRC_LAKE_TEST_BEARER", allow_http_localhost=True
    )
    try:
        io = catalog._load_file_io({"s3.endpoint": "http://169.254.169.254"})
        assert "s3.endpoint" not in io.properties
        assert io.new_input("file:///tmp/warehouse/metadata.json").location.startswith("file:")
        with pytest.raises(iceberg_export.IcebergPublicationError, match="storage location"):
            io.new_input("http://169.254.169.254/x")
        with server_execution("tenant-a"), pytest.raises(iceberg_export.IcebergPublicationError):
            catalog._load_file_io({}).new_input("file:///tmp/warehouse/metadata.json")
    finally:
        catalog.close()

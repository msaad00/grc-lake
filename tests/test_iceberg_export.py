"""Iceberg snapshot publication preserves tenant scope and retry semantics."""

import json
from pathlib import Path

import pytest

from security_lakehouse import iceberg_export, pipeline
from security_lakehouse.io import read_jsonl, write_jsonl

pytest.importorskip("pyiceberg")
pa = pytest.importorskip("pyarrow")
SqlCatalog = pytest.importorskip("pyiceberg.catalog.sql").SqlCatalog
StringType = pytest.importorskip("pyiceberg.types").StringType

RAW = Path(__file__).resolve().parents[1] / "data/raw/security_events.jsonl"
TENANT = "acme-prod"


@pytest.fixture
def setup(tmp_path):
    lake = tmp_path / "lake"
    pipeline.run_pipeline(RAW, lake, tenant_id=TENANT)
    catalog = SqlCatalog(
        "test", uri=f"sqlite:///{tmp_path / 'catalog.db'}", warehouse=(tmp_path / "warehouse").as_uri()
    )
    catalog.create_namespace("tenant_a", properties={"trustops.tenant_id": TENANT})
    return lake, catalog


def publish(setup, **kwargs):
    lake, catalog = setup
    return iceberg_export.publish_iceberg(
        lake, catalog, namespace="tenant_a", table_name="evidence", tenant_id=TENANT, **kwargs
    )


def test_publish_and_retry_preserve_one_snapshot(setup):
    receipt = publish(setup)
    table = setup[1].load_table(("tenant_a", "evidence"))
    assert table.scan().to_arrow().to_pylist() == [
        {"connector_id": None, "source_event_id": None, **row}
        for row in read_jsonl(setup[0] / "silver/normalized_events.jsonl")
    ]
    assert receipt["snapshot_id"] == table.current_snapshot().snapshot_id
    assert receipt["row_count"] == 10
    assert receipt["tenant_id"] == TENANT
    assert receipt["already_published"] is False
    again = publish(setup)
    assert again["already_published"] is True
    assert again["snapshot_id"] == receipt["snapshot_id"]
    assert len(setup[1].load_table(("tenant_a", "evidence")).snapshots()) == 1
    assert "token" not in json.dumps(receipt).lower()


def test_new_generation_replaces_current_but_keeps_history(setup, tmp_path):
    first = publish(setup)
    raw = tmp_path / "changed.jsonl"
    write_jsonl(raw, read_jsonl(RAW)[:1])
    pipeline.run_pipeline(raw, setup[0], tenant_id=TENANT)
    second = publish(setup)
    table = setup[1].load_table(("tenant_a", "evidence"))
    assert second["snapshot_id"] != first["snapshot_id"]
    assert table.scan().to_arrow().num_rows == 1
    assert table.scan(snapshot_id=first["snapshot_id"]).to_arrow().num_rows == 10


def test_table_with_different_normalization_contract_is_rejected(setup):
    first = publish(setup)
    table = setup[1].load_table(("tenant_a", "evidence"))
    with table.transaction() as txn:
        txn.set_properties({"trustops.normalization_version": "future-version"})
    with pytest.raises(iceberg_export.IcebergPublicationError, match="normalization"):
        publish(setup)
    assert setup[1].load_table(("tenant_a", "evidence")).current_snapshot().snapshot_id == first["snapshot_id"]


def test_historical_retry_does_not_roll_current_back(setup, tmp_path):
    from security_lakehouse.generations import active_generation

    first_generation = active_generation(setup[0])
    first = publish(setup)
    raw = tmp_path / "changed.jsonl"
    write_jsonl(raw, read_jsonl(RAW)[:1])
    pipeline.run_pipeline(raw, setup[0], tenant_id=TENANT)
    second = publish(setup)
    # The exporter receives a retained generation via its original root pin.
    from security_lakehouse import generations

    token = generations._pinned.set({setup[0].resolve(): first_generation})
    try:
        retried = publish(setup)
    finally:
        generations._pinned.reset(token)
    assert retried["snapshot_id"] == first["snapshot_id"]
    assert setup[1].load_table(("tenant_a", "evidence")).current_snapshot().snapshot_id == second["snapshot_id"]


@pytest.mark.parametrize("boundary", ["namespace", "table"])
def test_wrong_tenant_is_denied_before_replacement(setup, boundary):
    publish(setup)
    catalog = setup[1]
    table = catalog.load_table(("tenant_a", "evidence"))
    before = table.current_snapshot().snapshot_id
    if boundary == "namespace":
        catalog.update_namespace_properties("tenant_a", updates={"trustops.tenant_id": "other"})
    else:
        with table.transaction() as txn:
            txn.set_properties({"trustops.tenant_id": "other"})
    with pytest.raises(iceberg_export.IcebergPublicationError, match="tenant"):
        publish(setup)
    assert catalog.load_table(("tenant_a", "evidence")).current_snapshot().snapshot_id == before


def test_incomplete_local_generation_does_not_create_table(setup):
    from security_lakehouse.generations import active_generation

    (active_generation(setup[0]) / "silver/normalized_events.jsonl").write_text("")
    with pytest.raises(iceberg_export.IcebergPublicationError):
        publish(setup)
    assert not setup[1].table_exists(("tenant_a", "evidence"))


def test_optional_schema_evolution_preserves_existing_fields(setup, tmp_path):
    publish(setup)
    table = setup[1].load_table(("tenant_a", "evidence"))
    with table.update_schema() as update:
        update.add_column("review_note", StringType(), required=False)
    raw = tmp_path / "changed.jsonl"
    write_jsonl(raw, read_jsonl(RAW)[:1])
    pipeline.run_pipeline(raw, setup[0], tenant_id=TENANT)
    publish(setup)
    rows = setup[1].load_table(("tenant_a", "evidence")).scan().to_arrow().to_pylist()
    assert len(rows) == 1 and rows[0]["review_note"] is None


def test_incompatible_schema_is_denied(setup, tmp_path):
    publish(setup)
    table = setup[1].load_table(("tenant_a", "evidence"))
    with table.update_schema() as update:
        update.rename_column("source", "renamed_source")
    raw = tmp_path / "changed.jsonl"
    write_jsonl(raw, read_jsonl(RAW)[:1])
    pipeline.run_pipeline(raw, setup[0], tenant_id=TENANT)
    before = table.current_snapshot().snapshot_id
    with pytest.raises(iceberg_export.IcebergPublicationError, match="schema"):
        publish(setup)
    assert setup[1].load_table(("tenant_a", "evidence")).current_snapshot().snapshot_id == before


def test_empty_generation_publishes_a_snapshot(setup, tmp_path):
    raw = tmp_path / "empty.jsonl"
    raw.write_text("")
    pipeline.run_pipeline(raw, setup[0], tenant_id=TENANT)
    receipt = publish(setup)
    assert receipt["row_count"] == 0 and receipt["snapshot_id"] is not None
    assert setup[1].load_table(("tenant_a", "evidence")).scan().to_arrow().num_rows == 0


def test_lost_commit_response_is_reconciled_without_duplicate(setup, monkeypatch):
    catalog = setup[1]
    original = catalog.commit_table

    def lost(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("sensitive-provider-error")

    monkeypatch.setattr(catalog, "commit_table", lost)
    receipt = publish(setup)
    assert receipt["already_published"] is True
    assert len(catalog.load_table(("tenant_a", "evidence")).snapshots()) == 1


def test_failed_commit_does_not_expose_partial_table_or_backend_secrets(setup, monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("sensitive-provider-error")

    monkeypatch.setattr(setup[1], "commit_table", fail)
    with pytest.raises(iceberg_export.IcebergPublicationError) as error:
        publish(setup)
    assert "sensitive-provider-error" not in str(error.value)
    assert not setup[1].table_exists(("tenant_a", "evidence"))


@pytest.mark.parametrize(
    "uri",
    [
        "http://catalog.example.test/api",
        "https://user:secret@catalog.example.test",
        "https://catalog.example.test?token=secret",
    ],
)
def test_unsafe_catalog_urls_are_rejected_without_network(uri):
    with pytest.raises(iceberg_export.IcebergPublicationError):
        iceberg_export.rest_catalog(uri, warehouse="test", token_env="TRUSTOPS_TEST_MISSING")


def test_concurrent_writer_cannot_be_silently_overwritten(setup, tmp_path, monkeypatch):
    publish(setup)
    catalog = setup[1]
    other_lake = tmp_path / "other-writer-lake"
    other_raw = tmp_path / "other.jsonl"
    write_jsonl(other_raw, read_jsonl(RAW)[:2])
    pipeline.run_pipeline(other_raw, other_lake, tenant_id=TENANT)
    requested_raw = tmp_path / "requested.jsonl"
    write_jsonl(requested_raw, read_jsonl(RAW)[:1])
    pipeline.run_pipeline(requested_raw, setup[0], tenant_id=TENANT)
    original = catalog.commit_table
    interleaved = False

    def competing(*args, **kwargs):
        nonlocal interleaved
        if not interleaved:
            interleaved = True
            iceberg_export.publish_iceberg(other_lake, catalog, namespace="tenant_a", tenant_id=TENANT)
        return original(*args, **kwargs)

    monkeypatch.setattr(catalog, "commit_table", competing)
    with pytest.raises(iceberg_export.IcebergPublicationError):
        publish(setup)
    assert catalog.load_table(("tenant_a", "evidence")).scan().to_arrow().num_rows == 2


def test_rest_token_is_explicit_and_server_cannot_inject_auth_plugin(rest_stub, monkeypatch):
    url, state = rest_stub
    monkeypatch.setenv("TRUSTOPS_TEST_BEARER", "synthetic-ephemeral-bearer")
    state["overrides"] = {
        "token": "different-token",
        "auth": {"type": "custom", "impl": "nonexistent.plugin"},
        "py-io-impl": "nonexistent.plugin",
    }
    catalog = iceberg_export.rest_catalog(
        url, warehouse="fixture", token_env="TRUSTOPS_TEST_BEARER", allow_http_localhost=True
    )
    try:
        assert catalog.list_namespaces() == []
        assert state["headers"] == ["Bearer synthetic-ephemeral-bearer"] * 2
        from pyiceberg.io.pyarrow import PyArrowFileIO

        assert isinstance(catalog._load_file_io(), PyArrowFileIO)
    finally:
        catalog.close()


def test_expired_token_fails_without_implicit_refresh_or_retry(rest_stub, monkeypatch):
    url, state = rest_stub
    monkeypatch.setenv("TRUSTOPS_TEST_BEARER", "synthetic-ephemeral-bearer")
    catalog = iceberg_export.rest_catalog(
        url, warehouse="fixture", token_env="TRUSTOPS_TEST_BEARER", allow_http_localhost=True
    )
    try:
        state["expired"] = True
        with pytest.raises(iceberg_export.IcebergPublicationError, match="expired"):
            catalog.list_namespaces()
        assert len(state["headers"]) == 2  # Config and one denied request.
    finally:
        catalog.close()


def test_rest_redirect_cannot_forward_bearer_token(rest_stub, monkeypatch):
    url, state = rest_stub
    state["redirect"] = True
    monkeypatch.setenv("TRUSTOPS_TEST_BEARER", "synthetic-ephemeral-bearer")
    with pytest.raises(iceberg_export.IcebergPublicationError) as error:
        iceberg_export.rest_catalog(
            url, warehouse="fixture", token_env="TRUSTOPS_TEST_BEARER", allow_http_localhost=True
        )
    assert len(state["headers"]) == 1
    assert "synthetic-ephemeral-bearer" not in str(error.value)


def test_catalog_cannot_relocate_credentialed_endpoint(rest_stub, monkeypatch):
    url, state = rest_stub
    state["overrides"] = {"uri": "https://unrelated.example.test"}
    monkeypatch.setenv("TRUSTOPS_TEST_BEARER", "synthetic-ephemeral-bearer")
    with pytest.raises(iceberg_export.IcebergPublicationError, match="relocation"):
        iceberg_export.rest_catalog(
            url, warehouse="fixture", token_env="TRUSTOPS_TEST_BEARER", allow_http_localhost=True
        )
    assert len(state["headers"]) == 1


def test_cli_receipt_and_connection_cleanup(setup, monkeypatch, capsys):
    from security_lakehouse.cli import main

    catalog = setup[1]
    closed = []
    monkeypatch.setattr(catalog, "close", lambda: closed.append(True), raising=False)
    monkeypatch.setattr(iceberg_export, "rest_catalog", lambda *args, **kwargs: catalog)
    assert (
        main(
            [
                "pipeline",
                "publish-iceberg",
                "--lake",
                str(setup[0]),
                "--tenant-id",
                TENANT,
                "--catalog-uri",
                "https://catalog.example.test",
                "--warehouse",
                "fixture",
                "--namespace",
                "tenant_a",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["row_count"] == 10
    assert closed == [True]

"""Portable normalized evidence must match an independent Parquet reader."""

import hashlib
import json
from pathlib import Path

import pytest

from security_lakehouse import parquet_export, pipeline
from security_lakehouse.cli import main
from security_lakehouse.generations import active_generation, seal_generation
from security_lakehouse.io import read_json, read_jsonl, write_json, write_jsonl

duckdb = pytest.importorskip("duckdb")
pq = pytest.importorskip("pyarrow.parquet")

RAW = Path(__file__).resolve().parents[1] / "data/raw/security_events.jsonl"
TENANT = "acme-prod"


@pytest.fixture
def lake(tmp_path):
    path = tmp_path / "lake"
    pipeline.run_pipeline(RAW, path, tenant_id=TENANT)
    return path


def export(lake, out, **kwargs):
    return parquet_export.export_parquet(lake, out, tenant_id=TENANT, **kwargs)


def test_duckdb_reads_exact_typed_rows_and_provenance(lake, tmp_path):
    out = tmp_path / "export"
    result = export(lake, out, batch_size=3)
    source = read_jsonl(lake / "silver/normalized_events.jsonl")
    with duckdb.connect() as db:
        cursor = db.execute("SELECT * FROM read_parquet(?) ORDER BY event_id", [str(out / "evidence.parquet")])
        names = [column[0] for column in cursor.description]
        rows = [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]
    assert rows == sorted(
        [{"connector_id": None, "source_event_id": None, **row} for row in source], key=lambda row: row["event_id"]
    )
    assert result == read_json(out / "manifest.json")
    assert result["row_count"] == len(source)
    assert result["tenant_id"] == TENANT
    assert result["generation"]["generation_id"] == active_generation(lake).name
    assert result["parquet_sha256"] == hashlib.sha256((out / "evidence.parquet").read_bytes()).hexdigest()
    assert pq.read_metadata(out / "evidence.parquet").num_row_groups == 4
    assert (
        pq.read_schema(out / "evidence.parquet").metadata[b"trustops.schema_version"] == b"trustops.normalized_event.v1"
    )
    assert out.stat().st_mode & 0o777 == 0o700
    assert (out / "evidence.parquet").stat().st_mode & 0o077 == 0
    assert "raw_path" not in json.dumps(result)


def test_empty_generation_has_queryable_schema(tmp_path):
    raw = tmp_path / "empty.jsonl"
    raw.write_text("")
    lake = tmp_path / "lake"
    pipeline.run_pipeline(raw, lake, tenant_id=TENANT)
    result = export(lake, tmp_path / "export")
    with duckdb.connect() as db:
        assert db.execute(
            "SELECT count(event_id) FROM read_parquet(?)", [str(tmp_path / "export/evidence.parquet")]
        ).fetchone() == (0,)
    assert result["row_count"] == 0


def test_tenant_mismatch_does_not_publish(lake, tmp_path):
    out = tmp_path / "export"
    with pytest.raises(ValueError, match="tenant"):
        parquet_export.export_parquet(lake, out, tenant_id="other-tenant", batch_size=1)
    assert not out.exists()
    assert not list(tmp_path.glob(".parquet-*"))


def test_owned_generation_preserves_distinct_source_account_ids(lake, tmp_path):
    rows = read_jsonl(RAW)
    rows[-1]["tenant_id"] = "source-account-two"
    raw = tmp_path / "mixed.jsonl"
    write_jsonl(raw, rows)
    pipeline.run_pipeline(raw, lake, tenant_id=TENANT)
    out = tmp_path / "export"
    export(lake, out)
    landed = pq.read_table(out / "evidence.parquet").to_pylist()
    assert {row["tenant_id"] for row in landed} == {row["tenant_id"] for row in rows}
    assert pq.read_schema(out / "evidence.parquet").metadata[b"trustops.tenant_id"] == TENANT.encode()


def test_tampered_generation_is_rejected(lake, tmp_path):
    (active_generation(lake) / "silver/normalized_events.jsonl").write_text("")
    with pytest.raises(ValueError, match="hash mismatch"):
        export(lake, tmp_path / "export")
    assert not (tmp_path / "export").exists()


@pytest.mark.parametrize("invalid", ["version", "count", "field"])
def test_incompatible_contract_never_silently_loses_data(lake, tmp_path, invalid):
    generation = active_generation(lake)
    manifest = read_json(generation / "manifest.json")
    # Simulate a future producer before it seals the generation.
    (generation / "generation.json").unlink()
    if invalid == "version":
        manifest["normalization"]["schema_version"] = "future.v2"
    elif invalid == "count":
        manifest["row_counts"]["silver"] += 1
    else:
        rows = read_jsonl(generation / "silver/normalized_events.jsonl")
        rows[0]["future_field"] = "must not be discarded"
        write_jsonl(generation / "silver/normalized_events.jsonl", rows)
    write_json(generation / "manifest.json", manifest)
    seal_generation(generation)
    with pytest.raises(ValueError):
        export(lake, tmp_path / "export", batch_size=1)
    assert not (tmp_path / "export").exists()


def test_publication_during_export_keeps_original_generation(lake, tmp_path, monkeypatch):
    first = active_generation(lake).name
    before = read_jsonl(lake / "silver/normalized_events.jsonl")
    original = parquet_export.iter_jsonl
    changed = tmp_path / "changed.jsonl"
    write_jsonl(changed, read_jsonl(RAW)[:1])

    def interleave(path):
        for index, row in enumerate(original(path)):
            if index == 1:
                pipeline.run_pipeline(changed, lake, tenant_id=TENANT)
            yield row

    monkeypatch.setattr(parquet_export, "iter_jsonl", interleave)
    result = export(lake, tmp_path / "export", batch_size=1)
    assert active_generation(lake).name != first
    assert result["generation"]["generation_id"] == first
    assert result["row_count"] == len(before)
    assert pq.read_table(tmp_path / "export/evidence.parquet").to_pylist() == [
        {"connector_id": None, "source_event_id": None, **row} for row in before
    ]


def test_interrupted_export_has_no_visible_partial_bundle(lake, tmp_path, monkeypatch):
    original = parquet_export.iter_jsonl

    def interrupted(path):
        yield next(original(path))
        raise OSError("injected interruption")

    monkeypatch.setattr(parquet_export, "iter_jsonl", interrupted)
    with pytest.raises(OSError, match="injected"):
        export(lake, tmp_path / "export", batch_size=1)
    assert not (tmp_path / "export").exists()
    assert not list(tmp_path.glob(".parquet-*"))


def test_existing_export_is_never_replaced(lake, tmp_path):
    out = tmp_path / "export"
    export(lake, out)
    before = {p.name: p.read_bytes() for p in out.iterdir()}
    with pytest.raises(FileExistsError):
        export(lake, out)
    assert {p.name: p.read_bytes() for p in out.iterdir()} == before


def test_cannot_export_into_source_lake(lake):
    with pytest.raises(ValueError, match="outside"):
        export(lake, lake / "exports")
    assert not (lake / "exports").exists()


def test_legacy_lake_is_not_advertised_as_verified(tmp_path):
    with pytest.raises(ValueError, match="generation"):
        export(tmp_path / "legacy", tmp_path / "export")


def test_cli_normalize_then_export(tmp_path, capsys):
    lake = tmp_path / "lake"
    assert main(["ingestion", "normalize", "--raw", str(RAW), "--out", str(lake), "--tenant-id", TENANT]) == 0
    capsys.readouterr()
    assert (
        main(
            [
                "pipeline",
                "export-parquet",
                "--lake",
                str(lake),
                "--out",
                str(tmp_path / "export"),
                "--tenant-id",
                TENANT,
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["row_count"] == 10


def test_missing_optional_dependency_gives_install_guidance(lake, tmp_path, monkeypatch):
    import builtins

    original = builtins.__import__

    def without_arrow(name, *args, **kwargs):
        if name == "pyarrow":
            raise ImportError("optional library absent")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_arrow)
    with pytest.raises(RuntimeError, match=r"\[parquet\]"):
        export(lake, tmp_path / "export")
    assert not (tmp_path / "export").exists()


def test_cli_scope_failure_does_not_disclose_evidence(lake, tmp_path, capsys):
    assert (
        main(
            [
                "pipeline",
                "export-parquet",
                "--lake",
                str(lake),
                "--out",
                str(tmp_path / "export"),
                "--tenant-id",
                "other-tenant",
            ]
        )
        == 1
    )
    captured = capsys.readouterr()
    assert not captured.out
    assert "tenant" in captured.err
    assert TENANT not in captured.err
    assert not (tmp_path / "export").exists()


def test_migrated_legacy_generation_is_rejected(lake, tmp_path):
    marker = active_generation(lake) / "generation.json"
    manifest = json.loads(marker.read_text())
    manifest["legacy"] = True
    manifest["ccf_projection_version"] = None
    marker.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="legacy"):
        export(lake, tmp_path / "export")
    assert not (tmp_path / "export").exists()


def test_explicit_safeguard_bindings_survive_portable_export(tmp_path):
    raw = tmp_path / "raw.jsonl"
    rows = read_jsonl(RAW)[:1]
    rows[0]["safeguard_ids"] = ["SG-IDENTITY-001"]
    write_jsonl(raw, rows)
    lake = tmp_path / "lake"
    pipeline.run_pipeline(raw, lake, tenant_id=TENANT)
    out = tmp_path / "export"
    export(lake, out)
    assert pq.read_table(out / "evidence.parquet").to_pylist()[0]["safeguard_ids"] == ["SG-IDENTITY-001"]


@pytest.mark.parametrize("version", ["v1", "v2"])
def test_legacy_normalized_rows_remain_exportable(tmp_path, monkeypatch, version):
    normalize = pipeline._silver_row

    def legacy(row, digest):
        result = normalize(row, digest)
        result.pop("evidence_available")
        if version == "v1":
            result.pop("safeguard_ids")
        return result

    monkeypatch.setattr(pipeline, "_silver_row", legacy)
    monkeypatch.setattr(pipeline, "NORMALIZATION_TRANSFORM_VERSION", f"trustops.normalization.{version}")
    lake = tmp_path / "lake"
    pipeline.run_pipeline(RAW, lake, tenant_id=TENANT)
    out = tmp_path / "export"
    export(lake, out)
    names = pq.read_schema(out / "evidence.parquet").names
    assert ("safeguard_ids" in names) == (version == "v2")
    assert "connector_id" not in names
    assert "source_event_id" not in names


def test_connector_scoped_identity_survives_portable_export(tmp_path):
    rows = read_jsonl(RAW)[:2]
    rows[0]["connector_id"] = "source-one"
    raw = tmp_path / "raw.jsonl"
    write_jsonl(raw, rows)
    lake = tmp_path / "lake"
    pipeline.run_pipeline(raw, lake, tenant_id=TENANT)
    out = tmp_path / "export"
    export(lake, out)
    exported = pq.read_table(out / "evidence.parquet").to_pylist()
    scoped = next(row for row in exported if row["connector_id"])
    assert scoped["source_event_id"] == rows[0]["event_id"]
    assert scoped["event_id"] != scoped["source_event_id"]
    assert next(row for row in exported if not row["connector_id"])["source_event_id"] is None

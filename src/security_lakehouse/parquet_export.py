"""Local, generation-pinned Parquet exports of normalized security evidence.

This is a portable file bundle, not an Iceberg table or a compliance attestation.
The caller must already have filesystem access to the single-tenant source lake.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from pathlib import Path

from security_lakehouse.generations import (
    generation_identity,
    pin_generation,
    publication_lock,
    verify_generation,
)
from security_lakehouse.io import file_sha256, iter_jsonl, read_json

SCHEMA_VERSION = "trustops.normalized_event.v1"
EXPORT_VERSION = "trustops.parquet_export.v1"
_STRING_FIELDS = (
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
    "status",
    "evidence_id",
    "evidence_ref",
    "evidence_collected_at",
    "raw_sha256",
)
_LIST_FIELDS = ("control_ids", "evidence_types")
_FIELDS = frozenset((*_STRING_FIELDS, *_LIST_FIELDS, "severity_score"))


def _arrow_schema(pa, identity, tenant_id, *, safeguard_bindings=False, connector_identity=False):
    # Keep timestamp strings lossless: the normalized contract contains ISO text,
    # and evidence_collected_at is not guaranteed to have timestamp semantics.
    return pa.schema(
        [pa.field(name, pa.string(), nullable=False) for name in _STRING_FIELDS]
        + (
            [pa.field(name, pa.string(), nullable=True) for name in ("connector_id", "source_event_id")]
            if connector_identity
            else []
        )
        + [pa.field("severity_score", pa.int64(), nullable=False)]
        + [
            pa.field(name, pa.list_(pa.field("element", pa.string(), nullable=False)), nullable=False)
            for name in (*_LIST_FIELDS, *(("safeguard_ids",) if safeguard_bindings else ()))
        ],
        metadata={
            b"trustops.schema_version": SCHEMA_VERSION.encode(),
            b"trustops.export_version": EXPORT_VERSION.encode(),
            b"trustops.tenant_id": tenant_id.encode(),
            b"trustops.generation_id": identity["generation_id"].encode(),
            b"trustops.generation_manifest_sha256": identity["manifest_sha256"].encode(),
        },
    )


def _validate_row(row, tenant_id, *, safeguard_bindings=False, connector_identity=False):
    list_fields = (*_LIST_FIELDS, *(("safeguard_ids",) if safeguard_bindings else ()))
    fields = _FIELDS | ({"safeguard_ids"} if safeguard_bindings else set())
    if connector_identity and isinstance(row, dict):
        present = {"connector_id", "source_event_id"} & set(row)
        if present and (
            present != {"connector_id", "source_event_id"}
            or any(not isinstance(row[name], str) or not row[name].strip() for name in present)
        ):
            raise ValueError("normalized evidence contains invalid connector identity")
        fields |= present
    if not isinstance(row, dict) or set(row) != fields:
        raise ValueError("normalized evidence fields do not match the export schema")
    if row["tenant_id"] != tenant_id:
        raise ValueError("normalized evidence tenant does not match the requested export scope")
    if any(not isinstance(row[name], str) for name in _STRING_FIELDS):
        raise ValueError("normalized evidence contains an invalid string field")
    if any(
        not isinstance(row[name], list) or any(not isinstance(value, str) for value in row[name])
        for name in list_fields
    ):
        raise ValueError("normalized evidence contains an invalid list field")
    score = row["severity_score"]
    if type(score) is not int or not -(2**63) <= score < 2**63:
        raise ValueError("normalized evidence contains an invalid severity score")
    if not re.fullmatch(r"[0-9a-f]{64}", row["raw_sha256"]):
        raise ValueError("normalized evidence contains an invalid raw hash")


def _sha256(path):
    return file_sha256(path)


def _sync(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def export_parquet(lake_dir: str | Path, output_dir: str | Path, *, tenant_id: str, batch_size: int = 8192) -> dict:
    """Publish a new private directory containing evidence.parquet and manifest.json.

    Require an explicit matching tenant, a sealed generation, and the v1 schema.
    Unknown fields or mismatched counts fail closed. Existing outputs are never
    replaced. Conversion uses bounded row batches; source-generation verification
    retains the existing verifier's memory characteristics.
    """
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("a nonempty tenant scope is required")
    if type(batch_size) is not int or not 1 <= batch_size <= 65536:
        raise ValueError("batch size must be an integer between 1 and 65536")
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError:
        raise RuntimeError("Parquet export requires pip install 'trustops-security-data-lake[parquet]'") from None

    lake = Path(lake_dir).resolve()
    target = Path(output_dir).absolute()
    target = target.parent.resolve() / target.name
    if target == lake or target.is_relative_to(lake):
        raise ValueError("export destination must be outside the source lake")
    if os.path.lexists(target):
        raise FileExistsError("export destination already exists")

    with pin_generation(lake) as generation:
        if generation is None:
            raise ValueError("Parquet export requires a published assessment generation; normalize the lake first")
        verify_generation(generation)
        if read_json(generation / "generation.json").get("legacy", False):
            raise ValueError("legacy assessment generations must be normalized before export")
        source_manifest = read_json(generation / "manifest.json")
        if source_manifest.get("tenant_id") != tenant_id:
            raise ValueError("assessment tenant does not match the requested export scope")
        normalization = source_manifest.get("normalization", {})
        if normalization.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("unsupported normalized evidence schema version")
        expected_count = source_manifest.get("row_counts", {}).get("silver")
        if type(expected_count) is not int or expected_count < 0:
            raise ValueError("assessment has no valid normalized evidence count")
        identity = generation_identity(lake)
        transform = normalization.get("transform_version")
        if transform not in {"trustops.normalization.v1", "trustops.normalization.v2", "trustops.normalization.v3"}:
            raise ValueError("unsupported normalization transform version")
        safeguard_bindings = transform in {"trustops.normalization.v2", "trustops.normalization.v3"}
        connector_identity = transform == "trustops.normalization.v3"
        schema = _arrow_schema(
            pa, identity, tenant_id, safeguard_bindings=safeguard_bindings, connector_identity=connector_identity
        )
        source = generation / "silver/normalized_events.jsonl"
        source_digest = _sha256(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        staged = Path(tempfile.mkdtemp(prefix=".parquet-", dir=target.parent))
        try:
            parquet = staged / "evidence.parquet"
            count = 0
            batch = []
            with pq.ParquetWriter(parquet, schema, version="2.6", compression="zstd") as writer:
                for row in iter_jsonl(source):
                    _validate_row(
                        row, tenant_id, safeguard_bindings=safeguard_bindings, connector_identity=connector_identity
                    )
                    batch.append(row)
                    count += 1
                    if len(batch) >= batch_size:
                        writer.write_table(pa.Table.from_pylist(batch, schema=schema))
                        batch.clear()
                if batch:
                    writer.write_table(pa.Table.from_pylist(batch, schema=schema))
            parquet.chmod(0o600)
            if count != expected_count or pq.read_metadata(parquet).num_rows != count:
                raise ValueError("normalized evidence row count does not match the assessment")
            verify_generation(generation)
            if generation_identity(lake) != identity or _sha256(source) != source_digest:
                raise ValueError("assessment generation changed during export")
            manifest = {
                "schema_version": EXPORT_VERSION,
                "normalization": normalization,
                "tenant_id": tenant_id,
                "generation": identity,
                "control_map_sha256": source_manifest["control_map_sha256"],
                "catalog_bundle": read_json(generation / "catalog/bundle.json"),
                "source_artifact": "silver/normalized_events.jsonl",
                "source_sha256": source_digest,
                "parquet_file": "evidence.parquet",
                "parquet_sha256": _sha256(parquet),
                "row_count": count,
                "columns": [
                    {"name": field.name, "arrow_type": str(field.type), "nullable": field.nullable} for field in schema
                ],
                "writer": {
                    "library": "pyarrow",
                    "version": pa.__version__,
                    "parquet_version": "2.6",
                    "compression": "zstd",
                },
            }
            manifest_path = staged / "manifest.json"
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
            manifest_path.chmod(0o600)
            for path in (parquet, manifest_path, staged):
                _sync(path)
            # Serialize cooperating exporters at the destination to prevent an
            # existing empty directory from being replaced by POSIX rename.
            with publication_lock(target.parent):
                if os.path.lexists(target):
                    raise FileExistsError("export destination already exists")
                os.rename(staged, target)
                _sync(target.parent)
            return manifest
        finally:
            if staged.exists():
                shutil.rmtree(staged)

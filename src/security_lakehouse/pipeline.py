"""End-to-end security data lake pipeline."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sqlite3
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from security_lakehouse.asset_names import asset_names_from_raw, entity_asset_id
from security_lakehouse.control_verdict import evaluate_evidence_verdict
from security_lakehouse.controls import expand_controls, load_control_map
from security_lakehouse.event_identity import event_identity
from security_lakehouse.event_status import FAIL_STATUSES, normalize_event_status
from security_lakehouse.evidence_freshness import (
    build_evidence_freshness,
    stale_control_ids,
    summarize_source_freshness,
)
from security_lakehouse.evidence_types import expand_evidence_types
from security_lakehouse.execution_mode import evaluation_tenant_id
from security_lakehouse.generations import (
    active_generation,
    new_generation,
    publish_generation,
    seal_generation,
    serialized_publication,
)
from security_lakehouse.io import canonical_sha256 as _canonical_sha256
from security_lakehouse.io import file_sha256, iter_jsonl, read_json, read_jsonl, write_json, write_jsonl
from security_lakehouse.models import SEVERITY_SCORE, PipelineResult, parse_event_time, utc_iso
from security_lakehouse.policy import RuleResult
from security_lakehouse.programs import build_control_tests, with_program_requirements
from security_lakehouse.validation import validate_raw_event, validate_raw_events
from security_lakehouse.vocabulary import ControlVerdict

RAW_EVENT_SCHEMA_VERSION = "trustops.raw_event.v1"
NORMALIZED_EVENT_SCHEMA_VERSION = "trustops.normalized_event.v1"
NORMALIZATION_TRANSFORM_VERSION = "trustops.normalization.v4"
CONTROL_EVALUATION_VERSION = "trustops.control_evaluation.v8"


@serialized_publication
def run_pipeline(
    raw_path: str | Path,
    out_dir: str | Path,
    *,
    mapping_path: str | Path | None = None,
    tenant_id: str | None = None,
) -> PipelineResult:
    tenant_id = evaluation_tenant_id(out_dir, tenant_id)
    raw_rows = read_jsonl(raw_path)
    errors = validate_raw_events(raw_rows)
    if errors:
        raise ValueError("raw evidence validation failed:\n" + "\n".join(errors))
    bronze_rows = [_bronze_row(row) for row in raw_rows]
    silver_rows = [_silver_row(row, bronze["raw_sha256"]) for row, bronze in zip(raw_rows, bronze_rows, strict=True)]
    return _materialize_from_rows(
        raw_path=raw_path,
        out_dir=out_dir,
        raw_rows=raw_rows,
        bronze_rows=bronze_rows,
        silver_rows=silver_rows,
        mapping_path=mapping_path,
        tenant_id=tenant_id,
        materialize_mode="full",
    )


def normalize_raw_events(
    raw_path: str | Path,
    out_dir: str | Path,
    *,
    mapping_path: str | Path | None = None,
    tenant_id: str | None = None,
    incremental: bool = False,
) -> PipelineResult:
    """Normalize canonical raw evidence into the managed lake zones.

    This is the shared handoff for connector adapters, pre-landed raw evidence,
    and future existing-lake importers. Inputs must already satisfy the raw
    evidence contract; source-specific parsing belongs in the adapter before
    this boundary.
    """
    tenant_id = evaluation_tenant_id(out_dir, tenant_id)
    runner = run_pipeline_incremental if incremental else run_pipeline
    return runner(raw_path, out_dir, mapping_path=mapping_path, tenant_id=tenant_id)


@serialized_publication
def run_pipeline_incremental(
    raw_path: str | Path,
    out_dir: str | Path,
    *,
    mapping_path: str | Path | None = None,
    tenant_id: str | None = None,
) -> PipelineResult:
    """Detect changed raw evidence, then publish a complete replacement generation."""
    tenant_id = evaluation_tenant_id(out_dir, tenant_id)
    # Validate the catalog even when no raw rows changed.
    current_controls = with_program_requirements(load_control_map(mapping_path))
    out = active_generation(out_dir) or Path(out_dir)
    manifest_path = out / "manifest.json"
    if not manifest_path.is_file():
        return run_pipeline(raw_path, out_dir, mapping_path=mapping_path, tenant_id=tenant_id)

    manifest = read_json(manifest_path, base_dir=out)
    if (
        manifest.get("control_map_sha256") != _canonical_sha256(current_controls)
        or manifest.get("tenant_id") != tenant_id
        or manifest.get("evaluation_dependencies_sha256") != _evaluation_dependencies_sha256(lake=Path(out_dir))
    ):
        return run_pipeline(raw_path, out_dir, mapping_path=mapping_path, tenant_id=tenant_id)
    prior_index = manifest.get("raw_index") or {}
    if not isinstance(prior_index, dict):
        prior_index = {}

    delta_rows, removed_ids, new_index = _compute_raw_delta(raw_path, prior_index)
    due = manifest.get("next_freshness_transition")
    freshness_due = bool(due and datetime.now(UTC) >= parse_event_time(str(due)))
    if not delta_rows and not removed_ids and not freshness_due:
        return _pipeline_result_from_manifest(out, manifest)

    if removed_ids and len(removed_ids) > max(1000, len(prior_index) // 5):
        return run_pipeline(raw_path, out_dir, mapping_path=mapping_path, tenant_id=tenant_id)

    bronze_by_event: dict[str, dict[str, Any]] = {}
    silver_by_event: dict[str, dict[str, Any]] = {}
    bronze_path = out / "bronze" / "raw_events.jsonl"
    silver_path = out / "silver" / "normalized_events.jsonl"
    for bronze in read_jsonl(bronze_path, missing_ok=True, base_dir=out):
        event_id = event_identity(bronze.get("raw") or {})
        if event_id:
            bronze_by_event[event_id] = bronze
    for silver in read_jsonl(silver_path, missing_ok=True, base_dir=out):
        event_id = str(silver.get("event_id") or "")
        if event_id:
            silver_by_event[event_id] = silver

    for event_id in removed_ids:
        bronze_by_event.pop(event_id, None)
        silver_by_event.pop(event_id, None)

    if delta_rows:
        errors = validate_raw_events(delta_rows)
        if errors:
            raise ValueError("raw evidence validation failed:\n" + "\n".join(errors))
        for row in delta_rows:
            bronze = _bronze_row(row)
            silver = _silver_row(row, bronze["raw_sha256"])
            event_id = event_identity(row)
            bronze_by_event[event_id] = bronze
            silver_by_event[event_id] = silver

    bronze_rows = list(bronze_by_event.values())
    silver_rows = list(silver_by_event.values())
    raw_rows = [bronze["raw"] for bronze in bronze_rows]
    return _materialize_from_rows(
        raw_path=raw_path,
        out_dir=out_dir,
        raw_rows=raw_rows,
        bronze_rows=bronze_rows,
        silver_rows=silver_rows,
        mapping_path=mapping_path,
        tenant_id=tenant_id,
        materialize_mode="incremental",
        raw_index=new_index,
        delta_count=len(delta_rows),
        removed_count=len(removed_ids),
    )


def _materialize_from_rows(**kwargs) -> PipelineResult:
    lake = Path(kwargs["out_dir"]).resolve()
    generation = new_generation(lake)
    result = _write_generation(**{**kwargs, "out_dir": generation})
    from security_lakehouse.verification import verify_lake_integrity

    integrity = verify_lake_integrity(generation)
    if not integrity["ok"]:
        raise ValueError("staged assessment integrity verification failed")
    with sqlite3.connect(f"{Path(result.mart_path).as_uri()}?mode=ro", uri=True) as connection:
        if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise ValueError("staged assessment mart verification failed")
    seal_generation(generation)
    publish_generation(lake, generation)
    from security_lakehouse.execution_mode import in_server_mode

    root = lake.parent.parent if lake.parent.name == "tenants" else lake
    if (root / "server/app.db").is_file() or in_server_mode():
        from security_lakehouse.remediation_verification import reconcile_published_tasks

        reconcile_published_tasks(lake, tenant_id=kwargs.get("tenant_id", "default"))
    return result


def _write_generation(
    *,
    raw_path: str | Path,
    out_dir: str | Path,
    raw_rows: list[dict[str, Any]],
    bronze_rows: list[dict[str, Any]],
    silver_rows: list[dict[str, Any]],
    mapping_path: str | Path | None,
    tenant_id: str,
    materialize_mode: str,
    raw_index: dict[str, str] | None = None,
    delta_count: int | None = None,
    removed_count: int | None = None,
) -> PipelineResult:
    out = Path(out_dir)
    bronze_dir = out / "bronze"
    silver_dir = out / "silver"
    gold_dir = out / "gold"
    mart_dir = out / "mart"
    for directory in (bronze_dir, silver_dir, gold_dir, mart_dir):
        directory.mkdir(parents=True, exist_ok=True)

    control_map = with_program_requirements(load_control_map(mapping_path))
    from security_lakehouse.ccf_evaluation import evaluate_safeguards
    from security_lakehouse.mapping_review import effective_safeguards

    evaluated_at = datetime.now(UTC)
    effective = effective_safeguards(out.parent.parent)
    ccf_assessment = evaluate_safeguards(silver_rows, effective, control_map, now=evaluated_at)
    write_json(out / "catalog" / "safeguards.json", effective)
    write_json(gold_dir / "ccf_assessment.json", ccf_assessment)
    from security_lakehouse.catalog_versions import bundle_summary

    write_json(out / "catalog" / "control_map.json", {"controls": list(control_map.values())})
    write_json(out / "catalog" / "bundle.json", bundle_summary(catalog_path=out / "catalog" / "control_map.json"))
    evidence_freshness_rows = build_evidence_freshness(silver_rows, now=evaluated_at)
    stale_controls = stale_control_ids(
        evidence_freshness_rows,
        required_types={key: list(value.get("required_evidence_types") or []) for key, value in control_map.items()},
    )
    control_rows = _build_control_rows(silver_rows, control_map, stale_controls)
    # Applicability join: each asset_type -> the controls that declare it, so the
    # gold asset rows answer "which controls apply to this asset?".
    applicability: dict[str, list[str]] = defaultdict(list)
    for control_id, control in control_map.items():
        for asset_type in control.get("asset_types") or []:
            applicability[str(asset_type)].append(control_id)
    asset_rows = _build_asset_rows(
        silver_rows,
        {k: sorted(v) for k, v in applicability.items()},
        asset_names_from_raw(raw_rows),
    )
    control_test_rows = build_control_tests(silver_rows, control_rows, now=evaluated_at, control_catalog=control_map)
    metrics = _build_metrics(silver_rows, control_rows, asset_rows)
    metrics.update(_build_freshness_metrics(evidence_freshness_rows))
    metrics.update(_build_control_test_metrics(control_test_rows))
    dashboard_data = {
        "generated_at": utc_iso(datetime.now(UTC)),
        "lake_backends": [
            {
                "name": "Snowflake",
                "role": "Governed Evidence Lake",
                "best_for": "audit, GRC, RBAC, retention, executive reporting",
                "artifact": "deploy/snowflake/schema.sql",
            },
            {
                "name": "ClickHouse",
                "role": "Telemetry Analytics Lake",
                "best_for": "runtime events, detections, fast aggregations, dashboards",
                "artifact": "deploy/clickhouse/schema.sql",
            },
        ],
        "metrics": metrics,
        "pipeline_stages": _build_pipeline_stages(raw_rows, bronze_rows, silver_rows, control_rows, asset_rows),
        "source_mix": _build_source_mix(silver_rows),
        "severity_mix": _build_severity_mix(silver_rows),
        "backend_routes": _build_backend_routes(silver_rows),
        "source_freshness": summarize_source_freshness(evidence_freshness_rows),
        "evidence_freshness": evidence_freshness_rows,
        "control_posture": control_rows,
        "control_tests": control_test_rows,
        "asset_risk": asset_rows,
        "recent_events": sorted(silver_rows, key=lambda item: parse_event_time(item["event_time"]), reverse=True)[:10],
    }

    write_jsonl(bronze_dir / "raw_events.jsonl", bronze_rows)
    write_jsonl(silver_dir / "normalized_events.jsonl", silver_rows)
    write_jsonl(gold_dir / "control_posture.jsonl", control_rows)
    write_jsonl(gold_dir / "control_tests.jsonl", control_test_rows)
    write_jsonl(gold_dir / "evidence_freshness.jsonl", evidence_freshness_rows)
    write_jsonl(gold_dir / "asset_risk.jsonl", asset_rows)
    write_json(gold_dir / "metrics.json", metrics)
    write_json(gold_dir / "dashboard_data.json", dashboard_data)
    integrity = build_evidence_integrity(
        raw_rows=raw_rows,
        bronze_rows=bronze_rows,
        silver_rows=silver_rows,
        artifact_paths={
            "bronze_raw_events": bronze_dir / "raw_events.jsonl",
            "silver_normalized_events": silver_dir / "normalized_events.jsonl",
            "gold_control_posture": gold_dir / "control_posture.jsonl",
            "gold_control_tests": gold_dir / "control_tests.jsonl",
            "gold_evidence_freshness": gold_dir / "evidence_freshness.jsonl",
            "gold_asset_risk": gold_dir / "asset_risk.jsonl",
            "gold_metrics": gold_dir / "metrics.json",
            "gold_dashboard_data": gold_dir / "dashboard_data.json",
        },
    )
    write_json(gold_dir / "evidence_integrity.json", integrity)
    sqlite_mart_path = mart_dir / "security_lakehouse.sqlite"
    duckdb_mart_path = mart_dir / "security_data_lake.duckdb"
    wrote_duckdb = _write_duckdb_mart_if_available(
        duckdb_mart_path,
        silver_rows,
        control_rows,
        control_test_rows,
        evidence_freshness_rows,
        asset_rows,
        metrics,
        tenant_id=tenant_id,
    )

    write_json(
        out / "manifest.json",
        {
            "raw_path": str(raw_path),
            "tenant_id": tenant_id,
            "control_map_sha256": _canonical_sha256(control_map),
            "control_evaluation_version": CONTROL_EVALUATION_VERSION,
            "evaluation_dependencies_sha256": _evaluation_dependencies_sha256(ccf_payload=effective),
            "next_freshness_transition": _next_freshness_transition(evidence_freshness_rows),
            "generation_id": out.name,
            "materialize_mode": materialize_mode,
            "normalization": {
                "input_contract": RAW_EVENT_SCHEMA_VERSION,
                "schema_version": NORMALIZED_EVENT_SCHEMA_VERSION,
                "transform_version": NORMALIZATION_TRANSFORM_VERSION,
            },
            "delta_count": delta_count,
            "removed_count": removed_count,
            "raw_index": raw_index if raw_index is not None else _build_raw_index(raw_rows),
            "row_counts": {
                "raw": len(raw_rows),
                "bronze": len(bronze_rows),
                "silver": len(silver_rows),
                "gold_control_posture": len(control_rows),
                "gold_control_tests": len(control_test_rows),
                "gold_evidence_freshness": len(evidence_freshness_rows),
                "gold_asset_risk": len(asset_rows),
            },
            "zones": {
                "bronze": str(bronze_dir / "raw_events.jsonl"),
                "silver": str(silver_dir / "normalized_events.jsonl"),
                "gold_metrics": str(gold_dir / "metrics.json"),
                "gold_control_posture": str(gold_dir / "control_posture.jsonl"),
                "gold_control_tests": str(gold_dir / "control_tests.jsonl"),
                "gold_evidence_freshness": str(gold_dir / "evidence_freshness.jsonl"),
                "gold_asset_risk": str(gold_dir / "asset_risk.jsonl"),
                "gold_evidence_integrity": str(gold_dir / "evidence_integrity.json"),
            },
            "marts": {
                "sqlite": str(sqlite_mart_path),
                "duckdb": str(duckdb_mart_path) if wrote_duckdb else None,
            },
            "storage_roles": {
                "sqlite": "zero-dependency local smoke/demo SQL artifact",
                "duckdb": "optional local analytical mart for columnar datasets",
                "snowflake": "production governed evidence lake",
                "clickhouse": "production telemetry analytics lake",
            },
        },
    )

    _write_sqlite_mart(
        sqlite_mart_path,
        silver_rows,
        control_rows,
        control_test_rows,
        evidence_freshness_rows,
        asset_rows,
        metrics,
        tenant_id=tenant_id,
        ccf_assessment=ccf_assessment,
    )
    from security_lakehouse.assessment import write_current_posture

    write_current_posture(out)
    return PipelineResult(
        output_dir=str(out),
        raw_count=len(raw_rows),
        silver_count=len(silver_rows),
        control_count=len(control_rows),
        asset_count=len(asset_rows),
        mart_path=str(sqlite_mart_path),
        metrics_path=str(gold_dir / "metrics.json"),
        dashboard_data_path=str(gold_dir / "dashboard_data.json"),
        duckdb_mart_path=str(duckdb_mart_path) if wrote_duckdb else None,
    )


def _evaluation_dependencies_sha256(*, lake: Path | None = None, ccf_payload: dict[str, Any] | None = None) -> str:
    from security_lakehouse.connectors import load_connector_catalog
    from security_lakehouse.mapping_review import effective_safeguards
    from security_lakehouse.programs import load_program_catalog

    return _canonical_sha256(
        {
            "normalization": NORMALIZATION_TRANSFORM_VERSION,
            "control_evaluation": CONTROL_EVALUATION_VERSION,
            "ccf_projection_version": 1,
            "freshness": {key: row.get("freshness_slo_minutes") for key, row in load_connector_catalog().items()},
            "programs": load_program_catalog(),
            "safeguards": ccf_payload if ccf_payload is not None else effective_safeguards(lake),
        }
    )


def _next_freshness_transition(rows: list[dict[str, Any]]) -> str | None:
    # Freshness uses floor(age_minutes) and inclusive thresholds. The state
    # changes one minute after the published SLO boundary.
    moments = []
    for row in rows:
        if row["status"] not in {"fresh", "stale"} or not row.get("expires_at"):
            continue
        extra = 1 + (int(row["freshness_slo_minutes"]) if row["status"] == "stale" else 0)
        moments.append(parse_event_time(row["expires_at"]) + timedelta(minutes=extra))
    return utc_iso(min(moments)) if moments else None


def _raw_row_fingerprint(row: dict[str, Any]) -> str:
    canonical = json.dumps(row, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _build_raw_index(raw_rows: list[dict[str, Any]]) -> dict[str, str]:
    return {event_identity(row): _raw_row_fingerprint(row) for row in raw_rows}


def _compute_raw_delta(
    raw_path: str | Path,
    prior_index: dict[str, str],
) -> tuple[list[dict[str, Any]], set[str], dict[str, str]]:
    delta_rows: list[dict[str, Any]] = []
    new_index: dict[str, str] = {}
    for index, row in enumerate(iter_jsonl(raw_path), start=1):
        errors = validate_raw_event(row, index=index)
        if errors:
            raise ValueError("raw evidence validation failed: " + "; ".join(errors))
        event_id = event_identity(row)
        if event_id in new_index:
            raise ValueError("duplicate scoped event identity in incremental input")
        fingerprint = _raw_row_fingerprint(row)
        new_index[event_id] = fingerprint
        if prior_index.get(event_id) != fingerprint:
            delta_rows.append(row)
    removed_ids = set(prior_index) - set(new_index)
    return delta_rows, removed_ids, new_index


def _pipeline_result_from_manifest(out: Path, manifest: dict[str, Any]) -> PipelineResult:
    counts = manifest.get("row_counts") or {}
    zones = manifest.get("zones") or {}
    marts = manifest.get("marts") or {}
    gold_dir = out / "gold"
    return PipelineResult(
        output_dir=str(out),
        raw_count=int(counts.get("raw") or 0),
        silver_count=int(counts.get("silver") or 0),
        control_count=int(counts.get("gold_control_posture") or 0),
        asset_count=int(counts.get("gold_asset_risk") or 0),
        mart_path=str(marts.get("sqlite") or out / "mart" / "security_lakehouse.sqlite"),
        metrics_path=str(zones.get("gold_metrics") or gold_dir / "metrics.json"),
        dashboard_data_path=str(gold_dir / "dashboard_data.json"),
        duckdb_mart_path=marts.get("duckdb"),
    )


def _file_sha256(path: Path) -> str:
    return file_sha256(path)


def build_evidence_integrity(
    *,
    raw_rows: list[dict[str, Any]],
    bronze_rows: list[dict[str, Any]],
    silver_rows: list[dict[str, Any]],
    artifact_paths: dict[str, Path],
) -> dict[str, Any]:
    """Build deterministic integrity metadata for evidence and derived artifacts.

    The manifest separates two concerns:

    * ``idempotency.evidence_set_sha256`` is stable for the same logical input
      evidence even when a pipeline run has a new ingestion timestamp.
    * ``artifacts.*.sha256`` hashes the exact files written by this run so an
      auditor or agent can detect post-run drift in bronze/silver/gold outputs.
    """
    raw_hashes = [_canonical_sha256(row) for row in raw_rows]
    bronze_hashes = [str(row.get("raw_sha256") or "") for row in bronze_rows]
    silver_hashes = [str(row.get("raw_sha256") or "") for row in silver_rows]
    event_ids = [str(row.get("event_id") or "") for row in silver_rows]
    duplicate_event_ids = sorted(event_id for event_id, count in Counter(event_ids).items() if event_id and count > 1)
    evidence_items = sorted(
        (
            {"event_id": str(row.get("event_id") or ""), "raw_sha256": str(row.get("raw_sha256") or "")}
            for row in silver_rows
        ),
        key=lambda item: (item["event_id"], item["raw_sha256"]),
    )
    artifacts: dict[str, dict[str, Any]] = {}
    for name, path in sorted(artifact_paths.items()):
        artifacts[name] = {
            "path": str(path),
            "sha256": _file_sha256(path),
            "bytes": path.stat().st_size,
        }
    payload = {
        "schema_version": "trustops.evidence_integrity.v1",
        "generated_at": utc_iso(datetime.now(UTC)),
        "counts": {
            "raw": len(raw_rows),
            "bronze": len(bronze_rows),
            "silver": len(silver_rows),
            "unique_event_ids": len(set(event_ids)),
        },
        "hash_linkage": {
            "raw_matches_bronze": raw_hashes == bronze_hashes,
            "silver_hashes_subset_of_bronze": set(silver_hashes).issubset(set(bronze_hashes)),
            "missing_silver_hashes": sorted(set(silver_hashes) - set(bronze_hashes)),
        },
        "idempotency": {
            "event_ids_unique": len(duplicate_event_ids) == 0,
            "duplicate_event_ids": duplicate_event_ids,
            "evidence_set_sha256": _canonical_sha256(evidence_items),
        },
        "artifacts": artifacts,
    }
    payload["manifest_sha256"] = _canonical_sha256({k: v for k, v in payload.items() if k != "manifest_sha256"})
    return payload


def _bronze_row(row: dict[str, Any]) -> dict[str, Any]:
    canonical = json.dumps(row, sort_keys=True, separators=(",", ":"), default=str)
    return {
        "ingested_at": utc_iso(datetime.now(UTC)),
        "raw_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "raw": row,
    }


def _silver_row(row: dict[str, Any], raw_sha256: str) -> dict[str, Any]:
    entity = row["entity"]
    evidence = row.get("evidence") or {}
    attributes = row.get("attributes") or {}
    asset_id = entity_asset_id(entity)
    severity = str(row.get("severity", "info")).lower()
    event_type = str(row["event_type"])
    return {
        "event_id": event_identity(row),
        **(
            {"connector_id": row["connector_id"], "source_event_id": str(row["event_id"])}
            if row.get("connector_id")
            else {}
        ),
        "tenant_id": str(row["tenant_id"]),
        "event_time": utc_iso(parse_event_time(str(row["event_time"]))),
        "source": str(row["source"]),
        "event_type": event_type,
        "evidence_types": expand_evidence_types(event_type),
        "asset_id": asset_id,
        "asset_type": str(entity.get("asset_type") or entity.get("type") or "unknown"),
        "asset_owner": str(entity.get("asset_owner") or entity.get("owner") or attributes.get("owner") or "unassigned"),
        "environment": str(entity.get("environment") or attributes.get("environment") or "unknown"),
        "severity": severity,
        "severity_score": SEVERITY_SCORE[severity],
        "status": normalize_event_status(row.get("status", "observed")),
        "evidence_available": bool(evidence),
        "control_ids": list(dict.fromkeys(str(item) for item in row.get("controls", []))),
        "safeguard_ids": sorted(set(row.get("safeguard_ids", []))),
        "evidence_id": str(evidence.get("evidence_id") or event_identity(row)),
        "evidence_ref": _evidence_ref(row, evidence, raw_sha256),
        "evidence_collected_at": utc_iso(
            parse_event_time(evidence.get("collected_at") or evidence.get("evidence_collected_at") or row["event_time"])
        ),
        "raw_sha256": raw_sha256,
    }


def _evidence_ref(row: dict[str, Any], evidence: dict[str, Any], raw_sha256: str) -> str:
    """Return an inspectable evidence pointer, even when a source lacks one.

    Some live cloud APIs expose posture facts without a durable object URL.
    GRC Lake still has an immutable bronze row for that fact, so use a stable
    internal evidence reference instead of letting freshness mark valid evidence
    as missing.
    """
    explicit = str(evidence.get("uri") or evidence.get("ref") or evidence.get("evidence_ref") or "").strip()
    if explicit:
        return explicit
    source = str(row.get("source") or "unknown").strip() or "unknown"
    event_id = event_identity(row).strip()
    if event_id:
        return f"trustops://bronze/{source}/{event_id}"
    return f"trustops://bronze/{source}/{raw_sha256}"


def _build_control_rows(
    silver_rows: list[dict[str, Any]],
    control_map: dict[str, dict[str, Any]],
    stale_controls: set[str] | None = None,
) -> list[dict[str, Any]]:
    stale = stale_controls or set()
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in silver_rows:
        for control in expand_controls(row["control_ids"], control_map):
            grouped[str(control["control_id"])].append({**row, "_control": control})

    control_rows: list[dict[str, Any]] = []
    for control_id, rows in grouped.items():
        control = rows[0]["_control"]
        failing_rows = [row for row in rows if row["status"] in FAIL_STATUSES]
        evidence_rows = [row for row in rows if row["evidence_ref"]]
        max_score = max((row["severity_score"] for row in failing_rows), default=0)
        result = (
            evaluate_evidence_verdict(control_id, rows, control.get("evaluation_rule"), stale=control_id in stale)
            if control_id in control_map
            else RuleResult(
                ControlVerdict.NOT_EVALUATED.value, "unmapped", ["No active control definition is available."]
            )
        )
        coverage = round(len(evidence_rows) / len(rows), 4) if rows else 0
        control_rows.append(
            {
                "control_id": control_id,
                "framework": str(control.get("framework", "unknown")),
                "title": str(control.get("title", "")),
                "risk_domain": str(control.get("risk_domain", "unknown")),
                "owner": str(control.get("owner", "security")),
                "status": result.status,
                "evaluation_rule": result.rule,
                "evaluation_version": CONTROL_EVALUATION_VERSION,
                "input_event_set_sha256": _canonical_sha256(
                    sorted(
                        [
                            {"event_id": str(row.get("event_id", "")), "raw_sha256": str(row.get("raw_sha256", ""))}
                            for row in rows
                        ],
                        key=lambda item: (item["event_id"], item["raw_sha256"]),
                    )
                ),
                "rule_reasons": result.reasons,
                "risk_score": max_score,
                "event_count": len(rows),
                "open_event_count": len(failing_rows),
                "evidence_count": len(evidence_rows),
                "evidence_coverage": coverage,
                "latest_event_time": max((row["event_time"] for row in rows), key=parse_event_time),
            }
        )
    return sorted(control_rows, key=lambda item: (-int(item["risk_score"]), item["control_id"]))


def _build_asset_rows(
    silver_rows: list[dict[str, Any]],
    applicability: dict[str, list[str]] | None = None,
    asset_names: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    applies = applicability or {}
    names = asset_names or {}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in silver_rows:
        grouped[row["asset_id"]].append(row)
    assets: list[dict[str, Any]] = []
    for asset_id, rows in grouped.items():
        sev = Counter(row["severity"] for row in rows if row["status"] in FAIL_STATUSES)
        risk_score = max((row["severity_score"] for row in rows), default=0) + min(20, len(rows) * 2)
        asset_type = rows[0]["asset_type"]
        asset = {
            "asset_id": asset_id,
            "asset_type": asset_type,
            "asset_owner": rows[0]["asset_owner"],
            "environment": rows[0]["environment"],
            "risk_score": min(100, risk_score),
            "critical_open": sev["critical"],
            "high_open": sev["high"],
            "event_count": len(rows),
            "applicable_control_ids": applies.get(asset_type, []),
            "latest_event_time": max((row["event_time"] for row in rows), key=parse_event_time),
        }
        if asset_id in names:
            asset["asset_name"] = names[asset_id]
        assets.append(asset)
    return sorted(assets, key=lambda item: (-int(item["risk_score"]), item["asset_id"]))


def _build_metrics(
    silver_rows: list[dict[str, Any]],
    control_rows: list[dict[str, Any]],
    asset_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    open_rows = [row for row in silver_rows if row["status"] in FAIL_STATUSES]
    runtime_rows = [row for row in silver_rows if row["event_type"].startswith("runtime.")]
    blocked_runtime = [row for row in runtime_rows if row["status"] in {"blocked", "failed"}]
    evidence_rows = [row for row in silver_rows if row["evidence_ref"]]
    passing_controls = [row for row in control_rows if row["status"] == "pass"]
    return {
        "total_events": len(silver_rows),
        "open_risk_events": len(open_rows),
        "critical_open": sum(1 for row in open_rows if row["severity"] == "critical"),
        "high_open": sum(1 for row in open_rows if row["severity"] == "high"),
        "control_count": len(control_rows),
        "control_pass_rate": round(len(passing_controls) / len(control_rows), 4) if control_rows else 0,
        "evidence_coverage": round(len(evidence_rows) / len(silver_rows), 4) if silver_rows else 1,
        "runtime_block_rate": round(len(blocked_runtime) / len(runtime_rows), 4) if runtime_rows else 0,
        "asset_count": len(asset_rows),
        "top_risk_asset": asset_rows[0]["asset_id"] if asset_rows else "",
        "avg_asset_risk": round(sum(float(row["risk_score"]) for row in asset_rows) / len(asset_rows), 2)
        if asset_rows
        else 0,
    }


def _build_control_test_metrics(control_test_rows: list[dict[str, Any]]) -> dict[str, Any]:
    failing = [row for row in control_test_rows if row["result"] == "fail"]
    ready = [row for row in control_test_rows if row["status"] in {"ready", "auditor_ready"}]
    avg_confidence = (
        round(sum(int(row["confidence_score"]) for row in control_test_rows) / len(control_test_rows), 2)
        if control_test_rows
        else 0
    )
    return {
        "control_test_count": len(control_test_rows),
        "failing_control_tests": len(failing),
        "ready_control_tests": len(ready),
        "control_test_readiness": round(len(ready) / len(control_test_rows), 4) if control_test_rows else 1,
        "avg_control_test_confidence": avg_confidence,
    }


def _build_freshness_metrics(evidence_freshness_rows: list[dict[str, Any]]) -> dict[str, Any]:
    stale_rows = [row for row in evidence_freshness_rows if row["status"] in {"stale", "expired", "missing"}]
    expired_rows = [row for row in evidence_freshness_rows if row["status"] == "expired"]
    return {
        "evidence_freshness_count": len(evidence_freshness_rows),
        "stale_evidence_count": len(stale_rows),
        "expired_evidence_count": len(expired_rows),
        "fresh_evidence_rate": round(1 - (len(stale_rows) / len(evidence_freshness_rows)), 4)
        if evidence_freshness_rows
        else 1,
    }


def _build_pipeline_stages(
    raw_rows: list[dict[str, Any]],
    bronze_rows: list[dict[str, Any]],
    silver_rows: list[dict[str, Any]],
    control_rows: list[dict[str, Any]],
    asset_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    mapped_controls = sum(len(row["control_ids"]) for row in silver_rows)
    return [
        {"name": "Ingest", "label": "raw evidence", "count": len(raw_rows)},
        {"name": "Bronze", "label": "hashed replay records", "count": len(bronze_rows)},
        {"name": "Silver", "label": "normalized events", "count": len(silver_rows)},
        {"name": "Map", "label": "control links", "count": mapped_controls},
        {"name": "Gold", "label": "controls + assets", "count": len(control_rows) + len(asset_rows)},
        {"name": "Serve", "label": "mart tables", "count": 4},
    ]


def _build_source_mix(silver_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in silver_rows:
        grouped[row["source"]].append(row)
    rows: list[dict[str, Any]] = []
    for source, items in grouped.items():
        open_count = sum(1 for item in items if item["status"] in FAIL_STATUSES)
        rows.append(
            {
                "source": source,
                "events": len(items),
                "open": open_count,
                "max_severity_score": max(item["severity_score"] for item in items),
                "route": _source_route(source),
            }
        )
    return sorted(rows, key=lambda item: (-int(item["events"]), item["source"]))


def _build_severity_mix(silver_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter(row["severity"] for row in silver_rows)
    order = ["critical", "high", "medium", "low", "info", "none"]
    return [{"severity": severity, "count": counts[severity]} for severity in order if counts[severity]]


def _build_backend_routes(silver_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    route_counts: dict[str, int] = Counter(_source_route(row["source"]) for row in silver_rows)
    return [
        {
            "backend": "Snowflake",
            "role": "governed evidence",
            "events": route_counts["Snowflake"] + route_counts["dual"],
            "primary_tables": ["RAW_EVENTS", "NORMALIZED_EVENTS", "CONTROL_POSTURE", "ASSET_RISK"],
        },
        {
            "backend": "ClickHouse",
            "role": "telemetry analytics",
            "events": route_counts["ClickHouse"] + route_counts["dual"],
            "primary_tables": ["normalized_events", "control_posture", "asset_risk", "runtime_policy_metrics"],
        },
    ]


def _source_route(source: str) -> str:
    clickhouse_sources = {"runtime-gateway", "siem"}
    snowflake_sources = {"audit-log", "compliance-export", "identity-provider", "model-registry"}
    if source in clickhouse_sources:
        return "ClickHouse"
    if source in snowflake_sources:
        return "Snowflake"
    return "dual"


def _write_sqlite_mart(
    mart_path: Path,
    silver_rows: list[dict[str, Any]],
    control_rows: list[dict[str, Any]],
    control_test_rows: list[dict[str, Any]],
    evidence_freshness_rows: list[dict[str, Any]],
    asset_rows: list[dict[str, Any]],
    metrics: dict[str, Any],
    *,
    tenant_id: str = "default",
    ccf_assessment: dict[str, Any] | None = None,
) -> None:
    if mart_path.exists():
        mart_path.unlink()
    with sqlite3.connect(mart_path) as conn:
        conn.execute(
            """
            CREATE TABLE normalized_events (
                event_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                event_time TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                asset_type TEXT NOT NULL,
                asset_owner TEXT NOT NULL,
                environment TEXT NOT NULL,
                severity TEXT NOT NULL,
                severity_score INTEGER NOT NULL,
                status TEXT NOT NULL,
                control_ids_json TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                evidence_ref TEXT NOT NULL,
                evidence_collected_at TEXT NOT NULL,
                raw_sha256 TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE control_posture (
                tenant_id TEXT NOT NULL,
                control_id TEXT PRIMARY KEY,
                framework TEXT NOT NULL,
                title TEXT NOT NULL,
                risk_domain TEXT NOT NULL,
                owner TEXT NOT NULL,
                status TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                event_count INTEGER NOT NULL,
                open_event_count INTEGER NOT NULL,
                evidence_count INTEGER NOT NULL,
                evidence_coverage REAL NOT NULL,
                latest_event_time TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE asset_risk (
                tenant_id TEXT NOT NULL,
                asset_id TEXT PRIMARY KEY,
                asset_type TEXT NOT NULL,
                asset_owner TEXT NOT NULL,
                environment TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                critical_open INTEGER NOT NULL,
                high_open INTEGER NOT NULL,
                event_count INTEGER NOT NULL,
                latest_event_time TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE control_tests (
                tenant_id TEXT NOT NULL,
                test_id TEXT PRIMARY KEY,
                program_id TEXT NOT NULL,
                control_id TEXT NOT NULL,
                framework TEXT NOT NULL,
                name TEXT NOT NULL,
                owner TEXT NOT NULL,
                cadence TEXT NOT NULL,
                automation_level TEXT NOT NULL,
                agent_skill TEXT NOT NULL,
                status TEXT NOT NULL,
                result TEXT NOT NULL,
                confidence_score INTEGER NOT NULL,
                confidence_inputs_json TEXT NOT NULL,
                required_evidence_types_json TEXT NOT NULL,
                observed_evidence_types_json TEXT NOT NULL,
                missing_evidence_types_json TEXT NOT NULL,
                evidence_count INTEGER NOT NULL,
                failing_evidence_count INTEGER NOT NULL,
                open_violation_count INTEGER NOT NULL,
                latest_evidence_at TEXT,
                freshness_status TEXT NOT NULL,
                stale_evidence_types_json TEXT NOT NULL,
                expired_evidence_types_json TEXT NOT NULL,
                evidence_freshness_json TEXT NOT NULL,
                remediation_sla_hours INTEGER NOT NULL,
                next_action TEXT NOT NULL,
                api_refs_json TEXT NOT NULL,
                evaluated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE evidence_freshness (
                event_id TEXT PRIMARY KEY,
                evidence_id TEXT NOT NULL,
                evidence_ref TEXT NOT NULL,
                source TEXT NOT NULL,
                connector_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                control_ids_json TEXT NOT NULL,
                evidence_collected_at TEXT NOT NULL,
                evaluated_at TEXT NOT NULL,
                freshness_slo_minutes INTEGER NOT NULL,
                status TEXT NOT NULL,
                score INTEGER NOT NULL,
                age_minutes INTEGER,
                expires_at TEXT,
                reason TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE TABLE metrics (metric TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.executemany(
            """
            INSERT INTO normalized_events VALUES (
                :event_id, :tenant_id, :event_time, :source, :event_type, :asset_id,
                :asset_type, :asset_owner, :environment, :severity, :severity_score,
                :status, :control_ids_json, :evidence_id, :evidence_ref,
                :evidence_collected_at, :raw_sha256
            )
            """,
            [{**row, "control_ids_json": json.dumps(row["control_ids"])} for row in silver_rows],
        )
        conn.executemany(
            "INSERT INTO control_posture VALUES (:tenant_id,:control_id,:framework,:title,:risk_domain,:owner,:status,:risk_score,:event_count,:open_event_count,:evidence_count,:evidence_coverage,:latest_event_time)",
            [
                {
                    "tenant_id": tenant_id,
                    **row,
                    "latest_event_time": parse_event_time(row["latest_event_time"])
                    .isoformat(timespec="microseconds")
                    .replace("+00:00", "Z"),
                }
                for row in control_rows
            ],
        )
        conn.executemany(
            "INSERT INTO asset_risk VALUES (:tenant_id,:asset_id,:asset_type,:asset_owner,:environment,:risk_score,:critical_open,:high_open,:event_count,:latest_event_time)",
            [
                {
                    "tenant_id": tenant_id,
                    **row,
                    "latest_event_time": parse_event_time(row["latest_event_time"])
                    .isoformat(timespec="microseconds")
                    .replace("+00:00", "Z"),
                }
                for row in asset_rows
            ],
        )
        conn.executemany(
            """
            INSERT INTO control_tests VALUES (
                :tenant_id, :test_id, :program_id, :control_id, :framework, :name, :owner,
                :cadence, :automation_level, :agent_skill, :status, :result,
                :confidence_score, :confidence_inputs_json, :required_evidence_types_json,
                :observed_evidence_types_json, :missing_evidence_types_json,
                :evidence_count, :failing_evidence_count, :open_violation_count,
                :latest_evidence_at, :freshness_status, :stale_evidence_types_json,
                :expired_evidence_types_json, :evidence_freshness_json,
                :remediation_sla_hours, :next_action, :api_refs_json, :evaluated_at
            )
            """,
            [{"tenant_id": tenant_id, **_control_test_sql_row(row)} for row in control_test_rows],
        )
        conn.executemany(
            """
            INSERT INTO evidence_freshness VALUES (
                :event_id, :evidence_id, :evidence_ref, :source, :connector_id,
                :event_type, :asset_id, :control_ids_json, :evidence_collected_at,
                :evaluated_at, :freshness_slo_minutes, :status, :score,
                :age_minutes, :expires_at, :reason
            )
            """,
            [_evidence_freshness_sql_row(row) for row in evidence_freshness_rows],
        )
        conn.executemany("INSERT INTO metrics VALUES (?, ?)", [(key, str(value)) for key, value in metrics.items()])
        _create_daily_compliance_views(conn)
        if ccf_assessment is not None:
            from security_lakehouse.ccf_queries import write_projection

            write_projection(conn, ccf_assessment)
        conn.commit()


def _create_daily_compliance_views(conn: sqlite3.Connection) -> None:
    """Expose two stable demo/warehouse projections over provenance-bearing rows."""
    conn.execute(
        """
        CREATE VIEW daily_control_results AS
        SELECT
            substr(t.evaluated_at, 1, 10) AS snapshot_date,
            e.tenant_id,
            t.program_id,
            t.framework,
            t.control_id,
            e.asset_id,
            t.result,
            t.confidence_score,
            t.freshness_status,
            e.evidence_ref,
            e.raw_sha256 AS evidence_hash,
            t.evaluated_at
        FROM control_tests t
        JOIN normalized_events e
          ON EXISTS (
             SELECT 1 FROM json_each(e.control_ids_json)
             WHERE json_each.value = t.control_id
         )
        """
    )
    conn.execute(
        """
        CREATE VIEW daily_posture_summary AS
        SELECT
            substr(max(latest_event_time), 1, 10) AS snapshot_date,
            tenant_id,
            framework,
            count(*) AS control_count,
            sum(CASE WHEN status = 'fail' THEN 1 ELSE 0 END) AS failing_controls,
            sum(CASE WHEN status = 'stale' THEN 1 ELSE 0 END) AS stale_controls,
            round(avg(evidence_coverage), 4) AS evidence_coverage,
            round(avg(risk_score), 2) AS average_risk_score,
            max(latest_event_time) AS evaluated_through
        FROM control_posture
        GROUP BY tenant_id, framework
        """
    )


def _control_test_sql_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        **row,
        "confidence_inputs_json": json.dumps(row["confidence_inputs"], sort_keys=True),
        "required_evidence_types_json": json.dumps(row["required_evidence_types"], sort_keys=True),
        "observed_evidence_types_json": json.dumps(row["observed_evidence_types"], sort_keys=True),
        "missing_evidence_types_json": json.dumps(row["missing_evidence_types"], sort_keys=True),
        "stale_evidence_types_json": json.dumps(row["stale_evidence_types"], sort_keys=True),
        "expired_evidence_types_json": json.dumps(row["expired_evidence_types"], sort_keys=True),
        "evidence_freshness_json": json.dumps(row["evidence_freshness"], sort_keys=True),
        "api_refs_json": json.dumps(row["api_refs"], sort_keys=True),
    }


def _evidence_freshness_sql_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        **row,
        "control_ids_json": json.dumps(row["control_ids"], sort_keys=True),
    }


def _insert_duckdb_rows(connection, statement, rows):
    # DuckDB rejects an empty executemany batch; an empty assessment still has
    # valid typed tables and must remain exportable.
    if rows:
        connection.executemany(statement, rows)


def _write_duckdb_mart_if_available(
    mart_path: Path,
    silver_rows: list[dict[str, Any]],
    control_rows: list[dict[str, Any]],
    control_test_rows: list[dict[str, Any]],
    evidence_freshness_rows: list[dict[str, Any]],
    asset_rows: list[dict[str, Any]],
    metrics: dict[str, Any],
    *,
    tenant_id: str = "default",
) -> bool:
    if importlib.util.find_spec("duckdb") is None:
        return False

    import duckdb

    from security_lakehouse.sinks.duckdb_sink import _coerce_datetime

    def utc_timestamp(value):
        return _coerce_datetime(value) if value else None

    if mart_path.exists():
        mart_path.unlink()
    with duckdb.connect(str(mart_path)) as conn:
        conn.execute(
            """
            CREATE TABLE normalized_events (
                event_id VARCHAR,
                tenant_id VARCHAR,
                event_time TIMESTAMP,
                source VARCHAR,
                event_type VARCHAR,
                asset_id VARCHAR,
                asset_type VARCHAR,
                asset_owner VARCHAR,
                environment VARCHAR,
                severity VARCHAR,
                severity_score INTEGER,
                status VARCHAR,
                control_ids_json VARCHAR,
                evidence_id VARCHAR,
                evidence_ref VARCHAR,
                evidence_collected_at TIMESTAMP,
                raw_sha256 VARCHAR
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE control_posture (
                tenant_id VARCHAR,
                control_id VARCHAR,
                framework VARCHAR,
                title VARCHAR,
                risk_domain VARCHAR,
                owner VARCHAR,
                status VARCHAR,
                risk_score INTEGER,
                event_count INTEGER,
                open_event_count INTEGER,
                evidence_count INTEGER,
                evidence_coverage DOUBLE,
                latest_event_time TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE asset_risk (
                tenant_id VARCHAR,
                asset_id VARCHAR,
                asset_type VARCHAR,
                asset_owner VARCHAR,
                environment VARCHAR,
                risk_score INTEGER,
                critical_open INTEGER,
                high_open INTEGER,
                event_count INTEGER,
                latest_event_time TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE control_tests (
                tenant_id VARCHAR,
                test_id VARCHAR,
                program_id VARCHAR,
                control_id VARCHAR,
                framework VARCHAR,
                name VARCHAR,
                owner VARCHAR,
                cadence VARCHAR,
                automation_level VARCHAR,
                agent_skill VARCHAR,
                status VARCHAR,
                result VARCHAR,
                confidence_score INTEGER,
                confidence_inputs_json VARCHAR,
                required_evidence_types_json VARCHAR,
                observed_evidence_types_json VARCHAR,
                missing_evidence_types_json VARCHAR,
                evidence_count INTEGER,
                failing_evidence_count INTEGER,
                open_violation_count INTEGER,
                latest_evidence_at TIMESTAMP,
                freshness_status VARCHAR,
                stale_evidence_types_json VARCHAR,
                expired_evidence_types_json VARCHAR,
                evidence_freshness_json VARCHAR,
                remediation_sla_hours INTEGER,
                next_action VARCHAR,
                api_refs_json VARCHAR,
                evaluated_at TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE evidence_freshness (
                event_id VARCHAR,
                evidence_id VARCHAR,
                evidence_ref VARCHAR,
                source VARCHAR,
                connector_id VARCHAR,
                event_type VARCHAR,
                asset_id VARCHAR,
                control_ids_json VARCHAR,
                evidence_collected_at TIMESTAMP,
                evaluated_at TIMESTAMP,
                freshness_slo_minutes INTEGER,
                status VARCHAR,
                score INTEGER,
                age_minutes INTEGER,
                expires_at TIMESTAMP,
                reason VARCHAR
            )
            """
        )
        conn.execute("CREATE TABLE metrics (metric VARCHAR, value VARCHAR)")
        _insert_duckdb_rows(
            conn,
            """
            INSERT INTO normalized_events VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            [
                (
                    row["event_id"],
                    row["tenant_id"],
                    utc_timestamp(row["event_time"]),
                    row["source"],
                    row["event_type"],
                    row["asset_id"],
                    row["asset_type"],
                    row["asset_owner"],
                    row["environment"],
                    row["severity"],
                    row["severity_score"],
                    row["status"],
                    json.dumps(row["control_ids"]),
                    row["evidence_id"],
                    row["evidence_ref"],
                    utc_timestamp(row["evidence_collected_at"]),
                    row["raw_sha256"],
                )
                for row in silver_rows
            ],
        )
        _insert_duckdb_rows(
            conn,
            "INSERT INTO control_posture VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    tenant_id,
                    row["control_id"],
                    row["framework"],
                    row["title"],
                    row["risk_domain"],
                    row["owner"],
                    row["status"],
                    row["risk_score"],
                    row["event_count"],
                    row["open_event_count"],
                    row["evidence_count"],
                    row["evidence_coverage"],
                    utc_timestamp(row["latest_event_time"]),
                )
                for row in control_rows
            ],
        )
        _insert_duckdb_rows(
            conn,
            "INSERT INTO asset_risk VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    tenant_id,
                    row["asset_id"],
                    row["asset_type"],
                    row["asset_owner"],
                    row["environment"],
                    row["risk_score"],
                    row["critical_open"],
                    row["high_open"],
                    row["event_count"],
                    utc_timestamp(row["latest_event_time"]),
                )
                for row in asset_rows
            ],
        )
        _insert_duckdb_rows(
            conn,
            "INSERT INTO control_tests VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    tenant_id,
                    row["test_id"],
                    row["program_id"],
                    row["control_id"],
                    row["framework"],
                    row["name"],
                    row["owner"],
                    row["cadence"],
                    row["automation_level"],
                    row["agent_skill"],
                    row["status"],
                    row["result"],
                    row["confidence_score"],
                    json.dumps(row["confidence_inputs"], sort_keys=True),
                    json.dumps(row["required_evidence_types"], sort_keys=True),
                    json.dumps(row["observed_evidence_types"], sort_keys=True),
                    json.dumps(row["missing_evidence_types"], sort_keys=True),
                    row["evidence_count"],
                    row["failing_evidence_count"],
                    row["open_violation_count"],
                    utc_timestamp(row["latest_evidence_at"]),
                    row["freshness_status"],
                    json.dumps(row["stale_evidence_types"], sort_keys=True),
                    json.dumps(row["expired_evidence_types"], sort_keys=True),
                    json.dumps(row["evidence_freshness"], sort_keys=True),
                    row["remediation_sla_hours"],
                    row["next_action"],
                    json.dumps(row["api_refs"], sort_keys=True),
                    utc_timestamp(row["evaluated_at"]),
                )
                for row in control_test_rows
            ],
        )
        _insert_duckdb_rows(
            conn,
            "INSERT INTO evidence_freshness VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    row["event_id"],
                    row["evidence_id"],
                    row["evidence_ref"],
                    row["source"],
                    row["connector_id"],
                    row["event_type"],
                    row["asset_id"],
                    json.dumps(row["control_ids"], sort_keys=True),
                    utc_timestamp(row["evidence_collected_at"]),
                    utc_timestamp(row["evaluated_at"]),
                    row["freshness_slo_minutes"],
                    row["status"],
                    row["score"],
                    row["age_minutes"],
                    utc_timestamp(row["expires_at"]),
                    row["reason"],
                )
                for row in evidence_freshness_rows
            ],
        )
        _insert_duckdb_rows(
            conn, "INSERT INTO metrics VALUES (?, ?)", [(key, str(value)) for key, value in metrics.items()]
        )
        conn.execute(
            """
            CREATE VIEW daily_control_results AS
            SELECT
                CAST(t.evaluated_at AS DATE) AS snapshot_date,
                e.tenant_id, t.program_id, t.framework, t.control_id,
                e.asset_id, t.result, t.confidence_score, t.freshness_status,
                e.evidence_ref, e.raw_sha256 AS evidence_hash, t.evaluated_at
            FROM control_tests t
            JOIN normalized_events e ON EXISTS (
                 SELECT 1 FROM json_each(e.control_ids_json) j
                 WHERE CAST(j.value AS VARCHAR) = '"' || t.control_id || '"'
             )
            """
        )
        conn.execute(
            """
            CREATE VIEW daily_posture_summary AS
            SELECT
                CAST(max(latest_event_time) AS DATE) AS snapshot_date,
                tenant_id, framework,
                count(*) AS control_count,
                sum(CASE WHEN status = 'fail' THEN 1 ELSE 0 END) AS failing_controls,
                sum(CASE WHEN status = 'stale' THEN 1 ELSE 0 END) AS stale_controls,
                round(avg(evidence_coverage), 4) AS evidence_coverage,
                round(avg(risk_score), 2) AS average_risk_score,
                max(latest_event_time) AS evaluated_through
            FROM control_posture
            GROUP BY tenant_id, framework
            """
        )
    return True

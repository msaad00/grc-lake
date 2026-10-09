"""Command line interface for GRC Lake Security Data Lake."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

from security_lakehouse import __version__, strict_json
from security_lakehouse.dashboard import render_dashboard
from security_lakehouse.io import read_jsonl
from security_lakehouse.pipeline import normalize_raw_events, run_pipeline
from security_lakehouse.runtime_environment import runtime_env
from security_lakehouse.validation import validate_raw_events

# Risk vocabulary mirrored from security_lakehouse.db.models (RISK_LEVELS /
# RISK_STATUSES). Duplicated as plain literals so the argument parser can be
# built without importing the 'server' extra (which pulls in SQLAlchemy).
_RISK_LEVEL_CHOICES = ("low", "medium", "high", "critical")
_RISK_STATUS_CHOICES = ("open", "mitigating", "accepted", "closed")


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        from security_lakehouse.distributed.config import ClusterConfig

        if ClusterConfig.from_env() is not None and args.command not in {"cluster", "serve", "scheduler", "db"}:
            raise ValueError(
                "distributed mode uses cluster commands or the authenticated API; local lake commands require local mode"
            )
        return int(args.func(args))
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1


# Mirrors security_lakehouse.db.models.USER_ROLES without importing the optional
# server extra at CLI parse time; tests pin the two together.
_USER_ROLE_CHOICES = ("admin", "security_admin", "compliance_reviewer", "contributor", "auditor", "read_only")
_REVIEW_LAKE_HELP = "apply this lake's org mapping review decisions (default: shipped review status only)"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="grc-lake")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    from security_lakehouse.distributed.commands import register

    register(sub)

    validate = sub.add_parser("validate", help="validate raw JSONL evidence")
    validate.add_argument("--raw", required=True, help="raw security events JSONL")
    validate.set_defaults(func=_validate)

    pipeline = sub.add_parser("pipeline", help="pipeline commands")
    pipeline_sub = pipeline.add_subparsers(dest="pipeline_command", required=True)
    run = pipeline_sub.add_parser("run", help="run bronze/silver/gold pipeline")
    run.add_argument("--raw", required=True, help="raw security events JSONL")
    run.add_argument("--out", required=True, help="security data lake output directory")
    run.add_argument("--mapping", default=None, help="optional control mapping JSON")
    run.set_defaults(func=_run_pipeline)
    pipeline_eval = pipeline_sub.add_parser("eval", help="run scale-aware lake evaluation")
    pipeline_eval.add_argument("--lake", required=True, help="security data lake output directory")
    pipeline_eval.add_argument("--actor", default="cli", help="actor recorded on the eval run")
    pipeline_eval.set_defaults(func=_pipeline_eval)
    verify_integrity = pipeline_sub.add_parser(
        "verify-integrity",
        help="verify evidence hashes, idempotency signals, and artifact integrity",
    )
    verify_integrity.add_argument("--lake", required=True, help="security data lake output directory")
    verify_integrity.set_defaults(func=_verify_pipeline_integrity)
    export_parquet = pipeline_sub.add_parser(
        "export-parquet", help="export verified normalized evidence as a local Parquet bundle"
    )
    export_parquet.add_argument("--lake", required=True, help="single-tenant assessment lake")
    export_parquet.add_argument("--out", required=True, help="new directory outside the lake; never overwritten")
    export_parquet.add_argument("--tenant-id", required=True, help="must match both assessment and evidence tenant")
    export_parquet.add_argument("--batch-size", type=int, default=8192, help="rows per Parquet write batch (1–65536)")
    export_parquet.add_argument(
        "--partitioned", action="store_true", help="partition by tenant, source and UTC event date"
    )
    export_parquet.set_defaults(func=_export_parquet)
    publish_iceberg = pipeline_sub.add_parser(
        "publish-iceberg", help="publish verified evidence to a tenant-scoped Iceberg REST table"
    )
    publish_iceberg.add_argument("--lake", required=True, help="single-tenant assessment lake")
    publish_iceberg.add_argument("--tenant-id", required=True, help="must match evidence, namespace, and table scope")
    publish_iceberg.add_argument("--catalog-uri", required=True, help="HTTPS Iceberg REST catalog endpoint")
    publish_iceberg.add_argument("--warehouse", required=True, help="catalog warehouse name")
    publish_iceberg.add_argument("--namespace", required=True, help="preprovisioned tenant namespace")
    publish_iceberg.add_argument("--table", default="evidence", help="GRC Lake evidence table name")
    publish_iceberg.add_argument(
        "--token-env",
        default="GRC_LAKE_ICEBERG_TOKEN",
        help="environment variable containing a short-lived bearer token",
    )
    publish_iceberg.add_argument(
        "--allow-http-localhost", action="store_true", help="allow loopback HTTP for local catalog testing"
    )
    publish_iceberg.set_defaults(func=_publish_iceberg)

    connectors = sub.add_parser("connectors", help="connector catalog commands")
    connectors_sub = connectors.add_subparsers(dest="connectors_command", required=True)
    connectors_validate = connectors_sub.add_parser("validate", help="validate connector access contracts")
    connectors_validate.add_argument("--catalog", default=None, help="optional connector catalog JSON")
    connectors_validate.set_defaults(func=_connectors_validate)
    connectors_list = connectors_sub.add_parser("list", help="list connector access contracts")
    connectors_list.add_argument("--catalog", default=None, help="optional connector catalog JSON")
    connectors_list.set_defaults(func=_connectors_list)
    connectors_scaffold = connectors_sub.add_parser(
        "scaffold",
        help="generate starter connector adapter files for the in-repo registry",
    )
    connectors_scaffold.add_argument("connector_id", help="connector id slug (e.g. okta-system-log)")
    connectors_scaffold.add_argument("--title", default=None, help="human title for generated module docstring")
    connectors_scaffold.add_argument(
        "--output",
        default="connector-scaffold",
        help="directory to write starter files (default: ./connector-scaffold)",
    )
    connectors_scaffold.set_defaults(func=_connectors_scaffold)
    connectors_configure = connectors_sub.add_parser("configure", help="enable or disable a connector")
    connectors_configure.add_argument("--lake", required=True, help="security data lake output directory")
    connectors_configure.add_argument("--connector-id", required=True, help="connector id from connectors/catalog.json")
    connectors_configure.add_argument("--state", required=True, choices=["enabled", "disabled"], help="connector state")
    connectors_configure.add_argument("--actor", default="cli", help="actor recorded on the configuration event")
    connectors_configure.add_argument(
        "--credentials-json",
        default=None,
        help="JSON object with non-secret connector identity fields and secret references, never raw passwords",
    )
    connectors_configure.add_argument(
        "--options-json",
        default=None,
        help="JSON object with selected read scope, schedule, or connector options",
    )
    connectors_configure.add_argument(
        "--sync-schedule",
        default=None,
        help="optional scheduler expression for continuous connector syncs, for example 'every 15m'",
    )
    connectors_configure.add_argument(
        "--eval-schedule",
        default=None,
        help="lake-wide materialize/eval schedule when split ingest/eval is enabled (default every 6h)",
    )
    connectors_configure.add_argument(
        "--repo", default=None, help="GitHub OWNER/REPO for scheduled github-security sync"
    )
    connectors_configure.add_argument(
        "--fixture-dir",
        default=None,
        help="local fixture directory for scheduled offline connector sync",
    )
    connectors_configure.add_argument(
        "--token-env",
        default=None,
        help="environment variable containing the scheduled connector token",
    )
    connectors_configure.add_argument(
        "--no-materialize",
        action="store_true",
        help="scheduled sync collects raw evidence only; do not rebuild bronze/silver/gold outputs",
    )
    connectors_configure.set_defaults(func=_connectors_configure)
    connectors_discover = connectors_sub.add_parser("discover", help="discover selectable read scopes for a connector")
    connectors_discover.add_argument("--lake", required=True, help="security data lake output directory")
    connectors_discover.add_argument("--connector-id", required=True, help="connector id from connectors/catalog.json")
    connectors_discover.add_argument("--actor", default="cli", help="actor recorded on the discovery event")
    connectors_discover.add_argument("--account-id", default=None, help="AWS account id for aws-posture discovery")
    connectors_discover.add_argument(
        "--subscription-id", default=None, help="Azure subscription id for azure-posture discovery"
    )
    connectors_discover.add_argument("--account", default=None, help="Snowflake account for discovery")
    connectors_discover.add_argument("--user", default=None, help="Snowflake read-only user for discovery")
    connectors_discover.add_argument(
        "--oauth-token-env",
        default=None,
        help="environment variable reference for a Snowflake OAuth token; value is not read by discovery",
    )
    connectors_discover.add_argument("--warehouse", default=None, help="Snowflake warehouse selector")
    connectors_discover.add_argument("--database", default=None, help="Snowflake database selector")
    connectors_discover.add_argument("--schema", default=None, help="Snowflake schema selector")
    connectors_discover.set_defaults(func=_connectors_discover)
    connectors_probe = connectors_sub.add_parser("probe", help="test connector access before enabling it")
    connectors_probe.add_argument("--lake", required=True, help="security data lake output directory")
    connectors_probe.add_argument("--connector-id", required=True, help="connector id from connectors/catalog.json")
    connectors_probe.add_argument("--actor", default="cli", help="actor recorded on the probe event")
    connectors_probe.add_argument(
        "--credentials-json",
        default=None,
        help="JSON object with non-secret connector identity fields and secret references, never raw passwords",
    )
    connectors_probe.add_argument(
        "--options-json",
        default=None,
        help="JSON object with selected read scope or connector options",
    )
    connectors_probe.set_defaults(func=_connectors_probe)
    connectors_sync = connectors_sub.add_parser("sync", help="run a configured connector into the managed raw lake")
    connectors_sync.add_argument("--lake", required=True, help="security data lake output directory")
    connectors_sync.add_argument("--connector-id", required=True, help="connector id from connectors/catalog.json")
    connectors_sync.add_argument("--repo", default=None, help="GitHub OWNER/REPO for github-security")
    connectors_sync.add_argument(
        "--fixture-dir", default=None, help="local fixture directory for offline connector sync"
    )
    connectors_sync.add_argument(
        "--token-env",
        default="__provider_default__",
        help="override the provider-specific connector token environment variable",
    )
    connectors_sync.add_argument("--actor", default="cli", help="actor recorded on the connector run")
    connectors_sync.add_argument(
        "--no-materialize",
        action="store_true",
        help="collect raw evidence only; do not rebuild bronze/silver/gold outputs",
    )
    connectors_sync.set_defaults(func=_connectors_sync)

    lake = sub.add_parser("lake", help="bring-your-own-lake mapping commands (experimental)")
    lake_sub = lake.add_subparsers(dest="lake_command", required=True)
    retention = lake_sub.add_parser(
        "retention", help="report generation storage or explicitly archive old unreferenced generations"
    )
    retention.add_argument("--lake", required=True)
    retention.add_argument("--older-than-days", type=int, default=90)
    retention.add_argument("--keep-latest", type=int, default=3)
    retention.add_argument("--archive-to", default=None, help="external archive destination; omitted means report only")
    retention.set_defaults(func=_lake_retention)
    operational_retention = lake_sub.add_parser(
        "operational-retention", help="preview or archive old job payloads and request-audit rows"
    )
    operational_retention.add_argument("--lake", required=True)
    operational_retention.add_argument("--older-than-days", type=int, default=90)
    operational_retention.add_argument(
        "--archive-to", default=None, help="external archive destination; omitted means preview"
    )
    operational_retention.set_defaults(func=_operational_retention)
    lake_map = lake_sub.add_parser(
        "map",
        help="validate a lake mapping and preview mapped rows (--dry-run; writes nothing)",
    )
    lake_map_source = lake_map.add_mutually_exclusive_group(required=True)
    lake_map_source.add_argument("--mapping", default=None, help="mapping spec file (.json, .yaml, .yml)")
    lake_map_source.add_argument("--preset", default=None, help="built-in preset, for example ocsf/api_activity")
    lake_map_source.add_argument(
        "--connector-id", default=None, help="preview the mapping(s) configured on this connector in --lake"
    )
    lake_map.add_argument("--table", default=None, help="source table for --preset (namespace.table)")
    lake_map.add_argument("--input", default=None, help="sample source rows (.json list, .jsonl, or .parquet)")
    lake_map.add_argument("--lake", default=None, help="security data lake directory (with --connector-id)")
    lake_map.add_argument(
        "--fixture-dir", default=None, help="fixture directory for --connector-id instead of the live source"
    )
    lake_map.add_argument(
        "--dialect",
        default="snowflake",
        choices=["snowflake", "databricks", "clickhouse", "bigquery"],
        help="SQL dialect for the compiled query shown in the preview (default snowflake)",
    )
    lake_map.add_argument("--since", default=None, help="ISO-8601 watermark to preview an incremental read from")
    lake_map.add_argument("--limit", type=int, default=5, help="mapped rows to show (default 5)")
    lake_map.add_argument("--dry-run", action="store_true", help="preview only; required in this version")
    lake_map.set_defaults(func=_lake_map)
    lake_presets = lake_sub.add_parser("presets", help="list built-in mapping presets")
    lake_presets.set_defaults(func=_lake_presets)

    ingestion = sub.add_parser("ingestion", help="ingestion strategy commands")
    ingestion_sub = ingestion.add_subparsers(dest="ingestion_command", required=True)
    ingestion_plan = ingestion_sub.add_parser("plan", help="resolve per-source ingestion method + cost rationale")
    ingestion_plan.add_argument("--lake", default=None, help="optional lake directory (unused; catalog is global)")
    ingestion_plan.add_argument("--catalog", default=None, help="optional connector catalog JSON")
    ingestion_plan.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    ingestion_plan.set_defaults(func=_ingestion_plan)
    ingestion_normalize = ingestion_sub.add_parser(
        "normalize",
        help="normalize canonical raw evidence into bronze/silver/gold lake zones",
    )
    ingestion_normalize.add_argument("--raw", required=True, help="canonical raw security events JSONL")
    ingestion_normalize.add_argument("--out", required=True, help="security data lake output directory")
    ingestion_normalize.add_argument("--mapping", default=None, help="optional control mapping JSON")
    ingestion_normalize.add_argument("--tenant-id", default="default", help="tenant recorded in analytical marts")
    ingestion_normalize.add_argument(
        "--incremental",
        action="store_true",
        help="materialize only changed raw evidence when a prior manifest exists",
    )
    ingestion_normalize.set_defaults(func=_ingestion_normalize)

    scenario = sub.add_parser("scenario", help="run repeatable GRC Lake proof scenarios")
    scenario_sub = scenario.add_subparsers(dest="scenario_command", required=True)
    scenario_run = scenario_sub.add_parser("run", help="run a named scenario and emit a JSON report")
    scenario_run.add_argument("name", choices=["live-cloud-posture"], help="scenario name")
    scenario_run.add_argument("--lake", required=True, help="security data lake output directory")
    scenario_run.add_argument(
        "--connector",
        action="append",
        default=None,
        help="connector id to run; repeatable. Defaults to Azure, AWS, and Snowflake posture connectors.",
    )
    scenario_run.add_argument(
        "--fixture",
        action="append",
        default=None,
        help="offline fixture binding as connector_id=path; repeatable for CI or local demos",
    )
    scenario_run.add_argument("--actor", default="scenario", help="actor recorded on connector/workflow events")
    scenario_run.add_argument(
        "--continue-on-error",
        action="store_true",
        help="keep running later connectors and write a partial report if one connector fails",
    )
    scenario_run.add_argument(
        "--summary",
        action="store_true",
        help="emit a concise operator summary instead of the full JSON report",
    )
    scenario_run.set_defaults(func=_scenario_run)

    controls = sub.add_parser("controls", help="control catalog commands")
    controls_sub = controls.add_subparsers(dest="controls_command", required=True)
    controls_provenance = controls_sub.add_parser("provenance", help="list controls missing source provenance")
    controls_provenance.add_argument("--lake", default=None, help="optional lake directory (unused; catalog is global)")
    controls_provenance.add_argument("--catalog", default=None, help="optional control catalog JSON")
    controls_provenance.set_defaults(func=_controls_provenance)
    controls_applies = controls_sub.add_parser("applies-to", help="list controls that apply to an asset type")
    controls_applies.add_argument("--asset-type", required=True, help="asset type, e.g. iam_role, ai_model")
    controls_applies.add_argument("--catalog", default=None, help="optional control catalog JSON")
    controls_applies.set_defaults(func=_controls_applies_to)
    controls_history = controls_sub.add_parser("history", help="show every version of a control (active + retired)")
    controls_history.add_argument("--control-id", required=True, help="control id, e.g. SOC2-CC6.1")
    controls_history.set_defaults(func=_controls_history)
    controls_as_of = controls_sub.add_parser("as-of", help="control versions in force on a given date")
    controls_as_of.add_argument("--date", required=True, help="ISO date, e.g. 2026-03-15")
    controls_as_of.set_defaults(func=_controls_as_of)

    catalog_cmd = sub.add_parser("catalog", help="versioned catalog bundle commands")
    catalog_sub = catalog_cmd.add_subparsers(dest="catalog_command", required=True)
    catalog_bundle = catalog_sub.add_parser("bundle", help="print the content-addressed catalog bundle")
    catalog_bundle.add_argument("--as-of", default=None, help="bundle the control set in force on this ISO date")
    catalog_bundle.add_argument("--full", action="store_true", help="include per-control/per-framework version rows")
    catalog_bundle.set_defaults(func=_catalog_bundle)
    catalog_lock = catalog_sub.add_parser("lock", help="(re)write the bundle lockfile from the active catalog")
    catalog_lock.set_defaults(func=_catalog_lock)
    catalog_verify = catalog_sub.add_parser("verify", help="verify the active catalog matches the committed lockfile")
    catalog_verify.set_defaults(func=_catalog_verify)

    oscal = sub.add_parser("oscal", help="NIST OSCAL export commands")
    oscal_sub = oscal.add_subparsers(dest="oscal_command", required=True)
    oscal_export = oscal_sub.add_parser(
        "export", help="export an OSCAL component-definition or assessment-results JSON document"
    )
    oscal_export.add_argument(
        "--component-definition",
        action="store_true",
        help="emit an OSCAL component-definition from the CCF safeguards + control catalog",
    )
    oscal_export.add_argument(
        "--assessment-results",
        metavar="LAKE",
        default=None,
        help="emit OSCAL assessment-results from this security data lake's evaluated control posture",
    )
    oscal_export.add_argument(
        "--snapshot",
        default=None,
        help="with --assessment-results, pin metadata to a point-in-time snapshot id (default: current posture)",
    )
    oscal_export.add_argument(
        "--lake",
        default=None,
        help="with --component-definition, include this lake's org-reviewed mappings (and withhold org rejections)",
    )
    oscal_export.add_argument("--out", default=None, help="write JSON to this path (default stdout)")
    oscal_export.set_defaults(func=_oscal_export)

    dashboard = sub.add_parser("dashboard", help="render static dashboard HTML")
    dashboard.add_argument("--lake", required=True, help="security data lake output directory")
    dashboard.add_argument("--out", required=True, help="dashboard HTML output path")
    dashboard.set_defaults(func=_dashboard)

    query = sub.add_parser("query", help="run read-only SQL against the analytics mart")
    query.add_argument("--lake", required=True, help="security data lake output directory")
    query.add_argument("--engine", choices=["sqlite", "duckdb"], default="sqlite", help="local mart engine")
    query.add_argument("sql", help="SQL SELECT statement")
    query.set_defaults(func=_query)

    serve = sub.add_parser("serve", help="serve the interactive console and assessment API")
    serve.add_argument("--lake", required=True, help="security data lake output directory")
    serve.add_argument("--host", default="127.0.0.1", help="bind host")
    serve.add_argument("--port", type=int, default=8787, help="bind port")
    serve.add_argument(
        "--server",
        action="store_true",
        help="run server mode on FastAPI/uvicorn (requires the 'server' extra) instead of the stdlib server",
    )
    serve.add_argument(
        "--allow-insecure-no-auth",
        action="store_true",
        help="server mode only: disable authentication (local development only)",
    )
    serve.set_defaults(func=_serve)

    aibom = sub.add_parser("aibom", help="local CycloneDX/SPDX AI bill of materials commands")
    aibom_sub = aibom.add_subparsers(dest="aibom_command", required=True)
    aibom_import = aibom_sub.add_parser("import", help="import a JSON AIBOM into the local lake")
    aibom_import.add_argument("--input", required=True, help="CycloneDX or SPDX 3 JSON input")
    aibom_import.add_argument("--lake", required=True, help="security data lake output directory")
    aibom_import.set_defaults(func=_aibom_import)
    aibom_export = aibom_sub.add_parser("export", help="export the lake's canonical AIBOM inventory")
    aibom_export.add_argument("--lake", required=True, help="security data lake output directory")
    aibom_export.add_argument("--out", required=True, help="output JSON path")
    aibom_export.add_argument("--format", required=True, choices=["cyclonedx-1.7", "spdx-3.0.1"])
    aibom_export.set_defaults(func=_aibom_export)

    assessment = sub.add_parser("assessment", help="continuous compliance assessment commands")
    assessment_sub = assessment.add_subparsers(dest="assessment_command", required=True)
    workpaper = assessment_sub.add_parser("workpaper", help="export a reproducible auditor workpaper (JSON and HTML)")
    workpaper.add_argument("--lake", required=True)
    workpaper.add_argument("--plan", required=True)
    workpaper.add_argument("--baseline", required=True)
    workpaper.add_argument("--out", required=True, help="new directory outside the lake")
    workpaper.set_defaults(func=_assessment_workpaper)
    verify_workpaper = assessment_sub.add_parser("verify-workpaper", help="verify exported workpaper file hashes")
    verify_workpaper.add_argument("--dir", required=True)
    verify_workpaper.set_defaults(func=_assessment_verify_workpaper)
    restore = assessment_sub.add_parser(
        "restore-snapshots", help="recover ledger-named historical exports without changing the ledger"
    )
    restore.add_argument("--lake", required=True)
    restore.add_argument("--source", required=True)
    restore.set_defaults(func=_evidence_recovery)
    migrate = assessment_sub.add_parser("migrate-workpaper", help="re-render a legacy workpaper into a new export")
    migrate.add_argument("--source", required=True)
    migrate.add_argument("--out", required=True)
    migrate.add_argument("--content", default=None)
    migrate.set_defaults(func=_evidence_recovery)
    checkpoint = assessment_sub.add_parser("checkpoint", help="write a checkpoint to retain independently")
    checkpoint.add_argument("--lake", required=True)
    checkpoint.add_argument("--out", required=True)
    checkpoint.set_defaults(func=_evidence_recovery)
    check = assessment_sub.add_parser("verify-checkpoint", help="compare against an independently retained checkpoint")
    check.add_argument("--lake", required=True)
    check.add_argument("--checkpoint", required=True)
    check.set_defaults(func=_evidence_recovery)
    population = assessment_sub.add_parser("population", help="reconcile declared inventory against collected evidence")
    population.add_argument("--lake", required=True)
    population.add_argument("--baseline", required=True)
    population.add_argument("--details-limit", type=int, default=100)
    population.set_defaults(func=_assessment_population)
    control_plan = assessment_sub.add_parser("test-plan", help="produce draft design and period-test workpapers")
    control_plan.add_argument("--lake", required=True)
    control_plan.add_argument("--plan", required=True, help="versioned control test plan JSON")
    control_plan.set_defaults(func=_assessment_test_plan)
    status = assessment_sub.add_parser("status", help="print current posture")
    status.add_argument("--lake", required=True, help="security data lake output directory")
    status.add_argument("--freshness-days", type=int, default=7, help="evidence freshness window")
    status.add_argument("--format", choices=["json", "summary"], default="json", help="output format (default: json)")
    status.set_defaults(func=_assessment_status)
    snapshot = assessment_sub.add_parser("snapshot", help="write point-in-time assessment snapshot")
    snapshot.add_argument("--lake", required=True, help="security data lake output directory")
    snapshot.add_argument("--out", default=None, help="snapshot output path")
    snapshot.add_argument("--freshness-days", type=int, default=7, help="evidence freshness window")
    snapshot.add_argument("--reason", default="manual", help="snapshot reason")
    snapshot.set_defaults(func=_assessment_snapshot)
    verify_snapshots = assessment_sub.add_parser("verify-snapshots", help="verify the append-only snapshot hash-chain")
    verify_snapshots.add_argument("--lake", required=True, help="security data lake output directory")
    verify_snapshots.set_defaults(func=_assessment_verify_snapshots)
    reconcile = assessment_sub.add_parser(
        "reconcile-snapshots", help="preview or quarantine uncommitted snapshots without changing the ledger"
    )
    reconcile.add_argument("--lake", required=True, help="security data lake output directory")
    reconcile.add_argument("--apply", action="store_true", help="quarantine unledgered files; otherwise preview only")
    reconcile.set_defaults(func=_assessment_reconcile_snapshots)
    verify_tracking = assessment_sub.add_parser("verify-tracking", help="verify the append-only triage hash-chain")
    verify_tracking.add_argument("--lake", required=True, help="security data lake output directory")
    verify_tracking.set_defaults(func=_assessment_verify_tracking)
    posture_as_of = assessment_sub.add_parser(
        "posture-as-of", help="posture as of a point in time (newest snapshot at-or-before --as-of)"
    )
    posture_as_of.add_argument("--lake", required=True, help="security data lake output directory")
    posture_as_of.add_argument("--as-of", required=True, help="ISO date or datetime, e.g. 2026-04-15")
    posture_as_of.set_defaults(func=_assessment_posture_as_of)
    violations = assessment_sub.add_parser("violations", help="list open framework/control violations")
    violations.add_argument("--lake", required=True, help="security data lake output directory")
    violations.add_argument("--framework", default=None, help="optional framework filter")
    violations.set_defaults(func=_assessment_violations)
    tests = assessment_sub.add_parser("tests", help="list continuous control tests")
    tests.add_argument("--lake", required=True, help="security data lake output directory")
    tests.add_argument(
        "--result", default=None, choices=["pass", "fail", "needs_evidence"], help="optional result filter"
    )
    tests.set_defaults(func=_assessment_tests)
    stale_evidence = assessment_sub.add_parser("stale-evidence", help="list stale, expired, or missing evidence")
    stale_evidence.add_argument("--lake", required=True, help="security data lake output directory")
    stale_evidence.add_argument(
        "--status",
        default=None,
        choices=["fresh", "stale", "expired", "missing"],
        help="optional freshness status filter",
    )
    stale_evidence.set_defaults(func=_assessment_stale_evidence)

    fixtures = sub.add_parser("fixtures", help="mockup company fixture commands")
    fixtures_sub = fixtures.add_subparsers(dest="fixtures_command", required=True)
    fixtures_list = fixtures_sub.add_parser("list", help="list available mockup company fixtures")
    fixtures_list.set_defaults(func=_fixtures_list)
    fixtures_load = fixtures_sub.add_parser("load", help="pipe a mockup company fixture through the pipeline")
    fixtures_load.add_argument("--company", required=True, help="company directory under mockup_companies/")
    fixtures_load.add_argument("--out", required=True, help="security data lake output directory")
    fixtures_load.add_argument("--tenant-id", default="default", help="platform tenant owning this fixture generation")
    fixtures_load.add_argument(
        "--rebase-times",
        action="store_true",
        help="shift fixture timestamps so the newest event is three hours old (demo posture stays stable for about a day)",
    )
    fixtures_load.add_argument(
        "--no-demo-records",
        action="store_true",
        help="golden only: skip seeding synthetic remediation, risk, policy, vendor, and metrics records",
    )
    fixtures_load.set_defaults(func=_fixtures_load)
    fixtures_write_golden = fixtures_sub.add_parser(
        "write-golden",
        help="regenerate mockup_companies/golden/raw/security_events.jsonl (37 dashboard controls)",
    )
    fixtures_write_golden.add_argument(
        "--root",
        default=None,
        help="mockup_companies root (default: repository mockup_companies/)",
    )
    fixtures_write_golden.set_defaults(func=_fixtures_write_golden)
    fixtures_synthesize = fixtures_sub.add_parser(
        "synthesize-scale",
        help="stream synthetic audit-scale raw evidence (millions of events)",
    )
    fixtures_synthesize.add_argument("--count", type=int, required=True, help="number of raw events to generate")
    fixtures_synthesize.add_argument("--out", required=True, help="output JSONL path")
    fixtures_synthesize.add_argument("--tenant-id", default="audit-scale", help="tenant id stamped on each event")
    fixtures_synthesize.add_argument(
        "--controls-per-event",
        type=int,
        default=2,
        help="how many catalog controls to attach per event (finding fan-out multiplier)",
    )
    fixtures_synthesize.add_argument(
        "--open-ratio",
        type=float,
        default=0.12,
        help="fraction of events with open/failed/blocked/noncompliant status",
    )
    fixtures_synthesize.add_argument(
        "--framework-prefix",
        default=None,
        help="optional control id prefix filter (e.g. SOC2-CC)",
    )
    fixtures_synthesize.add_argument("--seed", type=int, default=42, help="random seed for reproducible lakes")
    fixtures_synthesize.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    fixtures_synthesize.set_defaults(func=_fixtures_synthesize_scale)

    benchmark = sub.add_parser("benchmark", help="throughput and latency benchmarks")
    benchmark_sub = benchmark.add_subparsers(dest="benchmark_command", required=True)
    benchmark_plan = benchmark_sub.add_parser("plan", help="project finding cardinality for an event volume")
    benchmark_plan.add_argument("--events", type=int, required=True, help="projected raw event count")
    benchmark_plan.add_argument("--controls-per-event", type=int, default=2)
    benchmark_plan.add_argument("--open-ratio", type=float, default=0.12)
    benchmark_plan.add_argument("--json", action="store_true")
    benchmark_plan.set_defaults(func=_benchmark_plan)
    benchmark_pipeline = benchmark_sub.add_parser("pipeline", help="time a full lake pipeline run")
    benchmark_pipeline.add_argument("--raw", required=True, help="raw evidence JSONL input path")
    benchmark_pipeline.add_argument("--out", required=True, help="lake output directory")
    benchmark_pipeline.add_argument("--tenant-id", default="audit-scale")
    benchmark_pipeline.add_argument("--json", action="store_true")
    benchmark_pipeline.set_defaults(func=_benchmark_pipeline)

    repo = sub.add_parser("repo", help="public repository audit commands")
    repo_sub = repo.add_subparsers(dest="repo_command", required=True)
    repo_audit = repo_sub.add_parser("audit", help="audit a public GitHub repository without credentials")
    repo_audit.add_argument("repo", help="public GitHub URL or OWNER/REPO")
    repo_audit.add_argument("--out", required=True, help="raw evidence JSONL output path")
    repo_audit.add_argument("--fixture-dir", default=None, help="local fixture directory for offline tests and demos")
    repo_audit.set_defaults(func=_repo_audit)
    repo_governance = repo_sub.add_parser(
        "governance-sync", help="sync authenticated GitHub/GitLab repository governance evidence"
    )
    repo_governance.add_argument("repo", help="GitHub or GitLab URL or NAMESPACE/PROJECT")
    repo_governance.add_argument("--out", required=True, help="raw evidence JSONL output path")
    repo_governance.add_argument("--fixture-dir", default=None, help="local fixture directory for offline tests")
    repo_governance.add_argument(
        "--provider",
        choices=("github", "gitlab"),
        default=None,
        help="force provider when the repo string is ambiguous",
    )
    repo_governance.add_argument(
        "--token-env",
        default=None,
        help="environment variable containing the access token (defaults by provider)",
    )
    repo_governance.set_defaults(func=_repo_governance_sync)

    frameworks = sub.add_parser("frameworks", help="framework registry commands")
    frameworks_sub = frameworks.add_subparsers(dest="frameworks_command", required=True)
    frameworks_sync = frameworks_sub.add_parser(
        "sync", help="re-fetch official sources, recompute sha256, record source changes"
    )
    frameworks_sync.add_argument(
        "--allow-network",
        action="store_true",
        help="fetch official sources (default is offline = mark every framework skipped)",
    )
    frameworks_sync.set_defaults(func=_frameworks_sync)
    frameworks_readiness = frameworks_sub.add_parser("readiness", help="show staged readiness gates per framework")
    frameworks_readiness.set_defaults(func=_frameworks_readiness)
    frameworks_coverage = frameworks_sub.add_parser("coverage", help="show the source-linked framework coverage ledger")
    frameworks_coverage.add_argument("--format", choices=["json", "markdown"], default="json", help="output format")
    frameworks_coverage.add_argument("--lake", default=None, help=_REVIEW_LAKE_HELP)
    frameworks_coverage.set_defaults(func=_frameworks_coverage)
    frameworks_review = frameworks_sub.add_parser(
        "review-queue",
        help="list proposed mappings with anchors and available source provenance",
    )
    frameworks_review.add_argument("--framework", default=None, help="filter to one framework_id")
    frameworks_review.add_argument(
        "--risk-domain",
        default=None,
        help="filter to one normalized category/family (for example governance or identity)",
    )
    frameworks_review.add_argument("--lake", default=None, help=_REVIEW_LAKE_HELP)
    frameworks_review.set_defaults(func=_frameworks_review_queue)
    from security_lakehouse.safeguards import REVIEW_STATE_DEFINITIONS, REVIEW_STATE_LABELS

    review = frameworks_sub.add_parser(
        "review",
        help="record org mapping review decisions (approve/reject/needs-changes) or export the decision log",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="review states:\n"
        + "\n".join(
            f"  {REVIEW_STATE_LABELS[state]}: {definition}" for state, definition in REVIEW_STATE_DEFINITIONS.items()
        ),
    )
    review_sub = review.add_subparsers(dest="review_command", required=True)
    for verb, decision in (("approve", "approve"), ("reject", "reject"), ("needs-changes", "needs_changes")):
        decide = review_sub.add_parser(verb, help=f"record a {verb} decision for one safeguard mapping")
        decide.add_argument("--lake", required=True, help="lake whose decision log records the decision")
        decide.add_argument("--safeguard", required=True, help="safeguard_id, e.g. SG-IDENTITY-001")
        decide.add_argument("--framework", required=True, help="framework_id of the requirement")
        decide.add_argument("--control", required=True, help="requirement control_id")
        decide.add_argument("--rationale", required=True, help="why (required; recorded in the audit trail)")
        decide.add_argument("--reviewer", required=True, help="who is deciding (local mode has no login)")
        decide.add_argument("--evidence-ref", default=None, help="optional evidence or ticket reference")
        decide.set_defaults(func=_frameworks_review_decide, decision=decision)
    review_export = review_sub.add_parser("export", help="export the decision log with its chain verification")
    review_export.add_argument("--lake", required=True, help="lake whose decision log to export")
    review_export.add_argument("--format", choices=["json", "csv"], default="json", help="output format")
    review_export.add_argument("--out", default=None, help="write to this path (default stdout)")
    review_export.set_defaults(func=_frameworks_review_export)
    review_resign = review_sub.add_parser(
        "resign",
        help="re-sign the decision log tip with the current GRC_LAKE_COOKIE_SIGNING_KEY after rotating it",
    )
    review_resign.add_argument("--lake", required=True, help="lake whose decision log to re-sign")
    review_resign.add_argument(
        "--previous-key-env",
        required=True,
        help="environment variable holding the signing key in use before the rotation",
    )
    review_resign.add_argument("--actor", default=None, help="who is re-signing (default: the OS user)")
    review_resign.set_defaults(func=_frameworks_review_resign)
    controls_ccf = frameworks_sub.add_parser(
        "safeguards",
        help="show Common Control Framework coverage (safeguards -> framework requirements)",
    )
    controls_ccf.add_argument("--format", choices=["json", "table"], default="json", help="output format")
    controls_ccf.add_argument("--lake", default=None, help=_REVIEW_LAKE_HELP)
    controls_ccf.set_defaults(func=_frameworks_safeguards)
    ccf_assessment = frameworks_sub.add_parser(
        "assessment", help="read published CCF results within observed asset scope"
    )
    ccf_assessment.add_argument("--lake", required=True)
    ccf_assessment.set_defaults(func=_frameworks_assessment)
    frameworks_enrich = frameworks_sub.add_parser(
        "enrich",
        help="fill placeholder control titles from public-domain NIST catalogs (network opt-in)",
    )
    frameworks_enrich.add_argument(
        "--allow-network",
        action="store_true",
        help="fetch the NIST OSCAL catalogs; without it the command only reports what would change",
    )
    frameworks_enrich.add_argument("--apply", action="store_true", help="write the enriched titles")
    frameworks_enrich.set_defaults(func=_frameworks_enrich)
    frameworks_sync_packs = frameworks_sub.add_parser(
        "sync-packs",
        help="merge full framework packs (SOC 2, NIST AI RMF, FedRAMP, CIS AWS, ISO) into the control catalog",
    )
    from security_lakehouse.framework_packs import PACK_BUILDERS

    frameworks_sync_packs.add_argument(
        "--pack",
        action="append",
        choices=sorted(PACK_BUILDERS),
        help="pack to sync (default: all full + limited packs)",
    )
    frameworks_sync_packs.set_defaults(func=_frameworks_sync_packs)

    scheduler = sub.add_parser("scheduler", help="connector sync, lake eval, and cron workflow scheduler")
    scheduler_sub = scheduler.add_subparsers(dest="scheduler_command", required=True)
    scheduler_tick_cmd = scheduler_sub.add_parser(
        "tick", help="fire every due connector sync, lake eval, and cron workflow once"
    )
    scheduler_tick_cmd.add_argument("--lake", required=True, help="security data lake output directory")
    scheduler_tick_cmd.add_argument(
        "--all-tenants", action="store_true", help="schedule registered tenants from the server lake root"
    )
    scheduler_tick_cmd.set_defaults(func=_scheduler_tick)
    scheduler_run_cmd = scheduler_sub.add_parser("run", help="run the scheduler daemon")
    scheduler_run_cmd.add_argument("--lake", required=True, help="security data lake output directory")
    scheduler_run_cmd.add_argument("--tick-seconds", type=int, default=60, help="seconds between ticks (default 60)")
    scheduler_run_cmd.add_argument(
        "--all-tenants", action="store_true", help="schedule registered tenants from the server lake root"
    )
    scheduler_run_cmd.set_defaults(func=_scheduler_run)
    repair = scheduler_sub.add_parser("repair-history", help="quarantine torn runtime tails and defer scheduled work")
    repair.add_argument("--lake", required=True, help="one tenant lake; evidence ledgers are never repaired")
    repair.set_defaults(func=_scheduler_repair_history)

    db = sub.add_parser("db", help="server-mode application-state database (requires the 'server' extra)")
    db_sub = db.add_subparsers(dest="db_command", required=True)
    db_upgrade = db_sub.add_parser("upgrade", help="create/upgrade the application-state schema")
    db_upgrade.add_argument("--lake", required=True, help="security data lake output directory")
    db_upgrade.add_argument("--revision", default="head", help="target Alembic revision (default head)")
    db_upgrade.set_defaults(func=_db_upgrade)
    db_current = db_sub.add_parser("current", help="print the current application-state schema revision")
    db_current.add_argument("--lake", required=True, help="security data lake output directory")
    db_current.set_defaults(func=_db_current)

    auth = sub.add_parser("auth", help="server-mode auth: tenants, users, API keys (requires the 'server' extra)")
    auth_sub = auth.add_subparsers(dest="auth_command", required=True)
    auth_tenant = auth_sub.add_parser("create-tenant", help="create a tenant/workspace")
    auth_tenant.add_argument("--lake", required=True, help="security data lake output directory")
    auth_tenant.add_argument("--slug", required=True, help="unique tenant slug")
    auth_tenant.add_argument("--name", required=True, help="tenant display name")
    auth_tenant.set_defaults(func=_auth_create_tenant)
    auth_user = auth_sub.add_parser("create-user", help="create a user in a tenant")
    auth_user.add_argument("--lake", required=True, help="security data lake output directory")
    auth_user.add_argument("--tenant-slug", required=True, help="tenant slug")
    auth_user.add_argument("--email", required=True, help="user email (unique within the tenant)")
    auth_user.add_argument("--display-name", default="", help="user display name")
    auth_user.add_argument(
        "--role",
        default="read_only",
        choices=list(_USER_ROLE_CHOICES),
        help="role: " + "/".join(_USER_ROLE_CHOICES),
    )
    auth_user.set_defaults(func=_auth_create_user)
    auth_key = auth_sub.add_parser("issue-key", help="mint an API key for a user")
    auth_key.add_argument("--lake", required=True, help="security data lake output directory")
    auth_key.add_argument("--tenant-slug", required=True, help="tenant slug")
    auth_key.add_argument("--email", required=True, help="user email the key acts as")
    auth_key.add_argument("--name", default="", help="key label")
    auth_key.add_argument("--expires-days", type=int, default=None, help="optional expiry in days")
    auth_key.set_defaults(func=_auth_issue_key)
    auth_revoke = auth_sub.add_parser("revoke-key", help="revoke an API key by id")
    auth_revoke.add_argument("--lake", required=True, help="security data lake output directory")
    auth_revoke.add_argument("--tenant-slug", required=True, help="tenant slug")
    auth_revoke.add_argument("--key-id", required=True, help="API key id")
    auth_revoke.set_defaults(func=_auth_revoke_key)
    auth_list = auth_sub.add_parser("list-keys", help="list API keys for a tenant")
    auth_list.add_argument("--lake", required=True, help="security data lake output directory")
    auth_list.add_argument("--tenant-slug", required=True, help="tenant slug")
    auth_list.set_defaults(func=_auth_list_keys)

    platform = sub.add_parser("platform", help="server-mode platform bootstrap commands")
    platform_sub = platform.add_subparsers(dest="platform_command", required=True)
    seed_dev = platform_sub.add_parser("seed-dev", help="seed a local dev tenant, admin user, and API key")
    seed_dev.add_argument("--lake", required=True, help="security data lake output directory")
    seed_dev.add_argument("--tenant-slug", default="dev", help="tenant slug")
    seed_dev.add_argument("--tenant-name", default="Development", help="tenant display name")
    seed_dev.add_argument("--email", default="admin@localhost", help="admin user email")
    seed_dev.add_argument("--display-name", default="Local Admin", help="admin user display name")
    seed_dev.set_defaults(func=_platform_seed_dev)

    risk = sub.add_parser("risk", help="server-mode GRC risk register (requires the 'server' extra)")
    risk_sub = risk.add_subparsers(dest="risk_command", required=True)
    risk_list = risk_sub.add_parser("list", help="list risks in a tenant register")
    risk_list.add_argument("--lake", required=True, help="security data lake output directory")
    risk_list.add_argument("--tenant", required=True, help="tenant slug")
    risk_list.add_argument("--status", default=None, choices=list(_RISK_STATUS_CHOICES), help="optional status filter")
    risk_list.add_argument(
        "--severity", default=None, choices=list(_RISK_LEVEL_CHOICES), help="optional severity filter"
    )
    risk_list.add_argument("--owner", default=None, help="optional owner filter")
    risk_list.set_defaults(func=_risk_list)
    risk_add = risk_sub.add_parser("add", help="add a risk to a tenant register")
    risk_add.add_argument("--lake", required=True, help="security data lake output directory")
    risk_add.add_argument("--tenant", required=True, help="tenant slug")
    risk_add.add_argument("--title", required=True, help="risk title")
    risk_add.add_argument("--description", default="", help="risk description")
    risk_add.add_argument("--category", default="", help="risk category")
    risk_add.add_argument("--severity", default="medium", choices=list(_RISK_LEVEL_CHOICES), help="risk severity")
    risk_add.add_argument("--likelihood", default="medium", choices=list(_RISK_LEVEL_CHOICES), help="risk likelihood")
    risk_add.add_argument("--impact", default="medium", choices=list(_RISK_LEVEL_CHOICES), help="risk impact")
    risk_add.add_argument("--owner", default="", help="risk owner")
    risk_add.add_argument("--control-id", default=None, help="linked control id")
    risk_add.set_defaults(func=_risk_add)

    workflow = sub.add_parser("workflow", help="lake-backed automation workflow engine")
    workflow_sub = workflow.add_subparsers(dest="workflow_command", required=True)
    workflow_list = workflow_sub.add_parser("list", help="list saved workflows (latest version per workflow)")
    workflow_list.add_argument("--lake", required=True, help="security data lake output directory")
    workflow_list.set_defaults(func=_workflow_list)
    workflow_run = workflow_sub.add_parser("run", help="execute a saved workflow and print the run record")
    workflow_run.add_argument("--lake", required=True, help="security data lake output directory")
    workflow_run.add_argument("--id", required=True, dest="workflow_id", help="workflow_id to run")
    workflow_run.add_argument("--actor", default="api", choices=["api", "console", "scheduler"], help="run actor")
    workflow_run.set_defaults(func=_workflow_run)

    agents = sub.add_parser("agents", help="optional human/headless agent harness")
    agents_sub = agents.add_subparsers(dest="agents_command", required=True)
    agents_review = agents_sub.add_parser(
        "posture-review",
        help="run the rules-only posture review harness and propose approval-gated actions",
    )
    agents_review.add_argument("--lake", required=True, help="security data lake output directory")
    agents_review.add_argument(
        "--role",
        default="read_only",
        choices=list(_USER_ROLE_CHOICES),
        help="role lens used for redaction",
    )
    agents_review.add_argument(
        "--objective",
        default="Review posture and propose evidence-gap actions.",
        help="agent objective recorded in the run state",
    )
    agents_review.add_argument(
        "--orchestrator",
        default="sequential",
        choices=["sequential", "langgraph"],
        help="deterministic node orchestrator; langgraph requires the agents extra",
    )
    agents_review.add_argument("--provider", default=None, help="override GRC_LAKE_AGENT_PROVIDER")
    agents_review.add_argument("--model", default=None, help="override GRC_LAKE_AGENT_MODEL")
    agents_review.add_argument("--base-url", default=None, help="override GRC_LAKE_AGENT_BASE_URL")
    agents_review.add_argument("--api-key-env", default=None, help="override GRC_LAKE_AGENT_API_KEY_ENV")
    agents_review.add_argument(
        "--use-model",
        action="store_true",
        help="call the configured model provider; default is deterministic rules-only",
    )
    agents_review.add_argument(
        "--max-context-chars",
        type=int,
        default=None,
        help="maximum serialized model context size before the model call is skipped",
    )
    agents_review.add_argument(
        "--max-fact-items",
        type=int,
        default=None,
        help="maximum evidence/alert/decision items included in model context",
    )
    agents_review.add_argument(
        "--max-output-tokens",
        type=int,
        default=None,
        help="maximum model output tokens requested from the provider",
    )
    agents_review.add_argument(
        "--checkpoint-thread",
        default=None,
        help="LangGraph MemorySaver thread id (enables checkpoint/resume for long reviews)",
    )
    agents_review.add_argument(
        "--resume",
        action="store_true",
        help="resume a prior LangGraph checkpoint for --checkpoint-thread",
    )
    agents_review.set_defaults(func=_agents_posture_review)
    agents_soc = agents_sub.add_parser(
        "soc-triage",
        help="run the deterministic SOC triage harness and propose approval-gated actions",
    )
    agents_soc.add_argument("--lake", required=True, help="security data lake output directory")
    agents_soc.add_argument(
        "--role",
        default="read_only",
        choices=list(_USER_ROLE_CHOICES),
        help="role lens used for redaction",
    )
    agents_soc.add_argument(
        "--objective",
        default="Triage open SOC alerts and propose guarded actions.",
        help="agent objective recorded in the run state",
    )
    agents_soc.add_argument(
        "--orchestrator",
        default="sequential",
        choices=["sequential", "langgraph"],
        help="deterministic node orchestrator; langgraph requires the agents extra",
    )
    agents_soc.add_argument("--provider", default=None, help="override GRC_LAKE_AGENT_PROVIDER")
    agents_soc.add_argument("--model", default=None, help="override GRC_LAKE_AGENT_MODEL")
    agents_soc.add_argument("--base-url", default=None, help="override GRC_LAKE_AGENT_BASE_URL")
    agents_soc.add_argument("--api-key-env", default=None, help="override GRC_LAKE_AGENT_API_KEY_ENV")
    agents_soc.add_argument(
        "--use-model",
        action="store_true",
        help="call the configured model provider; default is deterministic rules-only",
    )
    agents_soc.add_argument(
        "--max-context-chars",
        type=int,
        default=None,
        help="maximum serialized model context size before the model call is skipped",
    )
    agents_soc.add_argument(
        "--max-fact-items",
        type=int,
        default=None,
        help="maximum evidence/alert/decision items included in model context",
    )
    agents_soc.add_argument(
        "--max-output-tokens",
        type=int,
        default=None,
        help="maximum model output tokens requested from the provider",
    )
    agents_soc.add_argument(
        "--checkpoint-thread",
        default=None,
        help="LangGraph MemorySaver thread id (enables checkpoint/resume for long SOC reviews)",
    )
    agents_soc.add_argument(
        "--resume",
        action="store_true",
        help="resume a prior LangGraph checkpoint for --checkpoint-thread",
    )
    agents_soc.set_defaults(func=_agents_soc_triage)

    policy = sub.add_parser("policy", help="controls-as-code policy engine")
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)
    policy_lint = policy_sub.add_parser("lint", help="validate every control's evaluation_rule in the catalog")
    policy_lint.add_argument("--catalog", default=None, help="optional controls catalog JSON")
    policy_lint.set_defaults(func=_policy_lint)
    policy_rules = policy_sub.add_parser("rules", help="list the built-in named rules")
    policy_rules.set_defaults(func=_policy_rules)

    openapi = sub.add_parser("openapi", help="export the server-mode OpenAPI schema (requires the 'server' extra)")
    openapi.add_argument("--out", default=None, help="write JSON to this path (default stdout)")
    openapi.set_defaults(func=_openapi)

    return parser


def _validate(args: argparse.Namespace) -> int:
    rows = read_jsonl(args.raw)
    errors = validate_raw_events(rows)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"valid raw evidence: {len(rows)} records")
    return 0


def _run_pipeline(args: argparse.Namespace) -> int:
    result = run_pipeline(args.raw, args.out, mapping_path=args.mapping)
    print(json.dumps(result.__dict__, indent=2, sort_keys=True))
    return 0


def _pipeline_eval(args: argparse.Namespace) -> int:
    from security_lakehouse.lake_eval import run_lake_eval

    result = run_lake_eval(args.lake, actor=args.actor)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.result == "ok" else 1


def _verify_pipeline_integrity(args: argparse.Namespace) -> int:
    from security_lakehouse.verification import verify_lake_integrity

    result = verify_lake_integrity(args.lake)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


def _connectors_validate(args: argparse.Namespace) -> int:
    from security_lakehouse.connectors import validate_connector_catalog

    errors = validate_connector_catalog(args.catalog)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("valid connector catalog")
    return 0


def _connectors_list(args: argparse.Namespace) -> int:
    from security_lakehouse.connectors import load_connector_catalog

    connectors = load_connector_catalog(args.catalog)
    rows = [
        {
            "connector_id": connector["connector_id"],
            "name": connector["name"],
            "collection_mode": connector["collection_mode"],
            "access_boundary": connector["access_boundary"],
            "default_route": connector["default_route"],
            "freshness_slo_minutes": connector["freshness_slo_minutes"],
        }
        for connector in connectors.values()
    ]
    print(json.dumps({"connectors": rows, "count": len(rows)}, indent=2, sort_keys=True))
    return 0


def _connectors_scaffold(args: argparse.Namespace) -> int:
    from security_lakehouse.connectors_scaffold import scaffold_connector

    result = scaffold_connector(args.connector_id, title=args.title, output_dir=args.output)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _json_object(raw: str | None, *, flag: str) -> dict[str, object]:
    if raw is None:
        return {}
    try:
        payload = strict_json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{flag} must be a JSON object") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{flag} must be a JSON object")
    return payload


def _connectors_configure(args: argparse.Namespace) -> int:
    from security_lakehouse.connector_state import (
        append_config_event,
        configure_payload_error,
        enablement_probe_error,
    )

    credentials = _json_object(args.credentials_json, flag="--credentials-json")
    options = _json_object(args.options_json, flag="--options-json")
    cli_overrides = {
        key: value
        for key, value in {
            "sync_schedule": args.sync_schedule,
            "eval_schedule": args.eval_schedule,
            "repo": args.repo,
            "fixture_dir": args.fixture_dir,
            "token_env": args.token_env,
            "materialize": False if args.no_materialize else None,
        }.items()
        if value is not None
    }
    options = {**options, **cli_overrides}
    error = configure_payload_error(
        connector_id=args.connector_id,
        state=args.state,
        credentials=credentials,
        options=options,
    )
    if error:
        raise ValueError(error)
    error = enablement_probe_error(
        args.lake,
        connector_id=args.connector_id,
        state=args.state,
        credentials=credentials,
        options=options,
    )
    if error:
        raise ValueError(error)
    event = append_config_event(
        args.lake,
        connector_id=args.connector_id,
        state=args.state,
        actor=args.actor,
        credentials=credentials,
        options=options,
    )
    print(json.dumps({"event": event}, indent=2, sort_keys=True))
    return 0


def _connectors_discover(args: argparse.Namespace) -> int:
    from security_lakehouse.connector_state import run_discovery

    credentials = {
        key: value
        for key, value in {
            "account_id": args.account_id,
            "subscription_id": args.subscription_id,
            "account": args.account,
            "user": args.user,
            "credential_ref": args.oauth_token_env,
        }.items()
        if value is not None
    }
    options = {
        key: value
        for key, value in {
            "warehouse": args.warehouse,
            "database": args.database,
            "schema": args.schema,
        }.items()
        if value is not None
    }
    run = run_discovery(
        args.lake,
        connector_id=args.connector_id,
        actor=args.actor,
        credentials=credentials,
        options=options,
    )
    print(
        json.dumps(
            {
                "run": {
                    "connector_id": args.connector_id,
                    "kind": "discover",
                    "result": "ok" if run.get("result") == "ok" else "error",
                }
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if run.get("result") == "ok" else 1


def _connectors_probe(args: argparse.Namespace) -> int:
    from security_lakehouse.connector_state import run_probe

    run = run_probe(
        args.lake,
        connector_id=args.connector_id,
        actor=args.actor,
        credentials=_json_object(args.credentials_json, flag="--credentials-json"),
        options=_json_object(args.options_json, flag="--options-json"),
        # The CLI runs as the operator on their own machine, so the local SDK
        # credential chain (AWS_PROFILE, SSO) is a legitimate identity here.
        allow_ambient_credentials=True,
    )
    print(json.dumps({"run": run}, indent=2, sort_keys=True))
    return 0 if run.get("result") == "ok" else 1


def _connectors_sync(args: argparse.Namespace) -> int:
    from security_lakehouse.connector_runner import run_connector_sync

    result = run_connector_sync(
        args.lake,
        connector_id=args.connector_id,
        actor=args.actor,
        repo=args.repo,
        fixture_dir=args.fixture_dir,
        token_env=args.token_env,
        materialize=not args.no_materialize,
    )
    print(json.dumps(result.__dict__, indent=2, sort_keys=True))
    return 0


def _lake_presets(args: argparse.Namespace) -> int:
    from security_lakehouse.lake_mapping import list_presets, load_preset

    rows = [{"preset": name, "description": load_preset(name).get("description", "")} for name in list_presets()]
    print(json.dumps({"presets": rows}, indent=2, sort_keys=True))
    return 0


def _lake_map(args: argparse.Namespace) -> int:
    from security_lakehouse import lake_mapping as lm

    if not args.dry_run:
        print(
            "error: lake map only previews in this version; pass --dry-run. Ingest by configuring "
            "options.mapping on a lake connector and running 'connectors sync'.",
            file=sys.stderr,
        )
        return 1
    if args.limit < 0:
        raise ValueError("--limit must be zero or positive")
    if args.connector_id:
        return _lake_map_connector(args)
    try:
        if args.mapping:
            spec = lm.load_mapping_file(args.mapping)
        else:
            ref: dict[str, Any] = {"preset": args.preset}
            if args.table:
                ref["source"] = {"table": args.table}
            spec = lm.resolve_mapping_ref(ref)
        query = lm.compile_select(spec, args.dialect, since=args.since, limit=lm.DEFAULT_MAX_ROWS)
    except lm.MappingError as exc:
        print(json.dumps({"valid": False, "errors": exc.errors}, indent=2, sort_keys=True))
        return 1
    rows = _read_sample_rows(args.input) if args.input else []
    result = lm.map_rows(spec, rows, since=args.since)
    report = {
        "valid": True,
        "dry_run": True,
        "mapping": spec.name,
        "preset": spec.preset,
        "table": spec.source_table,
        "incremental": spec.incremental,
        "query": {"dialect": query.dialect, "sql": query.sql, "params": query.params},
        "rows_read": len(rows),
        "mapped_count": len(result.events),
        "filtered": result.filtered,
        "errors": result.errors,
        "preview": result.events[: args.limit],
    }
    print(json.dumps(report, indent=2, sort_keys=True, default=str))
    return 2 if result.errors else 0


def _lake_map_connector(args: argparse.Namespace) -> int:
    from security_lakehouse import lake_mapping as lm
    from security_lakehouse.connector_runner import DEFAULT_TOKEN_ENV, SyncInputs, effective_registry
    from security_lakehouse.connector_state import latest_config

    if not args.lake:
        raise ValueError("--connector-id previews need --lake")
    config = latest_config(args.lake, args.connector_id) or {}
    options = dict(config.get("options") or {})
    try:
        specs = lm.resolve_mappings(options)
    except lm.MappingError as exc:
        print(json.dumps({"valid": False, "errors": exc.errors}, indent=2, sort_keys=True))
        return 1
    if not specs:
        raise ValueError(f"{args.connector_id} has no options.mapping or options.mappings configured in {args.lake}")
    builder = effective_registry().get(args.connector_id)
    if builder is None:
        raise ValueError(f"no reader registered for connector_id {args.connector_id!r}")
    inputs = SyncInputs(
        repo=None,
        fixture_dir=args.fixture_dir,
        token_env=DEFAULT_TOKEN_ENV,
        env=dict(runtime_env()),
        since=args.since,
        credentials=dict(config.get("credentials") or {}),
        options={**options, "max_rows_per_sync": max(args.limit, 1) * 20},
    )
    with lm.capture_mapping_stats() as stats:
        events = builder(inputs)
    errors = [dict(error, mapping=item["mapping"]) for item in stats for error in item["errors"]]
    report = {
        "valid": True,
        "dry_run": True,
        "connector_id": args.connector_id,
        "mappings": [{key: value for key, value in item.items() if key != "errors"} for item in stats],
        "rows_read": sum(item["rows_read"] for item in stats),
        "mapped_count": len(events),
        "filtered": sum(item["filtered"] for item in stats),
        "errors": errors,
        "preview": events[: args.limit],
    }
    print(json.dumps(report, indent=2, sort_keys=True, default=str))
    return 2 if errors else 0


def _read_sample_rows(path: str) -> list[dict[str, Any]]:
    target = Path(path)
    suffix = target.suffix.lower()
    if suffix == ".parquet":
        try:
            import pyarrow.parquet as pq
        except ImportError as exc:
            raise ValueError("reading .parquet samples requires the 'parquet' extra (pyarrow)") from exc
        return [row for row in pq.read_table(target).to_pylist() if isinstance(row, dict)]
    text = target.read_text(encoding="utf-8")
    if suffix in {".jsonl", ".ndjson"}:
        return [
            row
            for row in (strict_json.loads(line) for line in text.splitlines() if line.strip())
            if isinstance(row, dict)
        ]
    payload = strict_json.loads(text)
    if not isinstance(payload, list):
        raise ValueError("--input JSON must be a list of row objects")
    return [row for row in payload if isinstance(row, dict)]


def _ingestion_plan(args: argparse.Namespace) -> int:
    from dataclasses import asdict

    from security_lakehouse.ingestion.strategy import plan_catalog

    plans = plan_catalog(args.catalog)
    if args.json:
        print(json.dumps([asdict(p) for p in plans], indent=2, sort_keys=True))
        return 0
    print(f"{'connector':28} {'velocity':18} {'method':32} {'slo':>6}")
    print("-" * 88)
    for p in plans:
        print(f"{p.connector_id:28} {p.velocity:18} {p.method:32} {p.freshness_slo:>6}")
        print(f"{'':28} └ {p.cost_note}")
    return 0


def _ingestion_normalize(args: argparse.Namespace) -> int:
    result = normalize_raw_events(
        args.raw,
        args.out,
        mapping_path=args.mapping,
        tenant_id=args.tenant_id,
        incremental=args.incremental,
    )
    print(json.dumps(result.__dict__, indent=2, sort_keys=True))
    return 0


def _scenario_run(args: argparse.Namespace) -> int:
    from security_lakehouse.scenarios import (
        format_live_cloud_posture_summary,
        parse_fixture_specs,
        run_live_cloud_posture_scenario,
    )

    report = run_live_cloud_posture_scenario(
        args.lake,
        connectors=args.connector,
        fixture_dirs=parse_fixture_specs(args.fixture),
        actor=args.actor,
        continue_on_error=args.continue_on_error,
    )
    if args.summary:
        print(format_live_cloud_posture_summary(report))
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["summary"]["ok"] else 1


def _controls_provenance(args: argparse.Namespace) -> int:
    from security_lakehouse.catalog import PROVENANCE_FIELDS, controls_missing_provenance

    gaps = controls_missing_provenance(args.catalog)
    if not gaps:
        print(f"All controls carry source provenance ({', '.join(PROVENANCE_FIELDS)}).")
        return 0
    print(f"{len(gaps)} control(s) missing provenance:")
    for control_id, missing in sorted(gaps.items()):
        print(f"  {control_id}: {', '.join(missing)}")
    return 1


def _controls_applies_to(args: argparse.Namespace) -> int:
    from security_lakehouse.catalog import controls_for_asset_type

    control_ids = controls_for_asset_type(args.asset_type, args.catalog)
    if not control_ids:
        print(f"No controls apply to asset type {args.asset_type!r}.")
        return 0
    print(f"{len(control_ids)} control(s) apply to {args.asset_type}:")
    for control_id in control_ids:
        print(f"  {control_id}")
    return 0


def _controls_history(args: argparse.Namespace) -> int:
    from security_lakehouse.catalog_versions import control_history

    versions = control_history(args.control_id)
    if not versions:
        print(f"No versions found for control {args.control_id!r}.")
        return 1
    rows = [
        {
            "version": v.get("version"),
            "valid_from": v.get("valid_from"),
            "valid_to": v.get("valid_to"),
            "lifecycle_status": v.get("lifecycle_status"),
            "supersedes": v.get("supersedes"),
            "superseded_by": v.get("superseded_by"),
            "change_reason": v.get("change_reason"),
        }
        for v in versions
    ]
    print(json.dumps({"control_id": args.control_id, "versions": rows}, indent=2))
    return 0


def _controls_as_of(args: argparse.Namespace) -> int:
    from security_lakehouse.catalog_versions import controls_as_of

    try:
        controls = controls_as_of(args.date)
    except ValueError as exc:
        print(f"error: {exc}")
        return 2
    rows = sorted(
        (
            {"control_id": cid, "version": c.get("version"), "framework_id": c.get("framework_id")}
            for cid, c in controls.items()
        ),
        key=lambda r: str(r["control_id"]),
    )
    print(json.dumps({"as_of": args.date, "control_count": len(rows), "controls": rows}, indent=2))
    return 0


def _catalog_bundle(args: argparse.Namespace) -> int:
    from security_lakehouse.catalog_versions import bundle_summary, compute_bundle

    bundle = compute_bundle(as_of=args.as_of) if args.full else bundle_summary(as_of=args.as_of)
    print(json.dumps(bundle, indent=2))
    return 0


def _catalog_lock(args: argparse.Namespace) -> int:
    from security_lakehouse.catalog_versions import write_bundle_lock

    bundle = write_bundle_lock()
    print(
        f"Wrote bundle lock: {bundle['bundle_sha256']} "
        f"({bundle['framework_count']} frameworks, {bundle['control_count']} controls)"
    )
    return 0


def _catalog_verify(args: argparse.Namespace) -> int:
    from security_lakehouse.catalog_versions import verify_bundle_lock

    result = verify_bundle_lock()
    if result["ok"]:
        print(f"Catalog bundle matches lockfile: {result['actual']}")
        return 0
    print("Catalog bundle DRIFTED from lockfile.")
    print(f"  expected: {result['expected']}")
    print(f"  actual:   {result['actual']}")
    print(f"  drifted:  {', '.join(result['drifted_components']) or '(hash mismatch)'}")
    return 1


def _oscal_export(args: argparse.Namespace) -> int:
    from security_lakehouse.oscal import build_assessment_results, build_component_definition

    if bool(args.component_definition) == bool(args.assessment_results):
        raise SystemExit("pass exactly one of --component-definition or --assessment-results")
    if args.component_definition:
        if args.snapshot:
            raise SystemExit("--snapshot only applies to --assessment-results")
        document = build_component_definition(lake_dir=args.lake)
    else:
        if args.lake:
            raise SystemExit("--lake only applies to --component-definition; --assessment-results takes the lake")
        document = build_assessment_results(args.assessment_results, snapshot_id=args.snapshot)
    text = json.dumps(document, indent=2, sort_keys=True)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text + "\n", encoding="utf-8")
        print(f"wrote OSCAL export: {args.out}")
    else:
        print(text)
    return 0


def _dashboard(args: argparse.Namespace) -> int:
    output = render_dashboard(args.lake, args.out)
    print(f"wrote dashboard: {output}")
    return 0


def _query(args: argparse.Namespace) -> int:
    sql = args.sql.strip()
    if not sql.lower().startswith("select"):
        raise ValueError("query command only allows SELECT statements")
    if args.engine == "duckdb":
        rows = _query_duckdb(Path(args.lake) / "mart" / "security_data_lake.duckdb", sql)
        print(
            json.dumps({"count": len(rows), "engine": args.engine, "rows": rows}, indent=2, sort_keys=True, default=str)
        )
        return 0

    mart = Path(args.lake) / "mart" / "security_lakehouse.sqlite"
    with sqlite3.connect(mart) as conn:
        conn.row_factory = sqlite3.Row
        rows = [dict(row) for row in conn.execute(sql).fetchall()]
    print(json.dumps({"count": len(rows), "engine": args.engine, "rows": rows}, indent=2, sort_keys=True))
    return 0


def _query_duckdb(mart: Path, sql: str) -> list[dict]:
    if not mart.exists():
        raise ValueError("DuckDB mart not found. Install with `pip install -e '.[analytics]'` and rerun the pipeline.")
    try:
        import duckdb
    except ImportError as exc:
        raise ValueError("DuckDB is not installed. Install with `pip install -e '.[analytics]'`.") from exc

    with duckdb.connect(str(mart), read_only=True) as conn:
        cursor = conn.execute(sql)
        columns = [column[0] for column in cursor.description]
        return [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]


def _serve(args: argparse.Namespace) -> int:
    if getattr(args, "server", False):
        try:
            from security_lakehouse.server_app import serve
        except ModuleNotFoundError as exc:
            raise SystemExit("server mode requires the 'server' extra: pip install 'grc-lake[server]'") from exc
        require_auth = not getattr(args, "allow_insecure_no_auth", False)
        mode = "server mode" if require_auth else "server mode, INSECURE no-auth"
        print(f"serving GRC Lake console ({mode}): http://{args.host}:{args.port}/")
        serve(args.lake, host=args.host, port=args.port, require_auth=require_auth)
    else:
        from security_lakehouse.server import serve as serve_local

        _refuse_exposed_local_mode(args.host)
        print(f"serving GRC Lake console (local mode, no authentication): http://{args.host}:{args.port}/")
        serve_local(args.lake, host=args.host, port=args.port)
    return 0


# Loopback and link-local. Anything else can be reached by something that is not
# the operator's own machine.
_LOCAL_ONLY_HOSTS = {"127.0.0.1", "::1", "localhost", "169.254.169.254"}


def _refuse_exposed_local_mode(host: str) -> None:
    """Stop local mode from binding an address other people can reach.

    Local mode is :mod:`security_lakehouse.server`, which has no authentication
    at all -- it never reads ``GRC_LAKE_OIDC_*``, ``GRC_LAKE_SESSION_SECRET``, or
    any other auth setting, because those belong to ``server_app``. Bound to
    0.0.0.0 it hands every control, violation, and piece of evidence to anyone
    who can route to the port, while an operator who configured OIDC has every
    reason to believe it is enforced.

    Refusing here rather than warning is deliberate: a warning scrolls past in a
    container log, and the failure it precedes is silent.
    """
    if runtime_env().get("GRC_LAKE_ENV", "").strip().lower() in {"production", "prod", "staging"}:
        raise SystemExit("unauthenticated local mode is forbidden in production or staging; use --server")
    if host in _LOCAL_ONLY_HOSTS or host.startswith("127."):
        return
    if runtime_env().get("GRC_LAKE_ALLOW_INSECURE_NO_AUTH", "").strip().lower() in {"1", "true", "yes"}:
        print(
            f"WARNING: serving UNAUTHENTICATED local mode on {host} — "
            "every control, violation, and evidence record is readable by anyone who can reach this port.",
            file=sys.stderr,
        )
        return
    raise SystemExit(
        f"refusing to serve local mode on {host}: local mode has no authentication.\n"
        "  Use --server (requires the 'server' extra) for authenticated serving, which is what\n"
        "  GRC_LAKE_OIDC_*, GRC_LAKE_SAML_*, and GRC_LAKE_SESSION_SECRET configure.\n"
        "  To serve without authentication anyway, set GRC_LAKE_ALLOW_INSECURE_NO_AUTH=true."
    )


def _db_upgrade(args: argparse.Namespace) -> int:
    try:
        from security_lakehouse.db import migrate
    except ModuleNotFoundError as exc:
        raise SystemExit("the db commands require the 'server' extra: pip install 'grc-lake[server]'") from exc
    url = migrate.upgrade(args.lake, revision=args.revision)
    print(f"application-state database upgraded to {args.revision}: {url}")
    return 0


def _db_current(args: argparse.Namespace) -> int:
    try:
        from security_lakehouse.db import migrate
    except ModuleNotFoundError as exc:
        raise SystemExit("the db commands require the 'server' extra: pip install 'grc-lake[server]'") from exc
    print(migrate.current(args.lake) or "(no revision applied)")
    return 0


def _auth_session(lake: str):
    """Ensure the schema exists and return a transactional session scope."""
    try:
        from security_lakehouse.db import migrate
        from security_lakehouse.db.base import create_engine_for, session_factory, session_scope
    except ModuleNotFoundError as exc:
        raise SystemExit("the auth commands require the 'server' extra: pip install 'grc-lake[server]'") from exc
    migrate.upgrade(lake)
    return session_scope(session_factory(create_engine_for(lake)))


def _auth_resolve_tenant(session, slug: str):
    from security_lakehouse.db import repository

    tenant = repository.get_tenant_by_slug(session, slug=slug)
    if tenant is None:
        raise SystemExit(f"no tenant with slug {slug!r}; create it with `auth create-tenant`")
    return tenant


def _auth_create_tenant(args: argparse.Namespace) -> int:
    from security_lakehouse.db import repository

    with _auth_session(args.lake) as session:
        tenant = repository.create_tenant(session, slug=args.slug, name=args.name)
        print(f"created tenant {tenant.slug} ({tenant.id})")
    return 0


def _auth_create_user(args: argparse.Namespace) -> int:
    from security_lakehouse.db import repository

    with _auth_session(args.lake) as session:
        tenant = _auth_resolve_tenant(session, args.tenant_slug)
        user = repository.create_user(
            session, tenant_id=tenant.id, email=args.email, display_name=args.display_name, role=args.role
        )
        print(f"created user {user.email} (role={user.role}, id={user.id})")
    return 0


def _credential_delivery_path(lake: str, key_id: str) -> Path:
    return Path(lake).resolve() / "server" / "credentials" / f"{key_id}.token"


def _store_new_api_key(session, lake: str, key_id: str, token: str) -> None:
    """Deliver a new credential privately; never overwrite or log its bytes."""
    path = _credential_delivery_path(lake, key_id)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(token + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        session.commit()
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _auth_issue_key(args: argparse.Namespace) -> int:
    from security_lakehouse.db import repository

    with _auth_session(args.lake) as session:
        tenant = _auth_resolve_tenant(session, args.tenant_slug)
        user = repository.get_user_by_email(session, tenant_id=tenant.id, email=args.email)
        if user is None:
            raise SystemExit(f"no user {args.email!r} in tenant {tenant.slug!r}; create it with `auth create-user`")
        expires_at = None
        if args.expires_days is not None:
            from datetime import UTC, datetime, timedelta

            expires_at = datetime.now(UTC) + timedelta(days=args.expires_days)
        key, token = repository.create_api_key(
            session, tenant_id=tenant.id, user_id=user.id, name=args.name, expires_at=expires_at
        )
        _store_new_api_key(session, args.lake, key.id, token)
        result = {
            "tenant": tenant.slug,
            "user_email": user.email,
            "api_key_id": key.id,
            "prefix": key.prefix,
            "status": key.status,
            "token_file": str(_credential_delivery_path(args.lake, key.id)),
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _auth_list_keys(args: argparse.Namespace) -> int:
    from security_lakehouse.db import repository

    with _auth_session(args.lake) as session:
        tenant = _auth_resolve_tenant(session, args.tenant_slug)
        rows = [
            {
                "id": key.id,
                "name": key.name,
                "prefix": key.prefix,
                "user_id": key.user_id,
                "user_email": key.user.email,
                "role": key.role,
                "status": key.status,
                "workspace_id": key.workspace_id,
                "created_at": key.created_at.isoformat() if key.created_at else None,
                "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None,
                "expires_at": key.expires_at.isoformat() if key.expires_at else None,
                "revoked_at": key.revoked_at.isoformat() if key.revoked_at else None,
            }
            for key in repository.list_api_keys(session, tenant_id=tenant.id)
        ]
    print(json.dumps({"tenant": args.tenant_slug, "count": len(rows), "api_keys": rows}, indent=2, sort_keys=True))
    return 0


def _auth_revoke_key(args: argparse.Namespace) -> int:
    from datetime import UTC, datetime

    from security_lakehouse.db import repository

    with _auth_session(args.lake) as session:
        tenant = _auth_resolve_tenant(session, args.tenant_slug)
        revoked = repository.revoke_api_key(session, tenant_id=tenant.id, key_id=args.key_id, now=datetime.now(UTC))
    print("revoked" if revoked else "not found or already revoked")
    return 0


def _platform_seed_dev(args: argparse.Namespace) -> int:
    from security_lakehouse.db import repository

    with _auth_session(args.lake) as session:
        tenant = repository.get_tenant_by_slug(session, slug=args.tenant_slug)
        if tenant is None:
            tenant = repository.create_tenant(session, slug=args.tenant_slug, name=args.tenant_name)
        user = repository.get_user_by_email(session, tenant_id=tenant.id, email=args.email)
        if user is None:
            user = repository.create_user(
                session,
                tenant_id=tenant.id,
                email=args.email,
                display_name=args.display_name,
                role="admin",
            )
        key, token = repository.create_api_key(session, tenant_id=tenant.id, user_id=user.id, name="local-dev")
        _store_new_api_key(session, args.lake, key.id, token)
        result = {
            "tenant_id": tenant.id,
            "tenant_slug": tenant.slug,
            "user_id": user.id,
            "email": user.email,
            "role": user.role,
            "api_key_id": key.id,
            "api_key_prefix": key.prefix,
            "token_file": str(_credential_delivery_path(args.lake, key.id)),
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _risk_list(args: argparse.Namespace) -> int:
    from security_lakehouse.db import risks

    with _auth_session(args.lake) as session:
        tenant = _auth_resolve_tenant(session, args.tenant)
        rows = [
            risks.risk_to_dict(risk)
            for risk in risks.list_risks(
                session,
                tenant_id=tenant.id,
                status=args.status,
                severity=args.severity,
                owner=args.owner,
            )
        ]
    print(json.dumps({"tenant": tenant.slug, "count": len(rows), "risks": rows}, indent=2, sort_keys=True))
    return 0


def _risk_add(args: argparse.Namespace) -> int:
    from security_lakehouse.db import risks

    with _auth_session(args.lake) as session:
        tenant = _auth_resolve_tenant(session, args.tenant)
        risk = risks.create_risk(
            session,
            tenant_id=tenant.id,
            title=args.title,
            description=args.description,
            category=args.category,
            severity=args.severity,
            likelihood=args.likelihood,
            impact=args.impact,
            owner=args.owner,
            control_id=args.control_id,
        )
        payload = risks.risk_to_dict(risk)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _workflow_list(args: argparse.Namespace) -> int:
    from security_lakehouse.workflows import list_workflows

    rows = list_workflows(args.lake)
    print(json.dumps({"count": len(rows), "workflows": rows}, indent=2, sort_keys=True))
    return 0


def _workflow_run(args: argparse.Namespace) -> int:
    from security_lakehouse.workflows import run_workflow

    run = run_workflow(args.lake, workflow_id=args.workflow_id, actor=args.actor)
    print(json.dumps(run, indent=2, sort_keys=True))
    return 0


def _assessment_workpaper(args: argparse.Namespace) -> int:
    from security_lakehouse.audit_workpapers import build_workpaper, export_workpaper
    from security_lakehouse.io import read_json

    lake, out = Path(args.lake).resolve(), Path(args.out).resolve()
    if out.is_relative_to(lake):
        raise ValueError("workpaper export must be outside the evidence lake")
    content = build_workpaper(lake, plan=read_json(Path(args.plan)), baseline=read_json(Path(args.baseline)))
    export_workpaper(content, out)
    print(f"wrote draft auditor workpaper: {out / 'index.html'}")
    return 0


def _assessment_verify_workpaper(args: argparse.Namespace) -> int:
    from security_lakehouse.audit_workpapers import verify_workpaper_export

    result = verify_workpaper_export(Path(args.dir))
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


def _assessment_test_plan(args: argparse.Namespace) -> int:
    from security_lakehouse.control_assurance import assess_control_plan
    from security_lakehouse.io import read_json

    print(json.dumps(assess_control_plan(Path(args.lake), read_json(Path(args.plan))), indent=2, sort_keys=True))
    return 0


def _assessment_population(args: argparse.Namespace) -> int:
    from security_lakehouse.io import read_json
    from security_lakehouse.population_reconciliation import assess_population

    print(
        json.dumps(
            assess_population(Path(args.lake), read_json(Path(args.baseline)), details_limit=args.details_limit),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _assessment_status(args: argparse.Namespace) -> int:
    from security_lakehouse.assessment import build_current_posture

    if not Path(args.lake).is_dir():
        raise ValueError("assessment lake directory does not exist")
    assessment = build_current_posture(args.lake, freshness_days=args.freshness_days)
    if args.format == "summary":
        posture = assessment["posture"]
        print(
            f"Posture    {posture['score']} / 100  {posture['state']}\n"
            f"Controls   {posture['control_count']} total, "
            f"{posture['not_evaluated_control_count']} not evaluated, {posture['stale_control_count']} stale\n"
            f"Tests      {posture['failed_control_test_count']} failing, "
            f"{posture['warning_control_test_count']} warning\n"
            f"Violations {posture['open_violation_count']} open "
            f"({posture['critical_violation_count']} critical, {posture['high_violation_count']} high)\n"
            f"Evidence   {assessment['evidence_freshness']['count']} records, "
            f"{posture['stale_evidence_count']} stale/expired/missing"
        )
    else:
        print(json.dumps(assessment, indent=2, sort_keys=True))
    return 0


def _assessment_snapshot(args: argparse.Namespace) -> int:
    from security_lakehouse.assessment import write_assessment_snapshot

    if not Path(args.lake).is_dir():
        raise ValueError("assessment lake directory does not exist")
    path = write_assessment_snapshot(args.lake, output=args.out, freshness_days=args.freshness_days, reason=args.reason)
    print(f"wrote assessment snapshot: {path}")
    return 0


def _assessment_verify_snapshots(args: argparse.Namespace) -> int:
    from security_lakehouse.assessment import verify_snapshot_chain

    if not Path(args.lake).is_dir():
        raise ValueError("assessment lake directory does not exist")
    result = verify_snapshot_chain(args.lake)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


def _assessment_reconcile_snapshots(args: argparse.Namespace) -> int:
    from security_lakehouse.snapshot_recovery import reconcile_snapshots

    result = reconcile_snapshots(args.lake, apply=args.apply)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not args.apply or result["integrity"]["ok"] else 1


def _assessment_verify_tracking(args: argparse.Namespace) -> int:
    from security_lakehouse.tracking import verify_tracking_chain

    if not Path(args.lake).is_dir():
        raise ValueError("assessment lake directory does not exist")
    result = verify_tracking_chain(args.lake)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


def _assessment_posture_as_of(args: argparse.Namespace) -> int:
    from security_lakehouse.assessment import posture_as_of

    try:
        result = posture_as_of(args.lake, as_of=args.as_of)
    except ValueError as exc:
        print(f"error: invalid --as-of value: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["found"] else 1


def _assessment_violations(args: argparse.Namespace) -> int:
    from security_lakehouse.assessment import build_current_posture

    posture = build_current_posture(args.lake)
    framework_controls = {
        control["control_id"]: control["framework"]
        for control in read_jsonl(Path(args.lake) / "gold" / "control_posture.jsonl")
    }
    rows = [
        violation
        for violation in posture["violations"]
        if args.framework is None or framework_controls.get(violation["control_id"]) == args.framework
    ]
    print(json.dumps({"count": len(rows), "violations": rows}, indent=2, sort_keys=True))
    return 0


def _aibom_import(args: argparse.Namespace) -> int:
    from security_lakehouse.aibom import import_aibom

    result = import_aibom(input_path=Path(args.input), lake=Path(args.lake))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _aibom_export(args: argparse.Namespace) -> int:
    from security_lakehouse.aibom import export_aibom

    result = export_aibom(lake=Path(args.lake), output_path=Path(args.out), output_format=args.format)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _fixtures_list(_args: argparse.Namespace) -> int:
    from security_lakehouse.fixtures import list_fixtures

    rows = [
        {
            "company": fixture.company,
            "raw_path": str(fixture.raw_path),
            "event_count": fixture.event_count,
            "sources": fixture.sources,
            "controls": fixture.controls,
        }
        for fixture in list_fixtures()
    ]
    print(json.dumps({"count": len(rows), "fixtures": rows}, indent=2, sort_keys=True))
    return 0


def _fixtures_load(args: argparse.Namespace) -> int:
    from security_lakehouse.fixtures import find_fixture

    fixture = find_fixture(args.company)
    if fixture is None:
        raise ValueError(f"unknown fixture {args.company!r}; run `grc-lake fixtures list` to see the options")
    raw_path = fixture.raw_path
    if getattr(args, "rebase_times", False):
        from security_lakehouse.fixtures import rebase_fixture_times

        rows = [strict_json.loads(line) for line in raw_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        raw_path = Path(args.out) / "_fixture_rebased" / raw_path.name
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(
            "\n".join(json.dumps(row, separators=(",", ":")) for row in rebase_fixture_times(rows)) + "\n",
            encoding="utf-8",
        )
    result = run_pipeline(raw_path, args.out, tenant_id=getattr(args, "tenant_id", "default"))
    demo_records = None
    if fixture.company == "golden" and not getattr(args, "no_demo_records", False):
        from security_lakehouse.demo_seed import seed_golden_demo

        demo_records = seed_golden_demo(args.out)
    print(
        json.dumps(
            {
                "company": fixture.company,
                "loaded_from": str(fixture.raw_path),
                **result.__dict__,
                **({"demo_records": demo_records} if demo_records is not None else {}),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _fixtures_synthesize_scale(args: argparse.Namespace) -> int:
    from security_lakehouse.scale_synthesis import audit_scale_plan, write_audit_scale_fixture

    plan = audit_scale_plan(
        args.count,
        controls_per_event=args.controls_per_event,
        open_ratio=args.open_ratio,
    )
    result = write_audit_scale_fixture(
        args.out,
        args.count,
        tenant_id=args.tenant_id,
        controls_per_event=args.controls_per_event,
        open_ratio=args.open_ratio,
        framework_prefix=args.framework_prefix,
        seed=args.seed,
    )
    payload = {"plan": plan, **result}
    print(json.dumps(payload, indent=2, sort_keys=True) if args.json else json.dumps(payload, sort_keys=True))
    return 0


def _benchmark_plan(args: argparse.Namespace) -> int:
    from security_lakehouse.scale_synthesis import audit_scale_plan

    payload = audit_scale_plan(
        args.events,
        controls_per_event=args.controls_per_event,
        open_ratio=args.open_ratio,
    )
    print(json.dumps(payload, indent=2, sort_keys=True) if args.json else json.dumps(payload, sort_keys=True))
    return 0


def _benchmark_pipeline(args: argparse.Namespace) -> int:
    from security_lakehouse.scale_synthesis import benchmark_pipeline

    payload = benchmark_pipeline(args.raw, args.out, tenant_id=args.tenant_id)
    print(json.dumps(payload, indent=2, sort_keys=True) if args.json else json.dumps(payload, sort_keys=True))
    return 0


def _fixtures_write_golden(args: argparse.Namespace) -> int:
    from pathlib import Path

    from security_lakehouse.golden_fixture import golden_fixture_summary, write_golden_fixture

    root = Path(args.root) if args.root else None
    path = write_golden_fixture(root=root)
    summary = golden_fixture_summary()
    print(
        json.dumps(
            {
                "written": str(path),
                "event_count": summary["control_count"],
                **summary,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _repo_audit(args: argparse.Namespace) -> int:
    from security_lakehouse.repo_audit import audit_public_repo

    rows = audit_public_repo(args.repo, out=args.out, fixture_dir=args.fixture_dir)
    signals = sorted({row["event_type"] for row in rows})
    print(json.dumps({"count": len(rows), "out": args.out, "signals": signals}, indent=2, sort_keys=True))
    return 0


def _repo_governance_sync(args: argparse.Namespace) -> int:
    from security_lakehouse.repo_governance import sync_repo_governance

    rows = sync_repo_governance(
        args.repo,
        out=args.out,
        fixture_dir=args.fixture_dir,
        token_env=args.token_env,
        provider=args.provider,
    )
    signals = sorted({row["event_type"] for row in rows})
    print(json.dumps({"count": len(rows), "out": args.out, "signals": signals}, indent=2, sort_keys=True))
    return 0


def _frameworks_sync(args: argparse.Namespace) -> int:
    from security_lakehouse.framework_sync import sync_frameworks

    results = sync_frameworks(allow_network=args.allow_network)
    rows = [
        {
            "framework_id": r.framework_id,
            "state": r.state,
            "old_sha": r.old_sha,
            "new_sha": r.new_sha,
            "pulled_at": r.pulled_at,
            "reason": r.reason,
            "transient": r.transient,
        }
        for r in results
    ]
    print(json.dumps({"count": len(rows), "results": rows}, indent=2, sort_keys=True))
    return 0


def _frameworks_readiness(_args: argparse.Namespace) -> int:
    from security_lakehouse.readiness import build_readiness_view

    rows = build_readiness_view()
    print(json.dumps({"count": len(rows), "frameworks": rows}, indent=2, sort_keys=True))
    return 0


def _frameworks_sync_packs(args: argparse.Namespace) -> int:
    from security_lakehouse.framework_packs import sync_framework_packs

    result = sync_framework_packs(packs=args.pack)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _frameworks_enrich(args: argparse.Namespace) -> int:
    """Fill placeholder titles from public-domain NIST catalogs.

    Network is opt-in, matching `frameworks sync`: an offline run reports how
    many titles are placeholders without fetching anything.
    """
    from security_lakehouse.catalog import load_control_catalog
    from security_lakehouse.framework_enrich import (
        PUBLIC_DOMAIN_SOURCES,
        enrich_catalog,
        fetch,
        is_placeholder,
        oscal_titles,
    )

    catalog = load_control_catalog()
    pending = {
        fw: sum(1 for c in catalog.values() if c.get("framework_id") == fw and is_placeholder(c.get("title", "")))
        for fw in PUBLIC_DOMAIN_SOURCES
    }

    if not args.allow_network:
        print(json.dumps({"placeholders": pending, "note": "pass --allow-network to fetch NIST catalogs"}, indent=2))
        return 0

    titles_by_framework = {}
    for framework, source in PUBLIC_DOMAIN_SOURCES.items():
        raw, digest = fetch(source["url"])
        titles_by_framework[framework] = (oscal_titles(raw), source["url"], digest)
        print(f"fetched {source['source_name']}: sha256 {digest[:16]}…", file=sys.stderr)

    report = enrich_catalog(titles_by_framework=titles_by_framework, apply=args.apply)
    print(json.dumps(report, indent=2))
    return 1 if report["unresolved"] else 0


def _frameworks_assessment(args: argparse.Namespace) -> int:
    from security_lakehouse.api_v1 import handle_get

    status, body = handle_get("/api/v1/ccf/assessment", {}, Path(args.lake))
    print(json.dumps(body["data"], indent=2))
    return 0 if status == 200 else 1


def _frameworks_safeguards(args: argparse.Namespace) -> int:
    """Report Common Control Framework coverage, and refuse to report a broken one."""
    from security_lakehouse.safeguards import coverage_by_framework, load_safeguards, validate_safeguards

    payload = load_safeguards()
    problems = validate_safeguards(payload)
    if problems:
        for problem in problems:
            print(f"invalid safeguard: {problem}", file=sys.stderr)
        return 1

    if args.lake:
        from security_lakehouse.mapping_review import effective_safeguards

        payload = effective_safeguards(args.lake, payload=payload)
    coverage = coverage_by_framework(payload)
    if args.format == "json":
        print(json.dumps(coverage, indent=2))
        return 0

    print(
        f"{coverage['safeguards']} safeguards map {coverage['covered']} of "
        f"{coverage['controls']} requirements ({coverage['coverage_pct']}%) — "
        f"{coverage['maintainer_reviewed']} maintainer-reviewed, {coverage['org_reviewed']} org-reviewed "
        f"({coverage['reviewed_pct']}% attestable), {coverage['proposed']} proposed; "
        f"{coverage['rejected_mappings']} mapping(s) rejected by the org"
    )
    print()
    print(f"{'framework':26s} {'requirements':>12s} {'covered':>8s} {'pct':>7s}")
    for name, row in coverage["frameworks"].items():
        print(f"{name:26s} {row['controls']:12d} {row['covered']:8d} {row['coverage_pct']:6.1f}%")
    print()
    print("CCF safeguard families by category (reviewed vs proposed mappings)")
    print(f"{'category / family':34s} {'safeguards':>10s} {'frameworks':>10s} {'reviewed':>10s} {'proposed':>10s}")
    families = {row["family_id"]: row for row in coverage["families"]}
    for category in coverage["categories"]:
        heading = f"{category['label']} ({category['family_count']})"
        print(
            f"{heading:34s} {category['safeguard_count']:10d} {category['framework_count']:10d} "
            f"{category['reviewed_mapping_count']:10d} {category['proposed_mapping_count']:10d}"
        )
        for family_id in category["family_ids"]:
            row = families.get(family_id)
            if row is None:
                continue
            print(
                f"  {row['label']:32s} {row['safeguard_count']:10d} {row['framework_count']:10d} "
                f"{row['reviewed_mapping_count']:10d} {row['proposed_mapping_count']:10d}"
            )
    return 0


def _frameworks_coverage(args: argparse.Namespace) -> int:
    from security_lakehouse.framework_coverage import (
        build_control_asset_applicability,
        build_framework_coverage,
        framework_coverage_summary,
        render_framework_coverage_markdown,
    )

    rows = build_framework_coverage(lake_dir=args.lake)
    applicability = build_control_asset_applicability()
    if args.format == "markdown":
        print(render_framework_coverage_markdown(rows, applicability))
    else:
        print(
            json.dumps(
                {
                    "summary": framework_coverage_summary(rows, applicability),
                    "frameworks": rows,
                    "applicability": applicability,
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0


def _frameworks_review_queue(args: argparse.Namespace) -> int:
    from security_lakehouse.safeguards import mapping_review_report

    payload = None
    if args.lake:
        from security_lakehouse.mapping_review import effective_safeguards

        payload = effective_safeguards(args.lake)
    report = mapping_review_report(payload, framework_id=args.framework, risk_domain=args.risk_domain)
    print(
        json.dumps(
            {
                **report,
                "note": "Review is a domain-expert equivalence judgment; nothing here is auto-promoted.",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _frameworks_review_decide(args: argparse.Namespace) -> int:
    """Record one local-mode org review decision; the reviewer is named on the command line."""
    from security_lakehouse.mapping_review import record_decisions

    record = record_decisions(
        args.lake,
        items=[{"safeguard_id": args.safeguard, "framework_id": args.framework, "control_id": args.control}],
        decision=args.decision,
        rationale=args.rationale,
        reviewer=args.reviewer,
        auth_method="cli-local",
        evidence_ref=args.evidence_ref,
    )[0]
    print(json.dumps(record, indent=2, sort_keys=True))
    return 0


_REVIEW_EXPORT_FIELDS = (
    "decided_at",
    "decision_id",
    "decision",
    "safeguard_id",
    "framework_id",
    "control_id",
    "reviewer",
    "reviewer_role",
    "auth_method",
    "rationale",
    "evidence_ref",
    "shipped_review_status",
    "supersedes",
    "batch_id",
    "prev_hash",
    "record_hash",
)


def _csv_cell(value: object) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")) else text


def _frameworks_review_export(args: argparse.Namespace) -> int:
    """Export the org decision log (oldest first) with its hash-chain verification."""
    import csv
    import io

    from security_lakehouse.mapping_review import list_decisions, verify_review_log

    decisions = list_decisions(args.lake)
    if args.format == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=_REVIEW_EXPORT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in decisions:
            writer.writerow({field: _csv_cell(row.get(field)) for field in _REVIEW_EXPORT_FIELDS})
        text = buffer.getvalue()
    else:
        text = json.dumps(
            {"decision_log": verify_review_log(args.lake), "decisions": decisions}, indent=2, sort_keys=True
        )
        text += "\n"
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
        print(f"wrote {len(decisions)} decision(s): {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


def _frameworks_review_resign(args: argparse.Namespace) -> int:
    """Verify the chain and old tip MAC with the previous key, then re-sign with the current one."""
    import getpass

    from security_lakehouse.mapping_review import resign_review_tip, verify_review_log

    previous = runtime_env().get(args.previous_key_env, "").strip()
    if not previous:
        raise ValueError(f"{args.previous_key_env} is not set; export the pre-rotation signing key there")
    try:
        os_user = getpass.getuser()
    except (KeyError, OSError):
        os_user = "unknown"
    actor = args.actor or f"cli-local:{os_user}"
    result = resign_review_tip(args.lake, previous_key=previous, actor=actor)
    print(json.dumps({**result, "decision_log": verify_review_log(args.lake)}, indent=2, sort_keys=True))
    return 0


def _scheduler_tick(args: argparse.Namespace) -> int:
    from security_lakehouse.scheduler import tick

    results = tick(args.lake, all_tenants=args.all_tenants)
    print(json.dumps({"fired": len(results), "results": results}, indent=2, sort_keys=True))
    return int(any(row.get("result") == "error" for row in results))


def _scheduler_run(args: argparse.Namespace) -> int:
    from security_lakehouse.scheduler import run_forever

    print(f"scheduler running every {args.tick_seconds}s against {args.lake}; Ctrl-C to stop")
    run_forever(args.lake, tick_seconds=args.tick_seconds, all_tenants=args.all_tenants)
    return 0


def _assessment_tests(args: argparse.Namespace) -> int:
    rows = read_jsonl(Path(args.lake) / "gold" / "control_tests.jsonl")
    if args.result:
        rows = [row for row in rows if row["result"] == args.result]
    print(json.dumps({"count": len(rows), "control_tests": rows}, indent=2, sort_keys=True))
    return 0


def _assessment_stale_evidence(args: argparse.Namespace) -> int:
    path = Path(args.lake) / "gold" / "evidence_freshness.jsonl"
    if path.exists():
        rows = read_jsonl(path)
    else:
        from security_lakehouse.evidence_freshness import build_evidence_freshness

        rows = build_evidence_freshness(read_jsonl(Path(args.lake) / "silver" / "normalized_events.jsonl"))
    if args.status:
        rows = [row for row in rows if row["status"] == args.status]
    else:
        rows = [row for row in rows if row["status"] in {"stale", "expired", "missing"}]
    print(json.dumps({"count": len(rows), "evidence": rows}, indent=2, sort_keys=True))
    return 0


def _agents_posture_review(args: argparse.Namespace) -> int:
    from dataclasses import asdict, is_dataclass

    from security_lakehouse.agents import run_posture_review

    state: dict[str, Any] = dict(
        run_posture_review(
            args.lake,
            role=args.role,
            objective=args.objective,
            provider=_agent_provider_from_args(args),
            budget=_agent_budget_from_args(args),
            orchestrator=args.orchestrator,
            checkpoint_thread_id=args.checkpoint_thread,
            resume=bool(args.resume),
        )
    )
    decisions = state.get("decisions") or []
    state["decisions"] = [
        asdict(item) if is_dataclass(item) and not isinstance(item, type) else item for item in decisions
    ]
    print(json.dumps(state, indent=2, sort_keys=True))
    return 0


def _agent_provider_from_args(args: argparse.Namespace):
    from security_lakehouse.agents.providers import ModelProviderConfig, normalize_provider, provider_from_env

    base_provider = provider_from_env()
    return ModelProviderConfig(
        provider=normalize_provider(args.provider or base_provider.provider),
        model=args.model if args.model is not None else base_provider.model,
        base_url=args.base_url if args.base_url is not None else base_provider.base_url,
        api_key_env=args.api_key_env if args.api_key_env is not None else base_provider.api_key_env,
        use_model=bool(args.use_model or base_provider.use_model),
        timeout_seconds=base_provider.timeout_seconds,
    )


def _agent_budget_from_args(args: argparse.Namespace):
    from security_lakehouse.agents.budgets import AgentBudgetPolicy

    base_budget = AgentBudgetPolicy.from_env()
    return AgentBudgetPolicy(
        max_context_chars=args.max_context_chars
        if args.max_context_chars is not None
        else base_budget.max_context_chars,
        max_fact_items=args.max_fact_items if args.max_fact_items is not None else base_budget.max_fact_items,
        max_output_tokens=args.max_output_tokens
        if args.max_output_tokens is not None
        else base_budget.max_output_tokens,
        max_string_chars=base_budget.max_string_chars,
    )


def _agents_soc_triage(args: argparse.Namespace) -> int:
    from dataclasses import asdict, is_dataclass

    from security_lakehouse.agents import run_soc_triage

    state: dict[str, Any] = dict(
        run_soc_triage(
            args.lake,
            role=args.role,
            objective=args.objective,
            provider=_agent_provider_from_args(args),
            budget=_agent_budget_from_args(args),
            orchestrator=args.orchestrator,
            checkpoint_thread_id=args.checkpoint_thread,
            resume=bool(args.resume),
        )
    )
    decisions = state.get("decisions") or []
    state["decisions"] = [
        asdict(item) if is_dataclass(item) and not isinstance(item, type) else item for item in decisions
    ]
    print(json.dumps(state, indent=2, sort_keys=True))
    return 0 if state.get("evaluation", {}).get("ok", False) else 1


def _policy_lint(args: argparse.Namespace) -> int:
    from security_lakehouse.controls import DEFAULT_CATALOG_PATH
    from security_lakehouse.io import read_json
    from security_lakehouse.policy import validate_rule

    catalog = read_json(args.catalog or DEFAULT_CATALOG_PATH)
    if not isinstance(catalog, dict) or not isinstance(catalog.get("controls"), list):
        raise ValueError("policy catalog must be an object containing a controls array")
    controls = catalog["controls"]
    if any(not isinstance(control, dict) for control in controls):
        raise ValueError("policy catalog controls must be objects")
    failures: list[str] = []
    for control in controls:
        control_id = str(control.get("control_id", "?"))
        for problem in validate_rule(control.get("evaluation_rule")):
            failures.append(f"{control_id}: {problem}")
    if failures:
        print("policy lint failed:\n" + "\n".join(f"  - {f}" for f in failures))
        return 1
    print(f"policy lint passed: {len(controls)} control rule(s) valid")
    return 0


def _policy_rules(args: argparse.Namespace) -> int:
    from security_lakehouse.policy import NAMED_RULES

    print(json.dumps(NAMED_RULES, indent=2, sort_keys=True))
    return 0


def _openapi(args: argparse.Namespace) -> int:
    import tempfile

    try:
        from security_lakehouse.server_app import create_app
    except ModuleNotFoundError as exc:
        raise SystemExit("the openapi command requires the 'server' extra: pip install 'grc-lake[server]'") from exc
    from security_lakehouse import api_v1

    with tempfile.TemporaryDirectory() as tmp:
        spec = create_app(tmp, require_auth=False).openapi()
    spec = api_v1.merge_openapi(spec)
    text = json.dumps(spec, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(f"wrote OpenAPI schema ({len(spec.get('paths', {}))} paths): {args.out}")
    else:
        print(text)
    return 0


def _export_parquet(args: argparse.Namespace) -> int:
    from security_lakehouse.parquet_export import export_parquet

    if args.partitioned:
        from security_lakehouse.distributed.partitioning import export_partitions

        result = export_partitions(args.lake, args.out, tenant_id=args.tenant_id, batch_size=args.batch_size)
    else:
        result = export_parquet(args.lake, args.out, tenant_id=args.tenant_id, batch_size=args.batch_size)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _publish_iceberg(args: argparse.Namespace) -> int:
    from security_lakehouse.iceberg_export import publish_iceberg, rest_catalog

    catalog = rest_catalog(
        args.catalog_uri,
        warehouse=args.warehouse,
        token_env=args.token_env,
        allow_http_localhost=args.allow_http_localhost,
    )
    try:
        result = publish_iceberg(
            args.lake, catalog, namespace=args.namespace, table_name=args.table, tenant_id=args.tenant_id
        )
    finally:
        catalog.close()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _scheduler_repair_history(args: argparse.Namespace) -> int:
    from security_lakehouse.scheduler import repair_history

    print(json.dumps(repair_history(args.lake), indent=2))
    return 0


def _evidence_recovery(args: argparse.Namespace) -> int:
    from security_lakehouse.evidence_migration import (
        integrity_checkpoint,
        migrate_workpaper,
        restore_snapshot_files,
        verify_checkpoint,
    )
    from security_lakehouse.io import read_json

    if args.assessment_command == "restore-snapshots":
        result = restore_snapshot_files(Path(args.lake), Path(args.source))
    elif args.assessment_command == "migrate-workpaper":
        result = migrate_workpaper(
            Path(args.source), Path(args.out), content_path=Path(args.content) if args.content else None
        )
    elif args.assessment_command == "checkpoint":
        out = Path(args.out).resolve()
        if out.is_relative_to(Path(args.lake).resolve()):
            raise ValueError("retain checkpoints outside the lake")
        result = integrity_checkpoint(Path(args.lake))
        with out.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
    else:
        result = verify_checkpoint(Path(args.lake), read_json(Path(args.checkpoint)))
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok", True) else 1


def _operational_retention(args: argparse.Namespace) -> int:
    from security_lakehouse.operational_retention import archive_operational_history

    result = archive_operational_history(
        Path(args.lake),
        older_than_days=args.older_than_days,
        archive_to=Path(args.archive_to) if args.archive_to else None,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _lake_retention(args: argparse.Namespace) -> int:
    from security_lakehouse.generation_retention import archive_generations

    result = archive_generations(
        Path(args.lake),
        older_than_days=args.older_than_days,
        keep_latest=args.keep_latest,
        archive_to=Path(args.archive_to) if args.archive_to else None,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Connector sync runner.

This module turns catalog entries from static access contracts into executable
evidence collection runs. Registered runners collect from source APIs or
existing evidence lakes, write raw evidence into the managed raw-event file,
and optionally materialize bronze/silver/gold outputs.
"""

from __future__ import annotations

import fcntl
import importlib.metadata
import logging
import os
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse import netguard
from security_lakehouse.connector_errors import ConnectorConfigError, collection_gaps
from security_lakehouse.connector_state import _safe_run_error, append_run_event, latest_config
from security_lakehouse.connectors import load_connector_catalog
from security_lakehouse.connectors_aws import (
    AWSClient,
    AWSFixtureClient,
    collect_aws_evidence,
    collect_aws_inventory_evidence,
    verify_aws_account,
)
from security_lakehouse.connectors_azure import (
    AzureFixtureClient,
    build_azure_client,
    collect_azure_evidence,
)
from security_lakehouse.connectors_bamboohr import (
    BambooHRClient,
    BambooHRFixtureClient,
    collect_bamboohr_evidence,
)
from security_lakehouse.connectors_bigquery import (
    BigQueryFixtureClient,
    client_from_config,
    collect_bigquery_evidence,
)
from security_lakehouse.connectors_clickhouse import (
    DEFAULT_DATABASE as CLICKHOUSE_DEFAULT_DATABASE,
)
from security_lakehouse.connectors_clickhouse import (
    DEFAULT_TABLE as CLICKHOUSE_DEFAULT_TABLE,
)
from security_lakehouse.connectors_clickhouse import (
    ClickHouseClient,
    ClickHouseFixtureClient,
    collect_clickhouse_evidence,
)
from security_lakehouse.connectors_crowdstrike import (
    CrowdStrikeClient,
    CrowdStrikeFixtureClient,
    collect_crowdstrike_evidence,
)
from security_lakehouse.connectors_databricks import (
    DatabricksClient,
    DatabricksFixtureClient,
    collect_databricks_evidence,
)
from security_lakehouse.connectors_gcp import (
    GCPClient,
    GCPFixtureClient,
    collect_gcp_evidence,
)
from security_lakehouse.connectors_google_workspace import (
    GoogleOAuthTokenSource,
    GoogleWorkspaceClient,
    GoogleWorkspaceFixtureClient,
    collect_google_workspace_evidence,
)
from security_lakehouse.connectors_iceberg import (
    IcebergFixtureClient,
    build_reader,
    collect_iceberg_evidence,
    resolve_iceberg_mappings,
)
from security_lakehouse.connectors_intune import (
    IntuneClient,
    IntuneFixtureClient,
    collect_intune_evidence,
)
from security_lakehouse.connectors_jamf import (
    JamfFixtureClient,
    JamfProClient,
    collect_jamf_evidence,
)
from security_lakehouse.connectors_jira import (
    JiraClient,
    JiraFixtureClient,
    collect_jira_evidence,
)
from security_lakehouse.connectors_knowbe4 import (
    KnowBe4Client,
    KnowBe4FixtureClient,
    collect_knowbe4_evidence,
)
from security_lakehouse.connectors_kubernetes import (
    KubernetesClient,
    KubernetesFixtureClient,
    collect_kubernetes_evidence,
)
from security_lakehouse.connectors_okta import (
    OktaClient,
    OktaFixtureClient,
    collect_okta_evidence,
    collect_okta_system_log_evidence,
)
from security_lakehouse.connectors_rippling import (
    RipplingClient,
    RipplingFixtureClient,
    collect_rippling_evidence,
)
from security_lakehouse.connectors_runtime import (
    RuntimeGatewayClient,
    RuntimeGatewayFixtureClient,
    collect_runtime_gateway_evidence,
)
from security_lakehouse.connectors_s3 import (
    S3Client,
    S3FixtureClient,
    collect_s3_evidence,
)
from security_lakehouse.connectors_siem import (
    SiemClient,
    SiemFixtureClient,
    collect_siem_evidence,
)
from security_lakehouse.connectors_snowflake import (
    DEFAULT_VIEWS as SNOWFLAKE_DEFAULT_VIEWS,
)
from security_lakehouse.connectors_snowflake import (
    SnowflakeClient,
    SnowflakeFixtureClient,
    _probe_query_params,
    collect_snowflake_evidence,
)
from security_lakehouse.connectors_workday import (
    WorkdayReportClient,
    WorkdayReportFixtureClient,
    collect_workday_evidence,
)
from security_lakehouse.delegation import azure_credential, gcp_credentials, server_env_override
from security_lakehouse.event_identity import source_event_key
from security_lakehouse.execution_mode import in_server_mode, server_execution, server_tenant_id
from security_lakehouse.ingestion.watermark import read_watermark, write_watermark
from security_lakehouse.io import read_jsonl, write_jsonl
from security_lakehouse.lake_mapping import (
    DEFAULT_MAX_ROWS,
    collect_mapped_evidence,
    resolve_mappings,
    write_mode_for_options,
)
from security_lakehouse.lake_scale import resolve_materialize_strategy, write_lake_scale_state
from security_lakehouse.offboarding import (
    OFFBOARDING_CONNECTOR_ID,
    correlate_offboarding,
    grace_days_from_env,
    is_offboarding_input,
)
from security_lakehouse.pipeline import normalize_raw_events
from security_lakehouse.repo_governance import sync_repo_governance
from security_lakehouse.secret_refs import resolve_provider_default, resolve_ref_or_default, resolve_secret_ref
from security_lakehouse.sinks import land_if_configured
from security_lakehouse.validation import validate_raw_events

logger = logging.getLogger(__name__)

CONNECTOR_RAW_FILE = "raw/connector_events.jsonl"

# ``entry_points`` group a third-party package registers connectors under (see
# ``effective_registry`` below and the "Ship a connector as a package" section
# of docs/ADDING_CONNECTORS.md).
CONNECTOR_ENTRY_POINT_GROUP = "trustops.connectors"

# Default ``token_env`` for the CLI sync entrypoint. Provider-specific
# installation or OAuth token environment variables are used unless an operator
# explicitly passes ``--token-env``.
DEFAULT_TOKEN_ENV = "__provider_default__"
GITHUB_APP_INSTALLATION_TOKEN_ENV = "TRUSTOPS_GITHUB_APP_INSTALLATION_TOKEN"


def _resolve_provider_token(token_env: str, provider_env: str, env: dict[str, str]) -> str | None:
    """Resolve a third-party source token without cross-provider reuse.

    An explicit ``--token-env`` override wins; otherwise the provider-specific
    variable is used. The generic default is never read for a connector, so one
    source credential cannot silently become another source's auth header.
    """
    if token_env != DEFAULT_TOKEN_ENV:
        explicit = resolve_secret_ref(token_env, env, field="credential_ref", file_first=False)
        if explicit:
            return explicit
    return resolve_provider_default(provider_env, env, file_first=False)


def _read_secret_file_first(name: str, env: dict[str, str]) -> str | None:
    """Resolve a secret named by ``name``, preferring a mounted file.

    A ``<NAME>_FILE`` variable naming a path (the Docker/K8s secret-file
    convention) is read first, so the raw secret can live on disk with
    least-privilege permissions and be revoked by rotating the file, rather than
    sitting inline in the process environment. Falls back to the ``<NAME>`` value
    when no file is configured. Returns ``None`` when neither is set. In hosted
    server mode the name must pass :mod:`secret_refs` policy.
    """
    return resolve_secret_ref(name, env)


def _resolve_provider_secret(ref: str, provider_env: str, env: dict[str, str]) -> str | None:
    """File-first secret resolution for a provider, without cross-provider reuse.

    An explicit ``ref`` (a stored ``*_ref`` credential naming the secret) wins;
    otherwise the provider-specific default variable is used. Each name is
    resolved file-first via :func:`_read_secret_file_first`.
    """
    value = resolve_secret_ref(ref, env) if (ref or "").strip() else None
    return value or resolve_provider_default(provider_env, env)


# Environment variable carrying the Okta org base URL for live collection. The
# token is read from ``token_env`` (defaults to OKTA_API_TOKEN for this runner).
OKTA_ORG_URL_ENV = "OKTA_ORG_URL"

# Environment variables carrying the AWS account id + region for live
# collection. Credentials resolve through boto3's standard provider chain,
# preferably SSO, assumed roles, workload identity, or instance roles.
AWS_ACCOUNT_ID_ENV = "AWS_ACCOUNT_ID"
AWS_REGION_ENV = "AWS_REGION"
# Optional cross-account assume-role auth (the hosted-GRC connect model): the
# customer deploys the read-only role and hands TrustOps only the Role ARN +
# External ID. TrustOps assumes it with its own ambient/base identity. These can
# come from the connector's stored credentials or be overridden by env.
AWS_ROLE_ARN_ENV = "AWS_ROLE_ARN"
AWS_EXTERNAL_ID_ENV = "AWS_EXTERNAL_ID"

# Environment variable carrying the Google Workspace customer id for live
# collection. The OAuth bearer token is read from ``token_env`` (defaults to
# GOOGLE_WORKSPACE_ACCESS_TOKEN for this runner).
GOOGLE_WORKSPACE_CUSTOMER_ID_ENV = "GOOGLE_WORKSPACE_CUSTOMER_ID"
# Optional OAuth refresh material for unattended/long-running collection: a
# refresh token plus the OAuth client id/secret let the runner mint fresh
# access tokens when the ~1h token lapses, rather than failing the sync. The
# refresh token and client secret resolve file-first (see
# ``_read_secret_file_first``); the client id is a non-secret identifier.
GOOGLE_WORKSPACE_REFRESH_TOKEN_ENV = "GOOGLE_WORKSPACE_REFRESH_TOKEN"
GOOGLE_WORKSPACE_OAUTH_CLIENT_ID_ENV = "GOOGLE_WORKSPACE_OAUTH_CLIENT_ID"
GOOGLE_WORKSPACE_OAUTH_CLIENT_SECRET_ENV = "GOOGLE_WORKSPACE_OAUTH_CLIENT_SECRET"

# Environment variable carrying the GCP project id for live collection.
# Credentials resolve through Google's Application Default Credentials chain
# (GOOGLE_APPLICATION_CREDENTIALS / workload identity / metadata server).
GCP_PROJECT_ID_ENV = "GCP_PROJECT_ID"

# Environment variable carrying the Azure subscription id for live collection.
# Locally, credentials resolve through DefaultAzureCredential (service-principal
# env vars, managed identity, CLI) unless the connector names its own app
# registration; hosted server mode requires the latter and ignores both env
# overrides (see delegation.azure_credential).
AZURE_SUBSCRIPTION_ID_ENV = "AZURE_SUBSCRIPTION_ID"
# DefaultAzureCredential's own tenant variable; intune-devices reuses it as the
# operator override for the configured tenant_id.
AZURE_TENANT_ID_ENV = "AZURE_TENANT_ID"

# Jamf Pro and CrowdStrike Falcon authenticate as OAuth API clients; only the
# client id and a reference to the secret are stored. KnowBe4 uses a Reporting
# API key referenced the same way. Kubernetes reads a kubeconfig path (or the
# in-cluster service account) — never an inline token.
JAMF_URL_ENV = "JAMF_URL"
JAMF_CLIENT_ID_ENV = "JAMF_CLIENT_ID"
JAMF_CLIENT_SECRET_ENV = "JAMF_CLIENT_SECRET"
CROWDSTRIKE_CLOUD_ENV = "CROWDSTRIKE_CLOUD"
CROWDSTRIKE_CLIENT_ID_ENV = "CROWDSTRIKE_CLIENT_ID"
CROWDSTRIKE_CLIENT_SECRET_ENV = "CROWDSTRIKE_CLIENT_SECRET"
KUBECONFIG_ENV = "KUBECONFIG"
KUBERNETES_SERVICE_HOST_ENV = "KUBERNETES_SERVICE_HOST"
KNOWBE4_API_TOKEN_ENV = "KNOWBE4_API_TOKEN"

# Environment variables carrying the Jira Cloud site base URL and the account
# email used for HTTP Basic read auth. The read-only API token is read from
# ``token_env`` (defaults to JIRA_API_TOKEN for this runner).
JIRA_BASE_URL_ENV = "JIRA_BASE_URL"
JIRA_EMAIL_ENV = "JIRA_EMAIL"

# Environment variables carrying Snowflake connection metadata for read-only
# evidence-lake collection. Browser SSO is only for human POCs. Continuous
# automation should use a service user with key-pair auth or OAuth materialized
# by the runtime secret manager.
SNOWFLAKE_ACCOUNT_ENV = "SNOWFLAKE_ACCOUNT"
SNOWFLAKE_USER_ENV = "SNOWFLAKE_USER"
SNOWFLAKE_OAUTH_TOKEN_ENV = "SNOWFLAKE_OAUTH_TOKEN"
SNOWFLAKE_PRIVATE_KEY_FILE_ENV = "SNOWFLAKE_PRIVATE_KEY_FILE"
SNOWFLAKE_PRIVATE_KEY_FILE_PWD_ENV = "SNOWFLAKE_PRIVATE_KEY_FILE_PWD"
SNOWFLAKE_AUTHENTICATOR_ENV = "SNOWFLAKE_AUTHENTICATOR"
SNOWFLAKE_WAREHOUSE_ENV = "SNOWFLAKE_WAREHOUSE"
SNOWFLAKE_DATABASE_ENV = "SNOWFLAKE_DATABASE"
SNOWFLAKE_SCHEMA_ENV = "SNOWFLAKE_SCHEMA"
SNOWFLAKE_ROLE_ENV = "SNOWFLAKE_ROLE"


@dataclass(frozen=True)
class ConnectorSyncResult:
    """Result returned by a connector sync run."""

    connector_id: str
    result: str
    raw_path: str
    evidence_count: int
    materialized: bool
    run: dict[str, Any]
    # High-water cursor this connector has synced through (append/event-log
    # connectors only); ``None`` for snapshot connectors that replace state.
    watermark_cursor: str | None = None
    # Sub-collections the provider would not serve (API disabled, permission
    # missing). The sync still lands everything readable; each gap is also a
    # ``*.collection_gap`` evidence row.
    coverage_gaps: list[dict[str, Any]] = field(default_factory=list)


def run_connector_sync(
    lake_dir: str | Path,
    *,
    connector_id: str,
    actor: str = "system",
    repo: str | None = None,
    fixture_dir: str | Path | None = None,
    token_env: str = DEFAULT_TOKEN_ENV,
    materialize: bool = True,
) -> ConnectorSyncResult:
    """Run one configured connector and persist its evidence + run event."""
    if in_server_mode() and not server_tenant_id():
        tenant_id = server_tenant_id(lake_dir)
        if tenant_id:
            # A hosted run without request context (a scheduler or CLI pass over
            # the server's tenant lakes) still acts for the lake's tenant, so
            # tenant-prefixed secret refs resolve and nothing else does.
            with server_execution(tenant_id):
                return run_connector_sync(
                    lake_dir,
                    connector_id=connector_id,
                    actor=actor,
                    repo=repo,
                    fixture_dir=fixture_dir,
                    token_env=token_env,
                    materialize=materialize,
                )
    lake = Path(lake_dir)
    start = time.perf_counter()
    try:
        config = _require_enabled(lake, connector_id)
        credentials = dict(config.get("credentials") or {})
        options = dict(config.get("options") or {})
        write_mode = _write_mode(connector_id, options)
        effective_repo = repo or str(options.get("repo") or "").strip() or None
        effective_fixture = fixture_dir or options.get("fixture_dir")
        effective_token_env = token_env
        if token_env == DEFAULT_TOKEN_ENV:
            ref = str(credentials.get("credential_ref") or options.get("token_env") or "").strip()
            if ref:
                effective_token_env = ref
        # Append/event-log connectors resume from their last high-water cursor so
        # a sync only needs to fetch what is new; snapshot connectors always pull
        # the full current state, so they carry no watermark.
        since = read_watermark(lake, connector_id) if write_mode == "append" else None
        rows = _collect(
            connector_id,
            repo=effective_repo,
            fixture_dir=effective_fixture,
            token_env=effective_token_env,
            since=since,
            credentials=credentials,
            options=options,
        )
        raw_path = lake / CONNECTOR_RAW_FILE
        _upsert_raw_events(raw_path, rows, connector_id=connector_id, write_mode=write_mode)
        if any(is_offboarding_input(row) for row in rows):
            _refresh_offboarding(raw_path, env=dict(os.environ))
        cursor = _advance_watermark(lake, connector_id, rows, write_mode=write_mode)
        if materialize:
            _materialize_after_sync(lake, raw_path, connector_id=connector_id)
            _fire_evidence_changed(lake, connector_id)
        # Rows sharing an event_id upsert onto one evidence row, so the landed
        # count is the distinct ids, not the collected list length.
        evidence_count = len({str(row.get("event_id")) for row in rows})
        gaps = collection_gaps(rows)
        run_metadata: dict[str, Any] = {}
        if gaps:
            run_metadata = {"partial": True, "coverage_gaps": gaps}
        if evidence_count != len(rows):
            run_metadata["collected_rows"] = len(rows)
        run = append_run_event(
            lake,
            connector_id=connector_id,
            kind="sync",
            result="ok",
            actor=actor,
            duration_ms=_duration_ms(start),
            evidence_count=evidence_count,
            metadata=run_metadata or None,
        )
        return ConnectorSyncResult(
            connector_id=connector_id,
            result="ok",
            raw_path=str(raw_path),
            evidence_count=evidence_count,
            materialized=materialize,
            run=run,
            watermark_cursor=cursor,
            coverage_gaps=gaps,
        )
    except Exception as exc:
        run = append_run_event(
            lake,
            connector_id=connector_id,
            kind="sync",
            result="error",
            actor=actor,
            duration_ms=_duration_ms(start),
            error=_safe_run_error(exc),
        )
        raise ConnectorSyncError(str(exc), run=run) from exc


class ConnectorSyncError(RuntimeError):
    """Raised when a connector sync fails after recording a run event."""

    def __init__(self, message: str, *, run: dict[str, Any]) -> None:
        super().__init__(message)
        self.run = run


def _materialize_after_sync(lake: Path, raw_path: Path, *, connector_id: str) -> None:
    """Run scale-aware materialize after a connector sync."""
    from security_lakehouse.lake_scale import LakeEvalError

    env = {} if in_server_mode() else os.environ
    strategy = resolve_materialize_strategy(lake, raw_path, env=env)
    mode = str(strategy["mode"])
    write_lake_scale_state(lake, strategy)
    if mode == "warehouse_required":
        raise LakeEvalError(str(strategy["recommendation"]))
    if mode == "warehouse":
        normalize_raw_events(raw_path, lake, incremental=(lake / "manifest.json").is_file())
        _land_to_sink(lake, connector_id=connector_id)
        return
    if mode == "local_incremental":
        normalize_raw_events(raw_path, lake, incremental=True)
    else:
        normalize_raw_events(raw_path, lake)
    _land_to_sink(lake, connector_id=connector_id)


def _land_to_sink(lake: Path, *, connector_id: str | None = None) -> None:
    """Project the freshly materialized lake to a configured external sink.

    The local lake is the source of truth; configured evidence sinks are optional,
    idempotent projections, so a sink failure — warehouse down, transient auth —
    is reported to stderr and swallowed rather than failing the sync. No-op
    unless a Snowflake, ClickHouse, or DuckDB sink is configured.
    """
    if in_server_mode():
        return
    env = dict(os.environ)
    if connector_id == "snowflake-evidence-lake":
        # Snowflake can be either an existing read-only evidence lake or an
        # optional write sink. A read-connector sync must not infer write-sink
        # intent from the same SNOWFLAKE_* runtime variables used for key-pair
        # auth, otherwise a least-privilege reader sees noisy sink failures.
        for key in (
            SNOWFLAKE_ACCOUNT_ENV,
            SNOWFLAKE_USER_ENV,
            SNOWFLAKE_PRIVATE_KEY_FILE_ENV,
            SNOWFLAKE_PRIVATE_KEY_FILE_PWD_ENV,
            SNOWFLAKE_ROLE_ENV,
            SNOWFLAKE_WAREHOUSE_ENV,
            SNOWFLAKE_DATABASE_ENV,
            SNOWFLAKE_SCHEMA_ENV,
        ):
            env.pop(key, None)
    try:
        landed = land_if_configured(lake, env)
    except Exception as exc:  # noqa: BLE001 - sink is optional; never fatal to collection
        print(
            f"warning: evidence sink load failed ({type(exc).__name__}); local lake is unaffected",
            file=sys.stderr,
        )
        return
    if landed:
        total = sum(sum(tables.values()) for tables in landed.values())
        print(f"evidence sink: landed {total} rows across {list(landed)} -> {landed}", file=sys.stderr)


def _fire_evidence_changed(lake: Path, connector_id: str) -> None:
    """Push side of continuous eval: a sync that landed evidence runs the
    ``trigger.evidence_changed`` workflows immediately, instead of waiting for the
    next cron tick. Best-effort — an automation failure never fails collection.
    """
    try:
        from security_lakehouse.workflows import run_evidence_changed_workflows  # noqa: PLC0415

        runs = run_evidence_changed_workflows(lake, connector_id=connector_id)
    except Exception as exc:  # noqa: BLE001 - automations are optional; never fatal to a sync
        print(f"warning: evidence_changed automations failed ({type(exc).__name__})", file=sys.stderr)
        return
    if runs:
        print(f"evidence_changed: fired {len(runs)} workflow(s) after {connector_id} sync", file=sys.stderr)


def _require_enabled(lake: Path, connector_id: str) -> dict[str, Any]:
    catalog = load_connector_catalog()
    if connector_id not in catalog:
        raise ValueError(f"unknown connector_id {connector_id!r}")
    config = latest_config(lake, connector_id)
    if not config or config.get("state") != "enabled":
        raise ValueError("connector is not enabled; configure it before sync")
    return config


@dataclass(frozen=True)
class SyncInputs:
    """The sync-call inputs handed to a registered connector builder.

    A builder receives the full set of inputs ``run_connector_sync`` knows
    about (plus process ``env``) and is free to use whichever apply to it. This
    keeps the registry contract uniform so a new connector never has to change
    the dispatch site.
    """

    repo: str | None
    fixture_dir: str | Path | None
    token_env: str
    env: dict[str, str]
    # Last high-water cursor for append/event-log connectors, so a builder can
    # scope its pull to records newer than ``since`` (``None`` = full pull).
    since: str | None = None
    # Non-secret identity fields persisted at configure time (e.g. subscription_id,
    # account_id, project_id). Secret material is never stored here — it is
    # redacted to a fingerprint in connector_state — so builders read live secrets
    # from env/credential providers and fall back to these for identity scoping.
    credentials: dict[str, Any] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=dict)


# A connector builder takes the uniform :class:`SyncInputs` and returns the
# collected raw evidence rows. Builders construct the right client (fixture vs
# live) and delegate to that connector's ``collect_*`` function unchanged.
ConnectorBuilder = Callable[[SyncInputs], list[dict[str, Any]]]


# ---------------------------------------------------------------------------
# Connector registry — the single dispatch table for sync collection.
#
# To add a connector, you do NOT edit run_connector_sync or any if/elif chain:
#
#   1. Write ``connectors_<x>.py`` exposing a ``collect_<x>_evidence`` function
#      (and its live + fixture client classes), mirroring connectors_okta.py.
#   2. Add one ``REGISTRY["<x>-id"] = _build_<x>`` entry below, where
#      ``_build_<x>`` is a builder closure that reads the relevant fields off
#      ``SyncInputs`` and calls your ``collect_*`` function.
#
# Registering here wires sync dispatch. Mark the same connector_id with
# ``is_implemented`` in ``connectors/catalog.json`` so connector probes and the
# console can report adapter availability without importing this module.
#
# A separate, additive path exists for connectors shipped as an installable
# package rather than an in-repo adapter: see ``effective_registry`` below and
# docs/ADDING_CONNECTORS.md.
# ---------------------------------------------------------------------------


def _build_github(inputs: SyncInputs) -> list[dict[str, Any]]:
    effective_repo = (inputs.repo or str(inputs.options.get("repo") or "")).strip()
    if not effective_repo:
        raise ValueError("github-security sync requires options.repo (owner/name)")
    # None lets repo governance fall back to the provider default, which the
    # secret-ref policy governs separately from an explicit reference.
    cred_ref = str(inputs.credentials.get("credential_ref") or "").strip()
    explicit = cred_ref or (None if inputs.token_env == DEFAULT_TOKEN_ENV else inputs.token_env)
    return sync_repo_governance(
        effective_repo,
        fixture_dir=inputs.fixture_dir,
        token_env=explicit,
        provider="github",
    )


def _build_gitlab(inputs: SyncInputs) -> list[dict[str, Any]]:
    effective_repo = (inputs.repo or str(inputs.options.get("repo") or "")).strip()
    if not effective_repo:
        raise ValueError("gitlab-security sync requires options.repo (namespace/project)")
    # None lets repo governance fall back to the provider default, which the
    # secret-ref policy governs separately from an explicit reference.
    cred_ref = str(inputs.credentials.get("credential_ref") or "").strip()
    explicit = cred_ref or (None if inputs.token_env == DEFAULT_TOKEN_ENV else inputs.token_env)
    return sync_repo_governance(
        effective_repo,
        fixture_dir=inputs.fixture_dir,
        token_env=explicit,
        provider="gitlab",
    )


def _build_okta(inputs: SyncInputs) -> list[dict[str, Any]]:
    return _collect_okta(
        fixture_dir=inputs.fixture_dir,
        token_env=inputs.token_env,
        env=inputs.env,
        credentials=inputs.credentials,
    )


def _build_okta_system_log(inputs: SyncInputs) -> list[dict[str, Any]]:
    return _collect_okta_system_log(
        fixture_dir=inputs.fixture_dir,
        token_env=inputs.token_env,
        env=inputs.env,
        credentials=inputs.credentials,
        since=inputs.since,
    )


def _build_aws(inputs: SyncInputs) -> list[dict[str, Any]]:
    return _collect_aws(
        fixture_dir=inputs.fixture_dir,
        env=inputs.env,
        credentials=inputs.credentials,
        options=inputs.options,
    )


def _build_google_workspace(inputs: SyncInputs) -> list[dict[str, Any]]:
    return _collect_google_workspace(
        fixture_dir=inputs.fixture_dir,
        token_env=inputs.token_env,
        env=inputs.env,
        credentials=inputs.credentials,
    )


def _build_gcp(inputs: SyncInputs) -> list[dict[str, Any]]:
    return _collect_gcp(fixture_dir=inputs.fixture_dir, env=inputs.env, credentials=inputs.credentials)


def _build_azure(inputs: SyncInputs) -> list[dict[str, Any]]:
    return _collect_azure(fixture_dir=inputs.fixture_dir, env=inputs.env, credentials=inputs.credentials)


def _build_intune(inputs: SyncInputs) -> list[dict[str, Any]]:
    return _collect_intune(fixture_dir=inputs.fixture_dir, env=inputs.env, credentials=inputs.credentials)


def _build_bamboohr(inputs: SyncInputs) -> list[dict[str, Any]]:
    return _collect_bamboohr(fixture_dir=inputs.fixture_dir, env=inputs.env, credentials=inputs.credentials)


def _build_rippling(inputs: SyncInputs) -> list[dict[str, Any]]:
    return _collect_rippling(fixture_dir=inputs.fixture_dir, env=inputs.env, credentials=inputs.credentials)


def _build_workday(inputs: SyncInputs) -> list[dict[str, Any]]:
    return _collect_workday(fixture_dir=inputs.fixture_dir, env=inputs.env, credentials=inputs.credentials)


def _build_databricks(inputs: SyncInputs) -> list[dict[str, Any]]:
    return _collect_databricks(
        fixture_dir=inputs.fixture_dir,
        env=inputs.env,
        credentials=inputs.credentials,
        options=inputs.options,
        since=inputs.since,
    )


def _build_jamf(inputs: SyncInputs) -> list[dict[str, Any]]:
    return _collect_jamf(fixture_dir=inputs.fixture_dir, env=inputs.env, credentials=inputs.credentials)


def _build_crowdstrike(inputs: SyncInputs) -> list[dict[str, Any]]:
    return _collect_crowdstrike(fixture_dir=inputs.fixture_dir, env=inputs.env, credentials=inputs.credentials)


def _build_kubernetes(inputs: SyncInputs) -> list[dict[str, Any]]:
    return _collect_kubernetes(fixture_dir=inputs.fixture_dir, env=inputs.env, credentials=inputs.credentials)


def _build_knowbe4(inputs: SyncInputs) -> list[dict[str, Any]]:
    return _collect_knowbe4(fixture_dir=inputs.fixture_dir, env=inputs.env, credentials=inputs.credentials)


def _build_jira(inputs: SyncInputs) -> list[dict[str, Any]]:
    return _collect_jira(
        fixture_dir=inputs.fixture_dir,
        token_env=inputs.token_env,
        env=inputs.env,
        credentials=inputs.credentials,
    )


def _build_snowflake(inputs: SyncInputs) -> list[dict[str, Any]]:
    return _collect_snowflake(
        fixture_dir=inputs.fixture_dir,
        token_env=inputs.token_env,
        env=inputs.env,
        credentials=inputs.credentials,
        options=inputs.options,
        since=inputs.since,
    )


def _build_clickhouse(inputs: SyncInputs) -> list[dict[str, Any]]:
    return _collect_clickhouse(
        fixture_dir=inputs.fixture_dir,
        env=inputs.env,
        credentials=inputs.credentials,
        options=inputs.options,
        since=inputs.since,
    )


def _build_object_storage(inputs: SyncInputs) -> list[dict[str, Any]]:
    return _collect_s3(
        fixture_dir=inputs.fixture_dir,
        env=inputs.env,
        credentials=inputs.credentials,
        options=inputs.options,
    )


def _build_siem(inputs: SyncInputs) -> list[dict[str, Any]]:
    return _collect_siem(
        fixture_dir=inputs.fixture_dir,
        env=inputs.env,
        credentials=inputs.credentials,
        options=inputs.options,
        since=inputs.since,
    )


def _build_runtime_gateway(inputs: SyncInputs) -> list[dict[str, Any]]:
    return _collect_runtime_gateway(
        fixture_dir=inputs.fixture_dir,
        env=inputs.env,
        credentials=inputs.credentials,
        options=inputs.options,
        since=inputs.since,
    )


def _build_iceberg(inputs: SyncInputs) -> list[dict[str, Any]]:
    specs = resolve_iceberg_mappings(inputs.credentials, inputs.options)
    reader: Any = (
        IcebergFixtureClient(inputs.fixture_dir)
        if inputs.fixture_dir
        else build_reader(inputs.credentials, inputs.options, env=inputs.env)
    )
    return collect_iceberg_evidence(reader, specs, since=inputs.since, max_rows=_max_rows_per_sync(inputs.options))


def _build_bigquery(inputs: SyncInputs) -> list[dict[str, Any]]:
    specs = resolve_mappings(inputs.options)
    if not specs:
        raise ValueError("bigquery-evidence-lake needs options.mapping or options.mappings")
    client: Any = (
        BigQueryFixtureClient(inputs.fixture_dir)
        if inputs.fixture_dir
        else client_from_config(inputs.credentials, inputs.options)
    )
    return collect_bigquery_evidence(client, specs, since=inputs.since, max_rows=_max_rows_per_sync(inputs.options))


REGISTRY: dict[str, ConnectorBuilder] = {
    "snowflake-evidence-lake": _build_snowflake,
    "clickhouse-telemetry-lake": _build_clickhouse,
    "object-storage-evidence": _build_object_storage,
    "siem-alerts": _build_siem,
    "runtime-gateway": _build_runtime_gateway,
    "github-security": _build_github,
    "gitlab-security": _build_gitlab,
    "okta-identity": _build_okta,
    "okta-system-log": _build_okta_system_log,
    "aws-posture": _build_aws,
    "google-workspace-identity": _build_google_workspace,
    "gcp-posture": _build_gcp,
    "azure-posture": _build_azure,
    "jira-ticketing": _build_jira,
    "intune-devices": _build_intune,
    "bamboohr-personnel": _build_bamboohr,
    "rippling-personnel": _build_rippling,
    "workday-personnel": _build_workday,
    "databricks-evidence-lake": _build_databricks,
    "jamf-devices": _build_jamf,
    "crowdstrike-falcon": _build_crowdstrike,
    "kubernetes-cluster": _build_kubernetes,
    "knowbe4-training": _build_knowbe4,
    "iceberg-parquet-lake": _build_iceberg,
    "bigquery-evidence-lake": _build_bigquery,
}


def registered_connector_ids() -> frozenset[str]:
    """The set of connector_ids with a sync builder registered in REGISTRY.

    Tests compare this against the catalog's ``is_implemented`` metadata so the
    runner dispatch table and UI/probe adapter flags cannot drift. This is the
    in-repo registry only — see :func:`effective_registry` for the dispatch
    view that also includes installed third-party connectors.
    """
    return frozenset(REGISTRY)


def _load_entry_point_connectors() -> dict[str, ConnectorBuilder]:
    """Discover connectors registered by installed packages.

    A third-party package declares connectors under the
    ``trustops.connectors`` entry-point group in its own ``pyproject.toml``
    (see docs/ADDING_CONNECTORS.md). Each entry point's name is the
    connector_id; loading it must yield a callable implementing the
    :data:`ConnectorBuilder` contract exactly (``Callable[[SyncInputs],
    list[dict[str, Any]]]``).

    A package that fails to import, or whose entry point does not resolve to
    a callable, is logged and excluded rather than raised: one broken
    third-party connector must never prevent the rest of the registry — or
    the app — from starting.
    """
    discovered: dict[str, ConnectorBuilder] = {}
    try:
        entry_points = importlib.metadata.entry_points(group=CONNECTOR_ENTRY_POINT_GROUP)
    except Exception:
        logger.warning("failed to enumerate %s entry points", CONNECTOR_ENTRY_POINT_GROUP, exc_info=True)
        return discovered
    for entry_point in entry_points:
        try:
            builder = entry_point.load()
        except Exception:
            logger.warning(
                "connector entry point %r (%s) failed to load; excluding it",
                entry_point.name,
                entry_point.value,
                exc_info=True,
            )
            continue
        if not callable(builder):
            logger.warning(
                "connector entry point %r (%s) did not resolve to a callable ConnectorBuilder; excluding it",
                entry_point.name,
                entry_point.value,
            )
            continue
        discovered[entry_point.name] = builder
    return discovered


def effective_registry() -> dict[str, ConnectorBuilder]:
    """The in-repo REGISTRY merged with connectors from installed packages.

    Third-party connectors extend the registry with new connector_ids; they
    can never shadow an in-repo adapter. A colliding entry-point connector_id
    is logged as a warning and dropped in favor of the built-in — silently
    overwriting a built-in adapter with an installed package is never safe.
    ``REGISTRY`` itself is left untouched by this merge.
    """
    merged = _load_entry_point_connectors()
    for connector_id in merged:
        if connector_id in REGISTRY:
            logger.warning(
                "connector entry point %r collides with a built-in connector_id; the built-in adapter wins",
                connector_id,
            )
    merged.update(REGISTRY)
    return merged


def _collect(
    connector_id: str,
    *,
    repo: str | None,
    fixture_dir: str | Path | None,
    token_env: str,
    since: str | None = None,
    credentials: dict[str, Any] | None = None,
    options: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    builder = effective_registry().get(connector_id)
    if builder is None:
        raise ValueError(f"no sync runner registered for connector_id {connector_id!r}")
    return builder(
        SyncInputs(
            repo=repo,
            fixture_dir=fixture_dir,
            token_env=token_env,
            env=dict(os.environ),
            since=since,
            credentials=dict(credentials or {}),
            options=dict(options or {}),
        )
    )


def _collect_okta(
    *,
    fixture_dir: str | Path | None,
    token_env: str,
    env: dict[str, str],
    credentials: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    client: OktaClient | OktaFixtureClient
    creds = credentials or {}
    if fixture_dir:
        client = OktaFixtureClient(fixture_dir)
    else:
        org_url = str(env.get(OKTA_ORG_URL_ENV) or creds.get("org_url") or "").strip()
        effective_token_env = str(creds.get("credential_ref") or token_env)
        token = _resolve_provider_token(effective_token_env, "OKTA_API_TOKEN", env)
        if not org_url or not token:
            raise ValueError(
                "okta-identity sync requires --fixture-dir, or "
                f"{OKTA_ORG_URL_ENV}/org_url plus a read-only API token (OKTA_API_TOKEN or --token-env)"
            )
        netguard.assert_url_is_public(org_url, label="okta org url")
        client = OktaClient(org_url, token=token)
    return collect_okta_evidence(client)


def _collect_okta_system_log(
    *,
    fixture_dir: str | Path | None,
    token_env: str,
    env: dict[str, str],
    credentials: dict[str, Any] | None = None,
    since: str | None = None,
) -> list[dict[str, Any]]:
    client: OktaClient | OktaFixtureClient
    creds = credentials or {}
    if fixture_dir:
        client = OktaFixtureClient(fixture_dir)
    else:
        org_url = str(env.get(OKTA_ORG_URL_ENV) or creds.get("org_url") or "").strip()
        effective_token_env = str(creds.get("credential_ref") or token_env)
        token = _resolve_provider_token(effective_token_env, "OKTA_API_TOKEN", env)
        if not org_url or not token:
            raise ValueError(
                "okta-system-log sync requires --fixture-dir, or "
                f"{OKTA_ORG_URL_ENV}/org_url plus a read-only API token (OKTA_API_TOKEN or --token-env)"
            )
        netguard.assert_url_is_public(org_url, label="okta org url")
        client = OktaClient(org_url, token=token)
    return collect_okta_system_log_evidence(client, since=since)


def _collect_aws(
    *,
    fixture_dir: str | Path | None,
    env: dict[str, str],
    credentials: dict[str, Any] | None = None,
    options: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    creds = credentials or {}
    scope = options or {}
    if fixture_dir:
        fixture_account = env.get(AWS_ACCOUNT_ID_ENV) or str(creds.get("account_id") or "") or "000000000000"
        return collect_aws_evidence(AWSFixtureClient(fixture_dir), account_id=fixture_account)
    # account_id and (optional) cross-account assume-role config come from the
    # connector's stored credentials, with env overrides for operators.
    account_id = env.get(AWS_ACCOUNT_ID_ENV) or str(creds.get("account_id") or "").strip()
    if not account_id:
        raise ConnectorConfigError(
            "aws-posture sync requires --fixture-dir, a configured account_id, or "
            f"{AWS_ACCOUNT_ID_ENV}, plus read-only AWS credentials "
            "(SSO profile, assumed role, instance role, or the standard provider chain)"
        )
    # An operator env override would point every hosted tenant at one role, so
    # server mode uses only the tenant's stored role and external id.
    role_arn = (server_env_override(env.get(AWS_ROLE_ARN_ENV)) or str(creds.get("role_arn") or "")).strip() or None
    external_id = (
        server_env_override(env.get(AWS_EXTERNAL_ID_ENV)) or str(creds.get("external_id") or "")
    ).strip() or None
    default_region = env.get(AWS_REGION_ENV) or str(scope.get("region") or "us-east-1")
    client = AWSClient(region_name=default_region, role_arn=role_arn, external_id=external_id)
    # Never label one account's evidence with another account's id.
    verify_aws_account(client, account_id)
    rows = collect_aws_evidence(client, account_id=account_id)
    raw_regions = scope.get("regions") or [default_region]
    regions = (
        [str(item).strip() for item in raw_regions]
        if isinstance(raw_regions, list)
        else [item.strip() for item in str(raw_regions).split(",")]
    )
    raw_services = scope.get("services") or []
    services = (
        [str(item).strip().lower() for item in raw_services]
        if isinstance(raw_services, list)
        else [item.strip().lower() for item in str(raw_services).split(",") if item.strip()]
    )
    if services:
        rows.extend(
            collect_aws_inventory_evidence(
                client,
                account_id=account_id,
                regions=[region for region in regions if region],
                services=services,
            )
        )
    return rows


def _collect_google_workspace(
    *,
    fixture_dir: str | Path | None,
    token_env: str,
    env: dict[str, str],
    credentials: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    client: GoogleWorkspaceClient | GoogleWorkspaceFixtureClient
    creds = credentials or {}
    if fixture_dir:
        client = GoogleWorkspaceFixtureClient(fixture_dir)
    else:
        customer_id = str(env.get(GOOGLE_WORKSPACE_CUSTOMER_ID_ENV) or creds.get("customer_id") or "").strip()
        effective_token_env = str(creds.get("credential_ref") or token_env)
        access_token = _resolve_provider_token(effective_token_env, "GOOGLE_WORKSPACE_ACCESS_TOKEN", env)
        token_source = _build_google_workspace_token_source(creds, env, access_token=access_token)
        if not customer_id or (token_source is None and not access_token):
            raise ValueError(
                "google-workspace-identity sync requires --fixture-dir, or "
                f"{GOOGLE_WORKSPACE_CUSTOMER_ID_ENV}/customer_id plus a read-only OAuth token "
                "(GOOGLE_WORKSPACE_ACCESS_TOKEN or --token-env), optionally with a refresh token "
                "and OAuth client id/secret for unattended refresh"
            )
        if token_source is not None:
            client = GoogleWorkspaceClient(customer_id, token_source=token_source)
        else:
            client = GoogleWorkspaceClient(customer_id, access_token=access_token)
    return collect_google_workspace_evidence(client)


def _build_google_workspace_token_source(
    creds: dict[str, Any],
    env: dict[str, str],
    *,
    access_token: str | None,
) -> GoogleOAuthTokenSource | None:
    """Build a self-refreshing token source when OAuth refresh material is set.

    Returns ``None`` when the full set (refresh token + client id + client
    secret) is not configured, so the connector falls back to the static
    access-token path unchanged. Secrets resolve file-first; the resolved token
    lives only in the source's memory and is never persisted.
    """
    refresh_ref = str(creds.get("refresh_token_ref") or "").strip()
    client_secret_ref = str(creds.get("client_secret_ref") or "").strip()
    refresh_token = _resolve_provider_secret(refresh_ref, GOOGLE_WORKSPACE_REFRESH_TOKEN_ENV, env)
    client_secret = _resolve_provider_secret(client_secret_ref, GOOGLE_WORKSPACE_OAUTH_CLIENT_SECRET_ENV, env)
    client_id = str(creds.get("client_id") or env.get(GOOGLE_WORKSPACE_OAUTH_CLIENT_ID_ENV) or "").strip()
    if not (refresh_token and client_id and client_secret):
        return None
    return GoogleOAuthTokenSource(
        refresh_token=refresh_token,
        client_id=client_id,
        client_secret=client_secret,
        access_token=access_token,
    )


def _collect_gcp(
    *,
    fixture_dir: str | Path | None,
    env: dict[str, str],
    credentials: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    stored_project = str((credentials or {}).get("project_id") or "").strip()
    if fixture_dir:
        fixture_project = env.get(GCP_PROJECT_ID_ENV) or stored_project or "fixture-project"
        return collect_gcp_evidence(GCPFixtureClient(fixture_dir, project_id=fixture_project))
    # Prefer the env override, else the project_id captured at configure time so an
    # enabled connector syncs without re-exporting GCP_PROJECT_ID.
    project_id = env.get(GCP_PROJECT_ID_ENV) or stored_project
    if not project_id:
        raise ConnectorConfigError(
            "gcp-posture sync requires --fixture-dir, a configured project_id, or "
            f"{GCP_PROJECT_ID_ENV}, plus read-only GCP credentials "
            "(Application Default Credentials: gcloud auth application-default login, "
            "GOOGLE_APPLICATION_CREDENTIALS, or workload identity)"
        )
    delegated = gcp_credentials(credentials or {})
    client = GCPClient(project_id, credentials=delegated) if delegated is not None else GCPClient(project_id)
    return collect_gcp_evidence(client, project_id=project_id)


def _collect_azure(
    *,
    fixture_dir: str | Path | None,
    env: dict[str, str],
    credentials: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    stored_subscription = str((credentials or {}).get("subscription_id") or "").strip()
    env_subscription = server_env_override(env.get(AZURE_SUBSCRIPTION_ID_ENV))
    if fixture_dir:
        subscription_id = env_subscription or stored_subscription or "00000000-0000-0000-0000-000000000000"
        return collect_azure_evidence(AzureFixtureClient(fixture_dir, subscription_id=subscription_id))
    # Prefer the env var (operator override, local only) but fall back to the subscription_id
    # captured at configure time so an enabled connector syncs without re-exporting it.
    subscription_id = env_subscription or stored_subscription
    if not subscription_id:
        raise ConnectorConfigError(
            "azure-posture sync requires --fixture-dir, a configured subscription_id, or "
            f"{AZURE_SUBSCRIPTION_ID_ENV} (local only), plus read-only Azure credentials "
            "(the tenant's app registration, or locally DefaultAzureCredential: service-principal "
            "env vars, managed identity, or az login)"
        )
    return collect_azure_evidence(build_azure_client(subscription_id, credentials or {}, env))


def _collect_intune(
    *,
    fixture_dir: str | Path | None,
    env: dict[str, str],
    credentials: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    tenant_id = (
        server_env_override(env.get(AZURE_TENANT_ID_ENV)) or str((credentials or {}).get("tenant_id") or "").strip()
    )
    if fixture_dir:
        return collect_intune_evidence(
            IntuneFixtureClient(fixture_dir, tenant_id=tenant_id or "00000000-0000-0000-0000-000000000000")
        )
    if not tenant_id:
        raise ConnectorConfigError(
            "intune-devices sync requires --fixture-dir, a configured tenant_id, or "
            f"{AZURE_TENANT_ID_ENV} (local only), plus an identity granted the Microsoft Graph "
            "application permission DeviceManagementManagedDevices.Read.All (the tenant's app "
            "registration, or locally DefaultAzureCredential)"
        )
    delegated = azure_credential({**(credentials or {}), "tenant_id": tenant_id}, env, label="intune-devices")
    return collect_intune_evidence(IntuneClient(tenant_id, credential=delegated))


def _collect_bamboohr(
    *,
    fixture_dir: str | Path | None,
    env: dict[str, str],
    credentials: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    creds = credentials or {}
    company_domain = str(creds.get("company_domain") or "").strip()
    if fixture_dir:
        return collect_bamboohr_evidence(BambooHRFixtureClient(fixture_dir, company_domain=company_domain or "fixture"))
    api_key = _resolve_provider_secret(str(creds.get("credential_ref") or ""), "BAMBOOHR_API_KEY", env)
    if not company_domain or not api_key:
        raise ValueError(
            "bamboohr-personnel sync requires --fixture-dir, or a configured company_domain plus an API key "
            "for a dedicated read-only BambooHR user (credential_ref naming the secret, or BAMBOOHR_API_KEY)"
        )
    return collect_bamboohr_evidence(BambooHRClient(company_domain, api_key=api_key))


def _collect_rippling(
    *,
    fixture_dir: str | Path | None,
    env: dict[str, str],
    credentials: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if fixture_dir:
        return collect_rippling_evidence(RipplingFixtureClient(fixture_dir))
    creds = credentials or {}
    token = _resolve_provider_secret(str(creds.get("credential_ref") or ""), "RIPPLING_API_TOKEN", env)
    if not token:
        raise ValueError(
            "rippling-personnel sync requires --fixture-dir, or a Rippling API token with the workers.read scope "
            "(credential_ref naming the secret, or RIPPLING_API_TOKEN)"
        )
    return collect_rippling_evidence(RipplingClient(token=token))


def _collect_workday(
    *,
    fixture_dir: str | Path | None,
    env: dict[str, str],
    credentials: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    creds = credentials or {}
    report_url = str(creds.get("report_url") or "").strip()
    if fixture_dir:
        return collect_workday_evidence(WorkdayReportFixtureClient(fixture_dir, report_url=report_url))
    username = str(creds.get("username") or "").strip()
    password = _resolve_provider_secret(str(creds.get("credential_ref") or ""), "WORKDAY_ISU_PASSWORD", env)
    if not report_url or not username or not password:
        raise ValueError(
            "workday-personnel sync requires --fixture-dir, or a configured report_url and username plus the "
            "integration system user's password (credential_ref naming the secret, or WORKDAY_ISU_PASSWORD)"
        )
    return collect_workday_evidence(WorkdayReportClient(report_url, username=username, password=password))


def _collect_databricks(
    *,
    fixture_dir: str | Path | None,
    env: dict[str, str],
    credentials: dict[str, Any] | None = None,
    options: dict[str, Any] | None = None,
    since: str | None = None,
) -> list[dict[str, Any]]:
    creds = credentials or {}
    host = str(creds.get("host") or env.get("DATABRICKS_HOST") or "").strip()
    if fixture_dir:
        fixture_client = DatabricksFixtureClient(fixture_dir, host=host)
        mapped = _collect_mapped(fixture_client, options or {}, since=since, source="databricks")
        return mapped if mapped is not None else collect_databricks_evidence(fixture_client)
    fields = {name: str(creds.get(name) or "").strip() for name in ("warehouse_id", "catalog", "schema", "client_id")}
    secret = _resolve_provider_secret(str(creds.get("client_secret_ref") or ""), "DATABRICKS_CLIENT_SECRET", env)
    if not host or not secret or not all(fields.values()):
        raise ValueError(
            "databricks-evidence-lake sync requires --fixture-dir, or a configured host, warehouse_id, catalog, "
            "schema, and service-principal client_id plus its OAuth secret (client_secret_ref or "
            "DATABRICKS_CLIENT_SECRET)"
        )
    client = DatabricksClient(
        host,
        client_id=fields["client_id"],
        client_secret=secret,
        warehouse_id=fields["warehouse_id"],
        catalog=fields["catalog"],
        schema=fields["schema"],
    )
    mapped = _collect_mapped(client, options or {}, since=since, source="databricks")
    return mapped if mapped is not None else collect_databricks_evidence(client)


def _collect_jamf(
    *,
    fixture_dir: str | Path | None,
    env: dict[str, str],
    credentials: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    creds = credentials or {}
    base_url = str(creds.get("base_url") or env.get(JAMF_URL_ENV) or "").strip()
    screen_lock_attribute = str(creds.get("screen_lock_attribute") or "").strip() or None
    if fixture_dir:
        return collect_jamf_evidence(
            JamfFixtureClient(fixture_dir, base_url=base_url or "https://fixture.jamfcloud.com"),
            screen_lock_attribute=screen_lock_attribute,
        )
    client_id = str(creds.get("client_id") or env.get(JAMF_CLIENT_ID_ENV) or "").strip()
    secret = _resolve_provider_secret(str(creds.get("client_secret_ref") or ""), JAMF_CLIENT_SECRET_ENV, env)
    if not base_url or not client_id or not secret:
        raise ValueError(
            "jamf-devices sync requires --fixture-dir, or a configured base_url and API client_id plus the "
            f"API client secret (client_secret_ref naming the secret, or {JAMF_CLIENT_SECRET_ENV}); the API "
            "client's role needs only Read Computers and Read Mobile Devices"
        )
    return collect_jamf_evidence(
        JamfProClient(base_url, client_id=client_id, client_secret=secret),
        screen_lock_attribute=screen_lock_attribute,
    )


def _collect_crowdstrike(
    *,
    fixture_dir: str | Path | None,
    env: dict[str, str],
    credentials: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    creds = credentials or {}
    cloud = str(creds.get("cloud") or env.get(CROWDSTRIKE_CLOUD_ENV) or "us-1").strip()
    if fixture_dir:
        return collect_crowdstrike_evidence(CrowdStrikeFixtureClient(fixture_dir, cloud=cloud))
    client_id = str(creds.get("client_id") or env.get(CROWDSTRIKE_CLIENT_ID_ENV) or "").strip()
    secret = _resolve_provider_secret(str(creds.get("client_secret_ref") or ""), CROWDSTRIKE_CLIENT_SECRET_ENV, env)
    if not client_id or not secret:
        raise ValueError(
            "crowdstrike-falcon sync requires --fixture-dir, or a Falcon API client_id plus its secret "
            f"(client_secret_ref naming the secret, or {CROWDSTRIKE_CLIENT_SECRET_ENV}) with only the "
            "Hosts, Prevention policies, and Alerts read scopes"
        )
    return collect_crowdstrike_evidence(CrowdStrikeClient(cloud, client_id=client_id, client_secret=secret))


def _collect_kubernetes(
    *,
    fixture_dir: str | Path | None,
    env: dict[str, str],
    credentials: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    creds = credentials or {}
    cluster_name = str(creds.get("cluster_name") or "").strip()
    allowed_registries = _split_list(creds.get("allowed_registries"))
    if fixture_dir:
        return collect_kubernetes_evidence(
            KubernetesFixtureClient(fixture_dir, cluster_name=cluster_name or "fixture-cluster"),
            allowed_registries=allowed_registries,
        )
    if not cluster_name:
        raise ValueError(
            "kubernetes-cluster sync requires --fixture-dir, or a configured cluster_name plus a read-only "
            "service account (in-cluster, or a kubeconfig named by kubeconfig_ref / KUBECONFIG)"
        )
    kubeconfig_ref = str(creds.get("kubeconfig_ref") or "").strip()
    kubeconfig_path = resolve_secret_ref(kubeconfig_ref, env, field="kubeconfig_ref", file_first=False)
    if in_server_mode(env):
        # The server's own service account and kubeconfig belong to the
        # operator; a hosted tenant must name its own kubeconfig.
        if _truthy(creds.get("in_cluster")) or not kubeconfig_path:
            raise ConnectorConfigError(
                "kubernetes-cluster in hosted mode requires kubeconfig_ref naming the tenant kubeconfig; "
                "the in-cluster service account and the server KUBECONFIG are not used"
            )
        in_cluster = False
    else:
        kubeconfig_path = kubeconfig_path or env.get(KUBECONFIG_ENV) or None
        in_cluster = _truthy(creds.get("in_cluster")) or (
            not kubeconfig_path and bool(env.get(KUBERNETES_SERVICE_HOST_ENV))
        )
    context = str(creds.get("context") or "").strip() or None
    return collect_kubernetes_evidence(
        KubernetesClient(cluster_name, context=context, kubeconfig_path=kubeconfig_path, in_cluster=in_cluster),
        allowed_registries=allowed_registries,
    )


def _collect_knowbe4(
    *,
    fixture_dir: str | Path | None,
    env: dict[str, str],
    credentials: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    creds = credentials or {}
    region = str(creds.get("region") or "us").strip().lower()
    if fixture_dir:
        return collect_knowbe4_evidence(KnowBe4FixtureClient(fixture_dir, region=region))
    token = _resolve_provider_secret(str(creds.get("credential_ref") or ""), KNOWBE4_API_TOKEN_ENV, env)
    if not token:
        raise ValueError(
            "knowbe4-training sync requires --fixture-dir, or a KnowBe4 Reporting API key "
            f"(credential_ref naming the secret, or {KNOWBE4_API_TOKEN_ENV}) and the account region"
        )
    return collect_knowbe4_evidence(KnowBe4Client(region, token=token))


def _split_list(value: Any) -> list[str] | None:
    items = value if isinstance(value, list) else str(value or "").split(",")
    cleaned = [str(item).strip() for item in items if str(item).strip()]
    return cleaned or None


def _truthy(value: Any) -> bool:
    return value is True or str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _collect_jira(
    *,
    fixture_dir: str | Path | None,
    token_env: str,
    env: dict[str, str],
    credentials: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    client: JiraClient | JiraFixtureClient
    creds = credentials or {}
    if fixture_dir:
        client = JiraFixtureClient(fixture_dir)
    else:
        base_url = str(env.get(JIRA_BASE_URL_ENV) or creds.get("base_url") or "").strip()
        email = str(env.get(JIRA_EMAIL_ENV) or creds.get("email") or "").strip()
        effective_token_env = str(creds.get("credential_ref") or token_env)
        token = _resolve_provider_token(effective_token_env, "JIRA_API_TOKEN", env)
        if not base_url or not email or not token:
            raise ValueError(
                "jira-ticketing sync requires --fixture-dir, or "
                f"{JIRA_BASE_URL_ENV}/base_url plus {JIRA_EMAIL_ENV}/email and a read-only API token "
                "(JIRA_API_TOKEN or --token-env)"
            )
        netguard.assert_url_is_public(base_url, label="jira base url")
        client = JiraClient(base_url, email=email, token=token)
    return collect_jira_evidence(client)


def _collect_clickhouse(
    *,
    fixture_dir: str | Path | None,
    env: dict[str, str],
    credentials: dict[str, Any] | None = None,
    options: dict[str, Any] | None = None,
    since: str | None = None,
) -> list[dict[str, Any]]:
    credentials = credentials or {}
    options = options or {}
    database = str(options.get("database") or CLICKHOUSE_DEFAULT_DATABASE).strip() or CLICKHOUSE_DEFAULT_DATABASE
    table = str(options.get("table") or CLICKHOUSE_DEFAULT_TABLE).strip() or CLICKHOUSE_DEFAULT_TABLE
    if fixture_dir:
        client: ClickHouseClient | ClickHouseFixtureClient = ClickHouseFixtureClient(fixture_dir, database=database)
    else:
        host = str(credentials.get("host") or env.get("CLICKHOUSE_HOST") or "").strip()
        user = str(credentials.get("user") or env.get("CLICKHOUSE_USER") or "default").strip() or "default"
        password = str(
            credentials.get("token")
            or credentials.get("password")
            or resolve_ref_or_default(
                credentials.get("credential_ref"), "CLICKHOUSE_PASSWORD", env, field="credential_ref", file_first=False
            )
            or ""
        ).strip()
        if not host:
            raise ValueError(
                "clickhouse-telemetry-lake sync requires --fixture-dir, or host plus read-only credentials"
            )
        from security_lakehouse import netguard

        netguard.assert_url_is_public(host, label="clickhouse host")
        client = ClickHouseClient(host, user=user, password=password, database=database)
    mapped = _collect_mapped(client, options, since=since, source="clickhouse")
    if mapped is not None:
        return mapped
    return collect_clickhouse_evidence(client, table=table, since=since)


def _collect_s3(
    *,
    fixture_dir: str | Path | None,
    env: dict[str, str],
    credentials: dict[str, Any] | None = None,
    options: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    credentials = credentials or {}
    options = options or {}
    bucket = str(options.get("bucket") or credentials.get("bucket") or "").strip()
    prefix = str(options.get("prefix") or credentials.get("prefix") or "").strip()
    if fixture_dir:
        client: S3Client | S3FixtureClient = S3FixtureClient(fixture_dir, bucket=bucket or "trustops-evidence")
    else:
        if not bucket:
            raise ValueError(
                "object-storage-evidence sync requires --fixture-dir, or options.bucket plus read-only S3 credentials"
            )
        role_arn = (
            server_env_override(env.get(AWS_ROLE_ARN_ENV)) or str(credentials.get("role_arn") or "")
        ).strip() or None
        external_id = (
            server_env_override(env.get(AWS_EXTERNAL_ID_ENV)) or str(credentials.get("external_id") or "")
        ).strip() or None
        client = S3Client(
            bucket=bucket,
            prefix=prefix,
            region_name=env.get(AWS_REGION_ENV) or str(credentials.get("region") or "").strip() or None,
            role_arn=role_arn,
            external_id=external_id,
        )
    return collect_s3_evidence(client, bucket=bucket or getattr(client, "bucket", None), prefix=prefix)


def _collect_siem(
    *,
    fixture_dir: str | Path | None,
    env: dict[str, str],
    credentials: dict[str, Any] | None = None,
    options: dict[str, Any] | None = None,
    since: str | None = None,
) -> list[dict[str, Any]]:
    credentials = credentials or {}
    options = options or {}
    index = str(options.get("index") or "alerts").strip() or "alerts"
    if fixture_dir:
        client: SiemClient | SiemFixtureClient = SiemFixtureClient(fixture_dir, index=index)
    else:
        host = str(credentials.get("host") or env.get("SIEM_EXPORT_URL") or "").strip()
        token = str(
            credentials.get("token")
            or resolve_ref_or_default(
                credentials.get("credential_ref"), "TRUSTOPS_SIEM_TOKEN", env, field="credential_ref", file_first=False
            )
            or ""
        ).strip()
        if not host:
            raise ValueError("siem-alerts sync requires --fixture-dir, or host plus read-only credentials")
        netguard.assert_url_is_public(host, label="siem export url")
        client = SiemClient(host, token=token, index=index)
    return collect_siem_evidence(client, since=since)


def _collect_runtime_gateway(
    *,
    fixture_dir: str | Path | None,
    env: dict[str, str],
    credentials: dict[str, Any] | None = None,
    options: dict[str, Any] | None = None,
    since: str | None = None,
) -> list[dict[str, Any]]:
    credentials = credentials or {}
    options = options or {}
    stream = str(options.get("stream") or "runtime-events").strip() or "runtime-events"
    if fixture_dir:
        client: RuntimeGatewayClient | RuntimeGatewayFixtureClient = RuntimeGatewayFixtureClient(
            fixture_dir, stream=stream
        )
    else:
        host = str(credentials.get("host") or env.get("RUNTIME_GATEWAY_URL") or "").strip()
        token = str(
            credentials.get("token")
            or resolve_ref_or_default(
                credentials.get("credential_ref"),
                "TRUSTOPS_RUNTIME_GATEWAY_TOKEN",
                env,
                field="credential_ref",
                file_first=False,
            )
            or ""
        ).strip()
        if not host:
            raise ValueError("runtime-gateway sync requires --fixture-dir, or host plus read-only credentials")
        netguard.assert_url_is_public(host, label="runtime gateway url")
        client = RuntimeGatewayClient(host, token=token, stream=stream)
    return collect_runtime_gateway_evidence(client, since=since)


def _collect_snowflake(
    *,
    fixture_dir: str | Path | None,
    token_env: str,
    env: dict[str, str],
    credentials: dict[str, Any] | None = None,
    options: dict[str, Any] | None = None,
    since: str | None = None,
) -> list[dict[str, Any]]:
    client: SnowflakeClient | SnowflakeFixtureClient
    credentials = credentials or {}
    options = options or {}
    account = str(credentials.get("account") or env.get(SNOWFLAKE_ACCOUNT_ENV) or "").strip() or None
    if fixture_dir:
        client = SnowflakeFixtureClient(fixture_dir, account=account or "fixture-snowflake")
    else:
        effective_credentials = {
            "account": account,
            "user": str(credentials.get("user") or env.get(SNOWFLAKE_USER_ENV) or "").strip(),
            "role": str(credentials.get("role") or env.get(SNOWFLAKE_ROLE_ENV) or "").strip(),
            "authenticator": str(
                credentials.get("authenticator") or env.get(SNOWFLAKE_AUTHENTICATOR_ENV) or ""
            ).strip(),
            "credential_ref": str(credentials.get("credential_ref") or "").strip(),
            "oauth_token_ref": str(credentials.get("oauth_token_ref") or "").strip(),
            "private_key_ref": str(credentials.get("private_key_ref") or "").strip(),
            "private_key_file_pwd_ref": str(credentials.get("private_key_file_pwd_ref") or "").strip(),
        }
        effective_options = {
            "warehouse": str(options.get("warehouse") or env.get(SNOWFLAKE_WAREHOUSE_ENV) or "").strip(),
            "database": str(options.get("database") or env.get(SNOWFLAKE_DATABASE_ENV) or "").strip(),
            "schema": str(options.get("schema") or env.get(SNOWFLAKE_SCHEMA_ENV) or "").strip(),
            "role": str(options.get("role") or env.get(SNOWFLAKE_ROLE_ENV) or "").strip(),
            "authenticator": str(options.get("authenticator") or env.get(SNOWFLAKE_AUTHENTICATOR_ENV) or "").strip(),
        }
        if token_env != DEFAULT_TOKEN_ENV and resolve_secret_ref(
            token_env, env, field="credential_ref", file_first=False
        ):
            effective_credentials["credential_ref"] = token_env
        elif not effective_credentials["credential_ref"] and resolve_provider_default(
            SNOWFLAKE_OAUTH_TOKEN_ENV, env, file_first=False
        ):
            effective_credentials["credential_ref"] = SNOWFLAKE_OAUTH_TOKEN_ENV
        if not effective_credentials["private_key_ref"] and resolve_provider_default(
            SNOWFLAKE_PRIVATE_KEY_FILE_ENV, env, file_first=False
        ):
            effective_credentials["private_key_ref"] = SNOWFLAKE_PRIVATE_KEY_FILE_ENV
        if not effective_credentials["private_key_file_pwd_ref"] and resolve_provider_default(
            SNOWFLAKE_PRIVATE_KEY_FILE_PWD_ENV, env, file_first=False
        ):
            effective_credentials["private_key_file_pwd_ref"] = SNOWFLAKE_PRIVATE_KEY_FILE_PWD_ENV
        try:
            params = _probe_query_params(credentials=effective_credentials, options=effective_options, env=env)
        except ConnectorConfigError:
            raise
        except ValueError as exc:
            raise ValueError(
                "snowflake-evidence-lake sync requires --fixture-dir, or "
                f"{SNOWFLAKE_ACCOUNT_ENV} plus {SNOWFLAKE_USER_ENV} with browser SSO "
                f"({SNOWFLAKE_AUTHENTICATOR_ENV}=externalbrowser), a Snowflake service-user key file "
                f"({SNOWFLAKE_PRIVATE_KEY_FILE_ENV}), or a read-only OAuth token "
                f"({SNOWFLAKE_OAUTH_TOKEN_ENV} or --token-env)"
            ) from exc
        views = {
            key: str(options.get(key) or env.get(f"SNOWFLAKE_VIEW_{key.upper()}") or default)
            for key, default in SNOWFLAKE_DEFAULT_VIEWS.items()
        }
        client = SnowflakeClient(query_params=params, views=views)
    mapped = _collect_mapped(client, options, since=since, source="snowflake")
    if mapped is not None:
        return mapped
    return collect_snowflake_evidence(client, account=account)


def _collect_mapped(
    client: Any, options: dict[str, Any], *, since: str | None, source: str
) -> list[dict[str, Any]] | None:
    """Collect through ``options.mapping``/``options.mappings`` when configured, else ``None``.

    ``None`` keeps the reader on its TrustOps-shaped view contract, so existing
    configurations behave exactly as before.
    """
    specs = resolve_mappings(options)
    if not specs:
        return None
    return collect_mapped_evidence(
        lambda spec, bound, limit: client.fetch_mapping_rows(spec, since=bound, limit=limit),
        specs,
        since=since,
        max_rows=_max_rows_per_sync(options),
        default_source=source,
    )


def _max_rows_per_sync(options: dict[str, Any]) -> int:
    raw = options.get("max_rows_per_sync")
    if raw is None or raw == "":
        return DEFAULT_MAX_ROWS
    try:
        value = int(str(raw))
    except (TypeError, ValueError) as exc:
        raise ValueError("options.max_rows_per_sync must be an integer") from exc
    if not 1 <= value <= 1_000_000:
        raise ValueError("options.max_rows_per_sync must be between 1 and 1000000")
    return value


# A connector whose evidence describes current state (IAM, config, inventory)
# is written as a per-run snapshot: the latest pull is the whole truth, so an
# entity removed at the source must disappear from the lake. Event-log evidence
# (audit/alert streams) is append-only: history is never overwritten.
SNAPSHOT_DATA_SHAPE = "current_state"


def _write_mode(connector_id: str, options: dict[str, Any] | None = None) -> str:
    """Resolve the raw-write mode for ``connector_id`` from its catalog data shape.

    ``current_state`` → ``snapshot`` (replace this connector's prior rows so
    deletions propagate); anything else → ``append`` (the non-destructive default,
    used for event-log sources and any connector that does not declare a shape).
    A configured lake mapping overrides the catalog shape: incremental mappings
    read event logs (append), full re-read mappings replace (snapshot).
    """
    mapped_mode = write_mode_for_options(options or {})
    if mapped_mode is not None:
        return mapped_mode
    entry = load_connector_catalog().get(connector_id) or {}
    return "snapshot" if entry.get("data_shape") == SNAPSHOT_DATA_SHAPE else "append"


def _advance_watermark(lake: Path, connector_id: str, rows: list[dict[str, Any]], *, write_mode: str) -> str | None:
    """Advance an append connector's high-water cursor to the newest event time.

    Returns the cursor written (the max ``event_time`` across ``rows``), or
    ``None`` for a snapshot connector or a pull with no timestamped rows. The
    cursor is monotonic: an out-of-order or partial re-pull never moves it back,
    so the next sync resumes from the true high-water mark.
    """
    if write_mode != "append":
        return None
    cursors = [str(row.get("event_time")) for row in rows if row.get("event_time")]
    if not cursors:
        return read_watermark(lake, connector_id)
    from security_lakehouse.models import parse_event_time, utc_iso

    cursor = utc_iso(max(parse_event_time(value) for value in cursors))
    prior = read_watermark(lake, connector_id)
    if prior is not None and parse_event_time(cursor) <= parse_event_time(prior):
        return prior
    write_watermark(lake, connector_id, cursor)
    return cursor


def _dedupe_latest(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Retain the newest instant per connector/source ID; reject ambiguous ties."""
    from security_lakehouse.io import canonical_sha256
    from security_lakehouse.models import parse_event_time

    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        key = source_event_key(row)
        prior = latest.get(key)
        moment = parse_event_time(str(row["event_time"]))
        if prior is None or moment > parse_event_time(str(prior["event_time"])):
            latest[key] = row
        elif moment == parse_event_time(str(prior["event_time"])):
            # Recollection metadata may advance while immutable source content
            # stays identical. A changed outcome at the same source time is ambiguous.
            def content(value):
                evidence = dict(value.get("evidence") or {})
                evidence.pop("collected_at", None)
                evidence.pop("evidence_collected_at", None)
                return {
                    **value,
                    "event_time": parse_event_time(str(value["event_time"])).isoformat(),
                    "evidence": evidence,
                }

            def collected(value):
                evidence = value.get("evidence") or {}
                return parse_event_time(
                    str(evidence.get("collected_at") or evidence.get("evidence_collected_at") or value["event_time"])
                )

            if canonical_sha256(content(row)) != canonical_sha256(content(prior)):
                raise ValueError("conflicting observations at the same event timestamp")
            if collected(row) > collected(prior):
                latest[key] = row
    return list(latest.values())


def _upsert_raw_events(
    raw_path: Path,
    rows: list[dict[str, Any]],
    *,
    connector_id: str,
    write_mode: str,
) -> list[dict[str, Any]]:
    # Stamp ownership so a snapshot replace can scope to this connector's rows
    # without disturbing evidence collected by any other connector.
    for row in rows:
        row["connector_id"] = connector_id

    raw_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = raw_path.with_suffix(".lock")
    with open(lock_path, "a") as lock_fd:
        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
        existing = read_jsonl(raw_path) if raw_path.exists() else []
        fresh = _dedupe_latest(rows)

        if write_mode == "snapshot":
            # Only this connector owns its snapshot deletions. Preserve newer
            # observations for redelivered IDs, independently of arrival order.
            incoming_keys = {source_event_key(row) for row in fresh}
            retained = [
                row
                for row in existing
                if row.get("connector_id") != connector_id or source_event_key(row) in incoming_keys
            ]
            merged = _dedupe_latest(retained + fresh)
        else:
            merged = _dedupe_latest(existing + fresh)

        errors = validate_raw_events(merged)
        if errors:
            raise ValueError("connector raw evidence validation failed:\n" + "\n".join(errors))
        write_jsonl(raw_path, merged)
    return merged


def _refresh_offboarding(raw_path: Path, *, env: dict[str, str]) -> None:
    """Rebuild the HR-termination ↔ IdP-account rows as a snapshot.

    Read and write happen under the same lock as ``_upsert_raw_events`` so two
    concurrent HR/IdP syncs cannot each derive from a view missing the other.
    """
    lock_path = raw_path.with_suffix(".lock")
    with open(lock_path, "a") as lock_fd:
        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
        existing = read_jsonl(raw_path) if raw_path.exists() else []
        now = datetime.now(UTC)
        derived = correlate_offboarding(
            (row for row in existing if row.get("connector_id") != OFFBOARDING_CONNECTOR_ID),
            as_of=now.date(),
            collected_at=now,
            grace_days=grace_days_from_env(env),
        )
        for row in derived:
            row["connector_id"] = OFFBOARDING_CONNECTOR_ID
        merged = [row for row in existing if row.get("connector_id") != OFFBOARDING_CONNECTOR_ID] + derived
        errors = validate_raw_events(merged)
        if errors:
            raise ValueError("offboarding evidence validation failed:\n" + "\n".join(errors))
        write_jsonl(raw_path, merged)


def _duration_ms(start: float) -> int:
    return max(0, int((time.perf_counter() - start) * 1000))

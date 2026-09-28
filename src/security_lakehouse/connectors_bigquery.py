"""BigQuery lake reader (preview).

Reads existing BigQuery tables through lake mappings with one parameterized
standard-SQL SELECT per mapping (``@name`` query parameters; only validated
identifiers reach the SQL text). Authentication is Application Default
Credentials: workload identity, an attached service account, or gcloud ADC.
No key file is configured in TrustOps. ``impersonate_service_account`` makes the
reader impersonate a customer service account from that ADC identity; hosted
server mode requires it, and there a fully qualified source table must live in
the configured project unless ``options.allow_cross_project`` is set.

Least privilege is ``roles/bigquery.jobUser`` on the project that runs the
query plus ``roles/bigquery.dataViewer`` on the source dataset. Every query
carries ``maximum_bytes_billed`` so a mapping that would scan more than the
cap fails instead of running up cost. The client only talks to Google's API
endpoint; no endpoint override is accepted.

Requires the ``bigquery`` extra (``google-cloud-bigquery``).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from security_lakehouse.connector_errors import ConnectorConfigError
from security_lakehouse.delegation import gcp_credentials
from security_lakehouse.execution_mode import in_server_mode
from security_lakehouse.lake_mapping import (
    DEFAULT_MAX_ROWS,
    MappingSpec,
    collect_mapped_evidence,
    compile_select,
    json_safe_row,
    read_fixture_table,
)

CONNECTOR_ID = "bigquery-evidence-lake"
SOURCE = "bigquery"
DEFAULT_MAXIMUM_BYTES_BILLED = 10 * 1024**3
MAX_MAXIMUM_BYTES_BILLED = 10 * 1024**4

_PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,61}[a-z0-9]$")
_DATASET = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,1023}$")
_LOCATION = re.compile(r"^[A-Za-z][A-Za-z0-9-]{1,40}$")


class BigQueryClient:
    """Read-only BigQuery client; credentials come from ADC unless injected (tests)."""

    def __init__(
        self,
        project: str,
        *,
        dataset: str | None = None,
        location: str | None = None,
        maximum_bytes_billed: int = DEFAULT_MAXIMUM_BYTES_BILLED,
        credentials: Any = None,
        allow_cross_project: bool = False,
    ) -> None:
        if not _PROJECT.fullmatch(str(project or "")):
            raise ValueError("project_id must be a Google Cloud project id (6-30 lowercase letters, digits, '-')")
        if dataset and not _DATASET.fullmatch(dataset):
            raise ValueError("dataset must contain only letters, digits, and underscores")
        if location and not _LOCATION.fullmatch(location):
            raise ValueError("location must be a BigQuery location such as US, EU, or us-central1")
        if not 1 <= int(maximum_bytes_billed) <= MAX_MAXIMUM_BYTES_BILLED:
            raise ValueError(f"maximum_bytes_billed must be between 1 and {MAX_MAXIMUM_BYTES_BILLED}")
        try:
            from google.cloud import bigquery  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover - optional extra
            raise RuntimeError(
                "bigquery-evidence-lake live reads need the 'bigquery' extra (google-cloud-bigquery)"
            ) from exc
        self._bigquery = bigquery
        self.project = project
        self.dataset = dataset
        self.maximum_bytes_billed = int(maximum_bytes_billed)
        self.allow_cross_project = bool(allow_cross_project)
        self.client = bigquery.Client(project=project, location=location, credentials=credentials)

    def fetch_mapping_rows(self, spec: MappingSpec, *, since: str | None, limit: int) -> list[dict[str, Any]]:
        parts = str(spec.source_table).split(".")
        if len(parts) == 3 and parts[0] != self.project and not self.allow_cross_project and in_server_mode():
            raise ConnectorConfigError(
                f"mapping {spec.name!r} reads a table outside the configured project; "
                "set options.allow_cross_project to allow it"
            )
        namespace = (self.project, self.dataset) if self.dataset else ()
        query = compile_select(spec, "bigquery", since=since, limit=limit, default_namespace=namespace)
        job_config = self._bigquery.QueryJobConfig(
            query_parameters=[
                self._bigquery.ScalarQueryParameter(name, type_, value)
                for name, type_, value in query.bigquery_parameters()
            ],
            use_legacy_sql=False,
            maximum_bytes_billed=self.maximum_bytes_billed,
            labels={"app": "trustops", "purpose": "lake-reader"},
        )
        rows = self.client.query_and_wait(query.sql, job_config=job_config)
        return [json_safe_row(dict(row.items())) for row in rows]


class BigQueryFixtureClient:
    """Offline reader: ``<table>.json``/``.jsonl`` rows from a fixture directory."""

    def __init__(self, fixture_dir: str | Path) -> None:
        self.fixture = Path(fixture_dir)

    def fetch_mapping_rows(self, spec: MappingSpec, *, since: str | None, limit: int) -> list[dict[str, Any]]:
        _ = since, limit  # map_rows applies the same bound; fixtures are small
        return read_fixture_table(self.fixture, spec.source_table)


def client_from_config(credentials: dict[str, Any], options: dict[str, Any]) -> BigQueryClient:
    raw_cap = options.get("maximum_bytes_billed")
    try:
        cap = DEFAULT_MAXIMUM_BYTES_BILLED if raw_cap in (None, "") else int(str(raw_cap))
    except ValueError as exc:
        raise ValueError("options.maximum_bytes_billed must be an integer") from exc
    return BigQueryClient(
        str(credentials.get("project_id") or "").strip(),
        dataset=str(credentials.get("dataset") or "").strip() or None,
        location=str(credentials.get("location") or "").strip() or None,
        maximum_bytes_billed=cap,
        credentials=gcp_credentials(credentials),
        allow_cross_project=str(options.get("allow_cross_project") or "").strip().lower() in {"1", "true", "yes"},
    )


def collect_bigquery_evidence(
    client: Any,
    specs: list[MappingSpec],
    *,
    since: str | None = None,
    max_rows: int = DEFAULT_MAX_ROWS,
    tenant_id: str = "customer-managed",
) -> list[dict[str, Any]]:
    return collect_mapped_evidence(
        lambda spec, bound, limit: client.fetch_mapping_rows(spec, since=bound, limit=limit),
        specs,
        since=since,
        max_rows=max_rows,
        tenant_id=tenant_id,
        default_source=SOURCE,
    )

"""Iceberg / Parquet lake reader (preview).

Reads tables the customer already runs, read-only, through lake mappings:

* Apache Iceberg tables through an AWS Glue catalog (for example Amazon
  Security Lake source version 2) or an Iceberg REST catalog.
* Plain Parquet datasets (Hive-style partitions allowed) on S3, or on a local
  path under an operator-set root.

No SQL is generated. Filters and the incremental watermark become pyiceberg
row filters or pyarrow dataset expressions built from validated column names
and typed values, so scans prune files and partitions. Rows are then ordered by
the observed-time column and bounded per sync, and ``lake_mapping.map_rows``
re-applies the same filters and bound.

Egress: Glue and S3 use the AWS SDK's regional endpoints; no endpoint override
is accepted from GRC Lake configuration. Catalog-supplied storage settings are
filtered, not trusted: FileIO keeps only vended short-lived credentials and the
region from a REST catalog's config/table responses (endpoint, proxy, signer,
role, retry and FileIO implementation keys are dropped), and every metadata,
manifest, and data location must use an s3 scheme (or the configured REST
warehouse's object-store scheme). HTTP is always refused; ``file:`` and bare paths are refused
for REST and Glue alike (see ``iceberg_export.guarded_file_io``). A REST catalog
URI must be HTTPS and resolve to a public address (netguard); the hardened REST
client from ``iceberg_export`` refuses redirects and endpoint relocation.

Requires the ``iceberg`` extra (pyiceberg + pyarrow) for Iceberg and the
``parquet`` extra (pyarrow) for Parquet; AWS catalogs also need boto3.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from security_lakehouse import netguard
from security_lakehouse.connector_errors import ConnectorConfigError
from security_lakehouse.delegation import require_aws_delegation
from security_lakehouse.execution_mode import in_server_mode, server_tenant_id
from security_lakehouse.lake_mapping import (
    DEFAULT_MAX_ROWS,
    MappingError,
    MappingSpec,
    collect_mapped_evidence,
    json_safe_row,
    lower_bound,
    read_fixture_table,
    resolve_mapping_ref,
    resolve_mappings,
)
from security_lakehouse.runtime_environment import runtime_env
from security_lakehouse.secret_refs import SecretRefPolicyError, secret_ref_denial

CONNECTOR_ID = "iceberg-parquet-lake"
SOURCE = "iceberg"
CATALOG_TYPES = ("glue", "rest", "parquet")
LOCAL_ROOT_ENV = "GRC_LAKE_LAKE_LOCAL_ROOT"
DEFAULT_REST_TOKEN_ENV = "GRC_LAKE_ICEBERG_TOKEN"
DEFAULT_INITIAL_WINDOW_DAYS = 30

# Amazon Security Lake source version 2 (OCSF 1.1.0, Iceberg) table suffixes and
# the presets that split each table by class_uid.
SECURITY_LAKE_PRESETS = {
    "cloud_trail_mgmt": ("ocsf/authentication", "ocsf/account_change", "ocsf/api_activity"),
    "sh_findings": ("ocsf/detection_finding", "ocsf/vulnerability_finding", "ocsf/compliance_finding"),
}

_REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d$")
_ROLE_ARN = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$")
_ACCOUNT_ID = re.compile(r"^\d{12}$")
_EXTERNAL_ID = re.compile(r"^[A-Za-z0-9+=,.@:/_-]{2,1224}$")
_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,254}$")


# --------------------------------------------------------------------------------
# Readers
# --------------------------------------------------------------------------------


class _WindowMixin:
    initial_window_days: int
    _now: Callable[[], datetime]

    def _effective_since(self, spec: MappingSpec, since: str | None) -> str | None:
        """The first incremental sync reads a bounded recent window, not the whole history."""
        if since or not spec.incremental or self.initial_window_days <= 0:
            return since
        return (self._now() - timedelta(days=self.initial_window_days)).isoformat()


class IcebergCatalogReader(_WindowMixin):
    """Read Iceberg tables from any pyiceberg catalog (Glue, REST, or SQL in tests)."""

    def __init__(
        self,
        catalog: Any,
        *,
        initial_window_days: int = DEFAULT_INITIAL_WINDOW_DAYS,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.catalog = catalog
        self.initial_window_days = initial_window_days
        self._now = now

    def fetch_mapping_rows(self, spec: MappingSpec, *, since: str | None, limit: int) -> list[dict[str, Any]]:
        from pyiceberg.expressions import (  # noqa: PLC0415
            AlwaysTrue,
            And,
            BooleanExpression,
            EqualTo,
            GreaterThanOrEqual,
            In,
            IsNull,
            NotEqualTo,
            NotIn,
            NotNull,
            Reference,
        )

        table = self.catalog.load_table(_table_identifier(spec.source_table))
        names = {field.name.lower(): field.name for field in table.schema().fields}
        observed = _require_column(names, spec, spec.observed_column)
        selected = tuple(names[column.lower()] for column in spec.top_level_columns() if column.lower() in names)

        expression: BooleanExpression = AlwaysTrue()
        for item in spec.filters:
            column = _require_column(names, spec, item.column)
            clause: BooleanExpression
            if item.op == "eq":
                clause = EqualTo(term=Reference(column), value=item.value)
            elif item.op == "ne":
                clause = NotEqualTo(term=Reference(column), value=item.value)
            elif item.op == "in":
                clause = In(term=Reference(column), values=set(item.value))
            elif item.op == "not_in":
                clause = NotIn(term=Reference(column), values=set(item.value))
            elif item.op == "is_null":
                clause = IsNull(term=Reference(column))
            else:
                clause = NotNull(term=Reference(column))
            expression = And(expression, clause)
        bound = lower_bound(spec, self._effective_since(spec, since))
        if bound is not None:
            expression = And(expression, GreaterThanOrEqual(term=Reference(observed), value=_typed_bound(spec, bound)))
        arrow = table.scan(row_filter=expression, selected_fields=selected).to_arrow()
        return _ordered_rows(arrow, observed, limit)


class ParquetDatasetReader(_WindowMixin):
    """Read Parquet datasets (optionally Hive-partitioned) from S3 or an allowed local root."""

    def __init__(
        self,
        paths: dict[str, str],
        *,
        region: str | None = None,
        credentials: dict[str, str] | None = None,
        initial_window_days: int = DEFAULT_INITIAL_WINDOW_DAYS,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        env: dict[str, str] | None = None,
    ) -> None:
        env = runtime_env(env)
        environment = runtime_env() if env is None else env
        self.locations = {table: _parse_location(uri, environment) for table, uri in paths.items()}
        self.region = region
        self._credentials = credentials or {}
        self.initial_window_days = initial_window_days
        self._now = now

    def fetch_mapping_rows(self, spec: MappingSpec, *, since: str | None, limit: int) -> list[dict[str, Any]]:
        import pyarrow.dataset as ds  # noqa: PLC0415

        location = self.locations.get(spec.source_table) or self.locations.get("*")
        if location is None:
            raise ValueError(f"no Parquet path is configured for table {spec.source_table!r}")
        kind, path = location
        filesystem = self._s3() if kind == "s3" else None
        dataset = ds.dataset(path, format="parquet", partitioning="hive", filesystem=filesystem)
        schema = dataset.schema
        names = {name.lower(): name for name in schema.names}
        observed = _require_column(names, spec, spec.observed_column)
        selected = [names[column.lower()] for column in spec.top_level_columns() if column.lower() in names]

        expression = None
        for item in spec.filters:
            column = _require_column(names, spec, item.column)
            clause = _arrow_filter(ds.field(column), schema.field(column).type, item.op, item.value)
            if clause is not None:
                expression = clause if expression is None else expression & clause
        bound = lower_bound(spec, self._effective_since(spec, since))
        if bound is not None:
            clause = _arrow_bound(ds.field(observed), schema.field(observed).type, spec, bound)
            if clause is not None:
                expression = clause if expression is None else expression & clause
        arrow = dataset.to_table(columns=selected, filter=expression)
        return _ordered_rows(arrow, observed, limit)

    def _s3(self) -> Any:
        from pyarrow import fs  # noqa: PLC0415

        kwargs: dict[str, Any] = {}
        if self.region:
            kwargs["region"] = self.region
        if self._credentials:
            kwargs.update(
                access_key=self._credentials["AccessKeyId"],
                secret_key=self._credentials["SecretAccessKey"],
                session_token=self._credentials["SessionToken"],
            )
        return fs.S3FileSystem(**kwargs)


class IcebergFixtureClient:
    """Offline reader: ``<table>.json``/``.jsonl`` rows from a fixture directory."""

    def __init__(self, fixture_dir: str | Path) -> None:
        self.fixture = Path(fixture_dir)

    def fetch_mapping_rows(self, spec: MappingSpec, *, since: str | None, limit: int) -> list[dict[str, Any]]:
        _ = since, limit  # map_rows applies the same bound; fixtures are small
        return read_fixture_table(self.fixture, spec.source_table)


# --------------------------------------------------------------------------------
# Construction from connector configuration
# --------------------------------------------------------------------------------


def build_reader(
    credentials: dict[str, Any], options: dict[str, Any], *, env: dict[str, str]
) -> IcebergCatalogReader | ParquetDatasetReader:
    env = runtime_env(env)
    catalog_type = str(credentials.get("catalog_type") or "").strip()
    window = _initial_window_days(options)
    if catalog_type == "glue":
        return IcebergCatalogReader(
            glue_catalog(
                region=_region(credentials),
                role_arn=_optional(credentials, "role_arn", _ROLE_ARN),
                external_id=_optional(credentials, "external_id", _EXTERNAL_ID),
                catalog_id=_optional(credentials, "catalog_id", _ACCOUNT_ID),
            ),
            initial_window_days=window,
        )
    if catalog_type == "rest":
        uri = str(credentials.get("uri") or "").strip()
        warehouse = str(credentials.get("warehouse") or "").strip()
        explicit_ref = str(credentials.get("credential_ref") or "").strip()
        token_env = explicit_ref or DEFAULT_REST_TOKEN_ENV
        if not uri or not warehouse:
            raise ValueError("iceberg-parquet-lake REST catalogs need uri and warehouse")
        if not _ENV_NAME.fullmatch(token_env):
            raise ValueError("credential_ref must name an environment variable holding the catalog bearer token")
        denial = secret_ref_denial(token_env, env=env, field="credential_ref")
        if denial and explicit_ref:
            raise SecretRefPolicyError(denial)
        if denial:
            raise ConnectorConfigError(
                "iceberg-parquet-lake REST catalogs in hosted mode need credential_ref naming the tenant token"
            )
        if not uri.startswith("https://"):
            raise ValueError("iceberg-parquet-lake REST catalog uri must use https")
        netguard.assert_url_is_public(uri, label="iceberg rest catalog")
        from security_lakehouse.iceberg_export import IcebergPublicationError, rest_catalog  # noqa: PLC0415

        try:
            catalog = rest_catalog(uri, warehouse=warehouse, token_env=token_env, pin_public=True)
        except IcebergPublicationError as exc:
            raise ValueError(f"Iceberg REST catalog: {exc}") from None
        return IcebergCatalogReader(catalog, initial_window_days=window)
    if catalog_type == "parquet":
        region = _region(credentials) if credentials.get("region") else None
        role_arn = _optional(credentials, "role_arn", _ROLE_ARN)
        paths = _parquet_paths(credentials, options)
        external_id = _optional(credentials, "external_id", _EXTERNAL_ID)
        if any(str(uri).strip().startswith("s3://") for uri in paths.values()):
            require_aws_delegation(role_arn, external_id, label="iceberg-parquet-lake")
        session_credentials = (
            _assume_role(role_arn, _optional(credentials, "external_id", _EXTERNAL_ID), region) if role_arn else None
        )
        return ParquetDatasetReader(
            paths, region=region, credentials=session_credentials, initial_window_days=window, env=env
        )
    raise ValueError(f"catalog_type must be one of {', '.join(CATALOG_TYPES)}")


def glue_catalog(
    *,
    region: str,
    role_arn: str | None = None,
    external_id: str | None = None,
    catalog_id: str | None = None,
) -> Any:
    """A pyiceberg Glue catalog whose FileIO is pinned to catalog-level settings."""
    require_aws_delegation(role_arn, external_id, label="iceberg-parquet-lake")
    try:
        import boto3  # noqa: PLC0415
        from pyiceberg.catalog.glue import GlueCatalog  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - optional extra
        raise RuntimeError(
            "iceberg-parquet-lake Glue reads need the 'iceberg' and 'cloud' extras (pyiceberg, pyarrow, boto3)"
        ) from exc

    properties: dict[str, str] = {"glue.region": region, "s3.region": region}
    session_kwargs: dict[str, Any] = {"region_name": region}
    if role_arn:
        creds = _assume_role(role_arn, external_id, region)
        session_kwargs.update(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
        properties.update(
            {
                "s3.access-key-id": creds["AccessKeyId"],
                "s3.secret-access-key": creds["SecretAccessKey"],
                "s3.session-token": creds["SessionToken"],
            }
        )
    if catalog_id:
        properties["glue.id"] = catalog_id
    glue_client = boto3.Session(**session_kwargs).client("glue")

    class PinnedGlueCatalog(GlueCatalog):
        def _load_file_io(self, properties: Any = None, location: str | None = None) -> Any:
            # Table metadata must not redirect storage reads (endpoint, proxy,
            # signer), choose the FileIO implementation, or point a metadata,
            # manifest, or data location at the local disk or an HTTP host.
            from security_lakehouse.iceberg_export import guarded_file_io  # noqa: PLC0415

            return guarded_file_io(dict(self.properties))

    return PinnedGlueCatalog("trustops_glue", client=glue_client, **properties)


def resolve_iceberg_mappings(credentials: dict[str, Any], options: dict[str, Any]) -> list[MappingSpec]:
    """Configured mappings, or the Security Lake OCSF presets for a Glue catalog."""
    specs = resolve_mappings(options)
    if specs:
        return specs
    if str(credentials.get("catalog_type") or "") != "glue":
        raise ValueError("iceberg-parquet-lake needs options.mapping or options.mappings for REST and Parquet sources")
    return security_lake_mappings(_region(credentials), options.get("security_lake_sources"))


def security_lake_mappings(region: str, sources: Any = None) -> list[MappingSpec]:
    if isinstance(sources, str):
        sources = [part.strip() for part in sources.split(",") if part.strip()]
    chosen = list(SECURITY_LAKE_PRESETS) if sources in (None, []) else sources
    if not isinstance(chosen, list) or not all(source in SECURITY_LAKE_PRESETS for source in chosen):
        raise ValueError(f"options.security_lake_sources must list any of {', '.join(SECURITY_LAKE_PRESETS)}")
    suffix = region.replace("-", "_")
    database = f"amazon_security_lake_glue_db_{suffix}"
    specs: list[MappingSpec] = []
    for source in dict.fromkeys(chosen):
        table = f"{database}.amazon_security_lake_table_{suffix}_{source}_2_0"
        specs.extend(
            resolve_mapping_ref({"preset": preset, "source": {"table": table}})
            for preset in SECURITY_LAKE_PRESETS[source]
        )
    return specs


def collect_iceberg_evidence(
    reader: Any,
    specs: list[MappingSpec],
    *,
    since: str | None = None,
    max_rows: int = DEFAULT_MAX_ROWS,
    collected_at: datetime | None = None,
    tenant_id: str = "customer-managed",
) -> list[dict[str, Any]]:
    return collect_mapped_evidence(
        lambda spec, bound, limit: reader.fetch_mapping_rows(spec, since=bound, limit=limit),
        specs,
        since=since,
        max_rows=max_rows,
        collected_at=collected_at,
        tenant_id=tenant_id,
        default_source=SOURCE,
    )


# --------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------


def _table_identifier(table: str) -> tuple[str, ...]:
    parts = tuple(table.split("."))
    if not 2 <= len(parts) <= 3 or not all(_IDENT.fullmatch(part) for part in parts):
        raise MappingError(f"source.table {table!r} must be namespace.table for an Iceberg catalog")
    return parts


def _require_column(names: dict[str, str], spec: MappingSpec, column: str) -> str:
    actual = names.get(column.lower())
    if actual is None:
        raise ValueError(f"mapping {spec.name!r}: table {spec.source_table!r} has no column {column!r}")
    return actual


def _typed_bound(spec: MappingSpec, bound: datetime) -> Any:
    if spec.observed_format == "epoch_ms":
        return int(bound.timestamp() * 1000)
    if spec.observed_format == "epoch_s":
        return int(bound.timestamp())
    return bound.isoformat()


def _arrow_filter(field: Any, arrow_type: Any, op: str, value: Any) -> Any:
    import pyarrow.types as pt  # noqa: PLC0415

    if op == "is_null":
        return field.is_null()
    if op == "is_not_null":
        return field.is_valid()
    values = value if isinstance(value, list) else [value]

    def compatible(item: Any) -> bool:
        if isinstance(item, bool):
            return bool(pt.is_boolean(arrow_type))
        if isinstance(item, int):
            return bool(pt.is_integer(arrow_type))
        return bool(pt.is_string(arrow_type) or pt.is_large_string(arrow_type) or pt.is_dictionary(arrow_type))

    if not all(compatible(item) for item in values):
        return None  # applied in Python by map_rows; never coerced into a wrong-typed comparison
    if op == "eq":
        return field == value
    if op == "ne":
        return field != value
    if op == "in":
        return field.isin(values)
    return ~field.isin(values)


def _arrow_bound(field: Any, arrow_type: Any, spec: MappingSpec, bound: datetime) -> Any:
    import pyarrow as pa  # noqa: PLC0415
    import pyarrow.types as pt  # noqa: PLC0415

    if pt.is_timestamp(arrow_type):
        value = bound if arrow_type.tz else bound.astimezone(UTC).replace(tzinfo=None)
        return field >= pa.scalar(value, type=arrow_type)
    if pt.is_integer(arrow_type) and spec.observed_format in {"epoch_ms", "epoch_s"}:
        return field >= _typed_bound(spec, bound)
    return None  # string or other encodings: bound applied in Python by map_rows


def _ordered_rows(arrow: Any, observed: str, limit: int) -> list[dict[str, Any]]:
    if arrow.num_rows == 0:
        return []
    ordered = arrow.sort_by([(observed, "ascending")]).slice(0, max(int(limit), 0))
    return [json_safe_row(row) for row in ordered.to_pylist()]


def _parse_location(uri: str, env: Any) -> tuple[str, str]:
    env = runtime_env(env)
    text = str(uri or "").strip()
    if text.startswith("s3://"):
        bucket, _, prefix = text[len("s3://") :].partition("/")
        if not _BUCKET.fullmatch(bucket) or ".." in prefix.split("/"):
            raise ValueError(f"invalid S3 location {text!r}")
        return "s3", f"{bucket}/{prefix}".rstrip("/")
    if "://" in text or not text.startswith("/"):
        raise ValueError("Parquet locations must be s3://bucket/prefix or an absolute local path")
    root = str(env.get(LOCAL_ROOT_ENV) or "").strip()
    if not root:
        raise ValueError(f"local Parquet paths are disabled; set {LOCAL_ROOT_ENV} to the directory they may read")
    resolved = Path(text).resolve()
    allowed = Path(root).resolve()
    if in_server_mode(env if isinstance(env, dict) else None):
        # The root is shared by the whole server; each hosted tenant reads only
        # its own <root>/<tenant_id> subtree.
        tenant_id = server_tenant_id()
        if not tenant_id or "/" in tenant_id or tenant_id in {".", ".."}:
            raise ValueError("local Parquet paths in hosted mode need a tenant context")
        allowed = (allowed / tenant_id).resolve()
        if resolved != allowed and allowed not in resolved.parents:
            raise ValueError(f"local Parquet path is outside this tenant's directory under {LOCAL_ROOT_ENV}")
        return "local", str(resolved)
    if resolved != allowed and allowed not in resolved.parents:
        raise ValueError(f"local Parquet path is outside {LOCAL_ROOT_ENV}")
    return "local", str(resolved)


def _parquet_paths(credentials: dict[str, Any], options: dict[str, Any]) -> dict[str, str]:
    paths = options.get("parquet_paths") or {}
    if not isinstance(paths, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in paths.items()):
        raise ValueError("options.parquet_paths must map table names to s3:// or local paths")
    result = dict(paths)
    default = str(credentials.get("path") or "").strip()
    if default:
        result.setdefault("*", default)
    if not result:
        raise ValueError("Parquet sources need credentials.path or options.parquet_paths")
    return result


def _assume_role(role_arn: str, external_id: str | None, region: str | None) -> dict[str, str]:
    try:
        import boto3  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - optional extra
        raise RuntimeError("assuming an AWS role needs boto3 (the 'cloud' extra)") from exc
    require_aws_delegation(role_arn, external_id, label="iceberg-parquet-lake")
    kwargs: dict[str, Any] = {"RoleArn": role_arn, "RoleSessionName": "trustops-lake-reader"}
    if external_id:
        kwargs["ExternalId"] = external_id
    sts = boto3.Session(region_name=region).client("sts")
    creds = sts.assume_role(**kwargs)["Credentials"]
    return {key: str(creds[key]) for key in ("AccessKeyId", "SecretAccessKey", "SessionToken")}


def _region(credentials: dict[str, Any]) -> str:
    region = str(credentials.get("region") or "").strip()
    if not _REGION.fullmatch(region):
        raise ValueError("region must be an AWS region name such as us-east-1")
    return region


def _optional(credentials: dict[str, Any], key: str, pattern: re.Pattern[str]) -> str | None:
    value = str(credentials.get(key) or "").strip()
    if not value:
        return None
    if not pattern.fullmatch(value):
        raise ValueError(f"{key} is not in the expected format")
    return value


def _initial_window_days(options: dict[str, Any]) -> int:
    raw = options.get("initial_window_days")
    if raw is None or raw == "":
        return DEFAULT_INITIAL_WINDOW_DAYS
    try:
        value = int(str(raw))
    except ValueError as exc:
        raise ValueError("options.initial_window_days must be an integer") from exc
    if not 0 <= value <= 3650:
        raise ValueError("options.initial_window_days must be between 0 and 3650")
    return value

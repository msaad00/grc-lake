"""Optional, single-table Iceberg REST publication of verified evidence."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from security_lakehouse import netguard
from security_lakehouse.execution_mode import in_server_mode
from security_lakehouse.parquet_export import SCHEMA_VERSION, export_parquet
from security_lakehouse.runtime_environment import runtime_env
from security_lakehouse.secret_refs import resolve_secret_ref

TENANT_PROPERTY = "trustops.tenant_id"
FORMAT_PROPERTY = "trustops.evidence_format"
FORMAT_VERSION = "trustops.iceberg_evidence.v1"

# Storage schemes a remote catalog's metadata may point FileIO at. Everything
# else -- file paths, bare paths, http(s), hdfs, other clouds -- is refused, so
# table metadata cannot read the GRC Lake host's disk or reach internal hosts.
OBJECT_STORE_SCHEMES = ("s3", "s3a", "s3n")
# Local warehouses (file: and bare paths) are allowed only outside server mode.
LOCAL_STORAGE_SCHEMES = ("file",)
# A REST warehouse configured on another object store opts in its scheme.
_WAREHOUSE_SCHEME_GROUPS = {"gs": ("gs", "gcs"), "gcs": ("gs", "gcs")}
# The only FileIO properties a catalog (config or table response) may supply:
# vended short-lived credentials, their expiry, and the region. Endpoints,
# proxies, signers, role ARNs, retry/FileIO implementation classes, and
# default-scheme overrides are dropped.
VENDED_STORAGE_KEYS = frozenset(
    {
        "s3.access-key-id",
        "s3.secret-access-key",
        "s3.session-token",
        "s3.region",
        "client.access-key-id",
        "client.secret-access-key",
        "client.session-token",
        "client.region",
        "gcs.oauth2.token",
        "gcs.oauth2.token-expires-at",
    }
)


class IcebergPublicationError(ValueError):
    """Safe error text for local operators; never exposes a provider response."""


def storage_properties(properties):
    """Keep only vended-credential FileIO properties from catalog-supplied config."""
    return {
        key: str(value)
        for key, value in dict(properties or {}).items()
        if key in VENDED_STORAGE_KEYS and value is not None
    }


def warehouse_schemes(warehouse):
    """Extra storage schemes a configured warehouse location opts in to."""
    scheme = urlsplit(str(warehouse or "")).scheme.lower()
    return _WAREHOUSE_SCHEME_GROUPS.get(scheme, ())


_GUARDED_IO_CLASS = None


def _guarded_io_class():
    global _GUARDED_IO_CLASS
    if _GUARDED_IO_CLASS is None:
        from pyiceberg.io import InputFile, OutputFile
        from pyiceberg.io.pyarrow import PyArrowFileIO

        class GuardedPyArrowFileIO(PyArrowFileIO):
            allowed_schemes = frozenset(OBJECT_STORE_SCHEMES)

            def _check(self, location):
                text = location.location if isinstance(location, InputFile | OutputFile) else str(location)
                # A bare path is a local file to pyiceberg.
                if (urlsplit(text).scheme.lower() or "file") not in self.allowed_schemes:
                    raise IcebergPublicationError(
                        "storage location must use an object-store scheme such as s3; "
                        "local paths, HTTP, and other schemes are refused"
                    )

            def _initialize_fs(self, scheme, netloc=None):
                if str(scheme).lower() not in self.allowed_schemes:
                    raise IcebergPublicationError("storage location scheme is not allowed")
                return super()._initialize_fs(scheme, netloc)

            def new_input(self, location):
                self._check(location)
                return super().new_input(location)

            def new_output(self, location):
                self._check(location)
                return super().new_output(location)

            def delete(self, location):
                self._check(location)
                return super().delete(location)

        _GUARDED_IO_CLASS = GuardedPyArrowFileIO
    return _GUARDED_IO_CLASS


def guarded_file_io(properties, *, extra_schemes=()):
    """A PyArrow FileIO limited to vended credentials and allowed storage locations.

    Locations must use an object-store scheme (plus ``extra_schemes``). Local
    ``file`` locations are also allowed in local/CLI mode, where the operator
    owns the filesystem, and refused in hosted server mode. The mode is fixed
    when the FileIO is built: pyiceberg reads data files on executor threads
    that do not carry the request's server-mode context.
    """
    io = _guarded_io_class()(storage_properties(properties))
    local_schemes = () if in_server_mode() else LOCAL_STORAGE_SCHEMES
    io.allowed_schemes = frozenset(OBJECT_STORE_SCHEMES) | frozenset(extra_schemes) | frozenset(local_schemes)
    return io


def _identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]{0,62}", value):
        raise IcebergPublicationError("namespace and table must be simple identifiers of at most 63 characters")
    return value


def rest_catalog(uri, *, warehouse, token_env="GRC_LAKE_ICEBERG_TOKEN", allow_http_localhost=False, pin_public=False):
    """Connect with an externally supplied short-lived bearer token, held in memory.

    No client-secret argument, credential file, implicit named catalog, or OAuth
    refresh credential is used. The catalog and its vended storage credentials
    remain trusted infrastructure and must enforce namespace/storage permissions.
    """
    parsed = urlsplit(uri)
    local_http = (
        allow_http_localhost and parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    )
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not (parsed.scheme == "https" or local_http)
    ):
        raise IcebergPublicationError(
            "catalog URI must use HTTPS without embedded credentials; loopback HTTP requires explicit opt-in"
        )
    if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", token_env):
        raise IcebergPublicationError("the configured bearer-token environment variable is missing or invalid")
    token = resolve_secret_ref(token_env, dict(runtime_env()), field="credential_ref", file_first=False)
    if not token:
        raise IcebergPublicationError("the configured bearer-token environment variable is missing or invalid")
    if any(character.isspace() for character in token):
        raise IcebergPublicationError("bearer token must not contain whitespace")
    extra_schemes = warehouse_schemes(warehouse)
    try:
        from pyiceberg.catalog.rest import RestCatalog

        class EvidenceRestCatalog(RestCatalog):
            def _fetch_config(self):
                super()._fetch_config()
                if self.uri.rstrip("/") != uri.rstrip("/"):
                    raise IcebergPublicationError("catalog endpoint relocation is not supported")
                # Server config must not introduce an auth plugin, refresh secret,
                # disabled TLS verification, or a different bearer credential.
                for name in ("auth", "credential", "oauth2-server-uri", "ssl", "rest.sigv4-enabled"):
                    self.properties.pop(name, None)
                self.properties["token"] = token

            def _create_session(self):
                session = super()._create_session()
                session.trust_env = False
                if pin_public:
                    adapter = netguard.pinned_requests_adapter(label="iceberg rest catalog")
                    session.mount("https://", adapter)
                    session.mount("http://", adapter)
                request = session.request

                def bounded_request(method, url, **kwargs):
                    kwargs["timeout"] = 30
                    kwargs["allow_redirects"] = False
                    return request(method, url, **kwargs)

                session.request = bounded_request  # type: ignore[method-assign,assignment]
                return session

            def _refresh_token(self):
                raise IcebergPublicationError(
                    "catalog token was rejected or expired; refresh it externally before retrying"
                )

            def _load_file_io(self, properties=None, location=None):
                # Never import a FileIO named by the server, and keep only the
                # vended credentials from its config/table responses: no
                # endpoint, proxy, signer, or local/HTTP locations.
                return guarded_file_io({**self.properties, **(properties or {})}, extra_schemes=extra_schemes)

        return EvidenceRestCatalog("trustops", uri=uri.rstrip("/"), warehouse=warehouse, token=token)
    except IcebergPublicationError:
        raise
    except ImportError:
        raise IcebergPublicationError("Iceberg publication requires pip install 'grc-lake[iceberg]'") from None
    except Exception:  # noqa: BLE001 - re-raised as a typed error; driver text may carry secrets
        raise IcebergPublicationError(
            "Iceberg REST connection failed; check endpoint, token lifetime, and catalog permissions"
        ) from None


def _snapshot_properties(manifest):
    return {
        "trustops.generation_id": manifest["generation"]["generation_id"],
        "trustops.generation_sha256": manifest["generation"]["manifest_sha256"],
        "trustops.source_sha256": manifest["source_sha256"],
        "trustops.control_map_sha256": manifest["control_map_sha256"],
        "trustops.row_count": str(manifest["row_count"]),
        TENANT_PROPERTY: manifest["tenant_id"],
        FORMAT_PROPERTY: FORMAT_VERSION,
    }


def _check_table(table, tenant_id, arrow_schema):
    import pyarrow as pa

    props = table.properties
    if props.get(TENANT_PROPERTY) != tenant_id:
        raise IcebergPublicationError("Iceberg table tenant does not match the evidence tenant")
    if props.get(FORMAT_PROPERTY) != FORMAT_VERSION:
        raise IcebergPublicationError("target table is not a GRC Lake evidence table")
    if props.get("trustops.normalization_version") != SCHEMA_VERSION:
        raise IcebergPublicationError("Iceberg table normalization version does not match normalized evidence")
    if props.get("commit.retry.num-retries") != "0":
        raise IcebergPublicationError("evidence table must disable automatic commit retries")
    if table.spec().fields or table.metadata.format_version != 2:
        raise IcebergPublicationError("only unpartitioned Iceberg v2 evidence tables are supported")
    target = table.schema().as_arrow()

    def compatible(left, right):
        if left == right:
            return True
        if (pa.types.is_string(left) or pa.types.is_large_string(left)) and (
            pa.types.is_string(right) or pa.types.is_large_string(right)
        ):
            return True
        if (pa.types.is_list(left) or pa.types.is_large_list(left)) and (
            pa.types.is_list(right) or pa.types.is_large_list(right)
        ):
            return compatible(left.value_type, right.value_type)
        return False

    for field in arrow_schema:
        if field.name not in target.names or not compatible(field.type, target.field(field.name).type):
            raise IcebergPublicationError("Iceberg schema is incompatible with normalized evidence")
    if any(not field.nullable and field.name not in arrow_schema.names for field in target):
        raise IcebergPublicationError("Iceberg schema adds a required field absent from normalized evidence")


def _find_snapshot(table, properties):
    # Search newest first: overwrite can stage a delete plus an append snapshot.
    # Only the snapshot whose actual total matches the evidence is a publication.
    for snapshot in reversed(table.snapshots()):
        summary = snapshot.summary
        if (
            summary
            and all(summary.get(key) == value for key, value in properties.items())
            and summary.get("total-records") == properties["trustops.row_count"]
        ):
            return snapshot
    return None


def _receipt(table, snapshot, manifest, identifier, already_published):
    return {
        "schema_version": "trustops.iceberg_publication.v1",
        "tenant_id": manifest["tenant_id"],
        "table": list(identifier),
        "table_uuid": str(table.metadata.table_uuid),
        "snapshot_id": snapshot.snapshot_id,
        "current_snapshot_id": table.current_snapshot().snapshot_id,
        "generation": manifest["generation"],
        "source_sha256": manifest["source_sha256"],
        "row_count": manifest["row_count"],
        "already_published": already_published,
    }


def publish_iceberg(lake_dir, catalog, *, namespace, table_name="evidence", tenant_id):
    """Atomically publish normalized evidence as a snapshot of one tenant table.

    The namespace must be preprovisioned with trustops.tenant_id. No namespaces,
    grants, credentials, or storage policies are created by this function. An
    existing table must carry the same tenant/format contract. Retained matching
    snapshots make retries idempotent, including historical retries after a newer
    generation is current. Snapshots must be retained for that retry guarantee.
    """
    identifier = (_identifier(namespace), _identifier(table_name))
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
        from pyiceberg.exceptions import NoSuchTableError

        with tempfile.TemporaryDirectory(prefix="trustops-iceberg-") as work:
            bundle = Path(work) / "export"
            manifest = export_parquet(lake_dir, bundle, tenant_id=tenant_id)
            parquet = pq.ParquetFile(bundle / "evidence.parquet")
            schema = parquet.schema_arrow.remove_metadata()
            if catalog.load_namespace_properties(namespace).get(TENANT_PROPERTY) != tenant_id:
                raise IcebergPublicationError("Iceberg namespace tenant does not match the evidence tenant")
            properties = _snapshot_properties(manifest)
            try:
                table = catalog.load_table(identifier)
            except NoSuchTableError:
                table = None
            if table is not None:
                _check_table(table, tenant_id, schema)
                existing = _find_snapshot(table, properties)
                if existing:
                    return _receipt(table, existing, manifest, identifier, True)
                transaction = table.transaction()
            else:
                transaction = catalog.create_table_transaction(
                    identifier,
                    schema=schema,
                    properties={
                        TENANT_PROPERTY: tenant_id,
                        FORMAT_PROPERTY: FORMAT_VERSION,
                        "trustops.normalization_version": SCHEMA_VERSION,
                        "format-version": "2",
                        "commit.retry.num-retries": "0",
                        "write.target-file-size-bytes": str(32 * 1024 * 1024),
                    },
                )
            # Build a fresh reader for this single attempt. Never replay a drained
            # reader or blindly retry an indeterminate catalog commit.
            reader = pa.RecordBatchReader.from_batches(schema, parquet.iter_batches(batch_size=8192))
            try:
                with transaction as txn:
                    if table is None:
                        txn.append(reader, snapshot_properties=properties)
                    else:
                        txn.overwrite(reader, snapshot_properties=properties)
            except Exception:
                # The server might have committed before the connection failed.
                # Reconcile by snapshot provenance; never remove remote data files.
                reconciled = catalog.load_table(identifier)
                _check_table(reconciled, tenant_id, schema)
                snapshot = _find_snapshot(reconciled, properties)
                if snapshot:
                    return _receipt(reconciled, snapshot, manifest, identifier, True)
                raise
            committed = catalog.load_table(identifier)
            _check_table(committed, tenant_id, schema)
            snapshot = _find_snapshot(committed, properties)
            if snapshot is None:
                raise IcebergPublicationError("catalog readback did not confirm the published generation")
            return _receipt(committed, snapshot, manifest, identifier, False)
    except IcebergPublicationError:
        raise
    except ImportError:
        raise IcebergPublicationError("Iceberg publication requires pip install 'grc-lake[iceberg]'") from None
    except Exception:  # noqa: BLE001 - re-raised as a typed error; driver text may carry secrets
        raise IcebergPublicationError(
            "Iceberg publication was not confirmed; check source integrity, catalog access, and retry the same generation"
        ) from None

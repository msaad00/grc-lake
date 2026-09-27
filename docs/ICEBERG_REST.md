# Iceberg REST evidence publication

`pipeline publish-iceberg` publishes the normalized evidence from a verified
assessment generation as a snapshot of one tenant's Iceberg v2 table. Local
JSONL remains the working evidence format. Parquet carries the data; Iceberg
provides table metadata and snapshots; an Iceberg REST catalog such as Polaris
authorizes and commits table changes. Evaluation and application state remain
in TrustOps.

## Connect and publish

Install the optional adapter. Container images from 0.2.10 onward also include these dependencies.

```bash
pip install 'trustops-security-data-lake[iceberg]>=0.2.10'
```

A catalog administrator must provision the warehouse/catalog and namespace,
set namespace property `trustops.tenant_id` to the evidence tenant, and grant the
writer access only to its tenant's namespace, table, and storage locations.
The adapter creates the evidence table when absent; it does not create namespaces,
roles, grants, storage policies, or token issuers. Use a dedicated table, since a
new assessment replaces its current contents while preserving older snapshots.

Have your identity system or secret broker supply a short-lived bearer token in
`TRUSTOPS_ICEBERG_TOKEN` for this process. Do not put the token in command arguments,
source files, shell history, or repository configuration. The command accepts an
environment-variable name, never a token value. Renew expired tokens externally;
the adapter does not retain a client secret or refresh token.

```bash
security-lakehouse pipeline publish-iceberg \
  --lake build/lakehouse \
  --tenant-id acme-prod \
  --catalog-uri https://catalog.example.com/api/catalog \
  --warehouse evidence_catalog \
  --namespace tenant_evidence \
  --table evidence
```

The example names are synthetic. Use the tenant recorded in your generation;
mixed or mismatched tenants are rejected. Namespace and table identifiers must
begin with a letter or underscore and contain only letters, digits, or underscores
(maximum 63 characters). Nested namespaces are not supported.

The JSON receipt contains the table UUID, published and current snapshot IDs,
generation identity, source hash, row count, and whether the generation was already
published. It excludes tokens, catalog configuration, storage credentials, and
metadata-file locations. Evidence itself can contain sensitive asset identifiers,
owners, and references; enforce storage access and retention accordingly.

## Snapshot, schema, and failure behavior

- Verify and pin a sealed generation using the [Parquet export contract](PARQUET_EXPORT.md).
  Reject incomplete, tampered, legacy, or incompatible input before table publication.
- Commit the table and first snapshot together. Later publications atomically
  replace the current contents of that one table. Readers see a committed snapshot;
  there is no multi-table assessment transaction.
- Record tenant, source, generation, and catalog hashes in snapshot properties.
  A retry finds a retained matching snapshot instead of appending duplicate rows.
  Retrying an older retained generation does not roll back the current snapshot.
- Disable automatic commit retries. A competing writer causes a conflict, preserving
  its committed snapshot. After an ambiguous response, reload metadata and confirm
  matching provenance before reporting success; otherwise fail without claiming
  publication. Retry the same generation after checking the current state.
- Support additional nullable columns; the publisher fills them with null on the
  next replacement. Preserve externally maintained annotations in a separate table.
  Reject renamed or missing source columns, incompatible types, extra required
  columns, partitioned tables, and format versions other than v2.
- An empty generation produces a queryable zero-row snapshot. It is not a passing
  assessment. Export row counts do not establish provider collection completeness.

Snapshot retention defines the retry deduplication window. Administrators must
retain snapshots long enough for their retry policy. Unknown commit outcomes may
leave unreferenced files. The adapter does not expire snapshots or delete remote
files; use catalog-aware maintenance after resolving pending writes.

## Authentication and storage boundary

HTTPS is required. `--allow-http-localhost` permits HTTP only for explicit loopback
tests. Requests have a 30-second timeout and do not follow redirects. Embedded URL
credentials, endpoint relocation, remote authentication plugins, and remote FileIO
implementation selection are rejected or ignored. REST sessions do not use ambient
netrc credentials or proxy settings. The adapter uses PyArrow FileIO and retains
catalog-vended storage settings; storage access must be configured separately.

The catalog and storage service remain trusted infrastructure. Tenant properties
are consistency checks, not authorization. A storage path or tenant label alone
does not establish isolation. Catalog roles and storage policies must enforce it.
The local compatibility check below tests a real catalog permission denial; it
does not establish object-storage isolation or credential vending for every cloud.

## Compatibility and validation

| Component                           | Tested boundary                                                                                                                               |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| PyIceberg 0.12.0 / PyArrow 24.0.0   | Streaming batches into unpartitioned Iceberg v2 evidence snapshots                                                                            |
| Apache Polaris 1.7.0                | Disposable loopback REST catalog with a synthetic local FILE warehouse                                                                        |
| DuckDB 1.5.3 with Iceberg extension | Independent metadata-file reads, all-field parity, current and historical snapshots                                                           |
| Schema evolution                    | Add a nullable string column, publish another generation, read the new schema                                                                 |
| Catalog authorization               | A writer for one catalog receives a REST denial from a second catalog                                                                         |
| Fault injection                     | Lost commit response, known failure, concurrent writer, tenant mismatch, tampering, incompatible schema, redirects, and auth-plugin injection |

Run the focused tests and the disposable integration check from a checkout:

```bash
uv sync --frozen --all-extras
uv run pytest tests/test_iceberg_export.py tests/test_parquet_export.py
uv run python tools/iceberg_rest_smoke.py
```

The integration script requires Docker and network access to the pinned Polaris
image and DuckDB extension. It generates synthetic credentials in memory, binds
only loopback ports, and removes its container and temporary warehouse. Its FILE
permissions are for disposable test data only. CI runs this same check.

S3/GCS/Azure storage, cloud credential vending, other REST catalogs, Spark/Trino
readers, partition evolution, distributed load, and production performance have
not been verified. Batches limit conversion work and generation artifact hashes
use a reusable 1 MiB buffer. Manifest parsing and individual source records are
not bounded here; this is not an end-to-end memory cap.
See the [benchmark protocol](BENCHMARKS.md) for accuracy, scale, and cost validation.

References: [PyIceberg API](https://py.iceberg.apache.org/api/),
[Apache Iceberg specification](https://iceberg.apache.org/spec/),
[Apache Polaris](https://polaris.apache.org/), and
[DuckDB Iceberg extension](https://duckdb.org/docs/stable/core_extensions/iceberg/overview).

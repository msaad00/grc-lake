# Portable evidence with Parquet

`pipeline export-parquet` writes the normalized evidence from one verified
assessment generation into a new local directory. PyArrow writes the file;
integration tests read it independently with DuckDB and compare every field,
including arrays, tenant IDs, evidence references, and raw hashes.

This is an optional file export. JSONL remains the working evidence format.
Iceberg tables, REST catalog commits, Polaris compatibility, remote storage,
framework verdict exports, and API/MCP export endpoints are not implemented by
this command. Use the separate [Iceberg REST adapter](ICEBERG_REST.md) for
snapshot publication.

## Try it locally

Install the optional dependencies (the example also uses repository sample data):

```bash
pip install 'grc-lake[parquet,analytics]>=0.2.10'
grc-lake ingestion normalize \
  --raw data/raw/security_events.jsonl --out build/parquet-demo-lake \
  --tenant-id acme-prod
grc-lake pipeline export-parquet \
  --lake build/parquet-demo-lake --tenant-id acme-prod \
  --out build/parquet-demo-export
```

The repository sample above contains only synthetic `acme-prod` evidence. For
real evidence, use the tenant recorded in both the assessment manifest and every
normalized row. A mixed-tenant lake or a mismatched manifest is rejected, not
silently filtered or relabeled. Normalize a correctly scoped source first.
The explicit tenant argument is a consistency check; local filesystem access
and permissions remain the authorization boundary.

Query with DuckDB without importing GRC Lake or PyArrow:

```python
import duckdb

with duckdb.connect() as db:
    rows = db.execute(
        "SELECT tenant_id, source, count(*) AS evidence_rows "
        "FROM read_parquet(?) GROUP BY tenant_id, source ORDER BY source",
        ["build/parquet-demo-export/evidence.parquet"],
    ).fetchall()
    print(rows)
```

The optional `parquet` extra adds PyArrow; `analytics` adds DuckDB for this
example. Neither is required for the basic local JSONL workflow. The versions
used by repository checks are pinned in `uv.lock`; each export records its
actual PyArrow writer version.

## Files and provenance

| File               | Content                                                                                                                                                                                  |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `evidence.parquet` | All normalized v1 fields with explicit types and non-null columns. Strings and ISO timestamp text remain lossless; severity score is an integer and evidence/control types remain lists. |
| `manifest.json`    | Export and normalization versions, tenant, source generation identity, catalog digests, source/output SHA-256 hashes, row count, column definitions, and writer version.                 |

Arrow schema metadata also carries the normalization version, tenant, generation
ID, and generation-manifest hash. The source generation and catalog hashes bind
the export to its assessment; catalog bodies, raw records, and operational
credentials are not copied. Evidence references, owners, and asset identifiers
can still be sensitive. Export directories are private (`0700`), with files
restricted to the owner (`0600`). Do not commit real exports to public repos.

The row count means all normalized rows in the selected generation were
exported. It does **not** establish that all provider evidence was collected,
that any framework passed, or that referenced evidence is fresh. An empty
assessment produces a zero-row file with a queryable schema, not a pass verdict.

## Failure and retry behavior

- Pin and verify one sealed generation before conversion. Concurrent publication
  of another generation does not change the export's selected evidence.
- Reject legacy/unsealed input, incompatible normalization versions, unknown or
  missing fields, invalid types/hashes, scope mismatches, and row-count drift.
- Reverify generation hashes before publication. Stage both files privately,
  flush them, then publish the directory using a same-filesystem rename.
- Reject any existing output, including symlinks. A retry cannot append duplicate
  rows or overwrite an earlier export. Choose a new destination to export again.
- Handled write failures remove staging files and leave no visible destination.
  A killed process can leave a hidden `.parquet-*` staging directory; it is not
  a published export and can be removed after confirming the writer has stopped.

The destination must be outside the source lake. Publication requires local
POSIX directory locks, rename, and fsync support. NFS, distributed writers,
object storage, and Windows publication guarantees have not been verified.
Conversion uses bounded row batches (`--batch-size`, default 8192; maximum
65536). Generation artifact hashes use a reusable 1 MiB buffer. This is not a
whole-pipeline memory guarantee: manifests are parsed in memory, and
source-record size is not bounded here.
No production throughput or cost benchmark is claimed.

## Validation

`uv run --all-extras pytest tests/test_parquet_export.py` checks independent-reader
parity, empty input, concurrent assessment publication, tenant denial, tampering,
unknown schemas/fields, incomplete writes, safe retries, and CLI errors.

Format references: [Apache Arrow Parquet writing](https://arrow.apache.org/docs/python/parquet.html)
and [DuckDB Parquet queries](https://duckdb.org/docs/current/guides/file_formats/query_parquet).

## Safeguard bindings and older generations

Normalization transform v2 adds the `safeguard_ids` list. New Parquet exports
preserve it with explicit string-list types, including empty lists. Retained v1
normalization generations keep their original export columns; they are not
rewritten. The normalized JSON contract remains v1 with this additive field.

Existing Iceberg tables without the new column fail schema validation before
publication. Provision a compatible table or explicitly evolve its schema before
publishing v2-normalized generations. GRC Lake does not silently mutate that table
schema. Historical snapshots and exports remain pinned to their source generation.

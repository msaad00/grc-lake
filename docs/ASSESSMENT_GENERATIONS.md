# Assessment publication and failure contracts

TrustOps keeps local JSONL and SQL artifacts as its working evidence mode. An
assessment publication consists of one verified generation. An optional
[Parquet export](PARQUET_EXPORT.md) preserves normalized evidence from one pinned
generation. Optional [Iceberg REST publication](ICEBERG_REST.md) commits that
evidence to one tenant table. The Helm chart does not provision a catalog or
remote storage.

## Invalid rules and incomplete collection

Unknown named rules and malformed inline predicates raise `PolicyError`. The
pipeline validates every catalog rule before evaluating, including controls with
no evidence and incremental runs with unchanged raw input. CLI evaluation exits
nonzero; API evaluation records an error and retains the prior published view.
A catalog or tenant change forces a new incremental assessment.

The shared cursor paginator raises `IncompleteCollectionError` when its page
budget is exhausted while a continuation cursor remains. It exposes
`pages_fetched` and `cursor` to its caller, without including the cursor in logs.
Finishing exactly at the budget is successful. Connector collectors consume the
whole iterator before writing evidence, so an incomplete pull records an error
and preserves raw evidence, the watermark, and the published assessment. Retry
starts from the previous successful watermark; durable partial-page checkpointing
is not implemented. These guarantees apply to consumers of the shared paginator,
not every provider-specific SDK pagination loop.

## Publication layout

```text
lake/
  generations/<generation-id>/
    catalog/                       # evaluated controls and catalog bundle summary
    bronze/ silver/ gold/ mart/    # materialized assessment artifacts
    manifest.json                 # counts, tenant, catalog digest, pinned paths
    generation.json               # SHA-256 digests for every generated artifact
  .active-generation -> generations/<generation-id>
  bronze/ silver/ gold/ mart/      # per-artifact links through the active pointer
  raw/                            # mutable intake remains outside generations
```

Operational files such as connector configuration, run history, assignments,
review events, and snapshot ledgers remain outside generations even where they
share the `gold` directory with assessment links.

Writers serialize per lake with an advisory directory lock. They stage a new
unique directory, verify evidence integrity and SQLite consistency, hash and
flush the artifacts, and atomically replace the active symlink. Before the
switch, a failed write or failed verification leaves the prior generation
active. Existing local lakes are migrated by retaining a copy of their previous
artifacts before installing compatibility links. The first successful publication
then switches to the new generation.

Published artifacts reject writes through TrustOps shared JSON IO. Local
administrators can still edit files directly; integrity verification detects
such changes. This is not object-lock/WORM storage or cryptographic signing.
Historical and interrupted staging directories are retained. Old unreferenced
generations are archived only by the retention command or by
[scheduled retention](OPERATIONS_CONTRACTS.md#automatic-retention), which is off by
default; account for disk growth.

## Reading and exporting

Posture, graph, framework-detail, ingestion-status, integrity, dashboard export,
and shared legacy/v1 API reads pin their generated JSON IO for the duration of
one operation. Assessment snapshots retain the generation identity and catalog
bundle used for that publication. V1 response metadata includes the generation
identity; separate requests can observe different generations.

`PipelineResult` paths identify the generation directly. To run several external
file or SQL reads against one assessment, use those returned paths or resolve
`.active-generation` once and read exclusively inside that directory. Reopening
the compatibility links for each file can cross a publication boundary. API
pagination across multiple requests does not yet offer a historical-generation
selector; compare returned generation identities before combining pages.

`security-lakehouse pipeline verify-integrity --lake <lake-directory>` checks the published
generation hashes as well as evidence integrity. An explicit generation directory
can also be inspected with `verify_generation(Path(...))` from
`security_lakehouse.generations`.

## Scope of validation

Regression tests inject failures during artifact writes, SQL materialization,
posture generation, and the pointer switch. They also cover interleaved reads,
legacy migration, catalog invalidation, corruption, cross-tenant pointer denial,
CLI/API errors, and preservation of previously published exports.

Publication requires a local POSIX filesystem with atomic same-filesystem rename,
symlinks, directory locks, and fsync support. This does not establish crash or
locking guarantees for NFS, object storage, Windows, or distributed writers. No
Iceberg commit or cloud deployment is proved by these tests. The separate
Parquet export tests verify normalized evidence parity with DuckDB; this does
not establish interoperability of every assessment artifact. Separate Iceberg
checks exercise a local Polaris catalog and independent DuckDB snapshot reads;
see the [tested adapter boundary](ICEBERG_REST.md#compatibility-and-validation).

## Current freshness and retained history

Freshness conclusions use the latest observation for each source, asset, and
evidence type within a control. New observations supersede that population's
older freshness state without deleting its evidence or historical generations.
Fresh evidence from another asset or source does not conceal a stale population.
Controls with declared evidence requirements consider those types and flag
missing requirements; unrelated optional history does not make them stale.

Comparisons use parsed UTC instants. Historical timestamps without an offset
retain the existing interpretation as UTC. Collection timestamps in the future
cannot establish freshness and are reported as missing usable collection
metadata. Per-record freshness outputs still retain historical rows for period
review; their counts are not the number of currently stale controls.

## Export and historical-read integrity

Live OSCAL findings require a verified generation when posture rows exist. Empty
lakes can still export an empty assessment. Run the pipeline to materialize an
unsealed legacy lake before exporting live findings. Event verification checks
published generation integrity as well as the original bronze hash. Unsealed
legacy event checks retain the narrower `bronze_hash_only` verification scope.

Historical queries resolve only verified snapshot ledger entries. Missing,
modified, unledgered, ambiguous, or symlinked snapshots fail explicitly; reads do
not rewrite or discard them. Snapshot exports retain a copy inside the lake for
ledger resolution. Existing exports whose ledger entry refers to a missing local
copy require operator reconciliation from the original artifact. New writes do
not extend a broken chain or overwrite a snapshot file.

Workpapers retain the synthetic label when any source evidence is synthetic,
including mixed inputs, and record the source beside referenced evidence.

Portable workpapers verify the rendered HTML against the JSON, as well as file
hashes, and reject additional files or symlinks. Rendering is deterministic from
the stored JSON and recorded as `trustops.workpaper_html.v1`. Older bundles whose
HTML cannot be reproduced from their JSON fail this stronger check; retain the
original and create a new export from verified evidence when needed.

These checks establish local consistency. An operator able to rewrite every
artifact and its ledger or manifest can create a new self-consistent history.
External tamper-proof anchoring and independent review identity authentication
are separate from portable bundle verification.

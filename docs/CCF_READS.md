# CCF assessment reads

New evaluations include an indexed CCF projection in the existing sealed SQLite
mart. The summary endpoint reads a single catalog-sized summary. The asset-results
endpoint filters and sorts in SQLite and deserializes only the requested page,
with the existing maximum of 1,000 rows. It does not load the complete CCF JSON
artifact or the pipeline manifest's raw-event index. The JSON result remains the
portable export; SQLite is a derived read projection sealed in the same generation,
rebuilt during evaluation rather than updated in place.

The API and MCP collection retain the existing response contract:
exact filtered counts, scalar/list membership filters, stable ordering, offsets,
and opaque next cursors. Values are SQL parameters; field names come from a fixed
allowlist. Unknown fields retain their existing empty-filter/default-order
behavior. A page and its count read the same immutable generation. Pagination
across separate requests still follows the current generation; consumers should
compare `meta.generation` and restart if an evaluation publishes between pages.

A small marker in `generation.json` identifies the projection. Missing, corrupt,
or redirected declared indexes return `409 assessment_unavailable`; they do not
silently fall back to JSON. Older generations without the marker retain their
original JSON compatibility path. Normal evaluation after an upgrade rebuilds
the projection because its version participates in incremental invalidation.
Historical generation files remain unchanged.

This bounds Python materialization by returned row content plus catalog size,
not by the entire observed asset population. One asset may still carry a large
evidence/reason list. Exact counts and unindexed/list sorts can scan rows or use
SQLite temporary storage; this is not a constant-time or fixed-byte guarantee.
The evaluation pipeline itself still materializes evidence in memory.

## Reproduce an isolated read measurement

```bash
uv run python tools/benchmark_ccf_reads.py --sizes 1000 10000 100000 --repeats 3
```

The harness compares the legacy JSON collection path with indexed reads in fresh
processes using a synthetic projection, fixed labels, and a 25-row page. It checks
both selected IDs and total filtered counts. It records instrumented elapsed time
and peak Python allocations under `tracemalloc`, not total process RSS. Fixtures
are limited to 100k rows and workers to 60 seconds. This does not measure the full
pipeline, HTTP latency, concurrent tenancy, or production capacity. Retain failures
and raw results with the source revision; compare these separately from the
[full-pipeline benchmark](benchmarks/CCF_PIPELINE.md).

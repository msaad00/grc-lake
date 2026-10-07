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

## Mapping coverage and AI status

Frameworks, CCF coverage, and AI Governance use the same tenant-effective mapping
ledger and seeded control-catalog denominator. Covered requirements include
proposed implementation mappings; reviewed requirements count only maintainer or
organization reviews. Maintainer and organization requirement buckets are disjoint,
and neither bucket measures operating effectiveness. Supporting and inherited
relationships are counted separately as context, even when reviewed. Source-cited
article mappings remain a separate catalog-curation measure.

A rejected mapping leaves that tenant's evaluated mapping coverage. A mapping
marked needs changes stays proposed. If the review log fails verification, the
views fall back to shipped mapping states and expose `review_log_verified: false`;
they do not retain unverified organization approvals. Catalog-version mismatches
retain the existing proposed-review behavior.

The AI governance score remains 55% inventory signals and 45% the observed-control
pass rate. The `governed` state additionally requires current evaluated evidence
for at least 50% of the catalog in every observed AI framework, with at least one
observed framework. Unseen frameworks remain unassessed and are excluded from this
scope; the state is not a claim that all AI frameworks or organizational assets
are covered. An otherwise high-scoring result with insufficient coverage remains
`on_track` and carries an explicit `state_reason` and `coverage_sufficient: false`.

AI rows expose `evaluated_control_count`, `catalog_control_count`, and
`coverage_pct` separately from the existing `controls_with_evidence` observed
count. Unknown, missing, stale, and non-catalog evidence cannot fill the evaluated
coverage numerator. Non-catalog identifiers cannot supply passing control credit.
Mapping review counts never supply either an operating pass or evaluated evidence.
Invalid or missing denominators fail closed, and the 50% comparison uses counts
before rounding the displayed percentage.

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

## Recorded result

[All 18 attempts](benchmarks/ccf-reads-2026-10-03.json) passed on clean revision
`17e23aeb69534cadb99e9318c87513781357fe0e` (Python 3.13.5, ARM64 macOS).
Each cell below is the median of three fresh-process attempts; allocation peaks
were identical across repeats. Timings include `tracemalloc` instrumentation.

| Assets  | Legacy seconds | Indexed seconds | Legacy Python MiB | Indexed Python MiB |
| ------- | -------------: | --------------: | ----------------: | -----------------: |
| 1,000   |        0.01191 |         0.00783 |             1.267 |              0.044 |
| 10,000  |        0.12642 |         0.00924 |            12.652 |              0.044 |
| 100,000 |        1.34120 |         0.04552 |           126.631 |              0.044 |

These measurements cover one scalar filter, one sort, and a 25-row page. They do
not measure native SQLite allocations, operating-system cache, or total RSS.

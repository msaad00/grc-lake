# Evidence population reconciliation

A passing control over collected assets does not establish that all expected
assets were collected. `assessment population` compares the generation against
an explicitly declared inventory baseline and collection receipts.

```sh
grc-lake assessment population --lake build/assurance-demo \
  --baseline examples/control-assurance/baseline.json
python tools/benchmark_population.py --assets 100000
```

Run the pipeline command in [the control walkthrough](CONTROL_TEST_WORKPAPERS.md)
first. Its synthetic baseline declares six assets, while the fixture contains
five. The report identifies the missing asset without changing any control score.

The versioned baseline names its platform tenant, cutoff, freshness limit,
inventory source, owner, export time, source accounts, and asset IDs. Each imported
collection receipt names a source, account, completion time, status, cursor
exhaustion, and observed asset count. Platform ownership and source-account
identity remain separate. A receipt is checked against the observed unique asset
count, collection times, and freshness cutoff.

The report checks missing and unexpected assets, duplicate inventory entries,
duplicate event IDs, ambiguous asset types, stale evidence, invalid timestamps,
and missing, partial, inconsistent, or stale collection receipts. A fresh
observation for an asset can supersede an older snapshot for inventory freshness;
control-period failures remain visible in the separate test workpaper.

`declared_scope_reconciled` means the supplied scope matched the observations and
receipts. It does not independently establish the inventory's completeness or
prove a provider returned every record. Imported receipts are explicitly labeled
`operator_supplied_receipts`. A reviewer must compare scope with authoritative
account inventories and inspect collection provenance. No live-provider
qualification is implied.

## Bounds and reproducibility

The report binds to a tenant-owned verified generation and hashes its baseline
and results. It supports up to 1,000 accounts and 100,000 declared assets. Event
indexing and reconciliation are linear before diagnostic sorting. Every issue
has a full count and an explicit truncation flag; detail lists default to 100 and
are capped at 500 items. These caps keep a large gap report readable without
silently understating its totals.

The benchmark measures synthetic in-memory reconciliation only, reporting three
runs and peak processing allocations. It excludes input allocation, disk IO,
generation integrity verification, and provider collection. It is a reproducible
microbenchmark, not an end-to-end capacity or availability claim.

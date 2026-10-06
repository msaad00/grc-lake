# Evidence operations

## Retention and recovery

Each successful publication is an immutable generation. Failed staged generations
are removed; previous published evidence remains readable during collection.
Retention is explicit and reports candidates without changing data by default:

```bash
security-lakehouse lake retention --lake ./lake --older-than-days 90 --keep-latest 3
security-lakehouse lake retention --lake ./lake --older-than-days 90 --keep-latest 3 --archive-to /mnt/evidence-archive
```

Archival copies and verifies a generation, flushes the copy to disk, then removes
the local copy. Active generations, active readers, retained snapshots,
workpapers, and verification receipts are protected. An existing archive target
fails closed for operator reconciliation. Back up the lake and application
database together before changing retention.

External exports and independent checkpoints cannot be discovered automatically.
Select a window covering the full evidence period and retain the archive for
those consumers. Do not delete an archive while an auditor needs its inputs.
Restore archived generations under `generations/<id>` to use an external export
that refers to them. Retention is not a storage-capacity guarantee: size the PVC
from measured ingestion, generation frequency, and your retention window.

See [evidence recovery](EVIDENCE_RECOVERY.md) for legacy ledgers, workpapers, and
independently retained integrity checkpoints. Hashes use the project's canonical
JSON serialization (`sort_keys`, compact separators, UTF-8, Python JSON value
encoding), not RFC 8785. Preserve original artifacts when verifying in other
languages; do not assume a different JSON encoder produces the same bytes.

## History and interactive reads

Connector history keeps JSONL as the authority and builds a temporary SQLite
index for pagination and filtering. Unchanged history reuses a bounded process
cache; a changed source rebuilds the index. Cold rebuild time remains linear in
history size. Index files are disposable and are not an additional authority.

Stream subscribers share computed payloads within a process, scoped by tenant
and generation. Non-generation changes may take up to ten seconds to appear.
Auditor redaction applies to each subscriber. Graph coverage counts the complete
population but bounds detail to 200 assets and 50 controls per asset; the API
reports truncation explicitly. Export source evidence for complete populations.

Collection and evaluation HTTP calls remain synchronous. Run scheduled or large
collections through the scheduler/CLI, with deployment timeouts appropriate to
the workload. Recollecting unchanged provider state still records a new
observation time; it must not silently preserve old freshness as new evidence.
Warehouse setup, authenticated-provider behavior, and production capacity need
separate verification in the target environment.

## Authority and assessment semantics

API credentials can propose work. Independent approval requires a signed-in,
authorized human who did not create the request. Migration 0021 deliberately
invalidates historical approvals without that authority: downgrading the schema
does not reactivate them. Restore a reviewed backup only under an explicit
operator recovery procedure.

The API's auditor view narrows both fields and write scopes; leaving that view
restores only the identity's actual permissions. When a flat single-tenant lake
is first bound to a tenant, its ownership is retained as more tenants are added.
A multitenant flat lake without an owner requires explicit migration rather than
guessing its owner.

Control results carry the evaluation version and a digest of sorted input event
IDs and raw hashes. OSCAL observations link the same generation's source events.
Historical snapshots never substitute today's population. Legacy snapshots
without retained source detail cannot assert event-level lineage.

Crosswalks express reviewed primary/equivalent mappings. They do not certify
supporting evidence, inheritance, applicability exclusions, or compensating
controls. These require a separately documented human assessment; a missing
mapping or absent evidence remains unevaluated. Local DuckDB queries execute
with the CLI operator's filesystem authority. Input JSONL must be UTF-8; an optional leading BOM is accepted by the strict
JSON reader. Non-finite numbers, duplicate keys, and excessive nesting fail
before publication. Evaluation responses stay sanitized; the private operator
log records the underlying exception for diagnosis.

## Extending a framework

Use the [framework pack guide](FRAMEWORK_PACKS.md), then update the owning registry,
control catalog, provenance, safeguard mappings, and applicable evidence rules.
A framework may also need navigation labels and assets. Generate derived
coverage, catalog locks, packaged resources, and the README header with the
repository scripts; run `security-lakehouse catalog verify` and the full relevant
checks. A new catalog entry alone is neither evaluated coverage nor provider
qualification.

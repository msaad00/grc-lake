# Evidence operations

## Retention and recovery

Each successful publication is an immutable generation. Failed staged generations
are removed; previous published evidence remains readable during collection.
Retention reports candidates without changing data by default, and runs only when
invoked or explicitly scheduled (see [automatic retention](#automatic-retention)):

```bash
security-lakehouse lake retention --lake ./lake --older-than-days 90 --keep-latest 3
security-lakehouse lake retention --lake ./lake --older-than-days 90 --keep-latest 3 --archive-to /mnt/evidence-archive
```

Archival copies and verifies a generation, flushes the copy to disk, then removes
the local copy. Active generations, active readers, retained snapshots,
workpapers, and verification receipts are protected. An existing archive target
fails closed for operator reconciliation unless it is a complete, verified copy
of the same generation left by an interrupted run. Back up the lake and application
database together before changing retention.

### Automatic retention

Retention can also run on a schedule. It is **off by default**: nothing runs
until an operator sets `TRUSTOPS_RETENTION_SCHEDULE`, because external exports
and checkpoints cannot be discovered (below) and only the operator can choose a
window and an archive on separately controlled storage.

| Variable                             | Default     | Meaning                                                        |
| ------------------------------------ | ----------- | -------------------------------------------------------------- |
| `TRUSTOPS_RETENTION_SCHEDULE`        | unset (off) | Scheduler grammar: `@hourly`, `@daily`, `every Nh`, `every Nm` |
| `TRUSTOPS_RETENTION_ARCHIVE_DIR`     | unset       | Absolute path outside the lake root; unset means preview only  |
| `TRUSTOPS_RETENTION_OLDER_THAN_DAYS` | `90`        | Same as `--older-than-days`                                    |
| `TRUSTOPS_RETENTION_KEEP_LATEST`     | `3`         | Same as `--keep-latest` (generations)                          |

The scheduler (`security-lakehouse scheduler tick`, the Helm CronJob, or
`scheduler run`) fires retention at most once per period, under the same
per-lake scheduler lock and attempt-before-run state as other scheduled targets.
It calls the same functions as the CLI, so every protection above applies
unchanged. Without an archive directory a run only reports candidates, like the
CLI without `--archive-to`. Generation retention runs per tenant lake, archived
under `<archive>/generations/<lake key>/`. Operational retention (job payloads
and request-audit rows) runs once per deployment root under
`<archive>/operational/`; a tenant-scoped API tick never compacts it. Every run
appends its report to `gold/retention_runs.jsonl` and its outcome to the
scheduler state; the tick result carries the same report. An invalid setting
reports an error on every tick and runs nothing. In Helm, set
`scheduler.retention.*` and mount the archive with `extraVolumes`.

An interrupted archival resumes when the archived copy is complete: its manifest
matches the local generation and every artifact hash verifies, and only then is
the local copy removed. Any other existing archive target still fails closed for
operator reconciliation and the scheduled run reports an error until resolved.
After automatic retention has run, a release without it rejects the `retention`
rows in `gold/scheduler_state.jsonl` and stops scheduling (fail closed); remove
those rows before downgrading.

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

### Background HTTP operations

The console and remote MCP submit evaluation, connector sync, scheduler ticks,
and snapshots with `Prefer: respond-async`. The server commits a durable job
before returning HTTP 202, a `Location` status URL, and `Retry-After: 1`. Read
`GET /api/v1/operations/{id}` for status and the completed API response, or page
`GET /api/v1/operations?limit=50&offset=0`. Recent jobs remain visible in the
console after a tab closes. Remote MCP returns the job immediately; use
`get_operation` to poll it and `list_operations` to inspect recent submissions.
Queued and running states do not establish successful collection or evaluation.

Send a stable `Idempotency-Key` (1–200 characters) when retrying an uncertain
submission. Reusing it for different work returns 409. Keys are scoped to the
lake root, tenant, and initiating user. Operations are authorized before
acceptance and again before execution against the current user role, API-key
revocation, and billing state. Queue payloads do not accept credentials or paths.
Existing HTTP clients without the preference retain synchronous responses;
local CLI and local MCP also retain direct execution.

The server lifespan starts one worker per process. SQL conditional claims
prevent duplicate execution of the same job across workers. Queued work survives
restart. Running work renews a 90-second lease; after a lost lease it becomes
`interrupted` and is never retried automatically. Effects may already have
occurred: inspect connector, evaluation, workflow, snapshot, and webhook delivery
history before submitting new work. HTTP errors become `failed`; a successful
HTTP result must still be interpreted using its domain outcome (for example,
blocked connectors or partially successful scheduler ticks). Responses over
1 MiB require inspection through the domain history and become `interrupted`.

Workers sharing an application database must use the same absolute lake-root
mount path and shared lake storage. Keep clocks synchronized. Back up application
state with the lake. Graceful shutdown waits up to 30 seconds for active work;
longer work or a forced stop requires interrupted-work reconciliation. The queue is for these
bounded operation types, not a general-purpose execution service. Other webhook
producers and legacy synchronous callers retain their existing delivery behavior.

Recollecting unchanged provider state still records a new observation time; it
must not silently preserve old freshness as new evidence.
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
guessing its owner. Public share lookup also excludes that ambiguous flat root.
CLI-issued links remain usable before any server tenant is registered.

If the original owner later gets a scoped tenant directory, share listing and
revocation still include its legacy flat-root shares. A copied share is revoked
in both locations. Other tenants cannot manage those legacy shares; evidence
reads, writes, and new shares continue to use the scoped directory.

Control results carry the evaluation version and a digest of sorted input event
IDs and raw hashes. OSCAL observations link the same generation's source events.
Historical snapshots never substitute today's population. Legacy snapshots
without retained source detail cannot assert event-level lineage.

Crosswalks distinguish primary/equivalent implementation mappings from supporting
and inherited context. Contextual relationships never add coverage or establish
an implemented requirement, even after mapping review. Period workpapers can
record evidence-bound N/A, inherited, or compensating assessment context through
the [independent review workflow](AUDITOR_WALKTHROUGH.md#assessment-context).
Approval leaves machine verdicts and score denominators unchanged; a missing
implementation mapping or absent evidence remains unevaluated. Local DuckDB queries execute
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

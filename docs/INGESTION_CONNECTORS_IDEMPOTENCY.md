# Ingestion, Connectors, Idempotency, and Headless GRC

GRC Lake is built for **continuous compliance automation**: connectors ingest
evidence into **your** lake, the pipeline materializes gold posture, and the
**same `/api/v1` contract** serves humans (console), agents (MCP/CLI), and CI.

There is no runtime plugin marketplace. Extensions are **code**: registries in
the OSS tree (connectors, workflow actions, framework packs), plus connectors
that a separate Python package registers under the `grc_lake.connectors`
entry-point group (legacy `trustops.connectors` is still loaded) ([Adding connectors](ADDING_CONNECTORS.md)).

## Architecture

```text
Sources (AWS, Azure, GCP, Snowflake, GitHub, Okta, Jira, …)
  → connector_runner (probe → sync → raw upsert)
  → raw/connector_events.jsonl
  → pipeline (bronze → silver → gold)
  → control_tests, violations, posture
  → /api/v1 (console, agents, MCP, scheduler)
```

| Layer           | Path / module                                               | Role                                                  |
| --------------- | ----------------------------------------------------------- | ----------------------------------------------------- |
| **Contracts**   | `connectors/catalog.json`                                   | 28 connector access contracts (25 executable)         |
| **Registry**    | `connector_runner.REGISTRY`                                 | Built-ins plus `grc_lake.connectors` entry points     |
| **State**       | `connector_state.py`                                        | Probe-gated enablement, run history JSONL             |
| **Incremental** | `ingestion/watermark.py`                                    | Cursors in `gold/watermarks.jsonl`                    |
| **Dedupe**      | `ingestion/merge.py`, `connector_runner._upsert_raw_events` | Newest instant per `(connector_id, event_id)`         |
| **Validation**  | `validation.py`                                             | Strict raw schema; reject duplicate scoped identities |
| **Scale**       | `docs/AUDIT_SCALE.md`, `io.iter_jsonl`                      | Streaming IO, capped violations, synthetic fixtures   |

## Unique IDs and timestamps

| Artifact           | ID field            | Timestamp                     | Notes                                 |
| ------------------ | ------------------- | ----------------------------- | ------------------------------------- |
| Raw evidence       | `event_id`          | `event_time`                  | Required; merge dedupes on id         |
| Silver events      | `event_id`          | normalized in pipeline        | Propagates from bronze                |
| Violations         | `violation_id`      | `evaluated_at` on assessment  | Control-linked findings               |
| Control tests      | `test_id`           | `evaluated_at`                | Pass/fail/warn                        |
| Triage audit       | `tracking_id`       | `occurred_at` (UTC ISO)       | Hash chain + optional idempotency key |
| Request audit      | `event_id` (UUID)   | `occurred_at`                 | Per HTTP decision row                 |
| Activity log entry | `event_id`          | `occurred_at`                 | Unified `/api/v1/audit-log`           |
| Agent runs         | DB `id`             | `created_at` / `completed_at` | Tenant-scoped                         |
| Snapshots          | `assessment_hash`   | `evaluated_at`                | Hash chain `prev_hash`                |
| Connector runs     | `run_id` in payload | `started_at`                  | In `connector_runs.jsonl`             |

All server timestamps use **UTC** with timezone-aware ISO-8601.

## Idempotency matrix

| Operation            | Mechanism                                | Header / key                          |
| -------------------- | ---------------------------------------- | ------------------------------------- |
| Connector raw upsert | Dedupe by `(connector_id, event_id)`     | N/A (natural key)                     |
| Violation triage     | `append_chained_jsonl`                   | `idempotency_key` in body             |
| Agent run create     | DB unique `(tenant_id, idempotency_key)` | `Idempotency-Key`                     |
| Trust share create   | Lake idempotency key                     | `Idempotency-Key`                     |
| Workflow webhook     | Stable derived key                       | `Idempotency-Key` on retry            |
| HTTP request audit   | **Not idempotent**                       | `X-Correlation-ID` traces one attempt |
| Pipeline rebuild     | `evidence_set_sha256`                    | Same input → same hash                |

**Important:** `X-Correlation-ID` ties one request for tracing; it does **not**
suppress duplicate audit rows on client retries. Use `Idempotency-Key` on
**mutating** API calls that must not double-apply.

## Security findings (not a separate issue tracker)

GRC Lake does not mirror Dependabot/Snyk as a standalone “security issues”
product. Findings flow through **normalized evidence → violations**:

| Source            | Event types                              | Downstream                        |
| ----------------- | ---------------------------------------- | --------------------------------- |
| GitHub governance | vulnerability alerts, branch protection  | Raw → silver → controls           |
| Jira              | security/governance tickets              | Workflow + SLA signals            |
| Cloud posture     | misconfigurations                        | Control tests                     |
| SOC agent         | `vulnerability.*`, `detection.*` filters | Triage proposals (approval-gated) |

Query open security posture via `GET /api/v1/violations` and control tests —
not a separate `/security-issues` store.

## Headless vs human

| Caller        | Entry                        | Write model                             | Audit                          |
| ------------- | ---------------------------- | --------------------------------------- | ------------------------------ |
| **Console**   | `/console/*`                 | Same API as agents                      | Session cookie + request audit |
| **CLI**       | `grc-lake`                   | Lake + server DB                        | Operator identity              |
| **CI / gate** | `POST /api/v1/...` + API key | Read posture; optional snapshot         | API key + correlation ID       |
| **MCP agent** | `mcp_server.py` tools        | Lake writes local; DB writes via server | Same RBAC as API key           |
| **Scheduler** | CronJob `scheduler tick`     | Connector sync + workflows              | System actor in connector runs |

Humans and agents read the **same JSON**; agents must not bypass approval gates
for remediation, trust shares, or workflow side effects.

See [AGENT_API.md](api/AGENT_API.md) and [CONTINUOUS_INGESTION.md](CONTINUOUS_INGESTION.md).

## API: unified activity log

```http
GET /api/v1/audit-log?category=connector&limit=100
GET /api/v1/audit-log?include_requests=true&category=request
Authorization: Bearer <token>
```

Returns v1 envelope with `event_id`, `occurred_at`, `category`, `actor`,
`summary`, `subject`, `payload`.

Legacy unversioned `GET /api/audit-log` remains for backward compatibility.

## Adding a connector

These steps add a built-in connector. To ship one as its own package, see
[Adding connectors](ADDING_CONNECTORS.md).

1. Implement collector in `src/security_lakehouse/connectors_<vendor>.py`
2. Register builder in `connector_runner.REGISTRY`
3. Add contract row to `connectors/catalog.json` with `is_implemented: true`
4. Add probe/sync tests under `tests/test_*_connector.py`
5. Document permissions in `docs/CONNECTORS.md`

## Scale

For million-finding workloads see [AUDIT_SCALE.md](AUDIT_SCALE.md):

- `fixtures synthesize-scale` + streaming pipeline
- Capped violation rollups in assessment API
- Warehouse sinks (Snowflake, ClickHouse) for analytics outside JSONL

Audit log aggregation uses `iter_jsonl` per source file; full k-way merge at
very large lake sizes is a follow-up for operator SIEM export.

## Related

- [CONNECTORS.md](CONNECTORS.md)
- [AUDIT_SCALE.md](AUDIT_SCALE.md)
- [api/AGENT_API.md](api/AGENT_API.md)
- [HEADLESS_GRC.md](HEADLESS_GRC.md)
- [AUDIT_READINESS.md](AUDIT_READINESS.md)

## Connector identity and UTC projections

Provider `event_id` values are local to a connector. Snapshot replacement removes
only that connector's prior rows, and append/upsert chooses the newest parsed
`event_time` rather than the last arrival. Different payloads at an equal instant
are rejected before replacing the raw file; identical redelivery is idempotent.
Watermarks also compare instants and retain a monotonic UTC cursor.

Normalization version `trustops.normalization.v3` assigns connector evidence a
stable scoped `event_id`. `source_event_id` retains the provider ID and
`connector_id` identifies its owner. Raw/bronze source records and their canonical
hashes are unchanged. Consumers should use the returned normalized ID for API
lookups and evidence verification, rather than constructing it from a provider ID.
Unscoped historical IDs keep their existing interpretation. The version change
forces a full materialization before subsequent incremental evaluation; prior
generations remain intact.

DuckDB `TIMESTAMP` columns store UTC wall time, regardless of connection timezone.
Explicit offsets are converted before insertion. Naive legacy timestamps retain
the documented UTC interpretation; new evidence contracts require explicit
zones. The stored schema does not reinterpret historical evidence bytes.

Normalization v3 carries connector and original source event IDs into Parquet and
Iceberg exports as nullable columns for legacy unscoped rows. Existing v1/v2
generations retain their export schemas. Recollection may advance only collection
metadata for an unchanged source event; changed content at the same source event
time remains a conflict. Watermark timestamps are emitted in UTC.

Existing Iceberg tables created from normalization v1/v2 need two nullable string
columns, `connector_id` and `source_event_id`, before publishing v3. Evolve those
columns through the catalog's schema API or use a new table. The exporter rejects
an incompatible table without advancing its snapshot. Schema evolution retains
prior snapshots and their original IDs.

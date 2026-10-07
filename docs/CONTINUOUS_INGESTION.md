# Continuous Ingestion Operating Model

TrustOps is not meant to run as a pile of one-off bootstrap scripts. Bootstrap
artifacts create customer-owned read scopes. The running product then uses the
same connector contract from the UI, REST API, CLI, scheduler, and agents.

```text
customer admin/IaC -> scoped identity + read views
operator/API       -> discover -> probe -> enable
scheduler          -> sync -> materialize -> evaluate -> snapshot/workflow
reviewers/agents   -> read posture, runs, evidence, snapshots, trust shares
```

## Responsibilities

| Layer              | Owns                                     | Must not own                         |
| ------------------ | ---------------------------------------- | ------------------------------------ |
| Customer platform  | Snowflake user, cloud role, secret mount | TrustOps app code                    |
| TrustOps connector | read scope, fingerprint, sync history    | passwords, PATs, raw private keys    |
| Scheduler          | due checks, locks, sync/evaluation runs  | broad cloud permissions              |
| Assessment engine  | normalized evidence, controls, snapshots | connector-specific compliance claims |

## Production Flow

1. **Provision access outside TrustOps.**
   Use Terraform, Bicep, CloudFormation, Snowflake SQL, or the customer secret
   manager. Identities are non-human and read-only by default.

2. **Discover available scope.**
   Discovery returns selectable databases, views, accounts, subscriptions, or
   recommended options without enabling collection.

   ```bash
   security-lakehouse connectors discover \
     --lake /lake \
     --connector-id snowflake-evidence-lake \
     --account "$SNOWFLAKE_ACCOUNT" \
     --user TRUSTOPS_INGEST_SVC \
     --warehouse TRUSTOPS_READ_WH \
     --database TRUSTOPS_SECURITY_LAKE \
     --schema EVIDENCE
   ```

3. **Probe exact access.**
   Probe validates the same identity and read scope that will be enabled. It
   writes a non-secret access fingerprint to `gold/connector_runs.jsonl`.

   ```bash
   security-lakehouse connectors probe \
     --lake /lake \
     --connector-id snowflake-evidence-lake \
     --credentials-json '{"account":"'"$SNOWFLAKE_ACCOUNT"'","user":"TRUSTOPS_INGEST_SVC","private_key_ref":"SNOWFLAKE_PRIVATE_KEY_FILE"}' \
     --options-json '{"warehouse":"TRUSTOPS_READ_WH","database":"TRUSTOPS_SECURITY_LAKE","schema":"EVIDENCE","role":"TRUSTOPS_READER","audit_events":"TRUSTOPS_AUDIT_EVENTS","control_posture":"TRUSTOPS_CONTROL_POSTURE","asset_risk":"TRUSTOPS_ASSET_RISK","evidence_bundles":"TRUSTOPS_EVIDENCE_BUNDLES"}'
   ```

4. **Enable only after a successful probe.**
   Public API and console enablement require the latest probe to be `ok` and to
   match the same credential/scope fingerprint.

   ```bash
   security-lakehouse connectors configure \
     --lake /lake \
     --connector-id snowflake-evidence-lake \
     --state enabled \
     --credentials-json '{"account":"'"$SNOWFLAKE_ACCOUNT"'","user":"TRUSTOPS_INGEST_SVC","private_key_ref":"SNOWFLAKE_PRIVATE_KEY_FILE"}' \
     --options-json '{"warehouse":"TRUSTOPS_READ_WH","database":"TRUSTOPS_SECURITY_LAKE","schema":"EVIDENCE","role":"TRUSTOPS_READER","audit_events":"TRUSTOPS_AUDIT_EVENTS","control_posture":"TRUSTOPS_CONTROL_POSTURE","asset_risk":"TRUSTOPS_ASSET_RISK","evidence_bundles":"TRUSTOPS_EVIDENCE_BUNDLES"}' \
     --sync-schedule "every 15m"
   ```

5. **Run continuously.**
   Production deployments should run `security-lakehouse scheduler tick` from a
   Kubernetes `CronJob`, system cron, CI scheduler, Airflow, Dagster, Prefect, or
   another orchestrator. The Helm chart ships a scheduler CronJob.

6. **Review outcomes from API/UI/agents.**
   Connector run history, evidence, controls, snapshots, and integrity checks
   are exposed through `/api/v1` resources and the console. Collection endpoints
   paginate with `limit` `1..1000`, `offset`, sort, filters, and next cursors.

## Runtime Contract

| Concern           | Current behavior                                                                                                                                                                                                                                                                     |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Credentials       | Connector config stores references and fingerprints, not raw passwords or private keys.                                                                                                                                                                                              |
| Enablement        | Public enablement is probe-gated and rejects changed scope until the new payload is probed.                                                                                                                                                                                          |
| Scheduling        | `scheduler tick` uses an advisory lock and persisted last-fired state to avoid overlapping fires. Connector syncs default to ingest-only (`materialize: false`) when `sync_schedule` is set; lake-wide `eval_schedule` (default `every 6h`) runs `run_lake_eval`.                    |
| Scale tiers       | Above ~100k events, local full JSONL rebuild is blocked unless a warehouse sink is configured; incremental evaluation reuses unchanged normalized rows but rewrites complete gold projections into a new immutable generation. Budget storage and write I/O for the full generation. |
| Idempotency       | Connector raw events are upserted by `event_id`; overlapping syncs do not double-count evidence.                                                                                                                                                                                     |
| Incremental reads | Append-style connectors advance persisted watermarks; full-scope syncs remain safe by upsert.                                                                                                                                                                                        |
| Lake sinks        | Snowflake, ClickHouse, and DuckDB projections are optional and best-effort; local evidence remains authoritative.                                                                                                                                                                    |
| Rate limits       | Shared backoff primitives exist; adapter-specific 429/backoff handling is implemented where wired.                                                                                                                                                                                   |
| API limits        | Collection APIs cap `limit` at 1000 and return `400 bad_request` for invalid paging params.                                                                                                                                                                                          |
| Errors            | Sync/probe failures are recorded in `gold/connector_runs.jsonl` with sanitized messages.                                                                                                                                                                                             |
| Integrity         | Pipeline integrity records evidence hashes and idempotency set hashes in gold artifacts.                                                                                                                                                                                             |
| Snapshots         | Point-in-time snapshots are hash-chained and verifiable through `/api/v1/snapshots/integrity`.                                                                                                                                                                                       |
| Agents            | Agents consume the same API/resources; model output can propose actions, not bypass controls.                                                                                                                                                                                        |

Connector upserts scope source IDs to their owning connector. For a redelivered
record, the newest source event time wins; when event times match, the newest
collection time wins. This allows a returned alert to close without changing its
original event time. Conflicting content with equal event and collection instants
is rejected without rewriting the raw store. Historical materialized generations
retain their earlier evidence. This ordering applies to records returned by the
provider; it does not expand the connector's incremental query window.

Snapshot readers share a lock; snapshot writers hold it exclusively. Every read
still checks the complete ledger, safe paths, and fresh bytes of every snapshot.
A process-local cache retains up to 4096 successful verification fingerprints,
including ledger hash, predecessor, and timestamp, so unchanged bytes need not
be strictly decoded and canonically hashed again. File timestamps alone never
establish integrity. Cache eviction or a new worker triggers full verification.
Historical files and their canonical hashes are unchanged.

After verification, a snapshot detail read decodes only matching candidates and
a limited framework trend read decodes only its selected snapshots. Each result
is a fresh object. Reads still perform I/O proportional to the whole history;
this is an optimization of repeated verification and decoding, not a constant-time
history store. Reproduce a bounded synthetic warm-read benchmark with
`PYTHONPATH=src python tools/benchmark_snapshot_reads.py`. Its medians exclude the
initial verification and are not production capacity or cold-start estimates.

## Snowflake Production Pattern

For Snowflake, `deploy/snowflake/bootstrap_poc.sql` and
`deploy/snowflake/bootstrap_service_user.sql` are examples of the customer-side
admin/IaC step. In production, a team should convert those objects into its
normal change-management system:

- `TRUSTOPS_READER` is a read-only role.
- `TRUSTOPS_INGEST_SVC` is a non-human service user.
- The RSA public key is set in Snowflake.
- The matching private key is stored in the customer secret manager.
- The TrustOps runtime mounts the private key and sets
  `SNOWFLAKE_PRIVATE_KEY_FILE`.

In Kubernetes, mount the key as a Secret and pass the file path to both the API
pod and scheduler CronJob through Helm values:

```yaml
env:
  - name: SNOWFLAKE_ACCOUNT
    value: MJFAYEE-YS65534
  - name: SNOWFLAKE_USER
    value: TRUSTOPS_INGEST_SVC
  - name: SNOWFLAKE_AUTHENTICATOR
    value: SNOWFLAKE_JWT
  - name: SNOWFLAKE_PRIVATE_KEY_FILE
    value: /var/run/secrets/trustops/snowflake_key.p8
  - name: SNOWFLAKE_ROLE
    value: TRUSTOPS_READER
  - name: SNOWFLAKE_WAREHOUSE
    value: TRUSTOPS_READ_WH
  - name: SNOWFLAKE_DATABASE
    value: TRUSTOPS_SECURITY_LAKE
  - name: SNOWFLAKE_SCHEMA
    value: EVIDENCE

extraVolumeMounts:
  - name: snowflake-key
    mountPath: /var/run/secrets/trustops
    readOnly: true

extraVolumes:
  - name: snowflake-key
    secret:
      secretName: trustops-snowflake-key
```

The bootstrap SQL proves the required Snowflake boundary; the continuous
TrustOps value comes from scheduled sync, deterministic evaluation, fresh
evidence status, snapshots, and shared API/UI/agent access to the same state.

## API Surface

The headless path uses the same operations as the UI:

| Operation                  | Route                                              | Scope              |
| -------------------------- | -------------------------------------------------- | ------------------ |
| Ingestion health           | `GET /api/v1/ingestion/status`                     | `read`             |
| List connectors            | `GET /api/v1/connectors`                           | `read`             |
| List connector run history | `GET /api/v1/connectors/{connector_id}/runs`       | `read`             |
| Discover scope             | `POST /api/v1/connectors/{connector_id}/discover`  | `connector_manage` |
| Probe access               | `POST /api/v1/connectors/{connector_id}/probe`     | `connector_manage` |
| Configure connector        | `POST /api/v1/connectors/{connector_id}/configure` | `connector_manage` |
| Create snapshot            | `POST /api/v1/snapshots`                           | `snapshot`         |
| Verify snapshot chain      | `GET /api/v1/snapshots/integrity`                  | `read`             |
| Run lake eval              | `POST /api/v1/ingestion/eval`                      | `connector_manage` |
| List eval runs             | `GET /api/v1/ingestion/eval/runs`                  | `read`             |
| Scheduler tick             | `POST /api/v1/scheduler/tick`                      | `connector_manage` |

This is the path external portals, internal platform automation, MCP tools, and
agent harnesses should use. CLI examples are wrappers around the same contract,
not a separate operating mode.

### Failed and interrupted scheduled attempts

The scheduler records and fsyncs an attempt in `gold/scheduler_state.jsonl`
before invoking a workflow, connector, or lake evaluation. Failures wait until
that attempt time plus the configured interval; they do not retry on every
scheduler tick. The existing `last_fired_at` field means an attempted invocation,
not successful collection or evaluation. The final `result` records the outcome;
`started` without a later outcome means execution was interrupted or its outcome
could not be persisted. An interrupted scheduled attempt also waits its interval.
This cadence guarantee does not establish exactly-once external side effects;
workflow approval execution retains its separate reconciliation requirements.

Legacy state timestamps without an offset retain their UTC interpretation.
Malformed state fails closed and is left unchanged for operator reconciliation;
reads do not skip corrupt rows or reset retry history. Preserve the original file
when investigating an interrupted attempt or repairing state.

### Connector status reads

Catalog, health, and ingestion status share a per-request index of connector
configuration and run history. Each file is read once within the request;
separate lakes have separate indexes, writes invalidate the current index, and
later requests reread current state. This cache does not persist across requests.
The latest successful sync is selected from all retained runs, even when more
than 50 newer failures exist. Recent-run response limits do not limit health
history. Reads reject malformed JSON records without rewriting or skipping them.

### Scheduling a hosted deployment

Use `security-lakehouse scheduler tick --lake /lake --all-tenants` for an
authenticated server lake root, or add `--all-tenants` to `scheduler run` for
the daemon. `TRUSTOPS_COMMERCIAL_HOSTED=1` also selects tenant enumeration for
unbound root ticks. The application database must already be migrated, with
the same `TRUSTOPS_DATABASE_URL` and storage root used by the API.

Only tenants registered in that database are considered. Within each lake,
only enabled connector schedules and configured cron workflows run. Each tenant
has its own lock and retry state; a locked or failing tenant does not stop the
others. Execution and snapshot webhooks carry that tenant's identity. Symlinked
tenant paths are rejected. A single tenant retains the API's existing flat-lake
binding; an ambiguous shared root is never scheduled for multiple tenants.

Authenticated HTTP ticks always remain tenant-local; the request body cannot
select all tenants. Local CLI ticks remain single-lake unless `--all-tenants`
is selected or hosted mode is enabled. The Helm scheduler defaults to
`scheduler.allTenants: true` for authenticated deployments and retains local
scheduling for explicitly configured insecure demos. Disable this value when
an external scheduler already invokes each tenant lake separately. A one-shot
CLI tick returns a nonzero exit status when an attempted target reports an error.

# Observability: Connector Sync Dashboards

This runbook helps operators monitor connector sync health before and after
adding OpenTelemetry export. Today the authoritative sync telemetry lives in
the lake and the HTTP API; use those sources for dashboards and alerts now,
then forward the same signals through OTel when instrumented.

```text
scheduler tick / manual sync
  -> connector runner
  -> gold/connector_runs.jsonl
  -> /api/v1/connectors/{id}/runs
  -> /api/v1/ingestion/status
  -> (future) OTel metrics -> Grafana / CloudWatch / Datadog
```

## Primary Data Sources

| Source                 | Path / route                                                  | Use for                           |
| ---------------------- | ------------------------------------------------------------- | --------------------------------- |
| Connector run log      | `$GRC_LAKE_LAKE/gold/connector_runs.jsonl`                    | sync/probe/discover history       |
| Connector config log   | `$GRC_LAKE_LAKE/gold/connector_config.jsonl`                  | enable/disable, scope changes     |
| Scheduler state        | `$GRC_LAKE_LAKE/gold/scheduler_state.jsonl`                   | last cron fire times              |
| Per-connector runs API | `GET /api/v1/connectors/{connector_id}/runs`                  | paginated run history             |
| Ingestion summary API  | `GET /api/v1/ingestion/status`                                | fleet health, recommended actions |
| Evidence freshness API | `GET /api/v1/evidence/freshness?status=stale,expired,missing` | SLO breaches                      |
| Kubernetes scheduler   | CronJob `{release}-scheduler`                                 | tick failures, job backlog        |

Each run row in `gold/connector_runs.jsonl` includes:

```json
{
  "connector_id": "snowflake-evidence-lake",
  "kind": "sync",
  "result": "ok",
  "actor": "scheduler",
  "duration_ms": 8421,
  "evidence_count": 128,
  "error": null,
  "access_fingerprint": "...",
  "occurred_at": "2026-07-03T04:15:00+00:00"
}
```

`kind` is one of `discover`, `probe`, `sync`. `result` is `ok`, `error`, or
`skipped`. Error text is sanitized — hostnames and secret paths are stripped
before persistence.

## Quick Health Checks

**API (authenticated):**

```bash
curl -s "$GRC_LAKE_URL/api/v1/ingestion/status" \
  -H "authorization: Bearer $GRC_LAKE_API_KEY" | jq '.data.state, .data.summary'
```

**Latest sync for one connector:**

```bash
curl -s "$GRC_LAKE_URL/api/v1/connectors/snowflake-evidence-lake/runs?limit=5" \
  -H "authorization: Bearer $GRC_LAKE_API_KEY" | jq '.data[] | {kind, result, occurred_at, duration_ms, evidence_count}'
```

**Local lake tail:**

```bash
tail -n 20 "$GRC_LAKE_LAKE/gold/connector_runs.jsonl" | jq -s '.'
```

**Helm scheduler CronJob:**

```bash
NS=grc-lake
kubectl -n "$NS" get cronjob
kubectl -n "$NS" get jobs -l app.kubernetes.io/component=scheduler --sort-by=.metadata.creationTimestamp
kubectl -n "$NS" logs job/grc-lake-scheduler-<timestamp>
```

The chart runs `grc-lake scheduler tick --lake /lake` on
`scheduler.schedule` (default `*/5 * * * *`). Both the API Deployment and
scheduler CronJob mount the same PVC (`{release}-lake`) at `GRC_LAKE_LAKE`.

## Recommended Dashboard Panels

Build these panels from API polling, log scraping, or a future OTel exporter.

### Fleet summary (single stat / gauge)

| Metric                       | Source field                                       | Alert when    |
| ---------------------------- | -------------------------------------------------- | ------------- |
| Ingestion state              | `ingestion.status.state`                           | not `healthy` |
| Enabled connectors           | `ingestion.status.summary.enabled_connectors`      | —             |
| Failed connectors            | `ingestion.status.summary.failed_connectors`       | > 0           |
| Never synced (enabled)       | `ingestion.status.summary.never_synced_connectors` | > 0           |
| Silent connectors (past SLO) | `ingestion.status.summary.silent_connectors`       | > 0           |
| Stale evidence rows          | `ingestion.status.summary.stale_evidence`          | trending up   |

### Per-connector sync table

| Column            | Derivation                                           |
| ----------------- | ---------------------------------------------------- |
| connector_id      | run row / catalog                                    |
| freshness_state   | `fresh` / `stale` / `never_synced` from catalog view |
| last_sync_at      | latest `kind=sync, result=ok` `occurred_at`          |
| last_result       | latest sync `result`                                 |
| duration_ms       | latest ok sync                                       |
| evidence_count    | latest ok sync                                       |
| freshness_slo_min | connector catalog `freshness_slo_minutes`            |

Freshness compares the last successful sync timestamp against each connector's
`freshness_slo_minutes` (default 1440). A connector is **silent** when enabled
but has no successful sync within its SLO.

### Time series (from `connector_runs.jsonl` or OTel)

| Series                                   | Labels                   | Aggregation  |
| ---------------------------------------- | ------------------------ | ------------ |
| `grc-lake_connector_sync_total`          | `connector_id`, `result` | counter      |
| `grc-lake_connector_sync_duration_ms`    | `connector_id`, `result` | histogram    |
| `grc-lake_connector_sync_evidence_count` | `connector_id`           | gauge (last) |
| `grc-lake_scheduler_tick_total`          | `result`                 | counter      |

Example PromQL-style queries once exported:

```promql
# Sync error rate (5m)
sum(rate(grc-lake_connector_sync_total{kind="sync",result="error"}[5m]))
  / sum(rate(grc-lake_connector_sync_total{kind="sync"}[5m]))

# p95 sync duration by connector
histogram_quantile(0.95,
  sum by (connector_id, le) (rate(grc-lake_connector_sync_duration_ms_bucket[1h])))
```

## Alert Rules

| Alert                      | Condition                                           | Runbook action                                       |
| -------------------------- | --------------------------------------------------- | ---------------------------------------------------- |
| ConnectorSyncFailed        | latest `kind=sync` has `result=error`               | Inspect sanitized `error`; re-probe; check secrets   |
| ConnectorSilent            | enabled + `freshness_state=stale` or `never_synced` | Run manual sync; verify scheduler CronJob            |
| SchedulerJobFailed         | Kubernetes Job `Failed` for `{release}-scheduler`   | Check pod logs; verify PVC mount and `GRC_LAKE_LAKE` |
| IngestionDegraded          | `ingestion.status.state` in `degraded`, `blocked`   | Follow `recommended_actions` in status payload       |
| EvidenceFreshnessSLOBreach | `stale_evidence` count increases                    | Identify sources via `/api/v1/evidence/freshness`    |

## OpenTelemetry Integration (Guidance)

Native OTel instrumentation is on the
[roadmap](../../ROADMAP.md). Until it ships, use one of these patterns:

### A. Sidecar / log shipper on `connector_runs.jsonl`

Tail `$GRC_LAKE_LAKE/gold/connector_runs.jsonl` with Fluent Bit, Vector, or
Promtail. Parse JSON lines and emit:

- log records with `connector_id`, `kind`, `result`, `duration_ms`
- derived metrics via your collector's log-to-metrics processor

Mount the lake PVC read-only on the shipper pod in the same namespace as
GRC Lake.

### B. Synthetic checker CronJob

Poll `/api/v1/ingestion/status` every minute from a small CronJob. Export
custom metrics to Prometheus Pushgateway or CloudWatch embedded metrics:

```bash
STATE=$(curl -s "$GRC_LAKE_URL/api/v1/ingestion/status" -H "authorization: Bearer $KEY" \
  | jq -r '.data.state')
echo "grc-lake_ingestion_state{state=\"$STATE\"} 1"
```

### C. Future first-class OTel (recommended end state)

When instrumented, export from the API and scheduler processes:

| OTel metric / span                                                  | Trigger                   |
| ------------------------------------------------------------------- | ------------------------- |
| `trustops.connector.sync` span                                      | each `run_connector_sync` |
| `trustops.connector.probe` span                                     | each probe                |
| `trustops.scheduler.tick` span                                      | each `scheduler tick`     |
| Attributes: `connector_id`, `tenant_id`, `result`, `evidence_count` |                           |

Use `GRC_LAKE_OTEL_EXPORTER_OTLP_ENDPOINT` (planned) or standard
`OTEL_EXPORTER_OTLP_ENDPOINT` with resource attributes:

```yaml
env:
  - name: OTEL_SERVICE_NAME
    value: grc-lake
  - name: OTEL_RESOURCE_ATTRIBUTES
    value: deployment.environment=prod,service.namespace=grc-lake
```

Scrape `/api/healthz` for uptime; do **not** expose lake paths on public
metrics labels.

## Grafana Dashboard Sketch

```text
Row 1: Ingestion state | Failed connectors | Silent connectors | Stale evidence
Row 2: Sync success rate (24h) | p95 duration by connector | Evidence ingested / sync
Row 3: Table — connector_id, freshness_state, last_sync_at, last_error
Row 4: Scheduler CronJob success/failure | Last tick age
Row 5: Log panel — connector_runs.jsonl (error rows only)
```

Import JSON is not checked in yet; build from the panel table above.

## Console Surfaces

Operators can triage without a dashboard:

- `/console/connectors/` — per-connector freshness badge and last sync
- `/console/dashboard/` — posture score driven by fresh evidence
- `/console/poc/` — setup blockers including failed syncs

## Related Docs

- [Continuous Ingestion](../CONTINUOUS_INGESTION.md) — scheduler and run contract
- [Connectors](../CONNECTORS.md) — probe/sync CLI and `connector_runs.jsonl`
- [Backup And Restore](BACKUP_RESTORE.md) — preserve run history across restores
- [Shareable POC Hosting](../SHAREABLE_POC_HOSTING.md) — Helm scheduler defaults

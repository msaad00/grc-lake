# Audit-scale ingestion, evaluation, and synthetic data

TrustOps evaluates evidence in the local Python process and can export the resulting generation to Snowflake, ClickHouse, or DuckDB. Configuring a sink does not provide warehouse-native evaluation or remove local memory limits. This document describes implementation limits and tools for bounded measurement; it does not establish million-event capacity.

## Audit findings (synthesis)

| Layer                   | POC behavior today                       | Million-finding risk              | Mitigation in this repo                                                                    |
| ----------------------- | ---------------------------------------- | --------------------------------- | ------------------------------------------------------------------------------------------ |
| **Raw JSONL**           | Full-file read on upsert/sync            | Single file grows without bound   | Streaming input helpers; full evaluation still materializes local rows                     |
| **Pipeline**            | Full rebuild per `materialize=True` sync | Replays entire raw lake each tick | `manifest.json` `row_counts`; benchmark CLI to measure throughput                          |
| **Silver → violations** | O(events × controls_per_event) in memory | Multi-million finding rows        | `build_violations(..., max_violations=N)` + `violation_summary` totals                     |
| **Posture API**         | Embeds all open violations               | Payload size / latency            | Auto-cap at 10k violations when silver > 100k; framework rollups from gold control posture |
| **Ingestion status**    | Loaded full silver for counts            | Status endpoint latency           | Manifest-backed counts + streaming field histograms                                        |
| **Synthetic fixtures**  | Golden = 37 events                       | No load-test data                 | `fixtures synthesize-scale` CLI (millions, streaming write)                                |

**Recommendation above ~100k events:** project findings with `benchmark plan`, generate synthetic lakes with `fixtures synthesize-scale`, measure pipeline with `benchmark pipeline`, and route auditor analytics to **Snowflake/ClickHouse** marts (`deploy/snowflake/schema.sql`, `deploy/clickhouse/schema.sql`) instead of expanding in-process JSONL.

## Synthetic data (audit-scale)

Generate reproducible raw evidence without live connectors:

```bash
# Project cardinality before generating
security-lakehouse benchmark plan --events 1000000 --controls-per-event 3 --open-ratio 0.12

# Stream 1M events (~360k findings at defaults) to disk
security-lakehouse fixtures synthesize-scale \
  --count 1000000 \
  --out /tmp/audit-scale/raw.jsonl \
  --controls-per-event 3 \
  --open-ratio 0.12 \
  --seed 42

# Materialize lake + timing
security-lakehouse benchmark pipeline --raw /tmp/audit-scale/raw.jsonl --out /tmp/audit-scale/lake
```

Controls are sampled from the active catalog. Each open event fans out to `controls_per_event` findings during evaluation.

## Integrity verification memory

Lake verification streams bronze and silver records. It retains hashes, event-ID
counts, and the sorted evidence-set metadata required by the existing digest
format; it no longer retains every parsed evidence payload. Memory still grows
with event count and the largest individual record. Evaluation and mart building
remain separate memory consumers. This optimization does not qualify the default
1 GiB Helm limit for a given dataset; measure the complete workload under its
actual container limit.

## Latency and throughput enhancements

### Incremental materialize (`pipeline.run_pipeline_incremental`)

When a prior `manifest.json` exists, incremental materialize:

- streams raw JSONL and compares each `event_id` fingerprint to `manifest.raw_index`
- upserts only changed/new rows into bronze/silver
- rebuilds gold/marts from the merged silver set (not a full raw replay of unchanged rows)
- records `materialize_mode`, `delta_count`, and `removed_count` on the manifest
- re-evaluates unchanged evidence when a freshness boundary is due
- rebuilds when rules, program settings, connector freshness policies, or the effective safeguard review overlay change

Use split schedules so connector sync stays ingest-only and lake eval runs less often:

```bash
security-lakehouse connectors configure \
  --lake /lake \
  --connector-id github-security \
  --state enabled \
  --sync-schedule "every 15m" \
  --eval-schedule "every 6h"

security-lakehouse pipeline eval --lake /lake
security-lakehouse scheduler tick --lake /lake
```

HTTP/API (same contract as UI, MCP, and agents):

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://trustops.example/api/v1/ingestion/eval -d '{"actor":"api"}'

curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://trustops.example/api/v1/scheduler/tick -d '{}'
```

MCP tools: `get_ingestion_status`, `list_eval_runs`, `run_lake_eval`, `run_scheduler_tick`, `sync_connector`, `list_connector_runs`.

### Export routing above 100k events

When silver/raw cardinality exceeds `100_000`, local full rebuild is blocked unless a
Snowflake, ClickHouse, or DuckDB sink is configured. This threshold is a routing guard, not a capacity guarantee: evaluation still materializes local data before export. `local_result` and `export_result` distinguish a committed assessment from a failed export. Export always reads that committed generation. The active tier is recorded in
`gold/lake_scale.json` and surfaced on `/api/v1/ingestion/status`.

### Streaming IO (`security_lakehouse.io`)

- `iter_jsonl` — line-at-a-time reads (no full-file `read_text`)
- `count_jsonl` — row counts without JSON parse
- `jsonl_field_counts` — histogram one field while streaming
- `iter_jsonl_batches` — chunked processing hook for future incremental pipeline stages
- `write_jsonl_from_iterable` — generator-friendly writes for synthesis

### Capped violation rollups (`security_lakehouse.assessment`)

- `build_violations(events=..., max_violations=N)` returns `(rows, summary)`
- `violation_summary` carries `total_count`, `severity_counts`, and `truncated`
- `write_current_posture` auto-applies `max_violations=10000` when silver > 100k
- Framework scores use gold `control_posture` aggregates when violations are truncated

### Manifest row counts (`manifest.json`)

After each pipeline run, `row_counts` records bronze/silver/gold cardinalities so `ingestion/status` avoids full-file scans.

## Related docs

- [CONTINUOUS_INGESTION.md](CONTINUOUS_INGESTION.md) — connector loop and watermarks
- [HERO_DATA_LAKES.md](HERO_DATA_LAKES.md) — warehouse adapters and evidence readers
- [FRAMEWORK_COVERAGE.md](FRAMEWORK_COVERAGE.md) — active control catalog size

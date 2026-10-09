# Data Flow

The product is assessment-first. Data can arrive from an existing security data
lake or from GRC Lake-managed connector outputs.

For the production operating loop that turns this data flow into continuous
collection, evaluation, snapshots, and API access, see
[`CONTINUOUS_INGESTION.md`](CONTINUOUS_INGESTION.md).

## Two Connection Modes

```mermaid
flowchart LR
  subgraph Existing["Existing Security Data Lake Mode"]
    Snowflake["Snowflake tables/views"]
    ClickHouse["ClickHouse tables/views"]
    SIEM["SIEM/export APIs"]
    ObjectStore["Object storage evidence"]
  end

  subgraph Managed["Managed Evidence Object Mode"]
    Connector["Connector adapter"]
    Raw["Raw JSONL evidence"]
    Bronze["Bronze hashed replay"]
    Silver["Silver normalized events"]
  end

  subgraph Assessment["Assessment Engine"]
    Normalize["Evidence normalization"]
    Controls["Control catalog"]
    Evaluate["Control evaluation"]
    Posture["Current posture"]
    Violations["Violations"]
    Snapshots["Point-in-time snapshots"]
  end

  Snowflake --> Normalize
  ClickHouse --> Normalize
  SIEM --> Normalize
  ObjectStore --> Normalize
  Connector --> Raw --> Bronze --> Silver --> Normalize
  Normalize --> Evaluate
  Controls --> Evaluate
  Evaluate --> Posture
  Evaluate --> Violations
  Posture --> Snapshots
```

## Existing Security Data Lake Mode

Use this when the company already has security evidence in Snowflake,
ClickHouse, object storage, a SIEM, or scanner exports.

The tool should:

1. connect read-only to existing tables, views, exports, or files
2. map source fields into the normalized evidence schema
3. evaluate controls without duplicating raw payloads where possible
4. write assessment results, violations, and snapshots to the configured store

This is the lowest-friction enterprise mode because the data stays where the
company already governs it.

## Managed Evidence Object Mode

Use this when the company does not have a clean security data model yet.

The tool creates:

- raw evidence files or landing tables
- bronze hashed replay records
- silver normalized evidence facts
- gold control posture, asset risk, current posture, and snapshots
- optional Snowflake and ClickHouse tables/views

The sample repo implements this locally from `data/raw/security_events.jsonl`.

The normalization handoff is explicit and reusable for pre-landed canonical raw
evidence:

```bash
grc-lake ingestion normalize \
  --raw ./raw/connector_events.jsonl \
  --out ./lake
```

Use `--incremental` for replay-safe updates when the output lake already has a
manifest. Direct connectors use the same normalization boundary after they land
raw evidence; existing Snowflake, ClickHouse, object-storage, and SIEM sources
must first be mapped by their source adapter into the canonical raw contract.

## Evaluation Steps

```text
source evidence
  -> normalize into canonical evidence facts
  -> join evidence to control mappings
  -> evaluate pass/fail/stale/missing evidence
  -> emit violations with owner, asset, evidence_ref, raw_sha256
  -> compute framework scores and current posture
  -> optionally freeze a point-in-time snapshot
```

## Current Implementation

| Step              | Current artifact                                                   |
| ----------------- | ------------------------------------------------------------------ |
| Source evidence   | `data/raw/security_events.jsonl`                                   |
| Validation        | `src/security_lakehouse/validation.py`                             |
| Normalization     | `src/security_lakehouse/pipeline.py`                               |
| Control mapping   | `mappings/control_map.json`                                        |
| Assessment engine | `src/security_lakehouse/assessment.py`                             |
| Current posture   | `build/lakehouse/gold/current_posture.json`                        |
| Violations        | `grc-lake assessment violations --lake build/lakehouse`            |
| Snapshot          | `grc-lake assessment snapshot --lake build/lakehouse --reason ...` |
| API               | `src/security_lakehouse/server_app.py`                             |

## Connector Contract

Connectors should emit evidence records with:

- `event_id`
- `tenant_id`
- `event_time`
- `source`
- `event_type`
- `entity.asset_id`
- `entity.asset_type`
- `severity`
- `status`
- `controls`
- `evidence.evidence_id`
- `evidence.evidence_ref`
- `evidence.evidence_collected_at`
- `evidence.raw_sha256`

Optionally, `entity.asset_name` gives the asset a human-readable name. It is
display data only: `asset_id` stays the key everywhere. The name is kept on the
gold asset rows (`gold/asset_risk.jsonl`), not on normalized events, and the
API adds it as `asset_name` to evidence, violations, assets, AI inventory, and
graph asset labels.

Connectors should not decide compliance. They only collect evidence. The
assessment engine decides posture.

## Evaluation Contract

Controls evaluate from:

- normalized evidence facts
- control mapping metadata
- freshness window
- status/severity rules
- owner and asset context
- exceptions, once implemented

Outputs:

- current posture
- framework scores
- control status
- open violations
- stale controls
- top risk assets
- assessment snapshots

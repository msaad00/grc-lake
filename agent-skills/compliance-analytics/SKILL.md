---
name: compliance-analytics
description: >-
  Use the local continuous compliance assessment artifacts and API to answer
  audit, control, evidence, vulnerability, runtime, posture, snapshot, and
  executive-risk questions. The skill is read-only unless the user explicitly
  requests a point-in-time snapshot.
license: Apache-2.0
metadata:
  author: Mohamed Saad
  data_flow: >-
    Reads generated lakehouse JSON and SQLite artifacts from the local repo.
    Does not call external services and does not modify production systems.
  file_reads:
    - build/fixture-lake/gold/current_posture.json
    - build/fixture-lake/gold/metrics.json
    - build/fixture-lake/gold/control_posture.jsonl
    - build/fixture-lake/gold/asset_risk.jsonl
    - build/fixture-lake/mart/security_lakehouse.sqlite
    - deploy/snowflake/schema.sql
    - deploy/clickhouse/schema.sql
  file_writes: []
  network: false
  autonomous_invocation: read_only
---

# Security Compliance Analytics

Use this skill when the user asks:

- "What are our top security risks?"
- "Which controls are failing?"
- "What evidence can I show an auditor?"
- "Which assets concentrate critical risk?"
- "What changed in runtime or AI governance posture?"
- "How would this land in Snowflake or ClickHouse?"
- "Create a point-in-time assessment snapshot for vendor diligence"
- "What does the current posture API say?"

## Required Artifacts

For an authorized local fixture demonstration, build a separate fixture lake;
do not replace the user's operational lake. Fixture results are illustrative:

```bash
security-lakehouse pipeline run \
  --raw data/raw/security_events.jsonl \
  --out build/fixture-lake
```

For dashboard review:

```bash
security-lakehouse dashboard \
  --lake build/fixture-lake \
  --out build/dashboard/index.html
```

For the human and agent API:

```bash
security-lakehouse serve --lake build/fixture-lake --port 8787
```

Agent routes:

- `GET /api/v1/posture/current`
- `GET /api/v1/violations`
- `GET /api/v1/controls`
- `GET /api/v1/assets`
- `POST /api/v1/snapshots`

## Query Patterns

Top failing controls:

```sql
select control_id, framework, status, risk_score, evidence_count, event_count
from control_posture
order by risk_score desc, open_event_count desc;
```

Highest-risk assets:

```sql
select asset_id, asset_type, asset_owner, environment, risk_score, critical_open, high_open
from asset_risk
order by risk_score desc;
```

Evidence behind one control:

```sql
select event_time, source, event_type, asset_id, severity, status, evidence_ref
from normalized_events
where control_ids_json like '%SOC2-CC6.1%'
order by event_time desc;
```

Backend architecture evidence:

- Snowflake governed evidence lake: `deploy/snowflake/schema.sql`
- ClickHouse telemetry analytics lake: `deploy/clickhouse/schema.sql`
- Dual-backend diagram: `docs/diagrams/dual-lakehouse.md`

Current posture:

```bash
security-lakehouse assessment status --lake build/fixture-lake
```

Open violations:

```bash
security-lakehouse assessment violations --lake build/fixture-lake
```

## Response Rules

- Cite generated artifacts or SQL results for every material claim.
- Separate observed evidence from recommended next actions.
- A passing control result is limited to its rule, evidence and assessment scope.
  It does not establish certification or complete framework compliance. Claim
  remediation completion only after verifying the changed state in fresh evidence.
- Treat `evidence_ref` as a pointer; do not invent contents that are not in the
  lakehouse artifacts.

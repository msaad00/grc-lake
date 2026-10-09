# Architecture — Local (file-backed) mode

GRC Lake runs in two modes that share one assessment engine:

- **Local mode** (this diagram): zero-dependency, file-backed Bronze/Silver/Gold
  zones with a SQLite analytics mart and a static dashboard. No cloud account or
  database required; `pip install` and run.
- **Server / warehouse mode**: the same engine behind a FastAPI server with an
  application-state database, RBAC, SSO, the Next.js console, and governed
  evidence in Snowflake or ClickHouse. See
  [`grc-lake-assessment-architecture.svg`](../images/grc-lake-assessment-architecture.svg)
  and [`dual-lakehouse.md`](dual-lakehouse.md).

The two are not alternatives to reconcile: local mode is the embedded
single-file path; server mode is the multi-tenant deployment path.

```mermaid
flowchart LR
  subgraph Sources["Security Evidence Sources"]
    CSPM["Cloud CSPM"]
    Vuln["Vulnerability Scanner"]
    Runtime["Runtime Gateway"]
    IDP["Identity Provider"]
    SIEM["SIEM"]
    Tickets["Ticketing"]
    Registry["Model Registry"]
  end

  subgraph Lake["File-Backed Security Lake"]
    Bronze["Bronze<br/>raw JSONL + SHA-256"]
    Silver["Silver<br/>normalized events"]
    Gold["Gold<br/>metrics, controls, assets"]
  end

  subgraph Mart["Analytics Mart"]
    SQLite["SQLite<br/>normalized_events<br/>control_posture<br/>asset_risk<br/>metrics"]
  end

  subgraph Consumption["Consumption"]
    Dashboard["Static dashboard"]
    SQL["SQL query CLI"]
    Agent["Agent skill"]
    Audit["Evidence package"]
  end

  CSPM --> Bronze
  Vuln --> Bronze
  Runtime --> Bronze
  IDP --> Bronze
  SIEM --> Bronze
  Tickets --> Bronze
  Registry --> Bronze
  Bronze --> Silver
  Silver --> Gold
  Gold --> SQLite
  Gold --> Dashboard
  SQLite --> SQL
  SQLite --> Agent
  Gold --> Audit
```

## Why This Design

The pipeline mirrors a real security analytics platform without requiring a
cloud account:

- raw records remain replayable and hash-linked
- transformations are deterministic and testable
- control mappings are separated from source ingestion
- metrics and dashboards are generated from gold data, not hand-written
- SQL access is available through a local mart

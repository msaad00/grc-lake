# Architecture — Local (file-backed) mode

This diagram shows the file-backed assessment pipeline. The same engine can run
from the CLI or behind the authenticated API and bundled console.

- **Local mode:** JSONL Bronze/Silver/Gold zones, a SQLite analytics mart, and an
  optional DuckDB mart. One writable application replica owns each lake.
- **Distributed mode:** multiple API replicas and tenant workers use private
  scratch storage, PostgreSQL coordination, and S3-compatible evidence objects.
  See [deployment models](deployment-models.md) and [distributed mode](../DISTRIBUTED.md).
- **Warehouse adapters:** Snowflake and ClickHouse are optional evidence sources
  or export destinations. They are separate from the application topology; see
  [dual lakehouse](dual-lakehouse.md).

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
    SQLite["SQLite + optional DuckDB<br/>normalized_events<br/>control_posture<br/>asset_risk<br/>metrics"]
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

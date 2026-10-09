# Hosting Model

```mermaid
flowchart LR
  subgraph Dev["Developer Laptop"]
    CLI["grc-lake CLI"]
    Files["build/lakehouse<br/>JSON + SQLite"]
    Static["build/dashboard/index.html"]
  end

  subgraph Cloud["Production Cloud Account"]
    Ingest["Object Storage Landing Zone"]
    Orchestrator["Scheduler / CI / Airflow"]
    Snowflake["Snowflake<br/>Governed Evidence Lake"]
    ClickHouse["ClickHouse<br/>Telemetry Analytics"]
    Dashboard["Dashboard Hosting<br/>Static site or internal app"]
  end

  subgraph Controls["Security Boundaries"]
    KMS["KMS / Secrets Manager"]
    RBAC["Warehouse RBAC"]
    Audit["Access Audit Logs"]
    Retention["Retention + Lifecycle Policy"]
  end

  CLI --> Files --> Static
  CLI --> Ingest
  Ingest --> Orchestrator
  Orchestrator --> Snowflake
  Orchestrator --> ClickHouse
  Snowflake --> Dashboard
  ClickHouse --> Dashboard
  KMS --> Orchestrator
  RBAC --> Snowflake
  RBAC --> ClickHouse
  Snowflake --> Audit
  ClickHouse --> Audit
  Ingest --> Retention
```

## Hosting Notes

- Local mode is dependency-light and runs anywhere with no managed services.
- Production mode can run from CI, Airflow, Dagster, Prefect, or a Kubernetes CronJob.
- Snowflake credentials should use key-pair or workload identity where possible.
- ClickHouse should use TLS, named users, least-privilege grants, and retention policies.
- Raw payloads can stay in object storage while warehouses retain hashes and evidence pointers.

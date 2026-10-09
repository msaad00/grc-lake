# Connector Ingestion — Read-Only Connection Model

How GRC Lake (and typical enterprise GRC tools) connect to sources:
**APIs and read-only roles**, not admin write access.

## GRC Lake ingestion loop

```mermaid
flowchart LR
  subgraph Customer["Customer boundary"]
    AWS["AWS IAM role<br/>read-only"]
    GH["GitHub App<br/>security scopes"]
    OKTA["Okta token<br/>directory read"]
    SF["Snowflake views<br/>SELECT only"]
  end

  subgraph GRC Lake["GRC Lake runtime"]
    DISC["Discover scope"]
    PROBE["Probe access"]
    SYNC["Sync scheduler"]
    BRZ["Bronze raw"]
    SLV["Silver facts"]
    GLD["Gold posture"]
  end

  subgraph Surfaces["Work surfaces"]
    UI["Console"]
    API["/api/v1"]
    TC["Trust center"]
  end

  AWS --> DISC
  GH --> DISC
  OKTA --> DISC
  SF --> DISC
  DISC --> PROBE --> SYNC --> BRZ --> SLV --> GLD
  GLD --> UI
  GLD --> API
  GLD --> TC
```

## Connection matrix

| Source           | Connection mechanism                                      | Permissions style                       |
| ---------------- | --------------------------------------------------------- | --------------------------------------- |
| AWS              | Cross-account **IAM role** + External ID (or SSO profile) | `List*`, `Get*`, `Describe*` — no write |
| Azure            | App registration / **Reader** / workload identity         | Subscription & IAM read                 |
| GCP              | Service account / WIF                                     | Asset & IAM inventory read              |
| GitHub           | **GitHub App** installation token                         | Security alert read scopes              |
| Okta             | **API token** or OAuth                                    | `okta.users.read`, policies read        |
| Google Workspace | OAuth bearer + customer ID                                | Directory read-only scopes              |
| Snowflake        | Key-pair service user                                     | `SELECT` on granted views only          |

## Lifecycle (probe-gated)

```mermaid
sequenceDiagram
  participant Admin as Customer admin
  participant TO as GRC Lake
  participant Src as Source API

  Admin->>TO: Configure credential ref + scope
  TO->>Src: Discover allowed objects
  TO->>Src: Probe read access
  Src-->>TO: ok + fingerprint
  Admin->>TO: Enable connector
  loop Scheduler
    TO->>Src: Sync (read-only)
    Src-->>TO: Evidence rows
    TO->>TO: Materialize bronze/silver/gold
  end
```

See also:

- [CONTINUOUS_INGESTION.md](../CONTINUOUS_INGESTION.md)
- [CONNECTORS.md](../CONNECTORS.md)
- [Read-only connections SVG](../images/grc-lake-readonly-connections.svg)

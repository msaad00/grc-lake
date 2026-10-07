# Diagram Index

Visual references for architecture, ingestion, auth, and deployment.

## Mermaid (in-repo)

| Diagram                                     | File                                                               |
| ------------------------------------------- | ------------------------------------------------------------------ |
| **Core GRC loop** (connect → prove)         | [core-grc-loop.md](core-grc-loop.md)                               |
| Connector ingestion & read-only connections | [connector-ingestion.md](connector-ingestion.md)                   |
| OIDC / SAML / API key identity              | [auth-identity.md](auth-identity.md)                               |
| OSS / self-hosted / hosted models           | [deployment-models.md](deployment-models.md)                       |
| Local file-backed architecture              | [architecture.md](architecture.md)                                 |
| Dual lakehouse routing                      | [dual-lakehouse.md](dual-lakehouse.md)                             |
| Evaluation lifecycle                        | [evaluation-lifecycle.md](evaluation-lifecycle.md)                 |
| Hosting topology                            | [hosting.md](hosting.md)                                           |
| Unified lake + app DB model                 | [unified-data-model.md](unified-data-model.md)                     |
| Single-replica topology and HA limits       | [../runbooks/HA_READ_REPLICAS.md](../runbooks/HA_READ_REPLICAS.md) |
| Agent workflow                              | [agent-workflow.md](agent-workflow.md)                             |

## SVG (README & docs)

| Asset                                                                                  | Use                          |
| -------------------------------------------------------------------------------------- | ---------------------------- |
| [trustops-assessment-architecture.svg](../images/trustops-assessment-architecture.svg) | Continuous assessment hero   |
| [trustops-readonly-connections.svg](../images/trustops-readonly-connections.svg)       | Enterprise read-only connect |
| [trustops-identity-boundary.svg](../images/trustops-identity-boundary.svg)             | SSO + API key boundary       |
| [trustops-readme-banner.svg](../images/trustops-readme-banner.svg)                     | README banner                |

## Console diagrams

Interactive flow strips live in `app/web/src/components/diagrams/`:

- `ConnectionCompareDiagram` — `/deploy` (evidence boundary reference)
- `AuthIdentityDiagram` — `/auth`
- `FlowStrip` — `/deploy` go-live path

Operational connector UI (`/connectors`) shows live status and setup steps only — no marketing compare blocks.

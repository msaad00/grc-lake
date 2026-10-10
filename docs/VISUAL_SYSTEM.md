# Visual System

The product should feel like an assessment console, not a report. The visual
language should make current posture, violations, owners, evidence, and
snapshots understandable for both humans and agents.

Product name, logo, taglines, and naming hierarchy: [BRAND.md](BRAND.md).

## GRC Lake mark

- Blue-to-mint evidence-lake mark (`#4f7cff` → `#42dfcf`) with cloud,
  identity, agent, and log glyphs. Use `GrcLakeMark` / `GrcLakeLogo` in the
  console shell and the SVG lockup in docs. Below 48 px, use the compact
  activity-log and waves variant.
- Console chrome label: **GRC Lake Console** (sidebar subtitle), not
  "Workbench" or "Assessment Console".

## Framework visual identity

Neutral **gradient marks** with Lucide icons identify each program (SOC 2, ISO,
FedRAMP, CIS AWS, etc.) without shipping official certification logos. See
`app/web/src/lib/framework-visuals.ts`, `FrameworkMark`, and `FrameworkBadge`.

Shared KPI tiles use `KpiTile` with tone accents (default / ready / attention /
critical / brand). Compliance rings and bar scoreboards summarize each
program on the **Dashboard** (`/dashboard`) and
**Continuous control monitoring** summary (`/controls`).

## Out-Of-Box Views

| View              | Purpose                                                       |
| ----------------- | ------------------------------------------------------------- |
| Executive posture | score, state, open violations, stale evidence, trend          |
| Control workbench | framework, control, owner, status, evidence coverage          |
| Violation queue   | severity, asset, owner, source, evidence, raw hash            |
| Evidence room     | evidence refs, source systems, collection time, snapshot hash |
| Data model        | assets, evidence, controls, tests, violations, snapshots      |
| Lake routing      | Snowflake governed evidence, ClickHouse telemetry analytics   |
| Agent console     | API routes, skills, allowed actions, snapshot controls        |
| Connectors        | vendor marks, ingestion pipeline, connection flow diagram     |
| Audit room        | score, gaps, freshness SLA, workflow checklist                |
| Access / auth     | API keys, users & roles, invites, IdP marks                   |
| Deploy            | OSS / self-hosted / hosted models + go-live flow              |

## Framework identity

Framework identity combines exact official names with project-owned Lucide
icons. Two NIST framework illustrations are approved and self-hosted with
attribution; other official marks remain restricted or unavailable. See
[THIRD_PARTY_ASSETS.md](THIRD_PARTY_ASSETS.md) and
`frameworks/identity-assets.json` for the provenance record.

| Family     | Component        | Policy                                              |
| ---------- | ---------------- | --------------------------------------------------- |
| Frameworks | `FrameworkBadge` | Approved NIST artwork or icon + exact official name |
| Connectors | `ConnectorMark`  | Brand SVG logos (Simple Icons) with text fallback   |
| Identity   | `AuthMark`       | IdP-colored abbreviations — Okta, Entra, SAML, KEY  |

See [THIRD_PARTY_ASSETS.md](THIRD_PARTY_ASSETS.md).

## Interaction Patterns

- filters for framework, owner, severity, source, status, and environment
- collapsible evidence details
- clickable controls and assets
- snapshot button with explicit reason
- copyable API routes
- tags for `current`, `snapshot`, `stale`, `open`, `owner`, `framework`
- horizontal **flow strips** for ingestion, auth, and deployment paths

## Diagram Inventory

Full index: [diagrams/README.md](diagrams/README.md)

### Architecture & data

- [Architecture](ARCHITECTURE.md)
- [Data Model](DATA_MODEL.md)
- [Dual Lakehouse](diagrams/dual-lakehouse.md)
- [Evaluation Lifecycle](diagrams/evaluation-lifecycle.md)
- [Hosting](diagrams/hosting.md)

### Connectors & ingestion

- [Connector ingestion (mermaid)](diagrams/connector-ingestion.md)
- [Read-only connections (SVG)](images/grc-lake-readonly-connections.svg)
- [Continuous ingestion](CONTINUOUS_INGESTION.md)

### Identity & deployment

- [Auth identity (mermaid)](diagrams/auth-identity.md)
- [Identity boundary (SVG)](images/grc-lake-identity-boundary.svg)
- [Deployment models (mermaid)](diagrams/deployment-models.md)
- [Deployment](DEPLOYMENT.md)

### Hero SVGs

- [Assessment architecture](images/grc-lake-assessment-architecture.svg)
- [Snowflake evidence lake](images/grc-lake-snowflake-evidence-lake.svg)

# Deployment

TrustOps is an **open-source trust operations platform** you can run locally or
self-host in your cloud. The product goal is enterprise-grade continuous
compliance — evidence ingestion, control tests, posture dashboards, trust-center
sharing, and agent APIs — without locking evidence in a vendor silo.

## Deployment models

| Model           | Who runs it                   | Best for                                                         |
| --------------- | ----------------------------- | ---------------------------------------------------------------- |
| **OSS local**   | You, on a laptop or CI runner | Contributors, evaluators, pipeline proofs                        |
| **Self-hosted** | You, in your VPC / cluster    | Teams that need data residency, custom connectors, full control  |
| **Hosted mode** | An operator you choose        | Teams that want a live URL without running Kubernetes themselves |

Evidence stays in **your boundary** in every model: local files, customer-owned
Snowflake/ClickHouse/DuckDB, or a tenant-scoped `/lake` volume on your cluster.
TrustOps is not a hosted evidence warehouse that copies your cloud posture into
an opaque SaaS database.

<p align="center">
  <img src="images/trustops-readonly-connections.svg" alt="Read-only connections vs vendor SaaS evidence boundary" width="92%">
</p>

Diagrams: [deployment-models.md](diagrams/deployment-models.md) · [connector-ingestion.md](diagrams/connector-ingestion.md)

```text
Sources (AWS, Azure, GCP, GitHub, Okta, Snowflake, …)
  -> read-only connectors
  -> bronze / silver / gold lake (your storage)
  -> deterministic control tests + snapshots
  -> console, API, trust-center shares, agents
```

### OSS local

Fastest path to evaluate the product, with Docker Compose v2:

```bash
docker compose up
```

Open `http://127.0.0.1:8787/console/dashboard/`. It serves the bundled sample
company with authentication off, on `127.0.0.1` only. The
[5-minute tutorial](TUTORIAL_5_MIN.md) covers the pip and source paths.

From a source checkout the console must be built first (`make web-install
web-build`, Node 22+); without that build `/console/` is a 404.

### Python and MCP

The wheel includes the CLI and static console. Optional extras select runtime
dependencies; they are not separate hosted services:

```bash
pip install 'trustops-security-data-lake[server,mcp]'
TRUSTOPS_LAKE=./lake trustops-mcp
```

`trustops-mcp` speaks stdio to an MCP client. It can read the operator's local
lake or call an authenticated TrustOps API using `TRUSTOPS_API_URL` and
`TRUSTOPS_API_KEY`. The HTTP server and console use `security-lakehouse serve
--server`; configure [server auth](SERVER_AUTH.md) before exposing them.
The Docker image also includes MCP, but its default command starts the HTTP
server. Neither package publication nor container publication creates a cloud
service.

### Self-hosted

Self-hosted shape: Helm chart on EKS/AKS/GKE (or Docker Compose for small pilots),
**one writable application replica**, OIDC/SAML for humans, API keys for agents,
persistent `/lake`, scheduler-driven
connector syncs, and token-scoped trust-center links.

| Component | Typical POC                        | Production hardening                               |
| --------- | ---------------------------------- | -------------------------------------------------- |
| Runtime   | Helm on a small managed cluster    | Private nodes, workload identity, external secrets |
| Auth      | One tenant, OIDC/SAML              | SCIM lifecycle, enforced SSO, least-privilege RBAC |
| State     | Encrypted PVC at `/lake`           | Backup/restore, per-tenant prefixes                |
| Evidence  | Read-only cloud/service identities | Customer IaC owns roles, grants, rotation          |

The chart rejects read-only lakes and multiple application replicas, even with
RWX storage or PostgreSQL. Updates have downtime. See the
[topology boundary](runbooks/HA_READ_REPLICAS.md). EKS has reference Terraform;
AKS/GKE use the same chart with operator-provisioned infrastructure.

Runbook: [Shareable POC Hosting](SHAREABLE_POC_HOSTING.md),
[deploy/README.md](../deploy/README.md),
[Server Auth](SERVER_AUTH.md).

### Hosted mode

Hosted mode is the same TrustOps binary and chart, run by an operator for
several tenants. There is no public managed service; operators enable the
hosted features with environment flags. Each tenant's connector secrets resolve
only under its own prefix, and cloud readers need delegated access: see
[hosted connector credentials](SERVER_AUTH.md#hosted-connector-credentials). See [COMMERCIAL_HOSTED.md](COMMERCIAL_HOSTED.md) for the
gated commercial features (invites, usage limits, SCIM 2.0, Stripe billing).

Evaluator flow: [Shareable Demo](SHAREABLE_DEMO.md).

## Feature parity lens (honest)

| Capability                                      | TrustOps 0.2.x                            |
| ----------------------------------------------- | ----------------------------------------- |
| Continuous control tests from live integrations | Yes (connectors + scheduler)              |
| Executive dashboard + framework readiness       | Yes                                       |
| Trust center / customer sharing                 | Yes (scoped tokens)                       |
| Policy/policy-template library                  | MVP (8 bundled templates + adopt/publish) |
| Auditor workflow / audit project management     | MVP (audit room + audit readiness API)    |
| Vendor risk questionnaires                      | MVP (bundled questionnaire templates)     |
| OSS + self-hosted                               | **Yes**                                   |
| Customer-owned evidence lake                    | **Yes**                                   |

See [Release Readiness](RELEASE_READINESS.md) and [Product Walkthrough](PRODUCT_WALKTHROUGH.md)
for shipped vs planned detail.

## Choosing a path

```text
Need to fork, air-gap, or pass strict data-residency review?
  -> Self-hosted (Helm / your cloud)

Want a live demo link for evaluators this week?
  -> Local fixtures + SHAREABLE_DEMO.md

Already centralize security evidence in Snowflake, Databricks, ClickHouse,
Iceberg/Parquet (Amazon Security Lake), BigQuery, or a SIEM lake?
  -> Existing-lake read mode + TrustOps assessment on top (BRING_YOUR_OWN_LAKE.md)
```

## Next steps

| Goal                                         | Doc                                                  |
| -------------------------------------------- | ---------------------------------------------------- |
| Run locally in 5 minutes                     | [README.md](../README.md#quick-start)                |
| Read the lake you already run                | [BRING_YOUR_OWN_LAKE.md](BRING_YOUR_OWN_LAKE.md)     |
| Host a shareable POC                         | [SHAREABLE_POC_HOSTING.md](SHAREABLE_POC_HOSTING.md) |
| Evaluator demo script                        | [SHAREABLE_DEMO.md](SHAREABLE_DEMO.md)               |
| Framework packs (SOC 2, NIST AI RMF, custom) | [FRAMEWORK_PACKS.md](FRAMEWORK_PACKS.md)             |
| Architecture                                 | [ARCHITECTURE.md](ARCHITECTURE.md)                   |

For self-hosted support inquiries, open a GitHub discussion or issue on the
repository.

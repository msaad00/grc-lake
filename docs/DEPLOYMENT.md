# Deployment

TrustOps is an **open-source trust operations platform** you can run locally or
self-host in your cloud. The product goal is enterprise-grade continuous
compliance — evidence ingestion, control tests, posture dashboards, trust-center
sharing, and agent APIs — without locking evidence in a vendor silo.

## Deployment models

| Model              | Who runs it                   | Best for                                                         |
| ------------------ | ----------------------------- | ---------------------------------------------------------------- |
| **OSS local**      | You, on a laptop or CI runner | Contributors, evaluators, pipeline proofs                        |
| **Self-hosted**    | You, in your VPC / cluster    | Teams that need data residency, custom connectors, full control  |
| **Managed hosted** | TrustOps operator (future)    | Teams that want a live URL without running Kubernetes themselves |

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

Fastest path to evaluate the product:

```bash
pip install -e ".[dev,server]"
make web-install web-build   # requires Node 22+; the console is not committed to the repo
security-lakehouse fixtures load --company fintech --out build/lakehouse
security-lakehouse serve --lake build/lakehouse --server --allow-insecure-no-auth --port 8787
```

Open `http://127.0.0.1:8787/console/dashboard/`. No account required.

Without the console build that URL is a 404 — `/console/` is mounted only when a
built console is present.

### Self-hosted

Production shape: Helm chart on EKS/AKS/GKE (or Docker Compose for small pilots),
OIDC/SAML for humans, API keys for agents, persistent `/lake`, scheduler-driven
connector syncs, and token-scoped trust-center links.

| Component | Typical POC                        | Production hardening                               |
| --------- | ---------------------------------- | -------------------------------------------------- |
| Runtime   | Helm on a small managed cluster    | Private nodes, workload identity, external secrets |
| Auth      | One tenant, OIDC/SAML              | SCIM lifecycle, enforced SSO, least-privilege RBAC |
| State     | Encrypted PVC at `/lake`           | Backup/restore, per-tenant prefixes                |
| Evidence  | Read-only cloud/service identities | Customer IaC owns roles, grants, rotation          |

Runbook: [Shareable POC Hosting](SHAREABLE_POC_HOSTING.md),
[deploy/README.md](../deploy/README.md),
[Server Auth](SERVER_AUTH.md).

### Managed hosted

Managed hosted is the same TrustOps binary and chart — operated for you on
dedicated or isolated tenant infrastructure. This model is **not publicly
available** in the OSS release; operators enable commercial hosted features via
environment flags. See [COMMERCIAL_HOSTED.md](COMMERCIAL_HOSTED.md) for the
gated commercial features (invites, usage limits, SCIM 2.0, Stripe billing).

Evaluator flow: [Shareable Demo](SHAREABLE_DEMO.md).

## Feature parity lens (honest)

| Capability                                      | TrustOps v0.2.16                          |
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

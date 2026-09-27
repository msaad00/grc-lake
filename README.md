<p align="center">
  <img src="docs/images/trustops-capability-header.svg" alt="TrustOps — read-only cloud, identity, code and data sources; Common Control Framework and framework packs." width="100%">
</p>

<p align="center"><strong>Open, self-hosted GRC for cloud and AI.</strong></p>

<p align="center">
  <a href="https://pypi.org/project/trustops-security-data-lake/"><img src="https://img.shields.io/pypi/v/trustops-security-data-lake?color=2b7bba&label=PyPI" alt="PyPI version"></a>
  <a href="https://pypi.org/project/trustops-security-data-lake/"><img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11+"></a>
  <a href="https://github.com/msaad00/trustops-security-data-lake/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/msaad00/trustops-security-data-lake/ci.yml?branch=main&amp;label=CI" alt="CI status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License: Apache 2.0"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#frameworks-and-common-controls">Frameworks & CCF</a> ·
  <a href="#explore">Explore</a> ·
  <a href="#develop-and-verify">Develop & verify</a>
</p>

TrustOps collects security evidence, evaluates controls, tracks follow-up work,
and exports assessments for review.

- **Customer-owned evidence lake.** Evidence stays in storage you run; deploy
  TrustOps in your environment. Data access and egress depend on the connectors,
  sinks, and model integrations you configure.
- **Deterministic rules decide pass or fail.** Every result traces to evidence
  and the evaluated catalog; models may summarize or propose, never decide.
- **Headless by design.** Use the console for investigation and review, or the
  API, CLI, MCP server, and CI gates for automation.

## Quick start

**Try the console with fixture data.** Use Python 3.11+,
[uv](https://docs.astral.sh/uv/), and Node 22+:

```bash
git clone https://github.com/msaad00/trustops-security-data-lake.git
cd trustops-security-data-lake
uv sync --frozen --extra dev --extra server
make demo-local
```

Open [localhost:8787/console/dashboard/](http://127.0.0.1:8787/console/dashboard/).
The command builds the console, loads the golden fixture, migrates the local
database, and starts the server. This local demo disables authentication; use
[authenticated deployment](deploy/README.md) for a shared environment.

<details>
<summary><strong>Other setup paths</strong> — pip, CLI-only, and deployment</summary>

For a source install without uv:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,server]"
make web-install web-build
security-lakehouse fixtures load --company golden --out build/lakehouse --rebase-times
security-lakehouse db upgrade --lake build/lakehouse
security-lakehouse serve --lake build/lakehouse --server --allow-insecure-no-auth --port 8787
```

For the CLI and local lake only:

```bash
pip install trustops-security-data-lake
security-lakehouse fixtures load --company golden --out ./lake --rebase-times
security-lakehouse assessment status --lake ./lake
```

To give an agent the same lake over MCP (stdio):

```bash
pip install 'trustops-security-data-lake[mcp]'
TRUSTOPS_LAKE=./lake trustops-mcp
```

See [headless GRC](docs/HEADLESS_GRC.md) for remote-server mode and the MCP trust boundary.

[Docker, Helm, and production configuration](deploy/README.md) ·
[Server authentication](docs/SERVER_AUTH.md)

</details>

## How it works

| Step         | What you do                                          | What you get                                        |
| ------------ | ---------------------------------------------------- | --------------------------------------------------- |
| **Collect**  | Connect a source with read-only access.              | Evidence with source, freshness, and provenance.    |
| **Evaluate** | Apply deterministic control rules.                   | Results tied to evidence and the evaluated catalog. |
| **Resolve**  | Assign findings, track fixes, and review exceptions. | Ownership and a record of follow-up decisions.      |
| **Export**   | Freeze an assessment and share reports.              | Evidence and assessment history for reviewers.      |

The [Common Control Framework](docs/COMMON_CONTROL_FRAMEWORK.md) reuses safeguards
across framework mappings. A mapping does not itself establish compliance.
Models may summarize or propose actions; deterministic rules decide control results.

## Frameworks and common controls

<!-- BEGIN README CCF SUMMARY -->

**16 framework packs · 78 reusable safeguards · 21 control families · 2,021 catalogued requirements.**

991 requirements have safeguard mappings; **350 have reviewed mappings**. Catalog coverage and evaluated customer posture are separate measures.

Control families: Identity and access · Data protection · Detection · Audit logging · Change management · Configuration management · Secure development · Secure architecture · Vulnerability management · Third-party risk · Risk management · Availability and recovery · Incident response · Governance · People security · Physical security · Network security · System maintenance · Processing integrity · Privacy · AI governance.

<!-- END README CCF SUMMARY -->

<table>
<tr>
<td align="center"><img src="app/web/public/frameworks/badges/soc2.svg" width="38" alt="SOC 2"><br><strong>SOC 2</strong></td>
<td align="center"><img src="app/web/public/frameworks/badges/iso.svg" width="38" alt="ISO framework family"><br><strong>ISO 27001 · 27017 · 42001</strong></td>
<td align="center"><img src="app/web/public/frameworks/badges/nist-csf.svg" width="38" alt="NIST CSF"><br><strong>NIST CSF 2.0</strong></td>
<td align="center"><img src="app/web/public/frameworks/badges/nist-ai-rmf.svg" width="38" alt="NIST AI RMF"><br><strong>NIST AI RMF</strong></td>
</tr>
<tr>
<td align="center"><img src="app/web/public/frameworks/badges/cis.svg" width="38" alt="CIS"><br><strong>CIS Controls · CIS AWS</strong></td>
<td align="center"><img src="app/web/public/frameworks/badges/cmmc.svg" width="38" alt="CMMC"><br><strong>CMMC 2.0</strong></td>
<td align="center"><img src="app/web/public/frameworks/badges/eu-ai-act.svg" width="38" alt="European framework family"><br><strong>EU AI Act · GDPR</strong></td>
<td align="center"><strong>NIST 800-53 · NIST RMF<br>FedRAMP · HIPAA · PCI DSS</strong></td>
</tr>
</table>

Framework identities show catalog scope. A pack may be a limited mapping;
see the [coverage matrix](docs/FRAMEWORK_COVERAGE.md) for the exact boundary.
**NIST RMF (SP 800-37 Rev. 2) is catalogued but not yet mapped** to safeguards, and
the **PCI DSS v4.0.1 pack covers its 12 principal requirements**, not every
sub-requirement. **SOC 1 and ISO 27701 are planned**, with no catalogued controls yet.

| CCF layer              | What it represents                                                                                           |
| ---------------------- | ------------------------------------------------------------------------------------------------------------ |
| **Control families**   | Risk domains that organize reusable safeguards.                                                              |
| **Safeguards**         | Evidence requirements, ownership, review frequency, and executable evaluation rules.                         |
| **Framework mappings** | Links from safeguards to individual framework requirements, with proposed and reviewed status kept separate. |
| **Assessment results** | Pass, fail, stale, or not-evaluated outcomes from the collected evidence.                                    |

<details>
<summary><strong>Evaluation details and further reading</strong></summary>

One safeguard can serve several frameworks. Every required mapped safeguard must
pass for a requirement to pass; an unmapped requirement remains unmapped.
A reviewed mapping is not certification or proof that a customer's controls pass.

| Area                                                 | Read more                                                                                                  |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Safeguards and executable rules                      | [Common Control Framework](docs/COMMON_CONTROL_FRAMEWORK.md) · [Executable catalog](controls/catalog.json) |
| Framework mappings and coverage                      | [Framework coverage](docs/FRAMEWORK_COVERAGE.md)                                                           |
| Findings, reviews, exceptions, and audit preparation | [Product walkthrough](docs/PRODUCT_WALKTHROUGH.md) · [Audit readiness](docs/AUDIT_READINESS.md)            |
| Implemented, partial, and planned capabilities       | [Product status](docs/PRODUCT_SHAPE.md) · [Roadmap](ROADMAP.md)                                            |

Inspect the current safeguard catalog from the CLI:

```bash
security-lakehouse frameworks safeguards --format table
```

</details>

## Explore

<details open>
<summary><strong>01 · Product tour</strong> — posture, evidence, frameworks, and triage</summary>

The images show the bundled demo fixture, not live customer evidence.
The inline images follow your GitHub theme.

<p align="center">
  <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/trustops-demo-dashboard-dark.png"><img src="docs/images/trustops-demo-dashboard.png" alt="TrustOps overview: assessment score, control pass rate, and open findings" width="100%"></picture>
  <br><sub><strong>Overview</strong> — assessment score, control pass rate, open findings, and evidence to refresh, with framework posture and the highest-risk findings below.</sub>
</p>

<p align="center">
  <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/trustops-demo-frameworks-dark.png"><img src="docs/images/trustops-demo-frameworks.png" alt="Requirement coverage summary with catalogued, mapped, and reviewed counts above the framework roster" width="100%"></picture>
  <br><sub><strong>Frameworks</strong> — catalogued, mapped, and reviewed requirements are counted separately, then broken down per framework.</sub>
</p>

<p align="center">
  <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/trustops-demo-evidence-dark.png"><img src="docs/images/trustops-demo-evidence.png" alt="Evidence table with source, asset, mapped control, status, freshness against its SLA, and evidence reference" width="100%"></picture>
  <br><sub><strong>Evidence</strong> — each normalized record shows its source, mapped control, freshness against the source's SLA, and where the original lives.</sub>
</p>

<p align="center">
  <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/trustops-demo-graph-dark.png"><img src="docs/images/trustops-demo-graph.png" alt="Compliance graph focused on one evidence type, with the assets it was collected from highlighted" width="100%"></picture>
  <br><sub><strong>Graph</strong> — focus one evidence type and see the controls it proves and the assets it came from.</sub>
</p>

<p align="center">
  <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/trustops-demo-triage-dark.png"><img src="docs/images/trustops-demo-triage.png" alt="Finding triage drawer with asset, owner, suggested remediation, and triage fields" width="55%"></picture>
  <br><sub><strong>Triage</strong> — a finding with its asset and owner, suggested remediation steps, and state, assignee, and due date recorded in triage history.</sub>
</p>

[Full walkthrough](docs/PRODUCT_WALKTHROUGH.md) ·
[Connections](docs/images/trustops-demo-connectors.png) ·
[Findings](docs/images/trustops-demo-findings.png) ·
[Remediation](docs/images/trustops-demo-remediation.png) ·
[Audit room](docs/images/trustops-demo-audit-room.png) ·
[Workflows](docs/images/trustops-demo-workflows.png) ·
[Trust center](docs/images/trustops-demo-trust-center.png)

</details>

<details>
<summary><strong>02 · Connect sources</strong> — cloud, identity, code, and existing lakes</summary>

In the console, open **Connectors → choose a source → Discover → Test → Enable → Sync**.
No pre-existing data lake is required. For automation, use the
[headless setup playbook](docs/playbooks/HEADLESS_CONNECTOR_SETUP.md).

Sources include AWS, Azure, GCP, GitHub, GitLab, Okta, Microsoft Intune, BambooHR, Rippling, Workday, Snowflake, Databricks (preview), and ClickHouse.
Check the [connector catalog](docs/CONNECTORS.md) for each integration's scope and status.
A connector can also ship as a separately installed Python package that
registers its sync builder and catalog row through entry points; see
[Shipping a connector as a package](docs/ADDING_CONNECTORS.md#shipping-a-connector-as-a-package).

Cloud connectors use short-lived or workload identity credentials: AWS STS sessions,
Azure managed or federated identity, and GCP Application Default Credentials
(workload identity or the metadata server; a service-account key file also works).
GitHub reads a GitHub App installation token, which expires within an hour; you mint
and rotate it. Other SaaS connectors (Okta, GitLab, Jira, BambooHR, Rippling, Workday)
use scoped API tokens or an integration-user login. Connector settings keep a credential
reference (an environment variable name or mounted secret file), not the secret itself.

- **AWS** uses STS AssumeRole, one External ID per deployed role, short-lived session credentials, and read-only IAM posture APIs. Temporary credentials expire after each session; TrustOps stores no long-lived access keys. Scale rollout with CloudFormation StackSets or Terraform workspaces; Bulk account import is planned. See the [cloud setup guide](docs/LIVE_CLOUD_POC.md).
- **Azure** supports a customer-owned Entra application, managed identity, or federated workload identity with Reader scope.
- **Snowflake** uses a read-only service identity with a key-pair or OAuth token reference. TrustOps stores identifiers, not passwords or private-key contents. Snowflake is the existing security-data-lake path.

[AWS credential lifecycle diagram](docs/images/trustops-aws-sts-lifecycle.svg) ·
[Continuous ingestion](docs/CONTINUOUS_INGESTION.md)

</details>

<details>
<summary><strong>03 · Deployment and interoperability</strong> — local, cloud, and evidence storage</summary>

```text
Source → Raw evidence → Normalized facts → Control evaluation → Assessment
                                                ↓                  ↓
                                           Owned findings    Review / export
```

| Layer                   | Current boundary                                                                                                |
| ----------------------- | --------------------------------------------------------------------------------------------------------------- |
| Evidence and evaluation | Local JSONL, deterministic rules, and verified assessment generations.                                          |
| Local analytics         | SQLite mart; DuckDB is optional.                                                                                |
| Operational state       | Application database and local state for jobs, assignments, and reviews.                                        |
| External storage        | Snowflake, ClickHouse, and Databricks (preview) integrations; verify the configured deployment.                 |
| Portable evidence       | Optional [Parquet export](docs/PARQUET_EXPORT.md) of one verified generation; independently tested with DuckDB. |
| Open table catalogs     | Optional [Iceberg REST publication](docs/ICEBERG_REST.md); local Polaris and DuckDB snapshot reads tested.      |

Run locally with Python or Docker, or deploy the Helm chart in your own cloud.
The current assessment writer needs durable local POSIX storage and one writer
per lake. Snowflake, ClickHouse, and Databricks integrations are evidence backends;
they do not host the TrustOps application. Snowflake Native App packaging is planned;
the Databricks evidence reader is in preview (live-workspace verification pending).
See the [deployment guide](deploy/README.md).

[Architecture guide](docs/ARCHITECTURE.md) ·
[Architecture diagram](docs/images/trustops-assessment-architecture.svg) ·
[Assessment publication and failure contracts](docs/ASSESSMENT_GENERATIONS.md)

</details>

<details>
<summary><strong>04 · API, agents, and CI</strong> — use the same assessment engine headlessly</summary>

| Surface                                 | Purpose                                                          |
| --------------------------------------- | ---------------------------------------------------------------- |
| Console                                 | Browse posture, evidence, findings, and reviews.                 |
| [API](docs/api/AGENT_API.md)            | Versioned `/api/v1` access for integrations.                     |
| CLI                                     | Collect, evaluate, verify, export, and run the local server.     |
| [MCP](docs/HEADLESS_GRC.md)             | Read assessments and propose actions through governed tools.     |
| [CI](docs/playbooks/CI_POSTURE_GATE.md) | Apply posture and control-test thresholds to delivery workflows. |
| [OSCAL export](docs/OSCAL_EXPORT.md)    | NIST OSCAL component-definition and assessment-results JSON.     |

[TrustOps operator skill](agent-skills/trustops-operator/SKILL.md) ·
[Specialist skills](agent-skills/FRAMEWORK_SKILLS.md) ·
[Agent workflow catalog](docs/api/AGENT_SKILLS.md) ·
[Webhooks](docs/WEBHOOKS.md) ·
[AI bill of materials](docs/AIBOM.md)

</details>

## Develop and verify

<details>
<summary><strong>Checks, repository layout, and documentation</strong></summary>

```bash
make smoke       # backend, contracts, docs, brand, pipeline, API
make web-ci      # install, typecheck, production build
make security    # dependency audits and pre-commit checks
```

Regenerate fixture screenshots with `make demo-screenshots-full`.

| Directory                               | Contents                                           |
| --------------------------------------- | -------------------------------------------------- |
| `src/security_lakehouse/`               | Assessment engine, API, auth, connectors, and MCP. |
| `app/web/`                              | Next.js console.                                   |
| `controls/`, `frameworks/`, `mappings/` | Rules, framework catalogs, and mappings.           |
| `deploy/`                               | Deployment and infrastructure examples.            |
| `docs/`                                 | Product, architecture, operations, and API guides. |

[Validation and benchmark plan](docs/BENCHMARKS.md) ·
[Deployment](docs/DEPLOYMENT.md) · [Roadmap](ROADMAP.md) ·
[Third-party assets](docs/THIRD_PARTY_ASSETS.md)

</details>

[Apache-2.0 license](LICENSE).

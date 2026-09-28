# Product Shape & Parity Map

Honest capability and UX reality for TrustOps v0.2.x — not marketing parity, but
where the platform sits versus **mature managed GRC SaaS** and what open issues
close each gap fastest.

Related: [TRUSTOPS_85_PLAN.md](TRUSTOPS_85_PLAN.md) (self-hosted bar) ·
[PRODUCT_WALKTHROUGH.md](PRODUCT_WALKTHROUGH.md) (shipped vs planned) ·
[PILOT_ROADMAP.md](PILOT_ROADMAP.md) (phase tracker) ·
[AUDIT_READINESS.md](AUDIT_READINESS.md) (audit workflow checklist)

## TL;DR

| Dimension             | Mature managed GRC SaaS     | TrustOps today                                              |
| --------------------- | --------------------------- | ----------------------------------------------------------- |
| **Product shape**     | Polished multi-tenant SaaS  | Self-hostable platform + optional commercial hosted mode    |
| **Core GRC loop**     | Mature, turnkey             | Strong on controls, evidence, audit room, shares            |
| **UI/UX**             | Best-in-class consumer SaaS | Good foundation — Epic #96 largely shipped (~65–70% polish) |
| **Integrations**      | 100+ deep connectors        | 25 executable connectors, 7 in preview; narrower long tail  |
| **Agents / API / CI** | Add-ons, limited vs core    | **Differentiator** — MCP, harness, headless-first           |
| **Data ownership**    | Vendor-hosted evidence      | **Customer lake** — ingest into it or read an existing lake |

**Overall:** TrustOps is a credible **self-hosted / headless GRC platform** with
real audit-room depth. It works in two modes: read-only connectors ingest evidence
into a lake you own, or readers evaluate the Snowflake, ClickHouse, Databricks
(preview), Iceberg/Parquet (preview), or BigQuery (preview) lake you already run
([BRING_YOUR_OWN_LAKE.md](BRING_YOUR_OWN_LAKE.md)). HRIS, device, and personnel
coverage is partial (Intune, BambooHR, Rippling, Workday, plus Jamf, CrowdStrike
Falcon, and KnowBe4 in preview), so it is not yet a drop-in replacement for teams
that want fully managed compliance out of the box.

## Product shape (two models, one core)

```mermaid
flowchart TB
  subgraph core [Deterministic core]
    LAKE[Customer lake bronze/silver/gold]
    TESTS[Control tests + violations]
    SNAP[Snapshots + hash chain]
    AUDIT[Audit log + readiness]
  end

  subgraph surfaces [Surfaces]
    CON[Console 30 routes]
    API["/api/v1 + SDK"]
    MCP[MCP + CI gates]
    AGT[Agent harness]
  end

  subgraph deploy [Deployment]
    OSS[OSS local]
    SH[Self-hosted Helm]
    HOST[Commercial hosted mode]
  end

  LAKE --> TESTS --> SNAP --> AUDIT
  core --> surfaces
  deploy --> core
```

| Surface             | Primary user                | Value                                                  |
| ------------------- | --------------------------- | ------------------------------------------------------ |
| **Console**         | Security, GRC, auditors     | Connect sources, review posture, fix gaps, share trust |
| **API / CLI / MCP** | Engineers, CI, agents       | Sync, query, automate without the UI                   |
| **Agent harness**   | Optional AI or rules runner | Summarize gaps; approval-gated writes only             |
| **Hosted mode**     | Teams wanting a live URL    | Signup, invites, usage limits, SCIM, Stripe billing    |

The assessment engine stays **model-independent**. LLMs orchestrate around
redacted facts; the engine owns normalization, control evaluation, snapshots,
hashes, RBAC, idempotency, and audit logs.

## Core GRC loop maturity

```text
Connect → Sync → Evaluate → Remediate → Review → Share → Prove
   │         │        │           │          │        │       │
   │         │        │           │          │        │       └─ Snapshots, PDF, trust shares, audit log
   │         │        │           │          │        └─ Audit room, access reviews, auditor role
   │         │        │           │          └─ Evidence requests, tasks, workflow canvas
   │         │        │           └─ Violations queue, remediation, vendor risk (MVP)
   │         │        └─ Deterministic control tests, framework readiness
   │         └─ Connector probe/sync, freshness signals
   └─ AWS/Azure/GCP/GitHub/Okta connectors + existing-lake readers
```

| Loop stage          | Maturity    | Notes                                                                          |
| ------------------- | ----------- | ------------------------------------------------------------------------------ |
| Connect & sync      | **Strong**  | Executable runners for core cloud/IdP; existing-lake readers (some preview)    |
| Evaluate            | **Strong**  | Lake-backed tests, not connector pass/fail widgets only                        |
| Remediate           | **Good**    | Tasks, evidence requests, workflow canvas with approvals                       |
| Audit review        | **Good**    | Audit room, readiness API, access reviews, executive PDF                       |
| Share & prove       | **Good**    | Trust-center shares, snapshots, hash chain, auditor redaction                  |
| Personnel / devices | **Partial** | Intune, Jamf (preview), CrowdStrike (preview); HRIS records; KnowBe4 (preview) |
| Policy program      | **Good**    | Template library + employee attestation MVP shipped                            |
| SaaS polish         | **Good**    | Trust Home, audit room SSE, saved views, tags, drill-down                      |

## Console surface (30 routes)

| Route                                                                                      | Purpose                                           |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------- |
| `/console/dashboard/`                                                                      | Trust Command Center — posture, KPIs, audit strip |
| `/console/audit-room/`                                                                     | Audit score, gaps, workflow checklist             |
| `/console/controls/`                                                                       | Control workbench                                 |
| `/console/evidence/`                                                                       | Evidence room                                     |
| `/console/violations/`                                                                     | Finding queue                                     |
| `/console/remediation/`                                                                    | Tasks and evidence requests                       |
| `/console/frameworks/`                                                                     | Framework readiness                               |
| `/console/connectors/`                                                                     | Source linking + sync health                      |
| `/console/access-reviews/`                                                                 | Certification campaigns                           |
| `/console/policies/`                                                                       | Policy template library                           |
| `/console/vendor-risk/`                                                                    | Vendor questionnaires (MVP)                       |
| `/console/trust-center/`                                                                   | Share management                                  |
| `/console/audit-log/`                                                                      | Unified request audit                             |
| `/console/agents/`                                                                         | Agent harness runs                                |
| `/console/automation/`                                                                     | Workflow canvas                                   |
| `/console/graph/`                                                                          | Compliance graph workbench                        |
| `/console/insights/`                                                                       | Trends and metrics                                |
| `/console/auth/`                                                                           | API keys, users, invites                          |
| `/console/onboarding/`                                                                     | First-run wizard                                  |
| `/console/deploy/`                                                                         | OSS / self-hosted / hosted                        |
| `/console/demo/`                                                                           | Evaluator landing                                 |
| + login, signup, invite, pricing, POC, risks, crosswalk, AI governance, public trust token |

## Parity scorecard (honest — not for investors)

Rough comparison vs mature managed GRC SaaS on capability + UX reality:

| Area                       | vs managed SaaS | TrustOps today                                                    |
| -------------------------- | --------------- | ----------------------------------------------------------------- |
| Audit room + readiness     | Strong          | **Shipped** — live SSE, gaps, vendor/policy strips                |
| Evidence freshness SLA     | Strong          | **Shipped** — summary, escalate, audit panel                      |
| Vendor diligence + policy  | MVP parity      | **Shipped** — questionnaires + attestation rollups                |
| Saved views + tags         | Good            | **Shipped** — controls, violations, evidence + tag filter         |
| Framework drill-down       | Good            | **Shipped** — control → rule → evidence → source                  |
| Live SSE updates           | Good            | **Shipped** — posture + audit-readiness stream                    |
| Integrations long tail     | Behind          | 25 executable connectors (7 preview); add more as Python packages |
| HRIS / devices / personnel | Partial         | Intune, HRIS, Jamf/CrowdStrike/KnowBe4 preview; offboarding check |
| Billing / full SCIM        | Good            | SCIM 2.0 + Stripe billing shipped; live account/IdP runs pending  |
| Premium onboarding polish  | Behind          | Wizard shipped; polish incremental                                |

## Parity scorecard (detailed)

Rough comparison vs mature managed GRC SaaS on capability + UX reality:

| Area                        | vs mature SaaS | TrustOps strength                                                     |
| --------------------------- | -------------- | --------------------------------------------------------------------- |
| SOC 2 / ISO control library | ~85%           | 2,245 catalogued requirements, 94 safeguards, framework packs as code |
| Continuous monitoring       | ~75%           | Core cloud/IdP connectors runnable                                    |
| Auditor experience          | ~70%           | Trust shares, PDF, audit room trends; no marketplace                  |
| Personnel / devices / HR    | Partial        | Intune, HRIS records; Jamf, CrowdStrike, KnowBe4 in preview           |
| Policy program              | ~70%           | Templates + attestation MVP                                           |
| Vendor risk                 | ~65%           | Questionnaires + audit-room rollups                                   |
| Self-host / API / agents    | **~120%**      | Ahead — they don't lead here                                          |
| SaaS polish / onboarding    | ~65–70%        | #96 shipped; incremental polish remains                               |

## Where TrustOps matches well (shipped)

These are real surfaces — not roadmap slides:

- **Audit workflow (headless + UI)** — continuous control tests, audit readiness API,
  audit room, trust shares, auditor role redaction, access reviews, evidence
  requests → remediation, point-in-time snapshots, unified audit log, executive PDF
- **Framework depth** — 17 packs, including SOC 2, ISO 27001/27017/42001, NIST CSF 2.0,
  NIST 800-53, NIST RMF, NIST AI RMF, FedRAMP Moderate, CMMC 2.0, CIS, HIPAA, PCI DSS,
  GDPR, EU AI Act, and a limited ISO 27701:2025 pack
- **Identity & access** (PR [#345](https://github.com/msaad00/trustops-security-data-lake/pull/345)) —
  user/role admin, API-key → browser session, IdP group → role mapping, SCIM 2.0
  users and groups
- **Deploy transparency** — Helm, EKS terraform, `/console/deploy`, OSS positioning

## Where mature SaaS is still ahead

### 1. UI/UX polish ([#96](https://github.com/msaad00/trustops-security-data-lake/issues/96))

Managed GRC products feel like finished consumer apps: guided onboarding, empty
states, microcopy, notification center, mobile-friendly auditor flows, integrated
help.

TrustOps has dark mode, Trust Command Center, audit strip, workflow canvas,
connector drawers — but not the same visual refinement, marketing-grade empty
states, or zero-config wow on first login.

### 2. Integration long tail

Mature SaaS: HRIS, device MDM, ticketing, training — hundreds of pre-built checks.

TrustOps: strong AWS / Azure / GCP / Snowflake / GitHub / Okta paths with vendor
marks in-console; open connector catalog; read-only posture. Intune (MDM) and
BambooHR, Rippling, and Workday (HRIS) ship; Jamf, CrowdStrike Falcon, Kubernetes,
and KnowBe4 ship in preview. Personnel and device coverage is still partial;
remaining gaps include pen-test coordination and the long tail of pre-built SaaS
checks.

### 3. Compliance OS convenience

| Feature                   | Mature SaaS  | TrustOps                                                                 |
| ------------------------- | ------------ | ------------------------------------------------------------------------ |
| Policy employee sign-off  | Native       | **MVP shipped** — publish + acknowledgment tracking                      |
| Personnel tracking        | Native       | **HRIS records (BambooHR, Rippling, Workday)** + IdP offboarding check   |
| Auditor marketplace       | Yes          | BYO auditor + trust share                                                |
| Device inventory          | Integrations | **Intune** per-device compliance; Jamf and CrowdStrike in preview        |
| Billing / self-serve SaaS | Native       | Stripe billing + signup shipped; live Stripe verification pending (#610) |
| SCIM lifecycle            | Full         | Per-tenant tokens, users + groups, group → role map; live IdP pending    |

### 4. Visual analytics ([#18](https://github.com/msaad00/trustops-security-data-lake/issues/18))

Insights/timeseries, framework readiness trends, evidence freshness charts, and
remediation SLA heatmaps ship on `/insights` and in the audit room trends panel.
Rich topology/workflow viz ([#15](https://github.com/msaad00/trustops-security-data-lake/issues/15) timeline) remains the main gap vs managed GRC exec dashboards.

## Where TrustOps is ahead (differentiators)

Hard for classic GRC SaaS to match:

| Differentiator                | Why it matters                                                |
| ----------------------------- | ------------------------------------------------------------- |
| **Self-host + customer lake** | Evidence in bronze/silver/gold — not a vendor silo            |
| **Existing-lake mode**        | Read the Snowflake/ClickHouse/OCSF lake you already run       |
| **Headless-first**            | Same `/api/v1` for console, MCP, CI gates, agents             |
| **Agent harness**             | Governed runs, approval-gated writes, LangGraph orchestration |
| **Deterministic assessment**  | Control tests from lake pipeline, not widget pass/fail only   |
| **Framework packs as code**   | `frameworks sync-packs`, custom frameworks, crosswalk         |
| **Interoperable scale**       | Correlation IDs, idempotency, RBAC on every route             |

If the buyer cares about data residency, agents in the IDE, or CI-enforced posture,
TrustOps is stronger. If they want sign-up and pass SOC 2 in 90 days with zero
engineering, managed SaaS still wins on packaging.

## Tools & app surface today

| Layer       | TrustOps today                                                                                       |
| ----------- | ---------------------------------------------------------------------------------------------------- |
| **Console** | Full GRC shell: dashboard → audit room → controls → evidence → frameworks → connectors → remediation |
| **CLI**     | Pipeline, seed-dev, auth, frameworks sync, executive PDF, connector validate                         |
| **API**     | `/api/v1/*` — posture, controls, audit-readiness, audit-log, remediation, agents                     |
| **MCP**     | Posture, controls, violations, audit log, audit readiness, snapshots, workflows (expanding)          |
| **CI**      | GitHub Action posture gate                                                                           |

## Issue map — what closes the gap fastest

Issues ranked by impact on **turnkey core GRC loop + premium UX**. All of them
are closed on GitHub — read the Status column, not the issue state, for what is
actually delivered.

| Priority | Issue                                                                        | Closes                                       | Status                                       |
| -------- | ---------------------------------------------------------------------------- | -------------------------------------------- | -------------------------------------------- |
| **P0**   | [#96](https://github.com/msaad00/trustops-security-data-lake/issues/96) Epic | Premium GRC SaaS feel — biggest UX gap       | **Mostly shipped** (#89–#95, #91)            |
| **P0**   | [#14](https://github.com/msaad00/trustops-security-data-lake/issues/14)      | Source-linked framework/control expansion    | **Partial** (17 packs; SOC 1 planned)        |
| **P1**   | [#13](https://github.com/msaad00/trustops-security-data-lake/issues/13)      | Evidence freshness SLA + stale → remediation | **Shipped**                                  |
| **P1**   | [#15](https://github.com/msaad00/trustops-security-data-lake/issues/15)      | Audit snapshot room + reviewer trust center  | **Shipped** (trends + timeline)              |
| **P1**   | [#18](https://github.com/msaad00/trustops-security-data-lake/issues/18)      | Product-grade topology, trend, workflow viz  | **Partial** (framework/freshness/SLA charts) |
| **P1**   | [#22](https://github.com/msaad00/trustops-security-data-lake/issues/22)      | GitHub/GitLab repo governance connector      | **Shipped** (GitLab UI + governance sync)    |
| **P1**   | [#23](https://github.com/msaad00/trustops-security-data-lake/issues/23)      | Repository topology graph workbench          | **Shipped** (demo data + inspector)          |
| **P1**   | [#16](https://github.com/msaad00/trustops-security-data-lake/issues/16)      | Headless agent workbench + guarded skills    | Partial                                      |
| **Ship** | [#345](https://github.com/msaad00/trustops-security-data-lake/pull/345)      | Identity/admin parity for enterprise SSO     | **Shipped**                                  |

### Epic #96 breakdown (experience uplift)

| Sub-issue | Surface                    | Bar                                |
| --------- | -------------------------- | ---------------------------------- |
| #89       | Design system + Trust Home | **Shipped**                        |
| #90       | Workflow canvas            | **Shipped**                        |
| #91       | Framework drill-down       | **Shipped**                        |
| #92       | Continuous-eval layer      | **Shipped** (SSE)                  |
| #93       | Headless parity            | **Shipped** (MCP catalog expanded) |
| #94       | Tags + saved views         | **Shipped**                        |
| #95       | Metrics & insights         | **Shipped**                        |

## Recommended execution order

Stack PRs to maximize “feels turnkey” signal per unit of work:

```text
1. Merge #345 (identity/admin)           → enterprise SSO parity
2. Ship #13 (evidence freshness SLA)     → audit room automation loop
3. #15 + #18 (audit trends + viz)        → exec/auditor storytelling
4. #96 P0 (#89 Trust Home, #90 canvas)   → premium first impression
5. #22 + #23 (repo graph)                → code governance depth
6. #14 (framework expansion)             → control library breadth
7. P5 billing/SCIM full lifecycle        → hosted SaaS completeness
```

Each PR should pass the pre-push gate: pre-commit, ruff, compileall, pytest,
web typecheck/build, `gh pr checks`.

## Target: interoperable, secure, scale, turnkey

| Pillar               | Today                       | Turnkey target                        | Primary issues     |
| -------------------- | --------------------------- | ------------------------------------- | ------------------ |
| **Interoperable**    | Strong API/MCP/CI           | Full OpenAPI + MCP catalog parity     | #93, #16           |
| **Secure**           | Auth/RBAC/audit spine       | SCIM lifecycle, signed cookies always | #345, P5           |
| **Scale**            | Audit-scale synth + HA docs | Multi-replica read paths proven       | ops runbooks       |
| **Turnkey core GRC** | Audit room + shares strong  | Freshness SLA, trends, premium UX     | #13, #15, #18, #96 |
| **Premium UI/UX**    | ~65–70%                     | ~80–85% managed-SaaS bar              | polish, #22/#23    |

See [TRUSTOPS_85_PLAN.md](TRUSTOPS_85_PLAN.md) for the self-hosted 85% exit
criteria and [ROADMAP.md](../ROADMAP.md) for shipped vs remaining milestones.

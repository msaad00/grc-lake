# TrustOps 85% Plan

This document defines the next product bar: not a managed SaaS clone, but a
self-hosted OSS trust platform that a team can deploy, open by URL, connect to
their cloud or evidence lake, and use without a terminal after bootstrap.

## 85% Definition

TrustOps reaches 85% when a team can complete this path in one short session:

1. Deploy the API, console, scheduler, and persistent lake with Helm.
2. Sign in through OIDC.
3. Connect Snowflake and at least one cloud account with read-only service
   identity.
4. Discover scope from granted objects instead of typing every table name.
5. Run first sync and see evidence, posture, findings, freshness, and hashes.
6. Create a trust-center share.
7. Run an optional agent review that proposes actions but cannot change
   deterministic verdicts.

## Scorecard

| Pillar                       | Now    | 85% target | What closes the gap                                      |
| ---------------------------- | ------ | ---------- | -------------------------------------------------------- |
| Deterministic assessment     | 80-85% | 90%        | More control packs, explainability, regression fixtures  |
| Live AWS/Azure/Snowflake     | 70-75% | 85%        | UI scope discovery, secret-manager wiring, run health    |
| Self-hosted deployment       | 65-70% | 85%        | Opinionated Helm values, OIDC, scheduler, POC runbook    |
| Human product UX             | 55-60% | 80-85%     | First-run wizard, fewer pages, richer dashboards         |
| Workflow automation          | 45-55% | 75-80%     | Templates, run inspector, approvals, retries, logs       |
| Headless and agent runtime   | 75-80% | 85%        | Persisted runs, MCP/API parity, model budgets, evals     |
| Framework and evidence depth | 45-55% | 75-80%     | SOC 2/ISO/HIPAA/GDPR/NIST/AI RMF mapping expansion       |
| Production operations        | 55-65% | 80-85%     | Backup, restore, observability, rate limits, HA guidance |

## Next Five Product PRs

1. **AWS + Snowflake POC package**: renderable Helm values, exact bootstrap
   runbook, and readiness gate for a shareable URL.
2. **First-run onboarding**: create org, verify auth, connect first source,
   run first sync, and issue first trust share from one guided flow.
3. **Connector secret and scope UX**: discover objects after auth, show
   selectable scopes, persist only references and fingerprints, and block
   enablement until probe succeeds.
4. **Workflow operating loop**: template library, run history, approvals,
   retries, egress guardrails, and action logs tied to findings.
5. **Framework packs and evidence coverage**: expand mapped controls, evidence
   requirements, owners, freshness windows, and “how to fix” guidance.

## Product Shape

TrustOps is three surfaces over one deterministic core — see the full parity
map, issue tracker, and execution order in [PRODUCT_SHAPE.md](PRODUCT_SHAPE.md).

| Surface       | Primary user                | Value                                                  |
| ------------- | --------------------------- | ------------------------------------------------------ |
| Console       | Security, GRC, auditors     | Connect sources, review posture, fix gaps, share trust |
| API/CLI/MCP   | Engineers, CI, agents       | Sync, query, automate, and integrate without the UI    |
| Agent harness | Optional AI or rules runner | Summarize gaps and propose approval-gated next actions |
| Hosted mode   | Teams wanting a live URL    | Signup, invites, usage limits, SCIM, Stripe billing    |

**Turnkey GRC target:** interoperable (API/MCP), secure (auth/RBAC/audit),
scale (HA + audit-scale), and premium UX (Epic #96) — without sacrificing the
customer-owned lake differentiator.

The core assessment engine remains model-independent. LLMs and LangGraph are
optional orchestration around already-redacted facts; the engine owns evidence
normalization, control evaluation, snapshots, hashes, RBAC, idempotency, and
audit logs.

## Non-Goals For 85%

- No billing or commercial SaaS tenant marketplace.
- No claim of certification, audit opinion, or framework completeness.
- No write/remediation permissions by default.
- No long-lived passwords or PATs in connector setup.
- No model-generated control verdicts.

## 85% Exit Criteria

- A fresh AWS-hosted deployment can be installed from the chart and example
  values.
- A user can connect Snowflake and AWS from the console after service bootstrap.
- At least one scheduled sync updates posture without a shell command.
- Dashboard, evidence, connector health, workflows, and trust share are all
  populated with non-empty live data.
- Agent runs are visible and show budget, mode, input hash, proposed actions,
  and guardrail evaluation.
- Docs explain exactly what is deterministic, what is advisory, and what a
  customer must own.

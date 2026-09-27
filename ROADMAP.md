# TrustOps Roadmap

Status as of v0.2.16. Open epics come first; the shipped priority lists below are kept
as the delivery record. Track work in GitHub issues.

## Open epics

Remaining gaps, each scoped in its own issue:

| Epic                                                                      | Area       | Gap it closes                                                                                                        |
| ------------------------------------------------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------- |
| [#611](https://github.com/msaad00/trustops-security-data-lake/issues/611) | Frameworks | ISO 27701:2025 limited pack (10/78 verified); SOC 1 stays planned (no official catalog)                              |
| [#608](https://github.com/msaad00/trustops-security-data-lake/issues/608) | Connectors | CIS Azure/GCP benchmarks, ISO 27001 clauses 4–10 (HRIS/MDM shipped)                                                  |
| [#609](https://github.com/msaad00/trustops-security-data-lake/issues/609) | Connectors | Databricks evidence reader shipped as preview; live-workspace verification against the `docs/HERO_DATA_LAKES.md` bar |
| [#610](https://github.com/msaad00/trustops-security-data-lake/issues/610) | Platform   | P5 billing/SCIM shipped; live Stripe + IdP verification pending                                                      |

#611 is the cheapest to start: `docs/FRAMEWORK_EXPANSION_PLAN.md` already carries the
rules and the contributor checklist, so it is execution rather than design.

## P0 — Shareable hosted demo (managed GRC-class entry)

- [x] Demo kit API (`demo_kit` on POC readiness) with copyable links
- [x] `/console/demo/` evaluator landing
- [x] Account-linking deep links (`/connectors/?connect=`)
- [x] First-run onboarding wizard (`/console/onboarding/`)
- [x] Hosted invite flow with email/SCIM (commercial SaaS)
- [x] One-click AWS/Azure/GCP cloud linking (OAuth-style / Terraform reader)

## P1 — Product depth

- [x] SOC 2 common criteria full pack (33 controls; with the TSC extensions below the SOC 2 pack now holds 61 requirements)
- [x] NIST AI RMF 1.0 full pack (72 subcategories)
- [x] FedRAMP Moderate foundation pack (287 NIST SP 800-53 Rev 5 controls)
- [x] CIS AWS Foundations v3.0 pack (62 recommendations)
- [x] ISO/IEC 27001:2022 and ISO/IEC 42001:2023 Annex A packs
- [x] `frameworks sync-packs` CLI + custom framework examples
- [x] Framework packs (SOC 2 Availability/Confidentiality/PI/Privacy TSC extensions)
- [x] Unified golden fixture (all 37 controls on dashboard)
- [x] Audit-scale synthetic data + streaming IO + capped violation rollups (`docs/AUDIT_SCALE.md`)
- [x] Executive PDF export from snapshots
- [x] Vendor risk questionnaire MVP
- [x] Policy template library MVP (bundled templates + adopt/publish)

## P2 — Agent-native moat

- [x] LangGraph for SOC triage harness
- [x] GitHub Action posture gate
- [x] MCP cookbook for evidence requests + approvals
- [x] Workflow operating loop (run inspector, dry-run preview, approval gate, retries)

## P3 — Operations

- [x] Backup/restore runbook for `/lake` + app DB
- [x] OpenTelemetry dashboards for connector sync
- [x] Helm guard: block insecure auth without explicit override
- [x] HA guidance (read replicas + single writer)

## P4 — Documentation & design

- [x] Shareable demo guide
- [x] Markdown image CI validation
- [x] OSS / self-hosted / hosted positioning (`docs/DEPLOYMENT.md`)
- [x] Console `/deploy` deployment summary page
- [x] Connector + auth flow diagrams (mermaid, SVG, console strips)
- [x] Commit demo PNG screenshots (`make demo-screenshots`)
- [x] Unified data model single-page diagram
- [x] Dark mode

## P5 — Commercial hosted

- [x] Commercial pricing API scaffold (gated env; not in OSS console)
- [x] Self-serve signup and tenant lifecycle
- [x] Usage limits enforcement scaffold
- [x] SCIM 2.0 provisioning (per-tenant tokens, users, groups → roles)
- [x] Billing (Stripe Checkout + portal, webhook-driven plan state, past-due grace → read-only)

## P6 — Headless GRC

- [x] Headless architecture guide (`docs/HEADLESS_GRC.md`)
- [x] Unified v1 audit-log with stable event IDs (#339)
- [x] Audit readiness API and audit room (#340)
- [x] MCP/API resource catalog parity for platform endpoints (access reviews, policies, vendor diligence, insights)

## P7 — Turnkey GRC loop + premium UX

Every issue below is **closed on GitHub**; the links are kept as the design record.
Closed does not mean complete — #14 (framework expansion) and #16 (agent workbench)
are still rated _Partial_. The live status column, not this table, is the honest
signal: [PRODUCT_SHAPE.md](docs/PRODUCT_SHAPE.md)

| Issue                                                                                                                                             | Closes                                                                       |
| ------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| [#96](https://github.com/msaad00/trustops-security-data-lake/issues/96)                                                                           | Premium GRC SaaS UX — design system, Trust Home, workflow canvas, drill-down |
| [#13](https://github.com/msaad00/trustops-security-data-lake/issues/13)                                                                           | Evidence freshness SLA + stale evidence → remediation                        |
| [#15](https://github.com/msaad00/trustops-security-data-lake/issues/15) / [#18](https://github.com/msaad00/trustops-security-data-lake/issues/18) | Audit room trends + product-grade visualizations                             |
| [#22](https://github.com/msaad00/trustops-security-data-lake/issues/22) / [#23](https://github.com/msaad00/trustops-security-data-lake/issues/23) | GitHub/GitLab governance + repo graph workbench                              |
| [#14](https://github.com/msaad00/trustops-security-data-lake/issues/14)                                                                           | Source-linked framework/control expansion                                    |
| [#345](https://github.com/msaad00/trustops-security-data-lake/pull/345)                                                                           | Identity/admin parity (users, API-key session, IdP roles, SCIM scaffold)     |

See [TRUSTOPS_85_PLAN.md](docs/TRUSTOPS_85_PLAN.md) for the 85% self-hosted bar.

# TrustOps Roadmap

Source status for v0.2.23 release preparation. Remaining gaps come first; the
shipped priority lists below are kept as the delivery record. Track work in GitHub issues.

## Remaining gaps

The linked epics are closed on GitHub; each row names what is still left.

| Epic                                                                      | Area           | What remains                                                                                                                                                          |
| ------------------------------------------------------------------------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [#611](https://github.com/msaad00/trustops-security-data-lake/issues/611) | Frameworks     | ISO 27701:2025 is a limited pack (10 of 78 Annex A controls); SOC 1 stays planned (no official catalog); NIST 800-171 Rev 3, NIS2, and DORA are new and proposed-only |
| [#608](https://github.com/msaad00/trustops-security-data-lake/issues/608) | Connectors     | CIS Azure/GCP benchmarks, ISO 27001 clauses 4–10; live-tenant runs for the Jamf, CrowdStrike, Kubernetes, KnowBe4 previews                                            |
| [#609](https://github.com/msaad00/trustops-security-data-lake/issues/609) | Existing lakes | Databricks, Iceberg/Parquet, and BigQuery readers are preview and lake mappings are experimental; live verification pending                                           |
| [#610](https://github.com/msaad00/trustops-security-data-lake/issues/610) | Platform       | P5 billing/SCIM shipped; live Stripe + IdP verification pending                                                                                                       |
| —                                                                         | Mapping review | 1,348 proposed safeguard mappings (including all NIST RMF, ISO 27701, NIST 800-171 Rev 3, NIS2, and DORA mappings) await human review before they are attestable      |

## Prepared for 0.2.23

- Bound braces recursion in console build tooling and check dependency regressions in CI.
- Keep legacy trust shares revocable after tenant-directory migration without crossing tenant boundaries.
- Cover snapshot payload/ledger predecessor checks with mutation-verified regression tests.

## Shipped for 0.2.22

- Correct Helm scheduler startup and validate signing configuration against the server.
- Guard explicit no-auth configuration and document staged EKS bootstrap prerequisites.

## Shipped for 0.2.21

- Consistent control/CCF verdicts, current-evidence checks, and coverage-aware readiness displays.
- Persistent human-review authority, tenant-scoped operations, and explicit interruption recovery.
- Verified generation and snapshot recovery, source-bound catalogs, and frozen offline reports.
- Bounded read projections, streaming integrity checks, and explicit operational archival.

See the [changelog](CHANGELOG.md) and [release gates](docs/RELEASE_READINESS.md)
for scope and the distinction between source qualification and publication.

## Shipped for 0.2.20

- [x] NIST SP 800-171 Rev 3, NIS2, and DORA framework packs from pinned official sources, with proposed mappings ([#776](https://github.com/msaad00/trustops-security-data-lake/pull/776))
- [x] AI governance life-cycle safeguards and a category layer over the 21 control families ([#774](https://github.com/msaad00/trustops-security-data-lake/pull/774))
- [x] Docker Compose quickstart, 5-minute tutorial, CI gate guide, contributor guide, and security policy ([#772](https://github.com/msaad00/trustops-security-data-lake/pull/772))
- [x] Hosted cloud-link forms for tenant-owned Azure and GCP identities ([#775](https://github.com/msaad00/trustops-security-data-lake/pull/775)); posture gate fails closed ([#773](https://github.com/msaad00/trustops-security-data-lake/pull/773))

## Shipped for 0.2.19

- [x] Org mapping review: approve, reject, or request changes with an append-only, attributable decision log ([#750](https://github.com/msaad00/trustops-security-data-lake/pull/750))
- [x] Tenant-scoped connector and workflow secrets and delegated cloud credentials in hosted mode ([#755](https://github.com/msaad00/trustops-security-data-lake/pull/755), [#761](https://github.com/msaad00/trustops-security-data-lake/pull/761))
- [x] Live-cloud probe parity, partial GCP collection, and actionable connector errors ([#749](https://github.com/msaad00/trustops-security-data-lake/pull/749))

## Shipped for 0.2.18

- [x] Bring your own lake: lake mapping spec (experimental) for the Snowflake, Databricks, and ClickHouse readers, OCSF presets for Amazon Security Lake, and preview Iceberg/Parquet and BigQuery readers ([#738](https://github.com/msaad00/trustops-security-data-lake/pull/738))
- [x] Jamf, CrowdStrike Falcon, Kubernetes, and KnowBe4 evidence connectors, in preview ([#736](https://github.com/msaad00/trustops-security-data-lake/pull/736))
- [x] Deeper control families and NIST RMF (SP 800-37 Rev. 2) mapped: 46 of 47 tasks, proposed ([#735](https://github.com/msaad00/trustops-security-data-lake/pull/735), [#739](https://github.com/msaad00/trustops-security-data-lake/pull/739))
- [x] Wider proposed mapping coverage for ISO 27001, NIST CSF 2.0, ISO 27017, NIST AI RMF, FedRAMP Moderate, and GDPR ([#739](https://github.com/msaad00/trustops-security-data-lake/pull/739))
- [x] ISO/IEC 27701:2025 limited privacy pack ([#741](https://github.com/msaad00/trustops-security-data-lake/pull/741))
- [x] Outbound HTTP pinned to validated IPs, shared SAML replay cache, stable demo data ([#740](https://github.com/msaad00/trustops-security-data-lake/pull/740))

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

- [x] Commercial pricing API (gated env; not in OSS console)
- [x] Self-serve signup and tenant lifecycle
- [x] Usage limits enforcement (users, pending invites, API keys)
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

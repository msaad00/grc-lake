# Wave 3 tracker (#96)

**Goal:** Managed GRC-grade **trust command center** on the same `/api/v1` — KPI tiles, framework readiness rings, control-test scoreboards, and connector health strips. Headless/agent paths stay primary; this wave polishes the human peer surface.

## Inspiration (managed GRC patterns)

| Pattern                   | Reference UX                     | TrustOps target                                       |
| ------------------------- | -------------------------------- | ----------------------------------------------------- |
| Framework readiness rings | SOC 2 / ISO progress donuts      | `FrameworkMark`, `ComplianceOverview` on `/dashboard` |
| Control monitoring table  | Failed/passed badges, filters    | `ControlTestTable`, `/controls`                       |
| KPI strip                 | MTTR, failing tests, connections | `KpiTile` row on trust command center                 |
| Connect health            | Account linking, sync status     | `ConnectorAccountLinkingStrip`, ingestion strip       |
| AI remediation card       | Summary + fix steps              | `AgentDecisionCard` (agents harness)                  |

Neutral copy only — no competitor trademarks in product UI.

## PR streams (max 2 in flight)

| Stream                    | Branch                             | Focus                                                   | Status |
| ------------------------- | ---------------------------------- | ------------------------------------------------------- | ------ |
| **O — Framework visuals** | `cursor/framework-visuals-ux-d259` | Dashboard KPI tiles, framework marks, compliance graphs | 🟡 PR  |
| **P — Connector health**  | `cursor/connectors-ux-fixes-d259`  | Sync health, account linking UX, probe gating polish    | 🟡 PR  |

## Acceptance

- [ ] `/dashboard` shows framework readiness scoreboard + KPI row (pass/fail/error counts)
- [ ] Framework badges use shared `framework-visuals.ts` tokens (no one-off colors)
- [ ] Connectors page surfaces account-linking strip and sync health without lake jargon
- [ ] E2E smoke covers dashboard + connectors happy path
- [ ] `docs/VISUAL_SYSTEM.md` documents KPI + framework mark usage

## Does not duplicate

| Issue   | Scope                                        |
| ------- | -------------------------------------------- |
| **#18** | Topology/workflow graphs — separate viz epic |
| **#15** | Audit snapshot room / public trust center    |
| **#14** | New framework pack YAML — backend            |

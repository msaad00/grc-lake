# Delivery tracker

**Single source of truth:** GitHub issue **#474** (Wave 2, complete). Wave 3 human UX rolls up under **#96**.

Last updated: **2026-07-13** (Wave 2 merged #482–#488; maintainer closeout pending)

## Wave 2 — complete (#474)

| Stream                      | Branch                             | Issue | Status                   |
| --------------------------- | ---------------------------------- | ----- | ------------------------ |
| **I — Headless connectors** | `cursor/headless-connectors-d259`  | #475  | ✅ #482 — **close #475** |
| **J — Agent contracts**     | `cursor/agent-contracts-d259`      | #476  | ✅ #481 — **close #476** |
| **K — CI posture gates**    | `cursor/ci-posture-gates-d259`     | #477  | ✅ #484 — **close #477** |
| **L — Agent harness UI**    | `cursor/agent-harness-d259`        | #478  | ✅ #485 — **close #478** |
| **M — Human connect UX**    | `cursor/human-connect-ux-d259`     | #479  | ✅ #486 — **close #479** |
| **N — Console copy**        | `cursor/console-human-polish-d259` | #480  | ✅ #487 — **close #480** |
| **Brand — TrustOps mark**   | `cursor/trustops-mark-d259`        | —     | ✅ #488                  |

**Positioning:** headless/agents/CI first; human console second. Default connect path is **agentless read-only API** — no customer SDL required ([CONNECTORS.md](../../docs/CONNECTORS.md), [HEADLESS_CONNECTOR_SETUP.md](../../docs/playbooks/HEADLESS_CONNECTOR_SETUP.md)).

## Wave 3 — managed GRC console (#96)

Managed GRC-style trust command center and connector health. See [issues/WAVE3_TRACKER.md](../../docs/issues/WAVE3_TRACKER.md).

| Stream                      | Branch                             | Issue | Status     |
| --------------------------- | ---------------------------------- | ----- | ---------- |
| **O — Framework visuals**   | `cursor/framework-visuals-ux-d259` | #96   | 🟡 PR next |
| **P — Connector health UX** | `cursor/connectors-ux-fixes-d259`  | #96   | 🟡 PR next |

## Wave 1 — complete (#449 streams A–H)

All Wave 1 streams merged (#447–#473). See [ISSUE_CONSOLIDATION.md](ISSUE_CONSOLIDATION.md) for issue→PR mapping.

## Maintainer: close shipped issues

Wave 2 is merged on `main`. Run once with a token that has `issues:write`:

```bash
DRY_RUN=1 ./tools/close_shipped_issues.sh   # preview
./tools/close_shipped_issues.sh              # closes #449, #416–#433, #475–#480, #16
```

Cloud agent tokens get **403** on `closeIssue` — repo owner must run locally.

## Open issues — keep vs close

| Keep open | Role                                                   |
| --------- | ------------------------------------------------------ |
| **#474**  | Wave 2 epic (complete — update or close after runbook) |
| **#96**   | Human UX epic — Wave 3 streams O–P                     |
| **#14**   | Framework expansion (ongoing packs)                    |
| **#18**   | Topology/workflow viz gaps                             |
| **#22**   | Org-level repo governance                              |
| **#15**   | Exec viz / trust-center polish                         |
| **#411**  | Backend audit roadmap rollup                           |
| **#434**  | Session hashing — verify #458                          |
| **#436**  | Deferred P3 AIBOM                                      |

| Close (shipped / duplicate)                                      | Shipped by   |
| ---------------------------------------------------------------- | ------------ |
| **#475–#480**                                                    | #482–#487    |
| **#16**                                                          | #485         |
| #449, #417, #416, #423, #424, #433, #422, #428, #429, #431, #432 | Wave 1 batch |

## CI before merge

`make ci`, `make web-ci`, `tools/run_e2e_console.sh`, `pre-commit run --all-files`.

# Wave 2 tracker (#474) — complete

**Positioning:** headless/agents/CI first; human console (managed GRC SaaS tier) second.

```text
Primary:   agents · CI · MCP · CLI  →  assessment store  →  audit trail
Secondary: console (reviewers, auditors, GRC leads)
Default connect: agentless read-only API — no customer SDL required
```

## PR streams

| Stream                      | Branch                             | Issue | Status         |
| --------------------------- | ---------------------------------- | ----- | -------------- |
| **I — Headless connectors** | `cursor/headless-connectors-d259`  | #475  | ✅ #482 merged |
| **J — Agent contracts**     | `cursor/agent-contracts-d259`      | #476  | ✅ #481 merged |
| **K — CI posture gates**    | `cursor/ci-posture-gates-d259`     | #477  | ✅ #484 merged |
| **L — Agent harness**       | `cursor/agent-harness-d259`        | #478  | ✅ #485 merged |
| **M — Human connect**       | `cursor/human-connect-ux-d259`     | #479  | ✅ #486 merged |
| **N — Console copy**        | `cursor/console-human-polish-d259` | #480  | ✅ #487 merged |
| **Brand**                   | `cursor/trustops-mark-d259`        | —     | ✅ #488 merged |

## Acceptance — all complete

- [x] #475 — curl/CLI/MCP lifecycle documented + tested (#482)
- [x] #476 — AGENT_SKILLS.md + openapi + resource-catalog committed (#481)
- [x] #477 — CI gate template fails on control regression (#484)
- [x] #478 — #16 AC (skills page, fixture mode, approvals) (#485)
- [x] #479 — onboarding wizard for agentless connect (#486)
- [x] #480 — source-sync copy, empty states, notifications (#487)

## Maintainer closeout

```bash
./tools/close_shipped_issues.sh
```

Closes child issues **#475–#480** and harness parent **#16**.

## Next wave

Human GRC console polish (managed GRC-grade trust command center) → [WAVE3_TRACKER.md](WAVE3_TRACKER.md) under epic **#96**.

# Issue closeout runbook

Drain duplicate and shipped issues so **#474** / **#96** are the only active trackers. Run after each merge batch.

## Wave 2 complete (2026-07-13)

All streams **#475–#480** merged (#482–#487). Brand otter mark in **#488**.

**Maintainer — run once now:**

```bash
DRY_RUN=1 ./tools/close_shipped_issues.sh   # preview
./tools/close_shipped_issues.sh              # all batches (idempotent)
```

Cloud agent tokens cannot close issues (`403` on `closeIssue` / `addComment`). Repo owner must run locally.

## Batch 2 — after #482 + #481 (2026-07-12)

| Close            | Shipped by             |
| ---------------- | ---------------------- |
| **#475**         | #482                   |
| **#476**         | #481                   |
| #449             | Wave 1 complete → #474 |
| #417             | duplicate #22 + #23    |
| #416, #423, #424 | #450                   |
| #433             | #453                   |
| #422, #428, #429 | #451                   |
| #431, #432       | #456                   |

Already closed on GitHub: #418, #430, #93.

## Batch 3 — after #484–#487 (2026-07-13)

| Close    | Shipped by   | PR               |
| -------- | ------------ | ---------------- |
| **#477** | CI gate      | #484             |
| **#478** | Harness UI   | #485             |
| **#479** | Onboarding   | #486             |
| **#480** | Console copy | #487             |
| **#16**  | Harness AC   | #485 (with #478) |

## After closeout

- **Keep open:** #474 (mark complete), #96 (Wave 3), #411, #22, #14, #18, #15, #434, #436
- **Wave 3 work:** [issues/WAVE3_TRACKER.md](../../docs/issues/WAVE3_TRACKER.md)

See [DELIVERY_TRACKER.md](DELIVERY_TRACKER.md) and [ISSUE_CONSOLIDATION.md](ISSUE_CONSOLIDATION.md).

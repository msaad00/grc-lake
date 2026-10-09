#!/usr/bin/env bash
# Close shipped/duplicate GitHub issues with a standard comment.
# Requires: gh auth with issues:write (repo owner or maintainer token).
# Dry run: DRY_RUN=1 ./tools/close_shipped_issues.sh
# Skip batches already run: CLOSE_BATCH=3 ./tools/close_shipped_issues.sh

set -euo pipefail

DRY_RUN="${DRY_RUN:-0}"
CLOSE_BATCH="${CLOSE_BATCH:-all}"

close_issue() {
  local num="$1"
  local comment="$2"
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "[dry-run] would close #$num — $comment"
    return 0
  fi
  if gh issue view "$num" --json state -q .state 2>/dev/null | grep -qx CLOSED; then
    echo "[skip] #$num already closed"
    return 0
  fi
  gh issue close "$num" --comment "$comment"
  echo "[closed] #$num"
}

run_batch2() {
  echo "Wave 2 shipped (close after #482 / #481 merge)"
  close_issue 475 "Shipped in #482 — headless connector playbook, lifecycle test, source-sync console copy."
  close_issue 476 "Shipped in #481 — AGENT_SKILLS.md, openapi.v1.json, resource-catalog.v1.json, agents page."

  echo ""
  echo "Wave 1 backlog drain (shipped on main)"
  close_issue 449 "Wave 1 complete. Tracker superseded by #474 (Wave 2)."
  close_issue 417 "Duplicate scope — track org-level work in #22 and repo graph in #23 (shipped #452)."
  close_issue 416 "Shipped in #450 — ESLint runs in CI for app/web."
  close_issue 423 "Shipped in #450 — LICENSE added."
  close_issue 424 "Shipped in #450 — Python 3.12 aligned across CI and Docker."
  close_issue 433 "Shipped in #453 — HRIS personnel audit playbook."
  close_issue 422 "Shipped in #451 — ai-governance on SSE platform stream."
  close_issue 428 "Shipped in #451 — dedicated /ai-governance console route."
  close_issue 429 "Shipped in #451 — AgentRunDrawer. Further harness polish tracked in #478."
  close_issue 431 "Shipped in #456 — accessibility pass (skip link, aria-live, table semantics)."
  close_issue 432 "Shipped in #456 — command palette and breadcrumbs expanded."
}

run_batch3() {
  echo ""
  echo "Wave 2 batch 3 (close after #484–#487 merge on main)"
  close_issue 477 "Shipped in #484 — CI posture gate fails on control regression; see docs/playbooks/CI_POSTURE_GATE.md."
  close_issue 478 "Shipped in #485 — agent harness workbench: fixture mode, approval UX, E2E."
  close_issue 479 "Shipped in #486 — human connect onboarding wizard (?onboarding=1 guided flow)."
  close_issue 480 "Shipped in #487 — console agent-first copy, source-sync empty states, notifications."
  close_issue 16 "Shipped in #485 — agent harness workbench AC complete (#478)."
}

case "$CLOSE_BATCH" in
  all)
    run_batch2
    run_batch3
    ;;
  2)
    run_batch2
    ;;
  3)
    run_batch3
    ;;
  *)
    echo "Unknown CLOSE_BATCH=$CLOSE_BATCH (use all, 2, or 3)" >&2
    exit 1
    ;;
esac

echo ""
echo "Done. Remaining open work: #474 epic, #96 Wave 3, epics #411 #22 #14 #18 #15 #434 #436."

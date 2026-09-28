/** Human-facing console copy — agentless read-only connect path. */

export const CONNECT_FLOW = {
  cycle: "Connect → test → enable → sync → evaluate",
  agentless: "Read-only API access — no customer evidence lake build required.",
  test: "Test connection",
  enable: "Enable source",
  sync: "Sync evidence",
  emptySources:
    "No sources connected yet. Start with a read-only cloud or IdP link.",
  emptyEvidence:
    "Connect and sync a source, or point at an existing evidence lake.",
  emptyActivity:
    "No activity yet. Connect a source, sync evidence, or triage a finding.",
} as const;

/** Canonical console route names: the rail, command palette, and page H1s
 * all read from here so a destination has exactly one name. */
export const ROUTE_LABELS = {
  "/dashboard": "Overview",
  "/insights": "Insights",
  "/connectors": "Connections",
  "/evidence": "Evidence",
  "/access-reviews": "Access reviews",
  "/vendor-risk": "Vendor risk",
  "/controls": "Controls",
  "/frameworks": "Frameworks",
  "/mapping-review": "Mapping review",
  "/violations": "Findings",
  "/risks": "Risk register",
  "/policies": "Policies",
  "/ai-governance": "AI governance",
  "/crosswalk": "Crosswalk",
  "/graph": "Graph",
  "/remediation": "Remediation",
  "/automation": "Workflows",
  "/agents": "Agents",
  "/audit-room": "Audit room",
  "/trust-center": "Trust center",
  "/audit-log": "Audit log",
  "/auth": "Access & keys",
  "/deploy": "Deploy",
  "/onboarding": "Onboarding",
  "/demo": "Demo",
  "/poc": "Launch",
} as const;

export type RouteHref = keyof typeof ROUTE_LABELS;

/** Review states of one safeguard-to-requirement mapping. Labels match the
 * server's REVIEW_STATE_LABELS (safeguards.py) and the CLI help. */
export const MAPPING_REVIEW_GLOSSARY = {
  maintainer_reviewed: {
    label: "Maintainer-reviewed",
    definition: "Confirmed by the catalog maintainers and shipped as reviewed.",
  },
  org_reviewed: {
    label: "Org-reviewed",
    definition:
      "Approved by a reviewer in your organization, with a rationale.",
  },
  proposed: {
    label: "Proposed",
    definition: "Suggested mapping that no one has reviewed; not attestable.",
  },
  needs_changes: {
    label: "Needs changes",
    definition: "Sent back by your organization; stays in the review queue.",
  },
  rejected: {
    label: "Rejected",
    definition: "Rejected by your organization; excluded from coverage.",
  },
} as const;

export type MappingReviewGlossaryKey = keyof typeof MAPPING_REVIEW_GLOSSARY;

/** Two scores, two names: keep them apart on every page. */
export const SCORE_COPY = {
  assessment: {
    label: "Assessment score",
    definition:
      "Risk-weighted control results across assessed frameworks, less stale evidence.",
  },
  auditReadiness: {
    label: "Audit readiness",
    definition:
      "Assessment score, control test pass rate, and frameworks ready, combined.",
  },
} as const;

/** One explanation of the Preview stage, shared by badges and legends. */
export const PREVIEW_COPY = {
  label: "Preview",
  definition:
    "Implemented and fixture-tested; not yet verified against a live tenant.",
} as const;

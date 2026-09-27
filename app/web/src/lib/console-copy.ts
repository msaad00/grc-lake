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

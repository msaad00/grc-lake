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

/** One headline score, everything else a named sub-indicator. Each name
 * says what it measures and over which scope; keep them apart on every page. */
export const SCORE_COPY = {
  assessment: {
    label: "Assessment score",
    scope: "Headline score for the whole workspace",
    definition:
      "Percentage of observed controls with fresh passing evidence, across every evaluated framework. Missing, unknown, stale, and failing controls receive no credit; catalog coverage is shown separately.",
  },
  framework: {
    label: "Framework score",
    definition:
      "The assessment score computed over one framework's observed controls only.",
  },
  auditReadiness: {
    label: "Audit readiness index",
    definition:
      "Audit-prep sub-indicator, not a second assessment score: a weighted blend of the assessment score (4 parts), control test pass rate (3 parts), and the share of evaluated frameworks that are ready (2 parts).",
  },
  frameworksReady: {
    label: "Evaluated frameworks ready",
    definition:
      "Frameworks in the current evaluation that score 100 with enough of their catalog assessed. Framework packs that have no evaluated controls are not counted here.",
  },
  aiGovernance: {
    label: "AI governance indicator",
    definition:
      "AI-only sub-indicator: 55% AI evidence signals (model inventory, lineage, model cards, agent activity) plus 45% fresh pass rate over observed AI framework controls. Not the assessment score.",
  },
} as const;

/** One explanation of the Preview stage, shared by badges and legends. */
export const PREVIEW_COPY = {
  label: "Preview",
  definition:
    "Implemented and fixture-tested; not yet verified against a live tenant.",
} as const;

/**
 * Hosted cloud linking: the server never collects with its own cloud identity,
 * so each tenant names its own Azure app registration or GCP service account.
 */
export const HOSTED_CLOUD_LINK_COPY = {
  azureSummary:
    "Grant Reader to an app registration in your Entra tenant, then enter its IDs and the environment variable that holds its credential. Hosted GRC Lake never reads Azure as its own identity.",
  gcpSummary:
    "Create a read-only service account in your project and let the GRC Lake identity impersonate it (Service Account Token Creator), then enter the project and service account.",
  refRule:
    "Enter the variable name only, never the secret. The operator sets its value on the server.",
  azureSecretKinds: {
    client_secret_ref: {
      label: "Client secret",
      suffix: "AZURE_CLIENT_SECRET",
    },
    client_certificate_ref: {
      label: "Certificate (PEM)",
      suffix: "AZURE_CLIENT_CERT",
    },
    federated_token_file_ref: {
      label: "Federated token file",
      suffix: "AZURE_TOKEN_FILE",
    },
  },
} as const;

export type AzureSecretKind =
  keyof typeof HOSTED_CLOUD_LINK_COPY.azureSecretKinds;

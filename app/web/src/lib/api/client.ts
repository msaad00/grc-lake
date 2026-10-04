import { isAuditorMode } from "@/lib/state/auditor";
import type {
  BillingStatus,
  CreatedScimToken,
  ScimToken,
  AccessReviewCampaign,
  AccessReviewCoverage,
  AccessReviewDecision,
  AccessReviewItem,
  AccessReviewSeedResult,
  AccessReviewStatus,
  ActionSpec,
  AgentRun,
  Assessment,
  AssetRisk,
  AuthMethods,
  AuthApiKey,
  AuthUser,
  AuthWhoami,
  CreatedAuthApiKey,
  CreateAuthKeyPayload,
  CreateInvitePayload,
  TenantInvite,
  UpdateAuthUserPayload,
  ControlExceptionItem,
  EvidenceRequestItem,
  PostureMetricPoint,
  PlatformUsage,
  PoamItem,
  PoamSyncResult,
  ProbePayload,
  RemediationInsights,
  RemediationTask,
  Risk,
  AuditLogEntry,
  ComplianceGraph,
  ConfigurePayload,
  ConnectorRun,
  ConnectorView,
  ControlPosture,
  ControlRemediation,
  ControlTest,
  ControlArticleMapping,
  DiscoverPayload,
  Crosswalk,
  CreateAgentRunPayload,
  EvidenceFreshness,
  EvidenceFreshnessSummary,
  EscalateFreshnessResult,
  EntityTag,
  FrameworkReadiness,
  FrameworkReadinessTrends,
  FrameworkCoveragePayload,
  FrameworkDetail,
  CcfCoverage,
  CcfAssessment,
  FrameworkEquivalence,
  FrameworkView,
  ReviewedCrosswalk,
  Health,
  IngestionStatus,
  LakeEvalRun,
  NormalizedEvent,
  PocReadiness,
  PlatformJobsFeed,
  AuditReadiness,
  AiGovernance,
  AiInventoryItem,
  PolicyDocument,
  PolicyAcknowledgment,
  PolicyAttestationSummary,
  PolicyTemplate,
  PolicyTemplateSummary,
  PolicyCoverage,
  SavedView,
  SlaHeatmap,
  SnapshotResponse,
  SnapshotSummary,
  SnapshotDetail,
  CloudLinkSession,
  CloudLinkCompleteResult,
  Tag,
  SprsReport,
  TrackingEvent,
  TriagePayload,
  TrustShare,
  VerifyResult,
  VendorAssessment,
  VendorAssessmentStatus,
  VendorQuestionnaireTemplate,
  VendorQuestionnaireTemplateSummary,
  MappingReviewDecision,
  MappingReviewDecisionRequest,
  MappingReviewItem,
  MappingReviewQueuePage,
  MappingReviewQueueParams,
  MappingReviewSummary,
  Violation,
  Workflow,
  WorkflowEdge,
  WorkflowNode,
  WorkflowRun,
} from "./types";

const BASE = "/api";
const LOGIN_PATH = "/console/login";

function redirectToLogin(): void {
  if (typeof window === "undefined") return;
  const pathname = window.location.pathname.replace(/\/$/, "");
  if (pathname === LOGIN_PATH) return;
  const returnTo = `${window.location.pathname}${window.location.search}${window.location.hash}`;
  // Authentication loss must discard cached data from the previous session.
  // eslint-disable-next-line @next/next/no-location-assign-relative-destination -- Full document reload is intentional at the auth boundary.
  window.location.assign(
    `${LOGIN_PATH}?return_to=${encodeURIComponent(returnTo)}`,
  );
}

function headers(): Record<string, string> {
  const out: Record<string, string> = { "content-type": "application/json" };
  if (isAuditorMode()) out["X-Trust-Role"] = "auditor";
  return out;
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    cache: "no-store",
    credentials: "same-origin",
    headers: headers(),
  });
  if (res.status === 401) redirectToLogin();
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return (await res.json()) as T;
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    credentials: "same-origin",
    headers: headers(),
    body: JSON.stringify(body ?? {}),
  });
  if (res.status === 401) redirectToLogin();
  if (!res.ok) {
    const payload = await res.json().catch(() => ({}));
    const reason =
      (payload as { reason?: string }).reason ??
      (payload as { errors?: Array<{ detail?: string }> }).errors?.[0]
        ?.detail ??
      `${res.status}`;
    throw new Error(`${path} -> ${reason}`);
  }
  return (await res.json()) as T;
}

// MAX_PAGE_LIMIT in security_lakehouse/db/base.py. Asking for more is not
// clamped — the server rejects it as a bad request.
const V1_MAX_PAGE = 500;

type V1Page<T> = {
  data: T[];
  meta: { count: number; returned: number; limit: number };
};

/**
 * Read every row of a paginated `/v1` collection.
 *
 * A single GET returns at most one page, and the server's default page is 100
 * rows — so calling a `/v1` list endpoint without paging silently returns a
 * prefix of the collection and reports success. On an estate with 1,448
 * violations, one unpaged read yields 100 of them.
 */
async function getAllV1<T>(
  path: string,
): Promise<{ items: T[]; count: number }> {
  // A caller-supplied limit is a deliberate bound — "the ten most recent eval
  // runs" — not an oversight. Honour it and read exactly one page, so this
  // helper is safe to apply to every paginated collection.
  if (/[?&]limit=/.test(path)) {
    const page = await get<V1Page<T>>(path);
    return { items: page.data, count: page.meta?.count ?? page.data.length };
  }

  const items: T[] = [];
  let offset = 0;
  let count = 0;

  for (;;) {
    const sep = path.includes("?") ? "&" : "?";
    const page = await get<V1Page<T>>(
      `${path}${sep}limit=${V1_MAX_PAGE}&offset=${offset}`,
    );
    count = page.meta?.count ?? page.data.length;
    items.push(...page.data);

    // A short page is the last one. The empty-page guard keeps a server that
    // reports a count it will not serve from spinning here forever.
    if (page.data.length < V1_MAX_PAGE || items.length >= count) break;
    offset += page.data.length;
  }

  return { items, count };
}

async function mutate<T>(
  path: string,
  method: "PATCH" | "DELETE",
  body?: unknown,
): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method,
    credentials: "same-origin",
    headers: headers(),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401) redirectToLogin();
  if (!res.ok) {
    const payload = await res.json().catch(() => ({}));
    const reason =
      (payload as { reason?: string }).reason ??
      (payload as { errors?: Array<{ detail?: string }> }).errors?.[0]
        ?.detail ??
      `${res.status}`;
    throw new Error(`${path} -> ${reason}`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  health: () => get<{ data: Health }>("/v1/healthz").then((body) => body.data),
  authMethods: () =>
    get<{ data: AuthMethods }>("/v1/auth/methods").then((body) => body.data),
  authWhoami: () =>
    get<{ data: AuthWhoami }>("/v1/auth/whoami").then((body) => body.data),
  authKeys: () =>
    get<{ data: AuthApiKey[]; meta?: { count?: number } }>(
      "/v1/auth/keys",
    ).then((body) => body.data),
  createAuthKey: (payload: CreateAuthKeyPayload) =>
    post<{ data: CreatedAuthApiKey }>("/v1/auth/keys", payload).then(
      (body) => body.data,
    ),
  revokeAuthKey: (keyId: string) =>
    mutate<{ data: { id: string; revoked: boolean } }>(
      `/v1/auth/keys/${encodeURIComponent(keyId)}`,
      "DELETE",
    ).then((body) => body.data),
  authUsers: () =>
    get<{ data: AuthUser[]; meta?: { count?: number } }>("/v1/auth/users").then(
      (body) => body.data,
    ),
  updateAuthUser: (userId: string, payload: UpdateAuthUserPayload) =>
    mutate<{ data: AuthUser }>(
      `/v1/auth/users/${encodeURIComponent(userId)}`,
      "PATCH",
      payload,
    ).then((body) => body.data),
  sessionFromKey: (apiKey: string) =>
    post<{ data: AuthWhoami }>("/v1/auth/session-from-key", {
      api_key: apiKey,
    }).then((body) => body.data),
  invites: () =>
    get<{ data: TenantInvite[]; meta?: { count?: number } }>(
      "/v1/invites",
    ).then((body) => body.data),
  createInvite: (payload: CreateInvitePayload) =>
    post<{ data: TenantInvite }>("/v1/invites", payload).then(
      (body) => body.data,
    ),
  scimTokens: () =>
    get<{ data: ScimToken[] }>("/v1/platform/scim/tokens").then(
      (body) => body.data,
    ),
  createScimToken: (name: string) =>
    post<{ data: CreatedScimToken }>("/v1/platform/scim/tokens", {
      name,
    }).then((body) => body.data),
  revokeScimToken: (tokenId: string) =>
    mutate<void>(
      `/v1/platform/scim/tokens/${encodeURIComponent(tokenId)}`,
      "DELETE",
    ),
  billing: () =>
    get<{ data: BillingStatus }>("/v1/billing").then((body) => body.data),
  billingCheckout: (plan: string) =>
    post<{ data: { url: string } }>("/v1/billing/checkout", { plan }).then(
      (body) => body.data,
    ),
  billingPortal: () =>
    post<{ data: { url: string } }>("/v1/billing/portal", {}).then(
      (body) => body.data,
    ),
  acceptInvite: (payload: { token: string; display_name?: string }) =>
    post<{ data: { email?: string; tenant_slug?: string } }>(
      "/v1/invites/accept",
      payload,
    ).then((body) => body.data),
  authLogout: () =>
    post<{ data: { ok: boolean } }>("/v1/auth/logout", {}).then(
      (body) => body.data,
    ),
  authFreshnessSummary: () =>
    get<{ data: EvidenceFreshnessSummary }>(
      "/v1/evidence/freshness/summary",
    ).then((body) => body.data),
  escalateStaleEvidence: (limit = 10) =>
    post<{ data: EscalateFreshnessResult }>("/v1/evidence/freshness/escalate", {
      limit,
      statuses: ["stale", "expired", "missing"],
    }).then((body) => body.data),
  pocReadiness: () =>
    get<{ data: PocReadiness }>("/v1/platform/poc-readiness").then(
      (body) => body.data,
    ),
  auditReadiness: () =>
    get<{ data: AuditReadiness }>("/v1/platform/audit-readiness").then(
      (body) => body.data,
    ),
  aiGovernance: () =>
    get<{ data: AiGovernance }>("/v1/platform/ai-governance").then(
      (body) => body.data,
    ),
  aiInventory: (query = "") =>
    getAllV1<AiInventoryItem>(
      `/v1/platform/ai-governance/inventory${query}`,
    ).then((r) => r.items),
  remediationTasks: (query = "") =>
    getAllV1<RemediationTask>(`/v1/remediation/tasks${query}`).then(
      (r) => r.items,
    ),
  createRemediationTask: (
    payload: Partial<RemediationTask> & { title: string },
  ) =>
    post<{ data: RemediationTask }>("/v1/remediation/tasks", payload).then(
      (b) => b.data,
    ),
  updateRemediationTask: (id: string, payload: Record<string, unknown>) =>
    mutate<{ data: RemediationTask }>(
      `/v1/remediation/tasks/${encodeURIComponent(id)}`,
      "PATCH",
      payload,
    ).then((b) => b.data),
  evidenceRequests: () =>
    getAllV1<EvidenceRequestItem>("/v1/remediation/evidence-requests").then(
      (r) => r.items,
    ),
  createEvidenceRequest: (payload: {
    control_id: string;
    requested_from?: string;
    note?: string;
  }) =>
    post<{ data: EvidenceRequestItem }>(
      "/v1/remediation/evidence-requests",
      payload,
    ).then((b) => b.data),
  setEvidenceRequestStatus: (id: string, status: string) =>
    mutate<{ data: EvidenceRequestItem }>(
      `/v1/remediation/evidence-requests/${encodeURIComponent(id)}`,
      "PATCH",
      { status },
    ).then((b) => b.data),
  controlExceptions: () =>
    getAllV1<ControlExceptionItem>("/v1/remediation/exceptions").then(
      (r) => r.items,
    ),
  createControlException: (payload: {
    control_id: string;
    reason?: string;
    expires_at?: string | null;
  }) =>
    post<{ data: ControlExceptionItem }>(
      "/v1/remediation/exceptions",
      payload,
    ).then((b) => b.data),
  approveControlException: (id: string) =>
    post<{ data: ControlExceptionItem }>(
      `/v1/remediation/exceptions/${encodeURIComponent(id)}/approve`,
      {},
    ).then((b) => b.data),
  verifyRemediationTask: (id: string, resolution_note: string) =>
    post<{ data: RemediationTask }>(
      `/v1/remediation/tasks/${encodeURIComponent(id)}/verify`,
      { resolution_note },
    ).then((b) => b.data),
  revokeControlException: (id: string) =>
    mutate<{ data: ControlExceptionItem }>(
      `/v1/remediation/exceptions/${encodeURIComponent(id)}`,
      "DELETE",
    ).then((b) => b.data),
  risks: (query = "") =>
    getAllV1<Risk>(`/v1/risks${query}`).then((r) => r.items),
  createRisk: (payload: Partial<Risk> & { title: string }) =>
    post<{ data: Risk }>("/v1/risks", payload).then((b) => b.data),
  updateRisk: (id: string, payload: Record<string, unknown>) =>
    mutate<{ data: Risk }>(
      `/v1/risks/${encodeURIComponent(id)}`,
      "PATCH",
      payload,
    ).then((b) => b.data),
  deleteRisk: (id: string) =>
    mutate<{ data: { id: string; deleted: boolean } }>(
      `/v1/risks/${encodeURIComponent(id)}`,
      "DELETE",
    ).then((b) => b.data),
  posture: () =>
    get<{ data: Assessment }>("/v1/posture/current").then((b) => b.data),
  ingestionStatus: () =>
    get<{ data: IngestionStatus }>("/v1/ingestion/status").then(
      (body) => body.data,
    ),
  platformJobs: (query = "") =>
    get<{ data: PlatformJobsFeed }>(`/v1/platform/jobs${query}`).then(
      (body) => body.data,
    ),
  controls: () =>
    getAllV1<ControlPosture>("/v1/controls").then((r) => ({
      controls: r.items,
    })),
  controlTests: () =>
    getAllV1<ControlTest>("/v1/control-tests").then(({ items, count }) => ({
      count,
      control_tests: items,
    })),
  violations: () =>
    getAllV1<Violation>("/v1/violations").then(({ items, count }) => ({
      count,
      violations: items,
    })),
  evidence: () =>
    getAllV1<NormalizedEvent>("/v1/evidence").then(({ items, count }) => ({
      count,
      evidence: items,
    })),
  evidenceFreshness: (query = "") =>
    getAllV1<EvidenceFreshness>(`/v1/evidence/freshness${query}`).then(
      (r) => r.items,
    ),
  assets: () =>
    getAllV1<AssetRisk>("/v1/assets").then((r) => ({ assets: r.items })),
  createSnapshot: (reason: string) =>
    post<{ data: SnapshotResponse }>("/v1/snapshots", { reason }).then(
      (b) => b.data,
    ),
  listSnapshots: () =>
    getAllV1<SnapshotSummary>("/v1/snapshots").then(({ items, count }) => ({
      count,
      snapshots: items,
    })),
  getSnapshotDetail: (snapshotId: string) =>
    get<{ data: SnapshotDetail }>(
      `/v1/snapshots/${encodeURIComponent(snapshotId)}`,
    ).then((b) => b.data),
  getTracking: (violationId: string) =>
    get<{
      data: {
        violation_id: string;
        current_state: string;
        events: TrackingEvent[];
      };
    }>(`/v1/violations/${encodeURIComponent(violationId)}/tracking`).then(
      (b) => b.data,
    ),
  triage: (violationId: string, payload: TriagePayload) =>
    post<{ data: TrackingEvent }>(
      `/v1/violations/${encodeURIComponent(violationId)}/triage`,
      payload,
    ).then((b) => ({ event: b.data })),
  verifyEvidence: (eventId: string) =>
    post<{ data: VerifyResult }>(
      `/v1/evidence/${encodeURIComponent(eventId)}/verify`,
      {},
    ).then((b) => b.data),
  listConnectors: () =>
    getAllV1<ConnectorView>("/v1/connectors").then((r) => ({
      count: r.count,
      connectors: r.items,
    })),
  configureConnector: (id: string, payload: ConfigurePayload) =>
    post<{ data: Record<string, unknown> }>(
      `/v1/connectors/${encodeURIComponent(id)}/configure`,
      payload,
    ).then((body) => ({ event: body.data })),
  probeConnector: (id: string, payload: ProbePayload = {}) =>
    post<{ data: ConnectorRun }>(
      `/v1/connectors/${encodeURIComponent(id)}/probe`,
      payload,
    ).then((body) => ({ run: body.data })),
  syncConnector: (
    id: string,
    payload: { actor?: string; materialize?: boolean } = {},
  ) =>
    post<{
      data: {
        connector_id: string;
        result: string;
        evidence_count: number | null;
        materialized: boolean;
        run: ConnectorRun;
      };
    }>(`/v1/connectors/${encodeURIComponent(id)}/sync`, payload).then(
      (body) => body.data,
    ),
  runLakeEval: (payload: { actor?: string } = {}) =>
    post<{
      data: {
        result: string;
        mode: string;
        duration_ms: number;
        error: string | null;
        strategy: Record<string, unknown>;
      };
    }>("/v1/ingestion/eval", payload).then((body) => body.data),
  listEvalRuns: (limit = 10) =>
    get<{ data: LakeEvalRun[] }>(
      `/v1/ingestion/eval/runs?limit=${encodeURIComponent(String(limit))}`,
    ).then((body) => body.data),
  runSchedulerTick: () =>
    post<{
      data: {
        fired: Array<Record<string, unknown>>;
        count: number;
      };
    }>("/v1/scheduler/tick", {}).then((body) => body.data),
  discoverConnector: (id: string, payload: DiscoverPayload = {}) =>
    post<{ data: ConnectorRun }>(
      `/v1/connectors/${encodeURIComponent(id)}/discover`,
      payload,
    ).then((body) => ({ run: body.data })),
  startCloudLink: (
    id: string,
    payload: { public_url?: string; tenant_id?: string } = {},
  ) =>
    post<{ data: CloudLinkSession }>(
      `/v1/connectors/${encodeURIComponent(id)}/link/start`,
      payload,
    ).then((body) => body.data),
  completeCloudLink: (
    id: string,
    payload: {
      session_id: string;
      role_arn?: string;
      subscription_id?: string;
      project_id?: string;
      delegation?: Record<string, string>;
    },
  ) =>
    post<{ data: CloudLinkCompleteResult }>(
      `/v1/connectors/${encodeURIComponent(id)}/link/complete`,
      payload,
    ).then((body) => body.data),
  connectorRuns: (id: string) =>
    get<{ data: ConnectorRun[]; meta: { connector_id: string } }>(
      `/v1/connectors/${encodeURIComponent(id)}/runs`,
    ).then((body) => ({
      connector_id: body.meta.connector_id,
      runs: body.data,
    })),
  listFrameworks: () =>
    getAllV1<FrameworkView>("/v1/frameworks").then(({ items, count }) => ({
      count,
      frameworks: items,
    })),
  mappingReviewQueue: (params: MappingReviewQueueParams) => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== "") query.set(key, String(value));
    }
    return get<{ data: MappingReviewItem[]; meta: { count: number } }>(
      `/v1/mapping-reviews/queue?${query.toString()}`,
    ).then((body): MappingReviewQueuePage => ({
      items: body.data,
      count: body.meta?.count ?? body.data.length,
    }));
  },
  mappingReviewSummary: () =>
    get<{ data: MappingReviewSummary }>("/v1/mapping-reviews/summary").then(
      (body) => body.data,
    ),
  mappingReviewHistory: (safeguardId: string, controlId: string) =>
    get<{ data: MappingReviewDecision[] }>(
      `/v1/mapping-reviews/decisions?safeguard_id=${encodeURIComponent(safeguardId)}&control_id=${encodeURIComponent(controlId)}&limit=1000`,
    ).then((body) => body.data),
  recordMappingReview: (payload: MappingReviewDecisionRequest) =>
    post<{ data: MappingReviewDecision[]; meta: { recorded: number } }>(
      "/v1/mapping-reviews/decisions",
      payload,
    ).then((body) => body.data),
  frameworkCoverage: () =>
    get<{ data: FrameworkCoveragePayload }>("/v1/frameworks/coverage").then(
      (body) => body.data,
    ),
  frameworkDetail: (id: string) =>
    get<{ data: FrameworkDetail }>(
      `/v1/frameworks/${encodeURIComponent(id)}/detail`,
    ).then((b) => b.data),
  listWorkflows: () =>
    getAllV1<Workflow>("/v1/workflows").then(({ items, count }) => ({
      count,
      workflows: items,
    })),
  getWorkflow: (id: string) =>
    get<{ data: Workflow }>(`/v1/workflows/${encodeURIComponent(id)}`).then(
      (b) => b.data,
    ),
  workflowRuns: (id: string) =>
    get<{ data: WorkflowRun[]; meta: { workflow_id: string } }>(
      `/v1/workflows/${encodeURIComponent(id)}/runs`,
    ).then((b) => ({ workflow_id: b.meta.workflow_id, runs: b.data })),
  workflowRun: (runId: string) =>
    get<{ data: WorkflowRun }>(
      `/v1/workflows/runs/${encodeURIComponent(runId)}`,
    ).then((b) => ({ run: b.data })),
  actionCatalog: () =>
    getAllV1<ActionSpec>("/v1/workflows/actions").then((r) => ({
      actions: r.items,
    })),
  saveWorkflow: (payload: {
    workflow_id?: string;
    name: string;
    description?: string;
    nodes: WorkflowNode[];
    edges: WorkflowEdge[];
  }) =>
    post<{ data: Workflow }>("/v1/workflows", payload).then((b) => ({
      workflow: b.data,
    })),
  runWorkflow: (id: string, payload: { dry_run?: boolean } = {}) =>
    post<{ data: WorkflowRun }>(
      `/v1/workflows/${encodeURIComponent(id)}/run`,
      payload,
    ).then((b) => ({ run: b.data })),
  retryWorkflowRun: (runId: string) =>
    post<{ data: WorkflowRun }>(
      `/v1/workflows/runs/${encodeURIComponent(runId)}/retry`,
      {},
    ).then((b) => ({ run: b.data })),
  approveWorkflowRun: (runId: string, note = "") =>
    post<{ data: WorkflowRun }>(
      `/v1/workflows/runs/${encodeURIComponent(runId)}/approve`,
      { note },
    ).then((b) => ({ run: b.data })),
  rejectWorkflowRun: (runId: string, note = "") =>
    post<{ data: WorkflowRun }>(
      `/v1/workflows/runs/${encodeURIComponent(runId)}/reject`,
      { note },
    ).then((b) => ({ run: b.data })),
  testAction: (node_type: string, params: Record<string, unknown>) =>
    post<{ data: Record<string, unknown> }>("/v1/workflows/actions/run", {
      node_type,
      params,
    }).then((b) => ({ output: b.data })),
  listTrustShares: () =>
    getAllV1<TrustShare>("/v1/trust-shares").then(({ items, count }) => ({
      count,
      shares: items,
    })),
  createTrustShare: (payload: {
    role: "auditor";
    scope?: "posture_full" | "posture_framework";
    framework_id?: string | null;
    sensitivity_ceiling?: string;
    expires_in_hours: number;
  }) =>
    post<{ data: TrustShare }>("/v1/trust-shares", payload).then((b) => ({
      share: b.data,
    })),
  revokeTrustShare: (share_id: string) =>
    post<{ data: TrustShare }>(
      `/v1/trust-shares/${encodeURIComponent(share_id)}/revoke`,
      {},
    ).then((b) => ({ share: b.data })),
  graph: () => get<{ data: ComplianceGraph }>("/v1/graph").then((b) => b.data),
  repoGraph: () =>
    get<{ data: ComplianceGraph }>("/v1/repo-graph").then((b) => b.data),
  readiness: () =>
    getAllV1<FrameworkReadiness>("/v1/readiness").then(({ items, count }) => ({
      count,
      frameworks: items,
    })),
  crosswalk: () =>
    get<{ data: Crosswalk }>("/v1/crosswalk").then((b) => b.data),
  reviewedCrosswalk: () =>
    get<{ data: ReviewedCrosswalk }>("/v1/crosswalk/reviewed").then(
      (b) => b.data,
    ),
  ccfAssessment: () =>
    get<{ data: CcfAssessment }>("/v1/ccf/assessment").then((b) => b.data),
  ccfCoverage: () =>
    get<{ data: CcfCoverage }>("/v1/ccf/coverage").then((b) => b.data),
  frameworkEquivalence: () =>
    get<{ data: FrameworkEquivalence }>("/v1/mappings/equivalence").then(
      (b) => b.data,
    ),
  mappings: () =>
    getAllV1<ControlArticleMapping>("/v1/mappings").then(
      ({ items, count }) => ({
        count,
        mappings: items,
      }),
    ),
  auditLog: (
    opts: {
      category?: string;
      actor?: string;
      include_requests?: boolean;
      limit?: number;
    } = {},
  ): Promise<{ count: number; entries: AuditLogEntry[] }> => {
    const qs = new URLSearchParams();
    if (opts.category) qs.set("category", opts.category);
    if (opts.actor) qs.set("actor", opts.actor);
    if (opts.include_requests !== undefined)
      qs.set("include_requests", String(opts.include_requests));
    if (opts.limit !== undefined) qs.set("limit", String(opts.limit));
    const tail = qs.toString();
    return getAllV1<AuditLogEntry>(
      `/v1/audit-log${tail ? `?${tail}` : ""}`,
    ).then((r) => ({
      count: r.count,
      entries: r.items,
    }));
  },

  // --- Tags + saved views ---
  listTags: () => get<{ data: Tag[] }>("/v1/tags").then((b) => b.data),
  createTag: (payload: { name: string; color?: string }) =>
    post<{ data: Tag }>("/v1/tags", payload).then((b) => b.data),
  deleteTag: (tagId: string) =>
    mutate<{ data: { id: string; deleted: boolean } }>(
      `/v1/tags/${encodeURIComponent(tagId)}`,
      "DELETE",
    ).then((b) => b.data),
  attachTag: (payload: {
    tag_id: string;
    entity_type: string;
    entity_id: string;
  }) =>
    post<{ data: EntityTag }>("/v1/tags/attach", payload).then((b) => b.data),
  detachTag: (payload: {
    tag_id: string;
    entity_type: string;
    entity_id: string;
  }) =>
    post<{ data: { detached: boolean } }>("/v1/tags/detach", payload).then(
      (b) => b.data,
    ),
  tagsForEntity: (entityType: string, entityId: string) =>
    getAllV1<Tag>(
      `/v1/tags/for?entity_type=${encodeURIComponent(entityType)}&entity_id=${encodeURIComponent(entityId)}`,
    ).then((r) => r.items),
  tagEntities: (tagId: string, entityType?: string) => {
    const params = new URLSearchParams({ tag_id: tagId });
    if (entityType) params.set("entity_type", entityType);
    return get<{ data: string[] }>(
      `/v1/tags/entities?${params.toString()}`,
    ).then((b) => b.data);
  },
  listSavedViews: (surface?: string) => {
    const qs = surface ? `?surface=${encodeURIComponent(surface)}` : "";
    return getAllV1<SavedView>(`/v1/saved-views${qs}`).then((r) => r.items);
  },
  createSavedView: (payload: {
    surface: string;
    name: string;
    filters: Record<string, unknown>;
  }) =>
    post<{ data: SavedView }>("/v1/saved-views", payload).then((b) => b.data),
  deleteSavedView: (viewId: string) =>
    mutate<{ data: { id: string; deleted: boolean } }>(
      `/v1/saved-views/${encodeURIComponent(viewId)}`,
      "DELETE",
    ).then((b) => b.data),
  insightsTimeseries: (limit = 90) =>
    get<{ data: PostureMetricPoint[] }>(
      `/v1/insights/timeseries?limit=${limit}`,
    ).then((b) => b.data),
  insightsRemediation: () =>
    get<{ data: RemediationInsights }>("/v1/insights/remediation").then(
      (b) => b.data,
    ),
  insightsCapture: () =>
    post<{ data: PostureMetricPoint }>("/v1/insights/capture", {}).then(
      (b) => b.data,
    ),
  insightsFrameworkTrends: (limit = 90) =>
    get<{ data: FrameworkReadinessTrends }>(
      `/v1/insights/framework-trends?limit=${limit}`,
    ).then((b) => b.data),
  insightsSlaHeatmap: () =>
    get<{ data: SlaHeatmap }>("/v1/insights/sla-heatmap").then((b) => b.data),
  agentRuns: (query = "") =>
    get<{ data: AgentRun[] }>(`/v1/agent-runs${query}`).then((b) => b.data),
  agentRun: (runId: string) =>
    get<{ data: AgentRun }>(`/v1/agent-runs/${encodeURIComponent(runId)}`).then(
      (b) => b.data,
    ),
  createAgentRun: (payload: CreateAgentRunPayload) =>
    post<{ data: AgentRun }>("/v1/agent-runs", payload).then((b) => b.data),
  approveAgentDecision: (runId: string, decisionIndex: number, note = "") =>
    post<{ data: AgentRun }>(
      `/v1/agent-runs/${encodeURIComponent(runId)}/decisions/${decisionIndex}/approve`,
      { note },
    ).then((b) => b.data),
  rejectAgentDecision: (runId: string, decisionIndex: number, reason: string) =>
    post<{ data: AgentRun }>(
      `/v1/agent-runs/${encodeURIComponent(runId)}/decisions/${decisionIndex}/reject`,
      { reason },
    ).then((b) => b.data),
  accessReviews: (query = "") =>
    getAllV1<AccessReviewCampaign>(`/v1/access-reviews${query}`).then(
      (r) => r.items,
    ),
  createAccessReview: (
    payload: { name: string } & Partial<AccessReviewCampaign>,
  ) =>
    post<{ data: AccessReviewCampaign }>("/v1/access-reviews", payload).then(
      (b) => b.data,
    ),
  accessReview: (id: string) =>
    get<{ data: AccessReviewCampaign }>(
      `/v1/access-reviews/${encodeURIComponent(id)}`,
    ).then((b) => b.data),
  setAccessReviewStatus: (id: string, status: AccessReviewStatus) =>
    mutate<{ data: AccessReviewCampaign }>(
      `/v1/access-reviews/${encodeURIComponent(id)}`,
      "PATCH",
      { status },
    ).then((b) => b.data),
  accessReviewItems: (id: string, query = "") =>
    get<{ data: AccessReviewItem[] }>(
      `/v1/access-reviews/${encodeURIComponent(id)}/items${query}`,
    ).then((b) => b.data),
  seedAccessReview: (id: string) =>
    post<{ data: AccessReviewSeedResult }>(
      `/v1/access-reviews/${encodeURIComponent(id)}/seed`,
      {},
    ).then((b) => b.data),
  decideAccessReviewItem: (
    itemId: string,
    decision: AccessReviewDecision,
    note = "",
  ) =>
    post<{ data: AccessReviewItem }>(
      `/v1/access-reviews/items/${encodeURIComponent(itemId)}/decision`,
      { decision, note },
    ).then((b) => b.data),
  accessReviewCoverage: () =>
    get<{ data: AccessReviewCoverage[] }>("/v1/access-reviews/coverage").then(
      (b) => b.data,
    ),
  policyTemplates: () =>
    get<{ data: PolicyTemplateSummary[] }>("/v1/policy-templates").then(
      (b) => b.data,
    ),
  policyTemplate: (templateId: string) =>
    get<{ data: PolicyTemplate }>(
      `/v1/policy-templates/${encodeURIComponent(templateId)}`,
    ).then((b) => b.data),
  policies: (query = "") =>
    getAllV1<PolicyDocument>(`/v1/policies${query}`).then((r) => r.items),
  adoptPolicy: (payload: {
    template_id: string;
    variables?: Record<string, string>;
    owner?: string;
  }) =>
    post<{ data: PolicyDocument }>("/v1/policies", payload).then((b) => b.data),
  policy: (id: string) =>
    get<{ data: PolicyDocument }>(
      `/v1/policies/${encodeURIComponent(id)}`,
    ).then((b) => b.data),
  updatePolicy: (
    id: string,
    payload: Partial<{
      title: string;
      content: string;
      owner: string;
      variables: Record<string, string>;
      status: string;
    }>,
  ) =>
    mutate<{ data: PolicyDocument }>(
      `/v1/policies/${encodeURIComponent(id)}`,
      "PATCH",
      payload,
    ).then((b) => b.data),
  publishPolicy: (id: string) =>
    post<{ data: PolicyDocument }>(
      `/v1/policies/${encodeURIComponent(id)}/publish`,
      {},
    ).then((b) => b.data),
  policyAcknowledgments: (id: string) =>
    get<{ data: PolicyAcknowledgment[] }>(
      `/v1/policies/${encodeURIComponent(id)}/acknowledgments`,
    ).then((b) => b.data),
  recordPolicyAcknowledgment: (
    id: string,
    payload: { user_email?: string; display_name?: string } = {},
  ) =>
    post<{ data: PolicyAcknowledgment }>(
      `/v1/policies/${encodeURIComponent(id)}/acknowledgments`,
      payload,
    ).then((b) => b.data),
  policyAttestationSummary: () =>
    get<{ data: PolicyAttestationSummary }>(
      "/v1/policies/attestation-summary",
    ).then((b) => b.data),
  policyCoverage: () =>
    get<{ data: PolicyCoverage[] }>("/v1/policies/coverage").then(
      (b) => b.data,
    ),
  vendorQuestionnaires: () =>
    get<{ data: VendorQuestionnaireTemplateSummary[] }>(
      "/v1/vendor-questionnaires",
    ).then((b) => b.data),
  vendorQuestionnaire: (templateId: string) =>
    get<{ data: VendorQuestionnaireTemplate }>(
      `/v1/vendor-questionnaires/${encodeURIComponent(templateId)}`,
    ).then((b) => b.data),
  vendorAssessments: (query = "") =>
    getAllV1<VendorAssessment>(`/v1/vendor-assessments${query}`).then(
      (r) => r.items,
    ),
  createVendorAssessment: (payload: {
    vendor_name: string;
    template_id: string;
    owner?: string;
    control_id?: string | null;
    due_at?: string | null;
  }) =>
    post<{ data: VendorAssessment }>("/v1/vendor-assessments", payload).then(
      (b) => b.data,
    ),
  vendorAssessment: (id: string) =>
    get<{ data: VendorAssessment }>(
      `/v1/vendor-assessments/${encodeURIComponent(id)}`,
    ).then((b) => b.data),
  updateVendorAssessment: (
    id: string,
    payload: Partial<{
      vendor_name: string;
      owner: string;
      control_id: string | null;
      due_at: string | null;
      responses: Record<string, { answer: string }>;
      status: VendorAssessmentStatus;
    }>,
  ) =>
    mutate<{ data: VendorAssessment }>(
      `/v1/vendor-assessments/${encodeURIComponent(id)}`,
      "PATCH",
      payload,
    ).then((b) => b.data),
  submitVendorAssessment: (id: string) =>
    post<{ data: VendorAssessment }>(
      `/v1/vendor-assessments/${encodeURIComponent(id)}/submit`,
      {},
    ).then((b) => b.data),
  controlRemediation: (controlId: string) =>
    get<{ data: ControlRemediation }>(
      `/v1/controls/${encodeURIComponent(controlId)}/remediation`,
    ).then((b) => b.data),
  sprsScore: () =>
    get<{ data: SprsReport }>("/v1/gov-compliance/sprs").then((b) => b.data),
  poamItems: (params?: { framework_id?: string; status?: string }) => {
    const qs = new URLSearchParams();
    if (params?.framework_id) qs.set("framework_id", params.framework_id);
    if (params?.status) qs.set("status", params.status);
    const suffix = qs.toString() ? `?${qs}` : "";
    return getAllV1<PoamItem>(`/v1/gov-compliance/poam${suffix}`).then(
      (r) => r.items,
    );
  },
  syncPoam: () =>
    post<{ data: PoamSyncResult }>("/v1/gov-compliance/poam/sync", {}).then(
      (b) => b.data,
    ),
  updatePoamItem: (id: string, payload: Record<string, unknown>) =>
    mutate<{ data: PoamItem }>(
      `/v1/gov-compliance/poam/${encodeURIComponent(id)}`,
      "PATCH",
      payload,
    ).then((b) => b.data),
  platformUsage: () =>
    get<{ data: PlatformUsage }>("/v1/platform/usage").then((b) => b.data),
};

export function bootstrapAssessment(): Assessment | null {
  if (typeof document === "undefined") return null;
  const tag = document.getElementById("app-data");
  if (!tag?.textContent) return null;
  try {
    const data = JSON.parse(tag.textContent);
    if (data && typeof data === "object" && "posture" in data) {
      return data as Assessment;
    }
  } catch {
    return null;
  }
  return null;
}

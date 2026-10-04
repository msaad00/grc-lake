// Wire types mirror security_lakehouse/assessment.py and gold/*.jsonl.

export interface FrameworkPosture {
  framework: string;
  score: number;
  state: "ready" | "attention_required";
  control_count: number;
  failing_control_count: number;
  violation_count: number;
  stale_control_count: number;
  critical_violation_count: number;
  high_violation_count: number;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Violation {
  violation_id: string;
  control_id: string;
  event_id: string;
  asset_id: string;
  /** Display name from the source, when it has one; asset_id stays the key. */
  asset_name?: string;
  asset_owner: string;
  environment: string;
  source: string;
  event_type: string;
  severity: Severity;
  severity_score: number;
  state: string;
  evidence_ref: string;
  raw_sha256: string;
  detected_at: string;
}

export interface PostureBlock {
  score: number;
  state: "ready" | "attention_required" | "critical" | "not_evaluated";
  framework_count: number;
  control_count: number;
  asset_count: number;
  open_violation_count: number;
  critical_violation_count: number;
  high_violation_count: number;
  failed_control_test_count: number;
  warning_control_test_count: number;
  stale_control_count: number;
  stale_evidence_count: number;
}

export interface AssetRisk {
  asset_id: string;
  asset_name?: string;
  asset_owner: string;
  asset_type: string;
  environment: string;
  risk_score: number;
  critical_open: number;
  high_open: number;
}

export interface Assessment {
  schema_version: string;
  assessment_type: string;
  evaluated_at: string;
  freshness_days: number;
  posture: PostureBlock;
  frameworks: FrameworkPosture[];
  violations: Violation[];
  top_risk_assets: AssetRisk[];
  stale_controls: string[];
  assessment_hash: string;
}

export interface ControlPosture {
  control_id: string;
  framework: string;
  status: "pass" | "fail" | "warn" | string;
  title: string;
  owner: string;
  risk_score: number;
  evidence_count: number;
  event_count: number;
}

export interface ControlTest {
  control_id: string;
  name: string;
  result: "pass" | "fail" | "warn" | string;
  status: string;
  owner: string;
  confidence_score: number;
  agent_skill: string;
  freshness_status: string;
  next_action: string;
}

export interface NormalizedEvent {
  event_id: string;
  event_time: string;
  source: string;
  status: string;
  severity: Severity;
  asset_id: string;
  asset_name?: string;
  asset_owner: string;
  evidence_ref: string;
  evidence_id: string;
  control_ids: string[];
  evidence_collected_at: string;
}

export type EvidenceFreshnessStatus = "fresh" | "stale" | "expired" | "missing";

export interface EvidenceFreshness {
  event_id: string;
  evidence_id: string;
  evidence_ref: string;
  source: string;
  connector_id: string;
  event_type: string;
  asset_id: string;
  control_ids: string[];
  evidence_collected_at: string | null;
  evaluated_at: string;
  freshness_slo_minutes: number;
  status: EvidenceFreshnessStatus | string;
  score: number;
  age_minutes: number | null;
  expires_at: string | null;
  reason: string;
  next_action: string;
}

export interface EvidenceFreshnessSourceSummary {
  source: string;
  connector_id: string;
  fresh_count: number;
  stale_count: number;
  expired_count: number;
  missing_count: number;
  evidence_count: number;
  latest_evidence_at: string | null;
  freshness_slo_minutes: number;
  state: string;
  status: string;
  next_action: string;
}

export interface EvidenceFreshnessSummary {
  total: number;
  fresh_count: number;
  stale_count: number;
  expired_count: number;
  missing_count: number;
  sla_breach_count: number;
  fresh_rate_pct: number;
  state: string;
  sources: EvidenceFreshnessSourceSummary[];
  sources_needing_action: number;
  top_breaches: Array<{
    event_id: string;
    source: string;
    status: string;
    age_minutes: number | null;
    reason: string;
    next_action: string;
    control_ids: string[];
  }>;
}

export interface EscalateFreshnessResult {
  created_count: number;
  skipped_duplicates: number;
  sla_breach_count: number;
  tasks: Array<{ id: string; title: string; status: string }>;
}

export interface Health {
  ok: boolean;
  service: string;
}

export type AgentHarness = "posture_review" | "soc_triage" | string;

export interface AgentDecision {
  action: string;
  reason?: string;
  payload?: Record<string, unknown>;
  requires_approval?: boolean;
  status?:
    "proposed" | "approved" | "executed" | "rejected" | "skipped" | string;
  approved_by?: string;
  approved_at?: string;
  rejected_by?: string;
  rejected_at?: string;
  rejection_reason?: string;
  execution_result?: Record<string, unknown>;
}

export interface AgentEvaluation {
  ok?: boolean;
  score?: number;
  confidence?: "high" | "medium" | "low" | string;
  risk_level?: "low" | "medium" | "high" | "critical" | string;
  checks?: unknown[];
  failures?: unknown[];
  coverage?: Record<string, unknown>;
}

export interface AgentRun {
  id: string;
  harness: AgentHarness;
  objective: string;
  role: string;
  mode: string;
  status: "completed" | "failed" | string;
  idempotency_key: string | null;
  input_hash: string;
  provider: Record<string, unknown>;
  budget: Record<string, unknown>;
  evaluation: AgentEvaluation;
  decisions: AgentDecision[];
  errors: string[];
  created_by: string;
  created_at: string;
  completed_at: string | null;
  state?: Record<string, unknown>;
}

export interface CreateAgentRunPayload {
  harness: AgentHarness;
  objective?: string;
  role?: string;
  idempotency_key?: string;
  orchestrator?: "sequential" | "langgraph";
  use_model?: boolean;
  max_context_chars?: number;
  max_fact_items?: number;
  max_output_tokens?: number;
}

export interface AuthMethod {
  id: "oidc" | "saml" | "api_key";
  label: string;
  configured: boolean;
  login_url: string;
  protocol?: string;
  provider_kind?: string;
  provider_label?: string;
  setup_hint?: string;
  issuer_host?: string;
  tenant_slug?: string;
  auto_provision?: boolean;
  metadata_url?: string;
}

export interface AuthWhoami {
  user_id: string;
  tenant_id: string;
  email: string;
  role: string;
  scopes: string[];
  /** True when connectors must use tenant-delegated access (hosted server mode). */
  hosted?: boolean;
  /** Env-var prefix the hosted secret-ref policy accepts for this tenant. */
  secret_ref_prefix?: string | null;
}

export interface AuthApiKey {
  id: string;
  name: string;
  prefix: string;
  user_email: string;
  role: string;
  created_at: string | null;
  last_used_at: string | null;
  expires_at: string | null;
  revoked: boolean;
}

export interface CreateAuthKeyPayload {
  user_email: string;
  name?: string;
  expires_in_days?: number | null;
}

export interface CreatedAuthApiKey {
  id: string;
  prefix: string;
  user_email: string;
  token: string;
}

export interface AuthUser {
  id: string;
  email: string;
  display_name: string;
  role: string;
  is_active: boolean;
  created_at: string | null;
}

export interface UpdateAuthUserPayload {
  role?: string;
  is_active?: boolean;
  display_name?: string;
}

export interface TenantInvite {
  id: string;
  tenant_id: string;
  email: string;
  role: string;
  status: string;
  invited_by: string;
  created_at: string | null;
  expires_at: string | null;
  accepted_at: string | null;
}

export interface CreateInvitePayload {
  email: string;
  role?: string;
}

export interface AuthMethods {
  require_auth: boolean;
  methods: AuthMethod[];
}

export interface PocReadinessStep {
  id: string;
  label: string;
  status: "ready" | "needs_setup" | "skipped" | string;
  detail: string;
  href: string | null;
  blocking: boolean;
  console_href?: string | null;
}

export interface OnboardingProgress {
  progress_percent: number;
  completed_blocking: number;
  blocking_total: number;
  current_step_id: string | null;
  steps: PocReadinessStep[];
}

export interface DemoShareLink {
  kind: string;
  label: string;
  description: string;
  url: string;
  audience: "internal" | "operator" | "evaluator" | string;
}

export interface DemoAccountLink {
  connector_id: string;
  label: string;
  setup_hint: string;
  status:
    "not_linked" | "connected" | "ingesting" | "enabled" | "error" | string;
  enabled: boolean;
  evidence_count: number;
  last_sync_at: string | null;
  last_sync_result: string | null;
  connect_url: string;
}

export interface DemoKit {
  shareable: boolean;
  public_url: string | null;
  share_links: DemoShareLink[];
  account_linking: DemoAccountLink[];
  account_linking_summary: {
    recommended: number;
    connected_or_ingesting: number;
    live_ingestion: number;
  };
  ingestion_proof: Record<string, unknown> | null;
}

export interface PocReadiness {
  state: "ready" | "internal_ready" | "needs_setup" | string;
  shareable: boolean;
  public_url: string | null;
  demo_kit?: DemoKit;
  workspace: {
    tenant_id: string;
    workspace_id: string;
    current_user: string;
    current_role: string;
  };
  access: {
    require_auth: boolean;
    browser_sso_configured: boolean;
    active_api_keys: number;
    users_by_role: Record<string, number>;
  };
  connectors: {
    enabled: number;
    failed: number;
    silent: number;
    evidence_count: number;
    source_count: number;
  };
  trust_shares: {
    active: number;
  };
  agents: {
    runs: number;
    completed: number;
    pending_decisions: number;
    latest_run_at: string | null;
  };
  ingestion: {
    state: string;
    posture_score: number | null;
    open_violations: number | null;
    recommended_actions: IngestionAction[];
  };
  steps: PocReadinessStep[];
  next_step: PocReadinessStep | null;
  onboarding?: OnboardingProgress;
}

export interface AuditWorkflowItem {
  id: string;
  label: string;
  shipped: boolean;
  note: string;
}

export interface AuditReadinessGap {
  id: string;
  label: string;
  href: string;
}

export interface AuditReadiness {
  state: "audit_ready" | "on_track" | "needs_work" | string;
  audit_score: number;
  evaluated_at: string;
  posture: {
    score: number;
    open_violations: number;
    frameworks_ready: number;
    frameworks_total: number;
  };
  control_tests: { passing: number; failing: number; total: number };
  evidence_freshness?: {
    total: number;
    stale_count: number;
    fresh_rate_pct: number;
  };
  evidence_requests: { open: number };
  access_reviews: { active: number; completed: number };
  trust_shares: { active: number; auditor: number };
  connectors: {
    enabled: number;
    failed: number;
    evidence_count: number;
    evidence_sources?: number;
  };
  snapshots: {
    latest_hash: string | null;
    latest_at: string | null;
    count: number;
  };
  agents: { pending_decisions: number };
  vendor_risk?: {
    total: number;
    open: number;
    overdue: number;
    completed: number;
    high_risk_open: number;
  };
  policy_attestation?: {
    published: number;
    acknowledged: number;
    unattested: number;
    total_acknowledgments: number;
  };
  personnel?: {
    identity_connectors: number;
    active_campaigns: number;
    completed_campaigns: number;
    pending_certifications: number;
    certified: number;
  };
  frameworks?: AuditReadinessFramework[];
  framework_ready_criteria?: { min_score: number; min_coverage_pct: number };
  gaps: AuditReadinessGap[];
  /** Product capabilities; informational only and not part of audit_score. */
  workflow_coverage: {
    scored: false;
    description?: string;
    score: number;
    checklist: AuditWorkflowItem[];
  };
}

export interface AuditReadinessFramework {
  framework: string;
  score: number;
  assessed_controls: number;
  /** null when the framework is not in the control catalog (coverage unknown). */
  total_controls: number | null;
  coverage_pct: number | null;
  ready: boolean;
}

export interface AiGovernanceFramework {
  framework_id: string;
  label: string;
  /** Catalogued requirements in the pack. */
  requirements: number;
  /** Requirements mapped to a safeguard; the Frameworks page's figure. */
  mapped_requirements: number;
  mapped_pct: number;
  controls_with_evidence: number;
  evidence_pct: number;
  passing_controls: number;
  failing_controls: number;
  unevaluated_controls: number;
  /** Pass rate over controls with evidence here; null when none. */
  score: number | null;
}

export interface AiGovernanceGap {
  id: string;
  label: string;
  href: string;
}

export interface AiGovernance {
  state: "governed" | "on_track" | "needs_work" | string;
  governance_score: number;
  evaluated_at: string;
  inventory: {
    total: number;
    models: number;
    agents: number;
    with_model_card: number;
    with_lineage: number;
  };
  events: {
    model_inventory: number;
    model_lineage: number;
    agent_runtime: number;
    repo_artifacts: number;
  };
  artifacts: {
    model_cards: number;
    repo_audit_signals: number;
  };
  frameworks: AiGovernanceFramework[];
  frameworks_ready: number;
  frameworks_total: number;
  gaps: AiGovernanceGap[];
  evidence_loops: {
    inventory_events: boolean;
    lineage_events: boolean;
    model_cards: boolean;
    agent_governance: boolean;
  };
  aibom: {
    shipped: boolean;
    note: string;
  };
}

export interface AiInventoryItem {
  asset_id: string;
  asset_name?: string;
  asset_type: string;
  owner: string;
  environment: string;
  model_card: boolean;
  lineage_complete: boolean;
  last_seen_at: string;
  sources: string[];
  control_ids: string[];
  event_types: string[];
}

export interface SnapshotResponse {
  snapshot_path: string;
  reason: string;
}

export interface SnapshotSummary {
  snapshot_id: string;
  snapshot_path: string;
  evaluated_at: string;
  reason: string;
  assessment_hash: string;
  posture_score: number | null;
  open_violation_count: number | null;
  critical_violation_count: number | null;
}

export interface SnapshotDetail {
  snapshot_id: string;
  evaluated_at: string | null;
  reason: string;
  assessment_hash: string | null;
  prev_hash: string | null;
  posture: Record<string, unknown> | null;
  frameworks: Array<{ framework?: string; score?: number; name?: string }>;
  violations: Array<{ control_id?: string; severity?: string }>;
  violation_count: number;
  stale_control_count: number;
  evidence_refs: string[];
  evidence_freshness?: unknown;
}

export interface CloudLinkSession {
  session_id: string;
  connector_id: string;
  status: string;
  account_scope?: string | null;
  external_id?: string | null;
  quick_create_url?: string | null;
  template_url?: string | null;
  terraform_url?: string | null;
  consent_url?: string | null;
  manual_template_path?: string | null;
  manual_terraform_path?: string | null;
  trusted_principal?: string | null;
  runtime_identity_ready?: boolean;
  cloudshell_command?: string | null;
  azure_tenant_id?: string | null;
  azure_app_id?: string | null;
  role_name?: string | null;
  deploy_command?: string | null;
  workload_identity_member?: string | null;
  delegation?: {
    required: boolean;
    secret_ref_prefix: string | null;
  } | null;
  deployment_methods?: Array<{
    id: string;
    label: string;
    detail: string;
  }> | null;
  scale_strategy?: {
    mode?: string | null;
    summary?: string | null;
    confirmation?: string | null;
    follow_up?: string | null;
  } | null;
}

export interface CloudLinkCompleteResult {
  session: CloudLinkSession;
  configure: Record<string, unknown>;
}

export type TrackingState =
  "open" | "triaged" | "in_progress" | "resolved" | "dismissed";

export interface TrackingEvent {
  tracking_id: string;
  violation_id: string;
  actor: string;
  state: TrackingState;
  assignee: string | null;
  due_at: string | null;
  note: string | null;
  occurred_at: string;
}

export interface TriagePayload {
  state: TrackingState;
  actor?: string;
  assignee?: string;
  due_at?: string;
  note?: string;
}

export interface VerifyResult {
  event_id: string;
  verified: boolean;
  expected_sha256: string | null;
  computed_sha256: string | null;
  source_layer: "bronze" | "missing";
  reason: string | null;
}

export type ConnectorState = "enabled" | "disabled";

export interface ConnectorRun {
  connector_id: string;
  kind: "discover" | "probe" | "sync";
  result: "ok" | "error" | "skipped";
  actor: string;
  duration_ms: number | null;
  evidence_count: number | null;
  error: string | null;
  access_fingerprint: string | null;
  metadata?: Record<string, unknown>;
  occurred_at: string;
}

export interface ConnectorView {
  connector_id: string;
  name: string;
  vendor?: string;
  description?: string;
  setup_hint?: string;
  category: string;
  collection_mode: string;
  access_boundary: string;
  credential_type: string;
  minimum_permissions: string[];
  evidence_types: string[];
  default_route: string;
  freshness_slo_minutes: number;
  production_status:
    "primary_lake" | "supported_connector" | "local_demo" | string;
  /** Access contract only when false — sync is unavailable. */
  is_implemented?: boolean;
  /** "preview" = implemented but not yet verified against a live tenant; absent = GA. */
  release_stage?: "ga" | "preview" | string;
  /** Present when the row came from an installed package, not the in-repo catalog. */
  provenance?: { source: "entry_point"; entry_point: string };
  state: ConnectorState;
  configured_at: string | null;
  credential_fingerprint: string | null;
  configured_options: Record<string, unknown>;
  last_probe: ConnectorRun | null;
  last_sync: ConnectorRun | null;
  last_successful_sync?: ConnectorRun | null;
  freshness_state?: "fresh" | "stale" | "never_synced" | string;
  last_sync_at?: string | null;
  next_run_at?: string | null;
}

export interface IngestionAction {
  priority: "p0" | "p1" | "p2" | string;
  action: string;
  reason: string;
}

export interface LakeEvalRun {
  kind: "eval";
  actor: string;
  result: "ok" | "error" | string;
  mode: string;
  duration_ms: number | null;
  event_count?: number | null;
  silver_count?: number | null;
  error: string | null;
  occurred_at: string;
  control_tests_total?: number | null;
  control_tests_passing?: number | null;
  control_tests_failing?: number | null;
  pass_rate?: number | null;
}

export interface EvalAccuracy {
  total_tests: number;
  passing: number;
  failing: number;
  warning: number;
  needs_evidence?: number;
  pass_rate: number | null;
  framework_count: number;
  evidence_source_count: number;
  has_tests: boolean;
}

export interface CatalogCoverage {
  total: number;
  implemented: number;
  enabled: number;
  contract_only?: number;
  implementation_rate: number;
  enabled_rate: number;
  by_category: Array<{
    category: string;
    total: number;
    implemented: number;
    enabled: number;
  }>;
}

export interface IngestionScale {
  mode:
    | "local_full"
    | "local_incremental"
    | "warehouse"
    | "warehouse_required"
    | string;
  event_count: number;
  silver_count: number;
  warehouse_row_threshold: number;
  warehouse_sink_configured: boolean;
  recommendation: string;
  eval_schedule: string | null;
  default_sync_schedule: string;
  default_eval_schedule: string;
  latest_eval?: {
    kind?: string;
    actor?: string;
    result?: string;
    mode?: string;
    duration_ms?: number;
    error?: string | null;
    occurred_at?: string;
  };
  last_fired_at?: string | null;
  next_eval_at?: string | null;
  eval_overdue?: boolean;
  manifest?: {
    materialize_mode?: string | null;
    delta_count?: number | null;
    removed_count?: number | null;
    row_counts?: Record<string, number>;
  };
}

export interface PlatformJob {
  id: string;
  kind: "connector_sync" | "lake_eval" | "workflow" | "agent_run" | string;
  status: string;
  label: string;
  started_at?: string | null;
  finished_at?: string | null;
  actor?: string | null;
  detail?: string | null;
}

export interface PlatformJobsFeed {
  jobs: PlatformJob[];
  count: number;
  running_count: number;
  counts_by_kind: Record<string, number>;
}

export interface IngestionStatus {
  state:
    | "active"
    | "attention_required"
    | "error"
    | "needs_configuration"
    | "needs_data"
    | string;
  summary: {
    connector_count: number;
    enabled_connectors: number;
    failed_connectors: number;
    never_synced_connectors: number;
    silent_connectors?: number;
    evidence_count: number;
    source_count: number;
    stale_evidence: number;
    posture_score: number | null;
    posture_state: string | null;
    open_violations: number | null;
  };
  sources: Array<{ source: string; evidence_count: number }>;
  connectors: Array<{
    connector_id: string;
    name: string;
    category: string;
    state: ConnectorState | string;
    production_status: string;
    collection_mode: string;
    access_boundary: string;
    freshness_slo_minutes: number;
    freshness_state: string | null;
    last_sync_at: string | null;
    next_run_at: string | null;
    latest_sync: {
      connector_id?: string;
      kind?: string;
      result: "ok" | "error" | "skipped" | null;
      occurred_at?: string | null;
      duration_ms?: number | null;
      evidence_count?: number | null;
      error?: string | null;
    };
    last_error: string | null;
  }>;
  latest_runs: ConnectorRun[];
  pipeline: Array<{
    name: string;
    path: string;
    exists: boolean;
    row_count: number | null;
  }>;
  integrity: {
    ok: boolean | null;
    evidence_count?: number | null;
    unique_event_ids?: number | null;
    duplicate_event_ids?: number | null;
    raw_sha256?: string | null;
  };
  proof: {
    report_path: string;
    report_exists: boolean;
    proof_pack_path: string;
    proof_pack_exists: boolean;
    scenario: string | null;
    status: string;
    proof_state: string | null;
    evidence_count: number | null;
    sources: string[];
    open_violations: number | null;
    recommended_actions: IngestionAction[];
  };
  recommended_actions: IngestionAction[];
  eval_accuracy?: EvalAccuracy;
  catalog_coverage?: CatalogCoverage;
  scale?: IngestionScale;
  health?: {
    evaluated_at: string;
    summary: {
      healthy: number;
      degraded: number;
      silent: number;
      never_succeeded: number;
      enabled: number;
      unhealthy: number;
    };
    connectors: Array<{
      connector_id: string;
      health: string;
      last_success_at: string | null;
      seconds_since_success: number | null;
    }>;
  };
}

export interface ConfigurePayload {
  state: ConnectorState;
  actor?: string;
  credentials?: Record<string, string>;
  options?: Record<string, unknown>;
}

export interface ProbePayload {
  actor?: string;
  credentials?: Record<string, string>;
  options?: Record<string, unknown>;
}

export type DiscoverPayload = ProbePayload;

export type FrameworkFreshness = "fresh" | "stale" | "expired" | "never_pulled";

export interface FrameworkView {
  framework_id: string;
  /** Product-owned grouping for scope marks; it is not a certification claim. */
  family?:
    | "assurance"
    | "security"
    | "privacy"
    | "ai-governance"
    | "cloud"
    | "sector"
    | string;
  name: string;
  version: string;
  effective_date: string | null;
  superseded_by: string | null;
  official_source_name: string;
  official_source_url: string;
  source_sha256: string | null;
  pulled_at: string | null;
  implementation_status: string;
  /** Registry entries without seeded requirements are stubs, not packs. */
  pack_state?: FrameworkPackState;
  copyright_guardrail: string;
  coverage_boundary?: string;
  evidence_focus?: string[];
  next_step?: string;
  sync_cadence_days: number;
  control_count: number;
  implemented_control_count: number;
  mapping_coverage_pct: number;
  freshness_state: FrameworkFreshness;
  pulled_age_days: number | null;
  next_pull_due: string | null;
}

export type FrameworkPackState = "seeded" | "planned" | "superseded";

export interface FrameworkCoverageSummary {
  /** Every registry entry, stubs included; use seeded_framework_count for packs. */
  framework_count: number;
  seeded_framework_count?: number;
  stub_framework_count?: number;
  superseded_framework_count?: number;
  implemented_framework_count: number;
  planned_framework_count: number;
  seeded_control_count: number;
  /** Every seeded requirement with an official-source identifier mapping. */
  source_cited_mapping_count?: number;
  /** Identifier mappings a human has reviewed (excludes proposed). */
  reviewed_mapping_count: number;
  missing_mapping_count: number;
  seeded_mapping_coverage_pct: number;
  evaluatable_requirement_count: number;
  attestable_requirement_count: number;
  evaluatable_coverage_pct: number;
  attestable_coverage_pct: number;
  /** Attestable requirements with a maintainer-reviewed mapping. */
  maintainer_reviewed_requirement_count?: number;
  /** Attestable only through this organization's own approvals. */
  org_reviewed_requirement_count?: number;
  org_reviewed_mapping_count?: number;
  needs_changes_mapping_count?: number;
  rejected_mapping_count?: number;
  asset_type_count: number;
  control_asset_applicability_link_count: number;
  official_logo_count: number;
  certification_seal_count: number;
}

export interface FrameworkCoverageRow {
  framework_id: string;
  name: string;
  version: string;
  official_source_name: string;
  official_source_url: string;
  effective_date: string | null;
  source_sha256: string | null;
  pulled_at: string | null;
  freshness_state: FrameworkFreshness;
  superseded_by?: string | null;
  pack_state?: FrameworkPackState;
  seeded_control_count: number;
  /** Every seeded requirement with an official-source identifier mapping. */
  source_cited_mapping_count?: number;
  /** Identifier mappings a human has reviewed (excludes proposed). */
  reviewed_mapping_count: number;
  missing_mapping_count: number;
  missing_mapping_control_ids: string[];
  seeded_mapping_coverage_pct: number;
  evaluatable_requirement_count: number;
  attestable_requirement_count: number;
  evaluatable_coverage_pct: number;
  attestable_coverage_pct: number;
  maintainer_reviewed_requirement_count?: number;
  org_reviewed_requirement_count?: number;
  org_reviewed_mapping_count?: number;
  needs_changes_mapping_count?: number;
  rejected_mapping_count?: number;
  implementation_status: string;
  source_policy: string;
  asset_policy: string;
}

export interface FrameworkCoveragePayload {
  summary: FrameworkCoverageSummary;
  frameworks: FrameworkCoverageRow[];
}

export interface FrameworkControlArticle {
  article_id: string;
  title: string;
  official_source_url: string;
  reviewed_by: string;
  reviewed_at: string;
  rationale: string;
  /** Absent on legacy human-reviewed rows; "proposed" = not yet reviewed. */
  review_status?: string;
}

export interface FrameworkSourceRollup {
  source: string;
  event_count: number;
  fresh_count: number;
  stale_count: number;
  expired_count: number;
  latest_evidence_at: string | null;
}

export interface FrameworkConnectorHint {
  connector_id: string;
  name: string;
  vendor: string;
  category: string;
  priority: "primary" | "secondary";
  configured: boolean;
  production_status: string;
  evidence_types: string[];
  setup_hint: string;
  rationale: string;
}

export interface FrameworkControlDetail {
  control_id: string;
  title: string;
  owner: string;
  risk_domain: string;
  frequency: string;
  implementation_status: string;
  evidence_requirement: string;
  evaluation_rule: string;
  official_source_ref: string;
  articles: FrameworkControlArticle[];
  posture: {
    status: "pass" | "fail" | "not_evaluated";
    risk_score: number | null;
    evidence_coverage: number | null;
    open_event_count: number;
    rule_reasons: string[];
  };
  test: {
    result: "pass" | "fail" | "not_run";
    confidence_score: number | null;
    freshness_status: string | null;
    required_evidence_types: string[];
    observed_evidence_types: string[];
    next_action: string | null;
  };
  evidence: {
    count: number;
    latest_evidence_at: string | null;
    freshness: {
      fresh: number;
      stale: number;
      expired: number;
    };
    sources: FrameworkSourceRollup[];
  };
  connector_hints: FrameworkConnectorHint[];
}

export interface FrameworkDetail {
  framework: FrameworkView;
  summary: {
    control_count: number;
    mapped_control_count: number;
    passing_control_count: number;
    failing_control_count: number;
    evidence_count: number;
    source_count: number;
    recommended_connector_count?: number;
    configured_recommended_connector_count?: number;
  };
  controls: FrameworkControlDetail[];
  sources: FrameworkSourceRollup[];
}

// --- Workflows --------------------------------------------------------------

export type ActionKind = "trigger" | "check" | "gate" | "action";

export interface ActionSchemaField {
  type: "string" | "number" | "boolean";
  label: string;
  required?: boolean;
  optional?: boolean;
  default?: string | number | boolean;
}

export interface ActionSpec {
  node_type: string;
  kind: ActionKind;
  label: string;
  description: string;
  input_schema: Record<string, ActionSchemaField>;
  output_schema: Record<string, string>;
}

export interface WorkflowNode {
  id: string;
  node_type: string;
  params: Record<string, unknown>;
  position?: { x: number; y: number };
}

export interface WorkflowEdge {
  source: string;
  target: string;
  /**
   * Edge condition. `always` (default) fires the target whenever the source
   * runs; `passed`/`failed` only fire when the source's output includes a
   * truthy/falsy `passed` field. Used by the backend's topological runner
   * to gate downstream actions on check results.
   */
  condition?: "always" | "passed" | "failed";
}

export interface Workflow {
  workflow_id: string;
  version: number;
  name: string;
  description: string;
  nodes: WorkflowNode[];
  edges: WorkflowEdge[];
  actor: string;
  occurred_at: string;
  hash: string;
}

export interface WorkflowRunNode {
  node_id: string;
  node_type: string;
  params: Record<string, unknown>;
  result: "ok" | "error" | "skipped";
  output?: Record<string, unknown>;
  error?: string;
  reason?: string;
}

export interface WorkflowRun {
  run_id?: string;
  workflow_id: string;
  workflow_version: number;
  actor: string;
  dry_run?: boolean;
  status?: "ok" | "error" | "awaiting_approval" | "rejected";
  result: "ok" | "error" | "awaiting_approval" | "rejected";
  started_at: string;
  finished_at: string;
  pending_node_id?: string;
  node_results: WorkflowRunNode[];
  resumed_from_run_id?: string;
  rejected_from_run_id?: string;
  approval_note?: string;
  rejection_note?: string;
}

// --- Trust shares -----------------------------------------------------------

export interface TrustShare {
  share_id: string;
  role: "auditor";
  scope: "posture_full" | "posture_framework";
  framework_id: string | null;
  sensitivity_ceiling: string;
  expires_at: string;
  created_at: string;
  created_by: string;
  revoked_at: string | null;
  token_sha256: string;
  token?: string; // returned only at create time
  expired: boolean;
}

// --- Audit log --------------------------------------------------------------

export interface AuditLogEntry {
  event_id: string;
  category:
    | "triage"
    | "connector"
    | "snapshot"
    | "workflow"
    | "trust_share"
    | "mapping_review"
    | "request";
  actor: string;
  occurred_at: string;
  summary: string;
  subject: string;
  result: string | null;
  payload: Record<string, unknown>;
}

// --- Compliance graph -------------------------------------------------------

export type GraphNodeKind =
  | "framework"
  | "control"
  | "evidence_type"
  | "asset"
  | "repository"
  | "directory"
  | "language"
  | "evidence_signal"
  | "governance_signal"
  | "signal_gap"
  | "workflow"
  | "dependency_manifest"
  | "ownership_file"
  | "security_file"
  | "file"
  | "principal"
  | "team"
  | "review_rule"
  | "status_check"
  | "workflow_permission"
  | "evidence";

export type GraphEdgeKind =
  | "framework_has_control"
  | "control_requires_evidence"
  | "evidence_covers_asset"
  | "contains"
  | "has_signal"
  | "has_evidence"
  | "evidence_maps_control"
  | "has_governance_signal"
  | "requires_status_check";

export interface GraphNode {
  id: string;
  kind: GraphNodeKind;
  label: string;
  subtitle?: string;
  framework_id?: string;
  owner?: string;
  environment?: string;
  risk_score?: number;
  event_count?: number;
  path_count?: number;
  evidence_id?: string;
  evidence_ref?: string;
  control_ids?: string[];
  event_type?: string;
  provider?: string;
  severity?: string;
  freshness_status?: string;
  freshness_age_minutes?: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  kind: GraphEdgeKind;
}

export interface ComplianceGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  counts: Record<GraphNodeKind, number>;
}

export interface CrosswalkCell {
  framework_id: string;
  shared_risk_domains: string[];
  shared_owners: string[];
  is_self: boolean;
}

export interface CrosswalkRow {
  framework_id: string;
  cells: CrosswalkCell[];
}

export interface Crosswalk {
  frameworks: string[];
  matrix: CrosswalkRow[];
}

export interface ReviewedArticle {
  article_id: string;
  title: string;
  official_source_url: string;
  reviewed_by: string;
  reviewed_at: string;
  rationale: string;
  /** Absent on legacy human-reviewed rows; "proposed" = not yet reviewed. */
  review_status?: string;
}

export interface ControlArticleMapping {
  control_id: string;
  framework_id: string;
  articles: ReviewedArticle[];
}

export interface ReviewedCrosswalkCell {
  framework_id: string;
  is_self: boolean;
  shared_domains: string[];
  shared_articles: string[];
  shared_controls: string[];
}

export interface ReviewedCrosswalkRow {
  framework_id: string;
  mapping_count: number;
  article_count: number;
  domain_count: number;
  cells: ReviewedCrosswalkCell[];
}

export interface ReviewedCrosswalk {
  frameworks: string[];
  matrix: ReviewedCrosswalkRow[];
}

export interface EquivalenceControlRef {
  control_id: string;
  framework_id: string;
  role?: string;
}

export interface FrameworkEquivalenceGroup {
  group_id: string;
  label: string;
  risk_domain: string;
  rationale: string;
  reviewed_by: string;
  reviewed_at: string;
  controls: EquivalenceControlRef[];
}

/** Mapping counts shared by the CCF family and category ledgers. */
export interface CcfLedgerCounts {
  safeguard_count: number;
  framework_count: number;
  frameworks: string[];
  mapped_requirement_count: number;
  mapping_count: number;
  reviewed_mapping_count: number;
  maintainer_reviewed_mapping_count: number;
  org_reviewed_mapping_count: number;
  proposed_mapping_count: number;
  needs_changes_mapping_count: number;
  rejected_mapping_count: number;
  state: "reviewed" | "partially_reviewed" | "proposed_only";
}

export interface CcfFamilyRow extends CcfLedgerCounts {
  family_id: string;
  label: string;
  description: string;
  category_id: string;
  category_label: string;
  nist_800_53_families: string[];
  cis_controls: string[];
}

export interface CcfCategoryRow extends CcfLedgerCounts {
  category_id: string;
  label: string;
  description: string;
  family_ids: string[];
  family_count: number;
}

/** GET /api/v1/ccf/coverage — CCF ledger with this lake's org review decisions. */
export interface CcfCoverage {
  categories: CcfCategoryRow[];
  families: CcfFamilyRow[];
  review_log_verified: boolean;
}

export interface FrameworkEquivalence {
  schema?: string;
  group_count: number;
  groups: FrameworkEquivalenceGroup[];
  index: Record<
    string,
    {
      group_id: string;
      label?: string;
      risk_domain?: string;
      role?: string;
      equivalent_controls: string[];
      group_controls: string[];
    }
  >;
}

export type ReadinessStage =
  | "source_pulled"
  | "mapped"
  | "evidence_defined"
  | "rule_versioned"
  | "coverage_verified";

export interface FrameworkReadiness {
  framework_id: string;
  name: string;
  version: string;
  control_count: number;
  mapped_control_count: number;
  coverage_pct: number;
  pack_state?: FrameworkPackState;
  gates: Record<ReadinessStage, boolean>;
  stage: ReadinessStage;
  is_ready: boolean;
}

export interface RemediationTask {
  id: string;
  title: string;
  description: string;
  control_id: string | null;
  violation_id: string | null;
  owner: string;
  status: "open" | "in_progress" | "blocked" | "resolved" | "dismissed";
  priority: "low" | "medium" | "high" | "critical";
  due_at: string | null;
  overdue: boolean;
  created_by: string;
  created_at: string | null;
  updated_at: string | null;
  resolved_at: string | null;
  resolution_note: string;
  verification_history?: Array<{
    verified_at: string;
    verified_by: string;
    generation: { generation_id: string };
  }>;
}

export interface SprsReport {
  framework_id: string;
  base_score: number;
  minimum_score: number;
  score: number;
  deduction_total: number;
  requirements_total: number;
  requirements_met: number;
  requirements_unmet: number;
  deductions: Array<{
    requirement_id: string;
    title: string;
    sprs_points: number;
    poam_eligible: boolean;
  }>;
  source?: string;
}

export interface PoamItem {
  id: string;
  framework_id: string;
  requirement_id: string;
  control_id: string;
  title: string;
  weakness: string;
  status: "open" | "in_progress" | "completed" | "risk_accepted";
  owner: string;
  milestone: string;
  sprs_points: number;
  poam_eligible: boolean;
  due_at: string | null;
  remediation_task_id: string | null;
  created_by: string;
  created_at: string | null;
  updated_at: string | null;
  completed_at: string | null;
}

export interface PoamSyncResult {
  framework_id: string;
  sprs: SprsReport;
  created: number;
  updated: number;
  closed: number;
  open_poam_count: number;
}

export interface PricingTierLimits {
  max_users: number;
  max_api_keys: number;
  max_invites_pending: number;
  max_connectors: number;
  scim: boolean;
}

export interface PlatformUsage {
  tenant_id: string;
  plan_tier: string;
  plan_name: string;
  usage: {
    users: number;
    api_keys: number;
    invites_pending: number;
  };
  limits: PricingTierLimits;
  within_limits: {
    users: boolean;
    api_keys: boolean;
    invites_pending: boolean;
  };
}

export type RiskLevel = "low" | "medium" | "high" | "critical";
export type RiskStatus = "open" | "mitigating" | "accepted" | "closed";

export interface Risk {
  id: string;
  tenant_id?: string;
  title: string;
  description: string;
  category: string;
  severity: RiskLevel;
  likelihood: RiskLevel;
  impact: RiskLevel;
  status: RiskStatus;
  treatment: string;
  owner: string;
  control_id: string | null;
  asset_id: string | null;
  due_at: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface EvidenceRequestItem {
  id: string;
  control_id: string;
  requested_from: string;
  status: "open" | "fulfilled" | "cancelled";
  note: string;
  due_at: string | null;
  created_by: string;
  created_at: string | null;
  fulfilled_at: string | null;
}

export interface ControlExceptionItem {
  id: string;
  control_id: string;
  reason: string;
  approved_by: string;
  status: "pending" | "active" | "revoked" | "expired";
  active: boolean;
  expires_at: string | null;
  created_by: string;
  created_at: string | null;
  revoked_at: string | null;
}

// --- Tags + saved views -----------------------------------------------------

export interface Tag {
  id: string;
  tenant_id: string;
  name: string;
  color: string;
  created_at: string | null;
}

export interface EntityTag {
  id: string;
  tenant_id: string;
  tag_id: string;
  entity_type: string;
  entity_id: string;
  created_at: string | null;
}

export interface SavedView {
  id: string;
  tenant_id: string;
  surface: string;
  name: string;
  filters: Record<string, unknown>;
  created_by: string;
  created_at: string | null;
}

export interface PostureMetricPoint {
  id: string;
  tenant_id: string;
  captured_at: string;
  posture_score: number;
  control_pass_rate: number;
  open_violations: number;
  critical_violations: number;
  stale_controls: number;
  evidence_fresh_pct: number;
  remediation_open: number;
  remediation_overdue: number;
}

export interface RemediationInsights {
  open: number;
  overdue: number;
  mttr_hours: number | null;
  sla_attainment_pct: number | null;
  resolved_count: number;
  sla_eligible_count: number;
}

// --- Metrics & insights (populated by migration 0006_metrics) ---------------

export type SlaHeatmapColumn =
  | "open_on_track"
  | "open_overdue"
  | "open_no_sla"
  | "resolved_on_time"
  | "resolved_late";

export interface SlaHeatmapRow {
  priority: "critical" | "high" | "medium" | "low";
  open_on_track: number;
  open_overdue: number;
  open_no_sla: number;
  resolved_on_time: number;
  resolved_late: number;
}

export interface SlaHeatmapOwnerRow {
  owner: string;
  open_on_track: number;
  open_overdue: number;
  open_no_sla: number;
  resolved_on_time: number;
  resolved_late: number;
}

export interface SlaHeatmap {
  columns: SlaHeatmapColumn[];
  rows: SlaHeatmapRow[];
  owner_rows: SlaHeatmapOwnerRow[];
}

export interface FrameworkTrendPoint {
  at: string;
  source: "snapshot" | "current";
  snapshot_id: string | null;
  frameworks: Record<string, number>;
}

export interface FrameworkReadinessTrends {
  frameworks: string[];
  points: FrameworkTrendPoint[];
}

export type AccessReviewStatus = "draft" | "active" | "completed" | "cancelled";
export type AccessReviewDecision =
  "pending" | "certified" | "revoked" | "flagged";

export interface AccessReviewCampaign {
  id: string;
  name: string;
  description: string;
  scope: string;
  status: AccessReviewStatus;
  control_id: string | null;
  due_at: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  progress?: AccessReviewProgress;
}

export interface AccessReviewProgress {
  total: number;
  reviewed: number;
  pending: number;
  certified: number;
  revoked: number;
  flagged: number;
}

export interface AccessReviewItem {
  id: string;
  campaign_id: string;
  subject_id: string;
  subject_name: string;
  source: string;
  access_summary: string;
  decision: AccessReviewDecision;
  reviewer: string;
  note: string;
  decided_at: string | null;
  created_at: string;
}

export interface AccessReviewSeedResult {
  added: number;
  skipped: number;
  candidates: number;
}

export interface AccessReviewCoverage {
  control_id: string;
  framework: string | null;
  title: string | null;
  campaigns: number;
  completed_campaigns: number;
  last_completed_at: string | null;
  current: boolean;
  decisions: Record<AccessReviewDecision, number>;
}

export type PolicyDocumentStatus = "draft" | "published" | "archived";

export interface PolicyTemplateSummary {
  template_id: string;
  title: string;
  category?: string;
  framework_ids: string[];
  related_control_ids: string[];
  owner_role?: string;
  review_cadence_days?: number;
  summary?: string;
  variables: string[];
}

export interface PolicyTemplate extends PolicyTemplateSummary {
  body_markdown: string;
}

export interface PolicyDocument {
  id: string;
  template_id: string;
  title: string;
  status: PolicyDocumentStatus;
  content: string;
  variables: Record<string, string>;
  related_control_ids: string[];
  owner: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  published_at: string | null;
  review_due_at: string | null;
}

export interface PolicyAcknowledgment {
  id: string;
  policy_document_id: string;
  user_email: string;
  display_name: string;
  acknowledged_at: string;
}

export interface PolicyAttestationSummary {
  published: number;
  acknowledged: number;
  unattested: number;
  total_acknowledgments: number;
}

export interface PolicyCoverage {
  control_id: string;
  framework: string | null;
  title: string | null;
  template_ids: string[];
  published: boolean;
  current: boolean;
  document_id: string | null;
  document_title: string | null;
  published_at: string | null;
  review_due_at: string | null;
}

export type VendorRiskLevel = "low" | "medium" | "high" | "critical";
export type VendorAssessmentStatus =
  "draft" | "in_review" | "completed" | "rejected";
export type VendorAnswer = "yes" | "partial" | "no" | "na";

export interface VendorQuestionnaireTemplateSummary {
  template_id: string;
  name: string;
  description?: string;
  control_ids: string[];
  framework_ids: string[];
  risk_domains: string[];
  safeguard_ids: string[];
  mapping_status: "proposed" | "reviewed";
  mapped_question_count: number;
  question_count: number;
}

export interface VendorQuestionnaireQuestion {
  question_id: string;
  prompt: string;
  response_type: string;
  weight: number;
  required: boolean;
  mapping_status: "proposed" | "reviewed";
  safeguard_ids: string[];
  risk_domains: string[];
  framework_ids: string[];
  control_ids: string[];
  section_id?: string;
  section_title?: string;
}

export interface VendorQuestionnaireSection {
  section_id: string;
  title: string;
  questions: VendorQuestionnaireQuestion[];
}

export interface VendorQuestionnaireTemplate extends VendorQuestionnaireTemplateSummary {
  sections: VendorQuestionnaireSection[];
}

export interface VendorAssessment {
  id: string;
  vendor_name: string;
  template_id: string;
  status: VendorAssessmentStatus;
  control_id: string | null;
  owner: string;
  responses: Record<string, { answer?: VendorAnswer } | VendorAnswer | string>;
  score: number | null;
  risk_level: VendorRiskLevel | null;
  due_at: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  template?: VendorQuestionnaireTemplate;
}

export interface ControlRemediation {
  control_id: string;
  risk_domain: string | null;
  framework: string | null;
  title: string | null;
  matched: boolean;
  summary: string;
  steps: string[];
  references: string[];
}

export interface ScimToken {
  id: string;
  name: string;
  token_prefix: string;
  created_by: string;
  created_at: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
}

/** Returned once on creation; the plaintext token is never shown again. */
export interface CreatedScimToken extends ScimToken {
  token: string;
}

export interface BillingStatus {
  plan_tier: string | null;
  subscription_status: string | null;
  access: "active" | "grace" | "read_only";
  customer_linked: boolean;
  current_period_end: string | null;
  cancel_at_period_end: boolean;
  past_due_since: string | null;
  grace_days: number;
  self_serve_plans: string[];
}

// --- Mapping review (org overlay over shipped safeguard mappings) ---

export type MappingReviewState =
  | "maintainer_reviewed"
  | "org_reviewed"
  | "proposed"
  | "needs_changes"
  | "rejected";

export type MappingReviewDecisionKind = "approve" | "reject" | "needs_changes";

export interface MappingSourceAnchor {
  name: string;
  url: string;
  sha256: string;
  locator: string;
}

export interface MappingReviewDecisionSummary {
  decision_id: string;
  decision: MappingReviewDecisionKind;
  rationale: string;
  reviewer: string;
  reviewer_role: string | null;
  decided_at: string;
  evidence_ref: string | null;
}

export interface MappingReviewItem {
  safeguard_id: string;
  safeguard_title: string | null;
  risk_domain: string | null;
  control_id: string;
  control_title: string | null;
  framework_id: string;
  role: string | null;
  shipped_review_status: string;
  review_state: MappingReviewState;
  review_label: string;
  mapping_basis: string | null;
  reviewed_anchors: string[];
  mapping_source: MappingSourceAnchor | null;
  latest_decision: MappingReviewDecisionSummary | null;
  decision_count: number;
}

export interface MappingReviewDecision extends MappingReviewDecisionSummary {
  batch_id: string;
  safeguard_id: string;
  control_id: string;
  framework_id: string;
  reviewer_id: string | null;
  auth_method: string;
  source_anchor: MappingSourceAnchor | null;
  shipped_review_status: string;
  supersedes: string | null;
  prev_hash: string | null;
  record_hash: string;
}

export interface MappingReviewProgressRow {
  framework_id: string;
  mapped: number;
  maintainer_reviewed: number;
  org_reviewed: number;
  needs_changes: number;
  rejected: number;
  pending: number;
}

export interface MappingReviewSummary {
  frameworks: MappingReviewProgressRow[];
  framework_names: Record<string, string>;
  families: Array<{
    family_id: string;
    label: string;
    category_id: string;
    category_label: string;
  }>;
  totals: Omit<MappingReviewProgressRow, "framework_id">;
  states: Record<MappingReviewState, string>;
  decision_log: {
    ok: boolean;
    length: number | null;
    tip_hash: string | null;
    issues: string[];
  };
}

export interface MappingReviewQueueParams {
  framework_id?: string;
  family?: string;
  status?: string;
  q?: string;
  limit: number;
  offset: number;
}

export interface MappingReviewQueuePage {
  items: MappingReviewItem[];
  count: number;
}

export interface MappingReviewDecisionRequest {
  decision: MappingReviewDecisionKind;
  rationale: string;
  evidence_ref?: string;
  items: Array<{
    safeguard_id: string;
    control_id: string;
    framework_id: string;
  }>;
}

/** Published CCF results cover observed assets; inventory completeness is separate. */
export interface CcfAssessment {
  schema_version: string;
  status?: "not_evaluated";
  scope: "observed_assets";
  population_completeness: "not_established";
  asset_count?: number;
  review_log_verified?: boolean;
  safeguards: {
    safeguard_id: string;
    title: string;
    status: "pass" | "fail" | "stale" | "not_evaluated";
    assessed_asset_count: number;
    applicable_asset_count: number;
    unassessed_asset_count: number;
  }[];
  requirements: { control_id: string; status: string }[];
}

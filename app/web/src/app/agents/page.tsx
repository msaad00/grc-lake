"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  Bot,
  ClipboardCopy,
  Gauge,
  GitBranch,
  Loader2,
  LockKeyhole,
  Play,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { notify } from "@/lib/toast";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { McpSetupStrip } from "@/components/agents/McpSetupStrip";
import {
  AgentDecisionCard,
  modeLabel,
  modeTone,
} from "@/components/agents/AgentDecisionCard";
import { AgentRunDrawer } from "@/components/drawers/AgentRunDrawer";
import { useAuditorMode } from "@/lib/state/auditor";
import { useAgentRuns, useCreateAgentRunMutation } from "@/lib/api/hooks";
import type { AgentHarness } from "@/lib/api/types";
import { ROUTE_LABELS } from "@/lib/console-copy";

type BadgeTone = "ready" | "info" | "attention" | "critical" | "default";

interface RouteSpec {
  method: "GET" | "POST";
  path: string;
  description: string;
  scope:
    | "agents"
    | "posture"
    | "controls"
    | "evidence"
    | "assets"
    | "snapshots"
    | "workflows"
    | "trust"
    | "audit"
    | "graph";
  body_example?: Record<string, unknown>;
  path_params?: Array<{ name: string; placeholder: string }>;
}

const ROUTES: RouteSpec[] = [
  {
    method: "GET",
    path: "/api/v1/agent-runs?limit=10",
    description: "Recent governed harness runs.",
    scope: "agents",
  },
  {
    method: "POST",
    path: "/api/v1/agent-runs",
    description: "Run a deterministic harness and persist evals + decisions.",
    scope: "agents",
    body_example: {
      harness: "posture_review",
      objective: "review current trust gaps",
      role: "analyst",
      use_model: false,
      idempotency_key: "manual-posture-review",
    },
  },
  {
    method: "POST",
    path: "/api/v1/agent-runs/{run_id}/decisions/{decision_index}/approve",
    description: "Approve one proposed write through the guarded executor.",
    scope: "agents",
    path_params: [
      { name: "run_id", placeholder: "run_..." },
      { name: "decision_index", placeholder: "0" },
    ],
    body_example: { note: "approved from console" },
  },
  {
    method: "GET",
    path: "/api/v1/healthz",
    description: "Server liveness envelope.",
    scope: "posture",
  },
  {
    method: "GET",
    path: "/api/v1/posture/current",
    description: "Full assessment posture + violations + frameworks.",
    scope: "posture",
  },
  {
    method: "GET",
    path: "/api/v1/control-tests?result=fail&limit=10",
    description: "Paginated control test results with confidence + freshness.",
    scope: "controls",
  },
  {
    method: "GET",
    path: "/api/v1/controls?sort=-risk_score",
    description: "Sortable control posture catalog.",
    scope: "controls",
  },
  {
    method: "GET",
    path: "/api/v1/violations?severity=critical,high",
    description: "Filterable open control failures.",
    scope: "controls",
  },
  {
    method: "GET",
    path: "/api/v1/evidence?control_ids=SOC2-CC6.1",
    description: "Filterable silver normalized events.",
    scope: "evidence",
  },
  {
    method: "GET",
    path: "/api/v1/assets?sort=-risk_score",
    description: "Sortable asset risk roll-up.",
    scope: "assets",
  },
  {
    method: "GET",
    path: "/api/v1/snapshots",
    description: "Point-in-time snapshot list.",
    scope: "snapshots",
  },
  {
    method: "POST",
    path: "/api/v1/snapshots",
    description: "Freeze a snapshot.",
    scope: "snapshots",
    body_example: { reason: "audit_request" },
  },
  {
    method: "GET",
    path: "/api/v1/connectors",
    description: "Connector catalog with live sync health.",
    scope: "controls",
  },
  {
    method: "POST",
    path: "/api/v1/connectors/{connector_id}/probe",
    description: "Test read-only access before enablement.",
    scope: "controls",
    path_params: [{ name: "connector_id", placeholder: "github-security" }],
    body_example: {
      actor: "coding-agent",
      credentials: {
        credential_ref: "TRUSTOPS_GITHUB_APP_INSTALLATION_TOKEN",
      },
      options: { repo: "acme/platform" },
    },
  },
  {
    method: "POST",
    path: "/api/v1/connectors/{connector_id}/configure",
    description: "Enable or disable after a successful probe.",
    scope: "controls",
    path_params: [{ name: "connector_id", placeholder: "github-security" }],
    body_example: {
      state: "enabled",
      actor: "coding-agent",
      credentials: {
        credential_ref: "TRUSTOPS_GITHUB_APP_INSTALLATION_TOKEN",
      },
      options: { repo: "acme/platform" },
    },
  },
  {
    method: "POST",
    path: "/api/v1/connectors/{connector_id}/sync",
    description: "Sync evidence from an enabled connector.",
    scope: "controls",
    path_params: [{ name: "connector_id", placeholder: "github-security" }],
    body_example: { actor: "coding-agent" },
  },
  {
    method: "POST",
    path: "/api/v1/ingestion/eval",
    description: "Run control evaluation over synced evidence.",
    scope: "controls",
    body_example: { actor: "coding-agent" },
  },
  {
    method: "GET",
    path: "/api/v1/ingestion/status",
    description: "Source sync health, schedules, and eval runs.",
    scope: "posture",
  },
  {
    method: "GET",
    path: "/api/v1/frameworks",
    description: "Framework registry + provenance + coverage.",
    scope: "controls",
  },
  {
    method: "GET",
    path: "/api/v1/workflows",
    description: "Workflow list (latest version per id).",
    scope: "workflows",
  },
  {
    method: "GET",
    path: "/api/v1/workflows/actions",
    description: "Action library with input/output schemas.",
    scope: "workflows",
  },
  {
    method: "POST",
    path: "/api/v1/workflows/actions/run",
    description: "Execute a single action against the lake.",
    scope: "workflows",
    body_example: {
      node_type: "check.evidence_exists",
      params: { control_id: "SOC2-CC6.1", minimum: 1 },
    },
  },
  {
    method: "GET",
    path: "/api/v1/trust-shares",
    description: "List active trust-share tokens.",
    scope: "trust",
  },
  {
    method: "POST",
    path: "/api/v1/trust-shares",
    description: "Issue a new auditor share (returns raw token once).",
    scope: "trust",
    body_example: {
      role: "auditor",
      scope: "posture_full",
      expires_in_hours: 24,
    },
  },
  {
    method: "GET",
    path: "/api/v1/audit-log",
    description: "Unified activity stream across every append-only log.",
    scope: "audit",
  },
  {
    method: "GET",
    path: "/api/v1/platform/audit-readiness",
    description: "Audit score, per-framework coverage, and blocking gaps.",
    scope: "posture",
  },
  {
    method: "GET",
    path: "/api/v1/platform/ai-governance",
    description:
      "AI model inventory, lineage, model-card artifacts, and NIST AI RMF / ISO 42001 / EU AI Act mapping.",
    scope: "posture",
  },
  {
    method: "GET",
    path: "/api/v1/graph",
    description: "Framework -> control -> evidence -> asset graph.",
    scope: "graph",
  },
  {
    method: "GET",
    path: "/api/v1/crosswalk",
    description: "Framework x framework cross-mapping matrix.",
    scope: "graph",
  },
];

interface AgentSkill {
  id: string;
  label: string;
  detail: string;
  mcp_tools: string[];
  route_path: string;
}

const AGENT_SKILLS: AgentSkill[] = [
  {
    id: "ingestion.connect",
    label: "Connect source",
    detail: "Agentless read-only: probe → enable → sync → eval",
    mcp_tools: [
      "probe_connector",
      "configure_connector",
      "sync_connector",
      "run_lake_eval",
    ],
    route_path: "/api/v1/connectors/{connector_id}/probe",
  },
  {
    id: "posture.read",
    label: "Read posture",
    detail: "Posture, failing tests, violations, evidence freshness",
    mcp_tools: ["get_posture", "list_violations", "get_ingestion_status"],
    route_path: "/api/v1/posture/current",
  },
  {
    id: "audit.prove",
    label: "Audit prove",
    detail: "Snapshots, trust shares, activity export",
    mcp_tools: ["create_snapshot", "list_audit_log", "create_trust_share"],
    route_path: "/api/v1/snapshots",
  },
  {
    id: "remediate.propose",
    label: "Propose remediation",
    detail: "Harness runs with approval-gated writes",
    mcp_tools: ["create_agent_run", "approve_agent_decision"],
    route_path: "/api/v1/agent-runs",
  },
];

const SCOPE_TONE: Record<RouteSpec["scope"], BadgeTone> = {
  agents: "info",
  posture: "info",
  controls: "ready",
  evidence: "info",
  assets: "attention",
  snapshots: "critical",
  workflows: "ready",
  trust: "critical",
  audit: "default",
  graph: "info",
};

const HARNESS_COPY: Record<
  "posture_review" | "soc_triage",
  { label: string; objective: string; icon: typeof ShieldCheck }
> = {
  posture_review: {
    label: "Run posture review",
    objective: "review current trust gaps and propose governed next actions",
    icon: ShieldCheck,
  },
  soc_triage: {
    label: "Run SOC triage",
    objective:
      "triage current security signals and propose governed next actions",
    icon: GitBranch,
  },
};

function expandPath(route: RouteSpec, params: Record<string, string>): string {
  let path = route.path;
  for (const p of route.path_params ?? []) {
    const value = params[p.name] || p.placeholder;
    path = path.replace(`{${p.name}}`, encodeURIComponent(value));
  }
  return path;
}

function curlFor(
  route: RouteSpec,
  path: string,
  body: string,
  role: string,
): string {
  const lines: string[] = [`curl -s -X ${route.method} \\`];
  if (role) lines.push(`  -H 'X-Trust-Role: ${role}' \\`);
  if (route.method === "POST") {
    lines.push(`  -H 'content-type: application/json' \\`);
    lines.push(`  -d '${body || "{}"}' \\`);
  }
  lines.push(`  http://127.0.0.1:8787${path}`);
  return lines.join("\n");
}

function toneForStatus(status: string | undefined): BadgeTone {
  if (status === "completed" || status === "executed" || status === "approved")
    return "ready";
  if (status === "failed") return "critical";
  if (status === "proposed") return "attention";
  return "default";
}

function toneForConfidence(confidence: string | undefined): BadgeTone {
  if (confidence === "high") return "ready";
  if (confidence === "medium") return "attention";
  if (confidence === "low") return "critical";
  return "default";
}

function shortHash(value: string | null | undefined): string {
  if (!value) return "none";
  return value.length <= 10 ? value : value.slice(0, 10);
}

function formatTime(value: string | null | undefined): string {
  if (!value) return "pending";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(date);
}

function jsonPreview(value: unknown): string {
  if (!value || typeof value !== "object") return "{}";
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return "{}";
  }
}

function harnessLabel(harness: AgentHarness): string {
  return harness.replaceAll("_", " ");
}

type Orchestrator = "sequential" | "langgraph";
type BudgetProfile = "small" | "standard";

const BUDGETS: Record<
  BudgetProfile,
  {
    label: string;
    max_fact_items: number;
    max_context_chars: number;
    max_output_tokens: number;
  }
> = {
  small: {
    label: "Small context",
    max_fact_items: 20,
    max_context_chars: 12000,
    max_output_tokens: 600,
  },
  standard: {
    label: "Standard review",
    max_fact_items: 40,
    max_context_chars: 20000,
    max_output_tokens: 900,
  },
};

function AgentsPageContent() {
  const searchParams = useSearchParams();
  const onboarding = searchParams.get("onboarding") === "1";
  const auditor = useAuditorMode();
  const agentRuns = useAgentRuns();
  const createRun = useCreateAgentRunMutation();
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [drawerRunId, setDrawerRunId] = useState<string | null>(null);
  const [selected, setSelected] = useState<RouteSpec>(ROUTES[0]);
  const [pathParams, setPathParams] = useState<Record<string, string>>({});
  const [body, setBody] = useState(
    ROUTES[0].body_example
      ? JSON.stringify(ROUTES[0].body_example, null, 2)
      : "",
  );
  const [role, setRole] = useState(auditor ? "auditor" : "");
  const [response, setResponse] = useState<string | null>(null);
  const [status, setStatus] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [orchestrator, setOrchestrator] = useState<Orchestrator>("sequential");
  const [useModel, setUseModel] = useState(false);
  const [budgetProfile, setBudgetProfile] = useState<BudgetProfile>("small");

  const runs = useMemo(() => agentRuns.data ?? [], [agentRuns.data]);
  const selectedRun =
    runs.find((run) => run.id === selectedRunId) ?? runs[0] ?? null;
  const pendingDecisionCount = runs.reduce(
    (sum, run) =>
      sum +
      run.decisions.filter((decision) => decision.status === "proposed").length,
    0,
  );

  useEffect(() => {
    if (!selectedRunId && runs[0]) setSelectedRunId(runs[0].id);
  }, [runs, selectedRunId]);

  useEffect(() => {
    if (!onboarding) return;
    document
      .getElementById("start-harness")
      ?.scrollIntoView({ behavior: "smooth" });
  }, [onboarding]);

  const flash = (msg: string) => notify.message(msg);

  const path = useMemo(
    () => expandPath(selected, pathParams),
    [selected, pathParams],
  );
  const curl = useMemo(
    () => curlFor(selected, path, body, role),
    [selected, path, body, role],
  );

  const runHarness = async (harness: "posture_review" | "soc_triage") => {
    const spec = HARNESS_COPY[harness];
    const budget = BUDGETS[budgetProfile];
    const safeOrchestrator = orchestrator;
    try {
      const run = await createRun.mutateAsync({
        harness,
        objective: spec.objective,
        orchestrator: safeOrchestrator,
        use_model: useModel,
        idempotency_key: `console-${harness}-${Date.now()}`,
        max_fact_items: budget.max_fact_items,
        max_context_chars: budget.max_context_chars,
        max_output_tokens: budget.max_output_tokens,
      });
      setSelectedRunId(run.id);
      flash("Harness run saved.");
    } catch (err) {
      flash(String((err as Error).message));
    }
  };

  const execute = async () => {
    setBusy(true);
    setResponse(null);
    setStatus(null);
    try {
      const init: RequestInit = {
        method: selected.method,
        headers: {
          ...(role ? { "X-Trust-Role": role } : {}),
          ...(selected.method === "POST"
            ? { "content-type": "application/json" }
            : {}),
        },
      };
      if (selected.method === "POST") init.body = body || "{}";
      const res = await fetch(path, init);
      setStatus(res.status);
      const text = await res.text();
      try {
        setResponse(JSON.stringify(JSON.parse(text), null, 2));
      } catch {
        setResponse(text);
      }
    } catch (err) {
      setResponse(String((err as Error).message));
    } finally {
      setBusy(false);
    }
  };

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      flash("Copied.");
    } catch {
      flash("Clipboard unavailable.");
    }
  };

  const selectRoute = (route: RouteSpec) => {
    setSelected(route);
    setPathParams({});
    setBody(
      route.body_example ? JSON.stringify(route.body_example, null, 2) : "",
    );
    setResponse(null);
    setStatus(null);
  };

  const selectSkill = (skill: AgentSkill) => {
    const match =
      ROUTES.find((route) => route.path === skill.route_path) ?? ROUTES[0];
    selectRoute(match);
  };

  return (
    <div className="page-shell grid gap-5">
      <PageHeader
        eyebrow="Agent harness"
        title={ROUTE_LABELS["/agents"]}
        description="Run deterministic harnesses, inspect evaluations, and approve proposed writes."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={agentRuns.isError ? "critical" : "info"}>
              <Bot className="mr-1 h-3 w-3" /> {runs.length}{" "}
              {runs.length === 1 ? "run" : "runs"}
            </Badge>
            {pendingDecisionCount > 0 && (
              <Badge tone="attention">{pendingDecisionCount} pending</Badge>
            )}
          </div>
        }
      />

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Agent skills</CardTitle>
          <CardDescription className="text-xs">
            Ready-made bundles that use the same routes as MCP and CI. Pick one
            to load its route in the API runner below.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
          {AGENT_SKILLS.map((skill) => (
            <button
              key={skill.id}
              type="button"
              onClick={() => selectSkill(skill)}
              className="rounded-lg border border-line bg-surface p-3 text-left transition-colors hover:border-brand"
            >
              <div className="text-xs font-black text-brand">{skill.id}</div>
              <div className="mt-1 text-sm font-black text-ink">
                {skill.label}
              </div>
              <div className="mt-1 text-xs leading-4 text-muted">
                {skill.detail}
              </div>
              <div className="mt-2 flex flex-wrap gap-1">
                {skill.mcp_tools.slice(0, 2).map((tool) => (
                  <Badge key={tool} tone="info" className="!text-[10px]">
                    {tool}
                  </Badge>
                ))}
              </div>
            </button>
          ))}
        </CardContent>
      </Card>

      <McpSetupStrip />

      <div className="grid gap-5 xl:grid-cols-[minmax(0,420px)_minmax(0,1fr)]">
        <Card className="overflow-hidden" id="start-harness">
          <CardHeader>
            <CardTitle>Start a harness</CardTitle>
            <CardDescription>
              {onboarding
                ? "Step 1 — run a fixture-mode review (no model required), then approve any proposed writes."
                : "Choose orchestration and budget, then run an approval-gated review."}
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3">
            <div className="grid gap-3 rounded-xl border border-line bg-surfaceMuted p-3">
              <div className="grid gap-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-xs font-black uppercase tracking-wide text-muted">
                    Orchestrator
                  </span>
                  <Badge tone={orchestrator === "langgraph" ? "info" : "ready"}>
                    {orchestrator}
                  </Badge>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  {(["sequential", "langgraph"] as const).map((value) => (
                    <button
                      key={value}
                      type="button"
                      onClick={() => setOrchestrator(value)}
                      className={[
                        "rounded-lg border px-3 py-2 text-left text-xs font-black capitalize",
                        orchestrator === value
                          ? "border-brand bg-blue-50 text-brand dark:bg-blue-500/10"
                          : "border-line bg-surface text-ink",
                      ].join(" ")}
                    >
                      {value}
                    </button>
                  ))}
                </div>
              </div>

              <label className="flex cursor-pointer items-start gap-2 rounded-lg border border-line bg-surface p-3">
                <input
                  type="checkbox"
                  checked={useModel}
                  onChange={(event) => setUseModel(event.target.checked)}
                  className="mt-1"
                />
                <span className="min-w-0">
                  <span className="block text-xs font-black text-ink">
                    Fixture mode (rules-only, no model)
                  </span>
                  <span className="mt-0.5 block text-xs leading-5 text-muted">
                    Default for analyst runs — deterministic evals against the
                    loaded lake. Enable only when a configured model provider is
                    required.
                  </span>
                </span>
              </label>

              <label className="grid gap-1 text-xs font-black uppercase tracking-wide text-muted">
                Budget
                <select
                  aria-label="Budget profile"
                  value={budgetProfile}
                  onChange={(event) =>
                    setBudgetProfile(event.target.value as BudgetProfile)
                  }
                  className="rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-brand"
                >
                  {Object.entries(BUDGETS).map(([value, budget]) => (
                    <option key={value} value={value}>
                      {budget.label} · {budget.max_fact_items} facts ·{" "}
                      {budget.max_output_tokens} tokens
                    </option>
                  ))}
                </select>
              </label>
            </div>

            <div className="grid gap-2 sm:grid-cols-3 xl:grid-cols-1">
              <div className="rounded-lg border border-line bg-surface p-3">
                <LockKeyhole className="h-4 w-4 text-brand" />
                <div className="mt-2 text-xs font-black text-ink">
                  Writes require approval
                </div>
              </div>
              <div className="rounded-lg border border-line bg-surface p-3">
                <Gauge className="h-4 w-4 text-brand" />
                <div className="mt-2 text-xs font-black text-ink">
                  Budget is enforced
                </div>
              </div>
              <div className="rounded-lg border border-line bg-surface p-3">
                <ShieldCheck className="h-4 w-4 text-brand" />
                <div className="mt-2 text-xs font-black text-ink">
                  Core owns verdicts
                </div>
              </div>
            </div>

            {(["posture_review", "soc_triage"] as const).map((harness) => {
              const spec = HARNESS_COPY[harness];
              const Icon = spec.icon;
              return (
                <Button
                  key={harness}
                  variant="default"
                  className="h-auto justify-start whitespace-normal px-3 py-3 text-left"
                  disabled={createRun.isPending}
                  onClick={() => runHarness(harness)}
                >
                  {createRun.isPending ? (
                    <Loader2 className="h-4 w-4 shrink-0 animate-spin" />
                  ) : (
                    <Icon className="h-4 w-4 shrink-0" />
                  )}
                  <span className="min-w-0">
                    <span className="block">{spec.label}</span>
                    <span className="block truncate text-xs font-bold text-muted">
                      {harness === "posture_review"
                        ? `${orchestrator} · ${useModel ? "model assisted" : "fixture mode"}`
                        : `${orchestrator} · ${useModel ? "model assisted" : "fixture mode"}`}
                    </span>
                  </span>
                </Button>
              );
            })}
            {agentRuns.isError && (
              <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-sm font-bold text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-300">
                Agent run API is unreachable.
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="overflow-hidden">
          <CardHeader className="flex-row items-start justify-between gap-3">
            <div className="min-w-0">
              <CardTitle>Recent runs</CardTitle>
              <CardDescription>
                Persisted evals, decisions, budget, and input hash.
              </CardDescription>
            </div>
            {agentRuns.isFetching && (
              <Loader2 className="mt-0.5 h-4 w-4 shrink-0 animate-spin text-muted" />
            )}
          </CardHeader>
          <div className="grid max-h-[360px] gap-2 overflow-auto p-4 pt-0">
            {runs.length === 0 ? (
              <div className="rounded-lg border border-dashed border-line px-4 py-8 text-center text-sm font-bold text-muted">
                No persisted runs yet.
              </div>
            ) : (
              runs.map((run) => (
                <div
                  key={run.id}
                  className={[
                    "grid min-w-0 gap-2 rounded-lg border px-3 py-3 transition",
                    selectedRun?.id === run.id
                      ? "border-brand bg-blue-50 dark:bg-blue-500/10"
                      : "border-line bg-surface hover:bg-surfaceMuted",
                  ].join(" ")}
                >
                  <button
                    type="button"
                    onClick={() => setSelectedRunId(run.id)}
                    className="grid min-w-0 gap-2 text-left"
                  >
                    <div className="flex min-w-0 flex-wrap items-center gap-2">
                      <span className="truncate text-sm font-black capitalize text-ink">
                        {harnessLabel(run.harness)}
                      </span>
                      <Badge tone={toneForStatus(run.status)}>
                        {run.status}
                      </Badge>
                      <Badge tone={modeTone(run.mode)}>
                        {modeLabel(run.mode)}
                      </Badge>
                      <Badge
                        tone={toneForConfidence(run.evaluation.confidence)}
                      >
                        {run.evaluation.confidence ?? "no confidence"}
                      </Badge>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-xs font-bold text-muted md:grid-cols-4">
                      <span>{run.decisions.length} decisions</span>
                      <span>{run.evaluation.score ?? 0} score</span>
                      <span>{shortHash(run.input_hash)}</span>
                      <span>{formatTime(run.created_at)}</span>
                    </div>
                  </button>
                  <div className="flex justify-end">
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => setDrawerRunId(run.id)}
                    >
                      View details
                    </Button>
                  </div>
                </div>
              ))
            )}
          </div>
        </Card>
      </div>

      <Card className="overflow-hidden">
        <CardHeader className="flex-row items-start justify-between gap-3">
          <div className="min-w-0">
            <CardTitle>Decision review</CardTitle>
            <CardDescription>
              Only allowlisted actions can execute from approval.
            </CardDescription>
          </div>
          {selectedRun && (
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={toneForStatus(selectedRun.status)}>
                {selectedRun.status}
              </Badge>
              <Badge tone={modeTone(selectedRun.mode)}>
                {modeLabel(selectedRun.mode)}
              </Badge>
            </div>
          )}
        </CardHeader>
        <CardContent>
          {!selectedRun ? (
            <div className="rounded-lg border border-dashed border-line px-4 py-8 text-center text-sm font-bold text-muted">
              Select or create a run.
            </div>
          ) : (
            <div className="grid gap-4">
              <div className="grid gap-3 rounded-lg border border-line bg-surfaceMuted p-3 md:grid-cols-4">
                <div>
                  <div className="text-xs font-black uppercase tracking-wide text-muted">
                    Harness
                  </div>
                  <div className="truncate text-sm font-black capitalize text-ink">
                    {harnessLabel(selectedRun.harness)}
                  </div>
                </div>
                <div>
                  <div className="text-xs font-black uppercase tracking-wide text-muted">
                    Confidence
                  </div>
                  <div className="text-sm font-black text-ink">
                    {selectedRun.evaluation.confidence ?? "none"}
                  </div>
                </div>
                <div>
                  <div className="text-xs font-black uppercase tracking-wide text-muted">
                    Input hash
                  </div>
                  <code className="block truncate text-sm font-black text-ink">
                    {shortHash(selectedRun.input_hash)}
                  </code>
                </div>
                <div>
                  <div className="text-xs font-black uppercase tracking-wide text-muted">
                    Budget
                  </div>
                  <div className="truncate text-sm font-black text-ink">
                    {jsonPreview(selectedRun.budget).replace(/\s+/g, " ")}
                  </div>
                </div>
              </div>

              {selectedRun.errors.length > 0 && (
                <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-sm font-bold text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-300">
                  {selectedRun.errors.join(" ")}
                </div>
              )}

              {selectedRun.state &&
              typeof selectedRun.state === "object" &&
              (
                selectedRun.state as {
                  data_readiness?: {
                    status?: string;
                    recommended_next_steps?: string[];
                  };
                }
              ).data_readiness?.status === "needs_ingestion" ? (
                <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-3 text-sm text-amber-950 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-300">
                  <div className="font-black">Lake needs ingestion</div>
                  <p className="mt-1 font-bold leading-5">
                    Fixture mode is ready, but this lake has no assessment data
                    yet. Load the golden fixture or connect a source, then
                    re-run the harness.
                  </p>
                  <ul className="mt-2 list-disc pl-5 text-xs font-bold">
                    {(
                      (
                        selectedRun.state as {
                          data_readiness?: {
                            recommended_next_steps?: string[];
                          };
                        }
                      ).data_readiness?.recommended_next_steps ?? []
                    )
                      .slice(0, 3)
                      .map((step) => (
                        <li key={step}>{step}</li>
                      ))}
                  </ul>
                </div>
              ) : null}

              <div className="grid gap-3">
                {selectedRun.decisions.length === 0 ? (
                  <div className="rounded-lg border border-dashed border-line px-4 py-6 text-sm font-bold text-muted">
                    This run did not propose any writes.
                  </div>
                ) : (
                  selectedRun.decisions.map((decision, index) => (
                    <AgentDecisionCard
                      key={`${selectedRun.id}-${index}`}
                      run={selectedRun}
                      decision={decision}
                      decisionIndex={index}
                    />
                  ))
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <details className="grid gap-3 rounded-xl border border-line bg-surface p-4">
        <summary className="flex min-w-0 cursor-pointer list-none flex-wrap items-center justify-between gap-2">
          <div className="min-w-0">
            <h2 className="text-lg font-black text-ink">API runner</h2>
            <p className="text-sm font-bold text-muted">
              Advanced contracts for CLI, scheduler, MCP, and headless agents.
            </p>
          </div>
          <Badge tone="info">
            <Sparkles className="mr-1 h-3 w-3" /> {ROUTES.length} routes
          </Badge>
        </summary>

        <div className="mt-4 grid gap-5 lg:grid-cols-[320px_minmax(0,1fr)]">
          <Card className="overflow-hidden">
            <CardHeader>
              <CardTitle>Routes</CardTitle>
              <CardDescription>Click to load into the runner.</CardDescription>
            </CardHeader>
            <div className="grid gap-1 p-4 pt-0">
              {ROUTES.map((route) => (
                <button
                  key={route.method + route.path}
                  type="button"
                  onClick={() => selectRoute(route)}
                  className={[
                    "grid grid-cols-[auto_minmax(0,1fr)] items-center gap-2 rounded-lg px-2 py-1.5 text-left text-xs",
                    selected.method + selected.path ===
                    route.method + route.path
                      ? "bg-ink text-surface"
                      : "text-ink hover:bg-surfaceMuted",
                  ].join(" ")}
                >
                  <Badge tone={route.method === "POST" ? "critical" : "ready"}>
                    {route.method}
                  </Badge>
                  <code className="truncate">{route.path}</code>
                </button>
              ))}
            </div>
          </Card>

          <div className="grid gap-5">
            <Card className="overflow-hidden">
              <CardHeader>
                <CardTitle className="flex min-w-0 flex-wrap items-center gap-2">
                  <Badge
                    tone={selected.method === "POST" ? "critical" : "ready"}
                  >
                    {selected.method}
                  </Badge>
                  <code className="min-w-0 truncate text-sm text-ink">
                    {selected.path}
                  </code>
                  <Badge tone={SCOPE_TONE[selected.scope]}>
                    {selected.scope}
                  </Badge>
                </CardTitle>
                <CardDescription>{selected.description}</CardDescription>
              </CardHeader>
              <div className="grid gap-3 p-5 pt-0">
                {(selected.path_params ?? []).map((p) => (
                  <label
                    key={p.name}
                    className="grid gap-1 text-xs font-black uppercase tracking-wide text-muted"
                  >
                    {p.name}
                    <input
                      value={pathParams[p.name] ?? ""}
                      placeholder={p.placeholder}
                      onChange={(e) =>
                        setPathParams((prev) => ({
                          ...prev,
                          [p.name]: e.target.value,
                        }))
                      }
                      className="rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-brand"
                    />
                  </label>
                ))}
                <label className="grid gap-1 text-xs font-black uppercase tracking-wide text-muted">
                  X-Trust-Role (optional)
                  <input
                    value={role}
                    onChange={(e) => setRole(e.target.value)}
                    placeholder="auditor (leave blank for default)"
                    className="rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-brand"
                  />
                </label>
                {selected.method === "POST" && (
                  <label className="grid gap-1 text-xs font-black uppercase tracking-wide text-muted">
                    Body (JSON)
                    <textarea
                      rows={6}
                      value={body}
                      onChange={(e) => setBody(e.target.value)}
                      className="rounded-lg border border-line bg-surface px-3 py-2 font-mono text-xs text-ink focus:outline-none focus:ring-1 focus:ring-brand"
                    />
                  </label>
                )}
                <div className="flex flex-wrap items-center gap-2">
                  <Button variant="primary" onClick={execute} disabled={busy}>
                    {busy ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Play className="h-4 w-4" />
                    )}{" "}
                    Run
                  </Button>
                  <Button variant="default" onClick={() => copy(curl)}>
                    <ClipboardCopy className="h-4 w-4" /> Copy curl
                  </Button>
                </div>
              </div>
            </Card>

            <Card className="overflow-hidden">
              <CardHeader>
                <CardTitle>curl</CardTitle>
                <CardDescription>
                  Reproduce this call from any shell.
                </CardDescription>
              </CardHeader>
              <pre className="overflow-auto bg-slate-950 p-4 text-xs text-slate-100">
                {curl}
              </pre>
            </Card>

            <Card className="overflow-hidden">
              <CardHeader>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <CardTitle>Response</CardTitle>
                  {status !== null && (
                    <Badge
                      tone={
                        status < 300
                          ? "ready"
                          : status < 500
                            ? "attention"
                            : "critical"
                      }
                    >
                      {status}
                    </Badge>
                  )}
                </div>
                <CardDescription>
                  Raw response from the selected endpoint.
                </CardDescription>
              </CardHeader>
              <pre className="max-h-[420px] overflow-auto bg-surfaceMuted p-4 text-xs text-ink">
                {response ?? "Click Run to fire the request."}
              </pre>
            </Card>
          </div>
        </div>
      </details>

      <AgentRunDrawer
        runId={drawerRunId}
        onClose={() => setDrawerRunId(null)}
      />
    </div>
  );
}

export default function AgentsPage() {
  return (
    <Suspense
      fallback={
        <div className="px-7 py-5 text-sm text-muted">
          Loading agent harness…
        </div>
      }
    >
      <AgentsPageContent />
    </Suspense>
  );
}

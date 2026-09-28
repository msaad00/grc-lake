"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { MarkerType, type Edge } from "@xyflow/react";
import {
  LayoutTemplate,
  Loader2,
  Play,
  Plus,
  Save,
  ServerCog,
  Shuffle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { notify } from "@/lib/toast";
import { ActionPalette } from "@/components/workflow/ActionPalette";
import { NodeConfigPanel } from "@/components/workflow/NodeConfigPanel";
import { RunInspectorDrawer } from "@/components/workflow/RunInspectorDrawer";
import { TemplateGallery } from "@/components/workflow/TemplateGallery";
import {
  WorkflowCanvas,
  toFlowNode,
  type FlowNode,
} from "@/components/workflow/WorkflowCanvas";
import {
  useActionCatalog,
  useApproveWorkflowRun,
  useRejectWorkflowRun,
  useRetryWorkflowRun,
  useRunWorkflow,
  useSaveWorkflow,
  useWorkflowRuns,
  useWorkflows,
} from "@/lib/api/hooks";
import type {
  ActionSpec,
  Workflow,
  WorkflowNode,
  WorkflowRun,
} from "@/lib/api/types";
import { useAuditorMode } from "@/lib/state/auditor";
import type { WorkflowTemplate } from "@/lib/workflow/templates";
import { WORKFLOW_TEMPLATES } from "@/lib/workflow/templates";
import { ROUTE_LABELS } from "@/lib/console-copy";
import { QueryState } from "@/components/QueryState";
import { displayLabel } from "@/lib/display";
import { plural } from "@/lib/format";

const NEW_WORKFLOW_ID = "__new__";

let counter = 0;
const nextNodeId = () => `n${Date.now()}_${counter++}`;

interface Editor {
  workflow_id: string | null;
  name: string;
  description: string;
  nodes: FlowNode[];
  edges: Edge[];
}

type WorkflowCondition = "always" | "passed" | "failed";

function emptyEditor(): Editor {
  return {
    workflow_id: null,
    name: "Untitled workflow",
    description: "",
    nodes: [],
    edges: [],
  };
}

const STARTER_TEMPLATE =
  WORKFLOW_TEMPLATES.find(
    (template) => template.id === "evidence-missing-alert",
  ) ?? WORKFLOW_TEMPLATES[0];

function starterEditor(catalog: ActionSpec[] = []): Editor {
  return STARTER_TEMPLATE
    ? fromTemplate(STARTER_TEMPLATE, catalog)
    : emptyEditor();
}

function firstNodeId(editor: Editor): string | null {
  return editor.nodes[0]?.id ?? null;
}

function edgeTone(condition: WorkflowCondition) {
  if (condition === "passed") return "#16b364";
  if (condition === "failed") return "#d92d20";
  return "#64748b";
}

function toFlowEdge(
  source: string,
  target: string,
  condition: WorkflowCondition = "always",
  index = 0,
): Edge {
  const tone = edgeTone(condition);
  return {
    id: `${source}-${target}-${index}`,
    source,
    target,
    animated: true,
    label: condition === "always" ? undefined : condition,
    data: { condition },
    markerEnd: { type: MarkerType.ArrowClosed, color: tone },
    style: { stroke: tone, strokeWidth: 2 },
  };
}

function arrangeNodes(nodes: FlowNode[], edges: Edge[]): FlowNode[] {
  if (nodes.length === 0) return nodes;
  const inbound = new Map(nodes.map((n) => [n.id, 0]));
  const outgoing = new Map(nodes.map((n) => [n.id, [] as string[]]));
  for (const edge of edges) {
    inbound.set(
      String(edge.target),
      (inbound.get(String(edge.target)) ?? 0) + 1,
    );
    outgoing.get(String(edge.source))?.push(String(edge.target));
  }

  const depth = new Map<string, number>();
  const queue = nodes
    .filter((n) => (inbound.get(n.id) ?? 0) === 0)
    .map((n) => n.id);
  for (const id of queue) depth.set(id, 0);

  while (queue.length > 0) {
    const id = queue.shift()!;
    const nextDepth = (depth.get(id) ?? 0) + 1;
    for (const target of outgoing.get(id) ?? []) {
      if ((depth.get(target) ?? -1) < nextDepth) {
        depth.set(target, nextDepth);
        queue.push(target);
      }
    }
  }

  const byDepth = new Map<number, FlowNode[]>();
  for (const node of nodes) {
    const fallback =
      node.data.kind === "trigger" ? 0 : node.data.kind === "check" ? 1 : 2;
    const d = depth.get(node.id) ?? fallback;
    byDepth.set(d, [...(byDepth.get(d) ?? []), node]);
  }

  return nodes.map((node) => {
    const fallback =
      node.data.kind === "trigger" ? 0 : node.data.kind === "check" ? 1 : 2;
    const d = depth.get(node.id) ?? fallback;
    const column = byDepth.get(d) ?? [node];
    const row = column.findIndex((n) => n.id === node.id);
    const offset = ((column.length - 1) * 78) / 2;
    return {
      ...node,
      position: {
        x: 110 + d * 270,
        y: 170 + row * 156 - offset,
      },
    };
  });
}

function arrangeEditor(editor: Editor): Editor {
  return { ...editor, nodes: arrangeNodes(editor.nodes, editor.edges) };
}

function fromWorkflow(w: Workflow, catalog: ActionSpec[]): Editor {
  const byType = new Map(catalog.map((a) => [a.node_type, a]));
  return arrangeEditor({
    workflow_id: w.workflow_id,
    name: w.name,
    description: w.description,
    nodes: w.nodes.map((n) => toFlowNode(n, byType.get(n.node_type))),
    edges: w.edges.map((e, idx) =>
      toFlowEdge(e.source, e.target, e.condition ?? "always", idx),
    ),
  });
}

function fromTemplate(
  template: WorkflowTemplate,
  catalog: ActionSpec[],
): Editor {
  const byType = new Map(catalog.map((a) => [a.node_type, a]));
  return arrangeEditor({
    workflow_id: null,
    name: template.name,
    description: template.description,
    nodes: template.nodes.map((n) => toFlowNode(n, byType.get(n.node_type))),
    edges: template.edges.map((e, idx) =>
      toFlowEdge(e.source, e.target, e.condition ?? "always", idx),
    ),
  });
}

function toApiNodes(nodes: FlowNode[]): WorkflowNode[] {
  return nodes.map((n) => ({
    id: n.id,
    node_type: n.data.node_type,
    params: n.data.params,
    position: n.position,
  }));
}

function toApiEdges(edges: Edge[]) {
  return edges.map((e) => ({
    source: String(e.source),
    target: String(e.target),
    condition:
      (e.data as { condition?: "always" | "passed" | "failed" } | undefined)
        ?.condition ?? "always",
  }));
}

function WorkflowHealthStrip({
  nodes,
  edges,
}: {
  nodes: FlowNode[];
  edges: Edge[];
}) {
  const counts = {
    triggers: nodes.filter((n) => n.data.kind === "trigger").length,
    checks: nodes.filter((n) => n.data.kind === "check").length,
    actions: nodes.filter((n) => n.data.kind === "action").length,
    edges: edges.length,
  };
  const connected = counts.edges > 0 || nodes.length <= 1;

  return (
    <div className="flex flex-wrap items-center gap-2 text-xs">
      <Badge tone={connected ? "ready" : "attention"}>
        {connected ? plural(counts.edges, "edge") : "Connect nodes"}
      </Badge>
      <span className="rounded-full bg-info-bg px-2.5 py-1 font-semibold text-info-fg">
        {plural(counts.triggers, "trigger")}
      </span>
      <span className="rounded-full bg-warning-bg px-2.5 py-1 font-semibold text-warning-fg">
        {plural(counts.checks, "check")}
      </span>
      <span className="rounded-full bg-success-bg px-2.5 py-1 font-semibold text-success-fg">
        {plural(counts.actions, "action")}
      </span>
    </div>
  );
}

function RunnerContract({
  nodes,
  edges,
}: {
  nodes: FlowNode[];
  edges: Edge[];
}) {
  return (
    <details className="group rounded-xl border border-line bg-surface shadow-card">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3">
        <div className="min-w-0">
          <div className="text-sm font-semibold text-ink">
            Workflow runner contract
          </div>
          <div className="truncate text-xs text-muted">
            Same saved DAG for UI, API, scheduler, CLI, MCP tools, and agents.
          </div>
        </div>
        <WorkflowHealthStrip nodes={nodes} edges={edges} />
      </summary>
      <div className="border-t border-line p-4">
        <div className="grid gap-3 lg:grid-cols-[auto_minmax(0,1fr)] lg:items-start">
          <span className="grid h-10 w-10 place-items-center rounded-lg bg-panel text-brand ring-1 ring-line">
            <ServerCog className="h-5 w-5" />
          </span>
          <div className="min-w-0">
            <p className="text-sm leading-5 text-muted">
              Save writes an append-only workflow version to{" "}
              <code>gold/workflows.jsonl</code>. Run executes the same DAG
              through the backend workflow engine, enforces RBAC and egress
              guards, writes results to <code>gold/workflow_runs.jsonl</code>,
              and exposes the run through human and headless surfaces.
            </p>
            <div className="mt-3 grid gap-2 text-xs md:grid-cols-4">
              <div className="rounded-lg border border-line bg-panel p-2">
                <b className="text-ink">Human</b>
                <div className="mt-1 text-muted">
                  Design, approve, run, inspect.
                </div>
              </div>
              <div className="rounded-lg border border-line bg-panel p-2">
                <b className="text-ink">Headless</b>
                <div className="mt-1 text-muted">REST/CLI run saved DAGs.</div>
              </div>
              <div className="rounded-lg border border-line bg-panel p-2">
                <b className="text-ink">Scheduler</b>
                <div className="mt-1 text-muted">
                  Cron triggers fire due flows.
                </div>
              </div>
              <div className="rounded-lg border border-line bg-panel p-2">
                <b className="text-ink">Agents</b>
                <div className="mt-1 text-muted">
                  MCP lists and runs workflows.
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </details>
  );
}

export default function AutomationPage() {
  const auditor = useAuditorMode();
  const workflows = useWorkflows();
  const catalog = useActionCatalog();
  const save = useSaveWorkflow();
  const run = useRunWorkflow();
  const saveWorkflow = save.mutateAsync;
  const runWorkflow = run.mutateAsync;
  const retryRun = useRetryWorkflowRun();
  const approveRun = useApproveWorkflowRun();
  const rejectRun = useRejectWorkflowRun();
  const [activeId, setActiveId] = useState<string>(NEW_WORKFLOW_ID);
  const [editor, setEditor] = useState<Editor>(() => starterEditor());
  const [selectedNode, setSelectedNode] = useState<string | null>(() =>
    firstNodeId(starterEditor()),
  );
  const [templatesOpen, setTemplatesOpen] = useState(false);
  const [lastRun, setLastRun] = useState<WorkflowRun | null>(null);
  const [starterLoaded, setStarterLoaded] = useState(false);
  const [fitTrigger, setFitTrigger] = useState(0);
  const runs = useWorkflowRuns(editor.workflow_id);

  const flash = useCallback((msg: string) => notify.success(msg), []);

  // Sync the editor whenever the user selects a different workflow.
  useEffect(() => {
    if (activeId === NEW_WORKFLOW_ID) return;
    const w = (workflows.data ?? []).find((x) => x.workflow_id === activeId);
    if (w) {
      const next = fromWorkflow(w, catalog.data ?? []);
      setEditor(next);
      setSelectedNode(firstNodeId(next));
      setLastRun(null);
    }
  }, [activeId, workflows.data, catalog.data]);

  useEffect(() => {
    if (starterLoaded) return;
    const firstWorkflow = (workflows.data ?? [])[0];
    if (firstWorkflow) {
      setActiveId(firstWorkflow.workflow_id);
      setStarterLoaded(true);
      return;
    }
    if (STARTER_TEMPLATE) {
      const next = starterEditor(catalog.data ?? []);
      setEditor(next);
      setSelectedNode(firstNodeId(next));
      setStarterLoaded(true);
    }
  }, [catalog.data, workflows.data, starterLoaded]);

  const specByType = useMemo(
    () => new Map((catalog.data ?? []).map((a) => [a.node_type, a])),
    [catalog.data],
  );

  // Merge last-run results into each node's render data so the canvas paints
  // a green/red halo around fired nodes after Run.
  const nodesWithRunState = useMemo<FlowNode[]>(() => {
    if (!lastRun) return editor.nodes;
    const byId = new Map(lastRun.node_results.map((r) => [r.node_id, r]));
    return editor.nodes.map((node) => {
      const result = byId.get(node.id);
      return {
        ...node,
        data: {
          ...node.data,
          runResult: result ? result.result : null,
        },
      };
    });
  }, [editor.nodes, lastRun]);

  const addNode = useCallback(
    (spec: ActionSpec, position?: { x: number; y: number }) => {
      const id = nextNodeId();
      const node: FlowNode = {
        id,
        type: "trustops",
        position: position ?? {
          x: 120 + (editor.nodes.length % 4) * 220,
          y: 140 + Math.floor(editor.nodes.length / 4) * 130,
        },
        data: {
          label: spec.label,
          kind: spec.kind,
          node_type: spec.node_type,
          params: {},
        },
      };
      setEditor((e) => ({ ...e, nodes: [...e.nodes, node] }));
      setSelectedNode(id);
    },
    [editor.nodes.length],
  );

  const updateNodeParams = useCallback(
    (id: string, params: Record<string, unknown>) => {
      setEditor((e) => ({
        ...e,
        nodes: e.nodes.map((n) =>
          n.id === id ? { ...n, data: { ...n.data, params } } : n,
        ),
      }));
    },
    [],
  );

  const deleteNode = useCallback((id: string) => {
    setEditor((e) => ({
      ...e,
      nodes: e.nodes.filter((n) => n.id !== id),
      edges: e.edges.filter((edge) => edge.source !== id && edge.target !== id),
    }));
  }, []);

  const loadTemplate = (template: WorkflowTemplate) => {
    const next = fromTemplate(template, catalog.data ?? []);
    setEditor(next);
    setActiveId(NEW_WORKFLOW_ID);
    setStarterLoaded(true);
    setLastRun(null);
    setSelectedNode(firstNodeId(next));
    flash(`Loaded "${template.name}" — save to persist.`);
  };

  const startNewWorkflow = () => {
    const next = starterEditor(catalog.data ?? []);
    setActiveId(NEW_WORKFLOW_ID);
    setEditor(next);
    setStarterLoaded(true);
    setLastRun(null);
    setSelectedNode(firstNodeId(next));
    flash("Starter workflow opened.");
  };

  const saveCurrentWorkflow = useCallback(
    async ({ announce }: { announce: boolean }): Promise<string | null> => {
      if (!editor.name.trim()) {
        flash("Workflow needs a name");
        return null;
      }
      if (editor.nodes.length === 0) {
        flash("Add at least one node before saving");
        return null;
      }
      try {
        const { workflow } = await saveWorkflow({
          workflow_id: editor.workflow_id ?? undefined,
          name: editor.name.trim(),
          description: editor.description.trim(),
          nodes: toApiNodes(editor.nodes),
          edges: toApiEdges(editor.edges),
        });
        setEditor((current) => ({
          ...current,
          workflow_id: workflow.workflow_id,
          name: workflow.name,
          description: workflow.description,
        }));
        setActiveId(workflow.workflow_id);
        if (announce) {
          flash(`Saved ${workflow.name} v${workflow.version}.`);
        }
        return workflow.workflow_id;
      } catch (err) {
        flash(`Save failed: ${(err as Error).message}`);
        return null;
      }
    },
    [editor, flash, saveWorkflow],
  );

  const persist = useCallback(async () => {
    await saveCurrentWorkflow({ announce: true });
  }, [saveCurrentWorkflow]);

  const execute = useCallback(
    async (dryRun = false) => {
      const workflowId =
        editor.workflow_id ?? (await saveCurrentWorkflow({ announce: false }));
      if (!workflowId) {
        return;
      }
      try {
        const { run: result } = await runWorkflow({
          id: workflowId,
          dry_run: dryRun,
        });
        setLastRun(result);
        flash(
          `${dryRun ? "Preview" : "Run"} ${result.result.toUpperCase()} — ${result.node_results.length} nodes executed.`,
        );
      } catch (err) {
        flash(
          `${dryRun ? "Preview" : "Run"} failed: ${(err as Error).message}`,
        );
      }
    },
    [editor.workflow_id, flash, runWorkflow, saveCurrentWorkflow],
  );

  const selected = nodesWithRunState.find((n) => n.id === selectedNode) ?? null;
  const selectedSpec = selected
    ? (specByType.get(selected.data.node_type) ?? null)
    : null;
  const selectedRunResult = useMemo(() => {
    if (!lastRun || !selectedNode) return null;
    const match = lastRun.node_results.find((r) => r.node_id === selectedNode);
    if (!match) return null;
    return { result: match.result, output: match.output, error: match.error };
  }, [lastRun, selectedNode]);

  const isTypingTarget = useCallback((target: EventTarget | null) => {
    if (!(target instanceof HTMLElement)) return false;
    const tag = target.tagName;
    return (
      tag === "INPUT" ||
      tag === "TEXTAREA" ||
      tag === "SELECT" ||
      target.isContentEditable
    );
  }, []);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (auditor || isTypingTarget(event.target)) return;

      if (event.key === "Escape") {
        if (lastRun) {
          setLastRun(null);
          event.preventDefault();
          return;
        }
        if (selectedNode) {
          setSelectedNode(null);
          event.preventDefault();
        }
        return;
      }

      if (
        (event.key === "Delete" || event.key === "Backspace") &&
        selectedNode
      ) {
        deleteNode(selectedNode);
        setSelectedNode(null);
        event.preventDefault();
        return;
      }

      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "s") {
        event.preventDefault();
        void persist();
        return;
      }

      if (
        (event.metaKey || event.ctrlKey) &&
        event.key === "Enter" &&
        editor.nodes.length > 0
      ) {
        event.preventDefault();
        void execute(false);
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [
    auditor,
    deleteNode,
    editor.nodes.length,
    execute,
    isTypingTarget,
    lastRun,
    persist,
    selectedNode,
  ]);

  return (
    <div className="page-shell grid grid-cols-[minmax(0,1fr)] gap-4">
      <PageHeader
        title={ROUTE_LABELS["/automation"]}
        description="Design and run trust automation from a populated canvas."
        actions={
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <Button onClick={startNewWorkflow}>
              <Plus className="h-4 w-4" /> New starter
            </Button>
            <select
              aria-label="Select workflow"
              value={activeId === NEW_WORKFLOW_ID ? "" : activeId}
              onChange={(e) => {
                const next = e.target.value;
                if (!next) return;
                setActiveId(next);
                setSelectedNode(null);
                setLastRun(null);
              }}
              className="max-w-full rounded-lg border border-line bg-surface px-3 py-2 text-sm font-semibold focus:outline-none focus:ring-1 focus:ring-brand sm:max-w-[260px]"
            >
              <option value="">Saved workflows</option>
              {(workflows.data ?? []).map((w) => (
                <option key={w.workflow_id} value={w.workflow_id}>
                  {w.name} · v{w.version}
                </option>
              ))}
            </select>
            <Button variant="default" onClick={() => setTemplatesOpen(true)}>
              <LayoutTemplate className="h-4 w-4" /> Templates
            </Button>
            <Button
              variant="default"
              onClick={() => {
                setEditor((current) => arrangeEditor(current));
                setFitTrigger((value) => value + 1);
                flash("Canvas arranged.");
              }}
            >
              <Shuffle className="h-4 w-4" /> Arrange
            </Button>
            {!auditor && (
              <>
                <Button
                  variant="default"
                  onClick={persist}
                  disabled={save.isPending}
                >
                  {save.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Save className="h-4 w-4" />
                  )}{" "}
                  Save
                </Button>
                <Button
                  variant="default"
                  onClick={() => execute(true)}
                  disabled={
                    run.isPending || save.isPending || editor.nodes.length === 0
                  }
                >
                  Preview
                </Button>
                <Button
                  variant="primary"
                  onClick={() => execute(false)}
                  disabled={
                    run.isPending || save.isPending || editor.nodes.length === 0
                  }
                >
                  {run.isPending || save.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Play className="h-4 w-4" />
                  )}{" "}
                  {editor.workflow_id ? "Run" : "Save & run"}
                </Button>
              </>
            )}
          </div>
        }
      />

      <Card className="overflow-hidden border-brand/20">
        <div className="grid gap-3 p-3 xl:grid-cols-[minmax(220px,0.7fr)_minmax(280px,1fr)_auto] xl:items-end">
          <label className="grid gap-1 text-xs font-semibold uppercase tracking-wide text-muted">
            Name
            <input
              value={editor.name}
              onChange={(e) =>
                setEditor((ed) => ({ ...ed, name: e.target.value }))
              }
              className="rounded-lg border border-line bg-surface px-3 py-2 text-sm font-semibold text-ink focus:outline-none focus:ring-1 focus:ring-brand"
              disabled={auditor}
            />
          </label>
          <label className="grid gap-1 text-xs font-semibold uppercase tracking-wide text-muted">
            Description
            <input
              value={editor.description}
              onChange={(e) =>
                setEditor((ed) => ({ ...ed, description: e.target.value }))
              }
              className="rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-brand"
              disabled={auditor}
            />
          </label>
          <div className="flex min-w-0 items-center xl:justify-end">
            <WorkflowHealthStrip nodes={editor.nodes} edges={editor.edges} />
          </div>
        </div>
      </Card>

      <QueryState queries={[workflows, catalog]} label="workflows">
        <div className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-4 xl:grid-cols-[240px_minmax(0,1fr)] 2xl:grid-cols-[240px_minmax(0,1fr)_340px]">
          <ActionPalette catalog={catalog.data ?? []} onAdd={addNode} />
          <WorkflowCanvas
            nodes={nodesWithRunState}
            edges={editor.edges}
            catalog={catalog.data ?? []}
            onNodesChange={(n) => setEditor((e) => ({ ...e, nodes: n }))}
            onEdgesChange={(es) => setEditor((e) => ({ ...e, edges: es }))}
            onSelectNode={setSelectedNode}
            onDropAction={addNode}
            fitTrigger={fitTrigger}
            lastRun={lastRun}
            onDismissRun={() => setLastRun(null)}
            onOpenTemplates={() => setTemplatesOpen(true)}
          />
          <NodeConfigPanel
            node={selected}
            spec={selectedSpec}
            lastResult={selectedRunResult}
            onClose={() => setSelectedNode(null)}
            onUpdateParams={updateNodeParams}
            onDelete={deleteNode}
          />
        </div>
      </QueryState>

      <RunnerContract nodes={editor.nodes} edges={editor.edges} />

      <p className="text-xs text-muted">
        Keyboard: <kbd className="rounded border border-line px-1">Esc</kbd>{" "}
        clear selection ·{" "}
        <kbd className="rounded border border-line px-1">Del</kbd> remove node ·{" "}
        <kbd className="rounded border border-line px-1">⌘/Ctrl+S</kbd> save ·{" "}
        <kbd className="rounded border border-line px-1">⌘/Ctrl+Enter</kbd> run
      </p>

      <Card className="overflow-hidden">
        <CardHeader>
          <CardTitle>Run history</CardTitle>
          <CardDescription>
            Latest runs for{" "}
            {editor.workflow_id ? (
              <code>{editor.workflow_id}</code>
            ) : (
              "this canvas"
            )}
            .
          </CardDescription>
        </CardHeader>
        <div className="grid gap-2 p-5 pt-0">
          {(runs.data ?? []).length === 0 ? (
            <div className="rounded-lg border border-dashed border-line p-3 text-xs text-muted">
              No runs yet. Save the workflow then click Run.
            </div>
          ) : (
            (runs.data ?? []).slice(0, 10).map((r) => (
              <button
                key={r.run_id ?? r.started_at + r.actor}
                type="button"
                onClick={() => setLastRun(r)}
                className="grid w-full gap-1 rounded-lg border border-line bg-surface p-3 text-left text-xs hover:border-brand"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-semibold">
                    v{r.workflow_version} · {r.node_results.length} nodes
                  </span>
                  <Badge
                    tone={
                      r.result === "ok"
                        ? "ready"
                        : r.result === "awaiting_approval"
                          ? "attention"
                          : "critical"
                    }
                  >
                    {displayLabel(r.result)}
                  </Badge>
                </div>
                <div className="text-muted">
                  actor <b className="text-ink">{r.actor}</b> · {r.started_at}
                  {r.run_id ? (
                    <>
                      {" "}
                      · <code>{r.run_id.slice(0, 8)}</code>
                    </>
                  ) : null}
                </div>
              </button>
            ))
          )}
        </div>
      </Card>

      {lastRun ? (
        <RunInspectorDrawer
          run={lastRun}
          auditor={auditor}
          onClose={() => setLastRun(null)}
          busy={
            retryRun.isPending || approveRun.isPending || rejectRun.isPending
          }
          onRetry={
            lastRun.run_id
              ? async () => {
                  const { run: next } = await retryRun.mutateAsync(
                    lastRun.run_id!,
                  );
                  setLastRun(next);
                  flash(`Retry ${next.result.toUpperCase()}.`);
                }
              : undefined
          }
          onApprove={
            lastRun.run_id
              ? async () => {
                  const { run: next } = await approveRun.mutateAsync({
                    runId: lastRun.run_id!,
                  });
                  setLastRun(next);
                  flash(`Approved — run ${next.result.toUpperCase()}.`);
                }
              : undefined
          }
          onReject={
            lastRun.run_id
              ? async () => {
                  const { run: next } = await rejectRun.mutateAsync({
                    runId: lastRun.run_id!,
                  });
                  setLastRun(next);
                  flash("Run rejected.");
                }
              : undefined
          }
        />
      ) : null}

      <TemplateGallery
        open={templatesOpen}
        onClose={() => setTemplatesOpen(false)}
        onPick={loadTemplate}
      />
    </div>
  );
}

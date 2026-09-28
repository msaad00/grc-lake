"use client";

import { useCallback, useEffect, useMemo, useRef } from "react";
import { useTheme } from "@/components/theme/ThemeProvider";
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  addEdge,
  applyEdgeChanges,
  applyNodeChanges,
  type Connection,
  type Edge,
  type EdgeChange,
  type Node,
  type NodeChange,
  type NodeProps,
  type NodeTypes,
  type ReactFlowInstance,
  type ReactFlowProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  AlertCircle,
  CheckCircle2,
  Cpu,
  GitFork,
  Loader2,
  Play,
  Shield,
  Zap,
} from "lucide-react";
import type { ActionSpec, WorkflowNode, WorkflowRun } from "@/lib/api/types";
import { cn } from "@/lib/utils";

// ---------------------------------------------------------------------------
// Node data + kind theming
// ---------------------------------------------------------------------------

interface NodeData extends Record<string, unknown> {
  label: string;
  kind: "trigger" | "check" | "gate" | "action";
  node_type: string;
  params: Record<string, unknown>;
  runResult?: "ok" | "error" | "skipped" | null;
  runPending?: boolean;
}

export type FlowNode = Node<NodeData, "trustops">;

interface KindStyle {
  border: string;
  borderSelected: string;
  bg: string;
  badgeBg: string;
  badgeFg: string;
  ring: string;
  Icon: React.ElementType;
}

const KIND_STYLE: Record<NonNullable<NodeData["kind"]>, KindStyle> = {
  trigger: {
    border: "#3b82f6",
    borderSelected: "#1d4ed8",
    bg: "#eff6ff",
    badgeBg: "#dbeafe",
    badgeFg: "#1e40af",
    ring: "rgba(59,130,246,0.35)",
    Icon: Zap,
  },
  check: {
    border: "#f59e0b",
    borderSelected: "#b45309",
    bg: "#fffbeb",
    badgeBg: "#fef3c7",
    badgeFg: "#92400e",
    ring: "rgba(245,158,11,0.35)",
    Icon: GitFork,
  },
  gate: {
    border: "#8b5cf6",
    borderSelected: "#6d28d9",
    bg: "#f5f3ff",
    badgeBg: "#ede9fe",
    badgeFg: "#5b21b6",
    ring: "rgba(139,92,246,0.35)",
    Icon: Shield,
  },
  action: {
    border: "#10b981",
    borderSelected: "#047857",
    bg: "#ecfdf5",
    badgeBg: "#d1fae5",
    badgeFg: "#065f46",
    ring: "rgba(16,185,129,0.35)",
    Icon: Cpu,
  },
};

// ---------------------------------------------------------------------------
// Custom node card
// ---------------------------------------------------------------------------

function NodeCard({ data, selected }: NodeProps<FlowNode>) {
  const tone = KIND_STYLE[data.kind] ?? KIND_STYLE.action;
  const Icon = tone.Icon;

  const runRingColor =
    data.runResult === "ok"
      ? "rgba(16,185,129,0.6)"
      : data.runResult === "error"
        ? "rgba(239,68,68,0.6)"
        : data.runPending
          ? "rgba(99,102,241,0.5)"
          : selected
            ? tone.ring
            : "transparent";

  const borderColor = selected ? tone.borderSelected : tone.border;
  const borderWidth = selected ? 2 : 1.5;

  const StatusIcon =
    data.runResult === "ok"
      ? CheckCircle2
      : data.runResult === "error"
        ? AlertCircle
        : data.runPending
          ? Loader2
          : null;

  const statusColor =
    data.runResult === "ok"
      ? "#10b981"
      : data.runResult === "error"
        ? "#ef4444"
        : "#6366f1";

  return (
    <div
      style={{
        borderColor,
        background: `color-mix(in srgb, ${tone.border} 10%, var(--color-surface))`,
        borderWidth,
        boxShadow: `0 0 0 3px ${runRingColor}, 0 2px 8px rgba(15,23,42,0.08)`,
        minWidth: 220,
      }}
      className="rounded-xl border text-left transition-all"
    >
      {/* Top handle */}
      <Handle
        type="target"
        position={Position.Top}
        className="!h-2.5 !w-2.5 !rounded-full !border-2 !border-white"
        style={{ background: tone.border }}
      />

      <div className="px-3.5 py-3">
        {/* Header row: kind badge + status icon */}
        <div className="flex items-center justify-between gap-2">
          <span
            className="flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase tracking-widest"
            style={{
              background: `color-mix(in srgb, ${tone.border} 18%, var(--color-surface))`,
              color: `color-mix(in srgb, ${tone.badgeFg} 60%, var(--color-ink))`,
            }}
          >
            <Icon className="h-2.5 w-2.5" aria-hidden />
            {data.kind}
          </span>

          {StatusIcon ? (
            <StatusIcon
              className={cn("h-3.5 w-3.5", data.runPending && "animate-spin")}
              style={{ color: statusColor }}
              aria-label={data.runResult ?? "running"}
            />
          ) : (
            <code className="text-[10px] text-muted">{data.node_type}</code>
          )}
        </div>

        {/* Label */}
        <div className="mt-1.5 text-sm font-semibold leading-snug text-ink">
          {data.label}
        </div>

        {/* Param pills */}
        {Object.keys(data.params).length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1">
            {Object.entries(data.params)
              .slice(0, 3)
              .map(([k, v]) => (
                <span
                  key={k}
                  className="inline-flex max-w-[160px] items-center truncate rounded border border-line bg-surface px-1.5 py-0.5 text-[10px] text-muted"
                  title={`${k}: ${String(v)}`}
                >
                  <span className="mr-0.5 font-semibold text-ink">{k}</span>
                  {String(v) && (
                    <>
                      <span className="mx-0.5 opacity-40">:</span>
                      <span className="truncate">{String(v)}</span>
                    </>
                  )}
                </span>
              ))}
          </div>
        )}

        {/* node_type subtitle when no run result */}
        {!data.runResult && (
          <div className="mt-1 text-[10px] text-muted">{data.node_type}</div>
        )}
      </div>

      {/* Bottom handle */}
      <Handle
        type="source"
        position={Position.Bottom}
        className="!h-2.5 !w-2.5 !rounded-full !border-2 !border-white"
        style={{ background: tone.border }}
      />
    </div>
  );
}

const nodeTypes: NodeTypes = { trustops: NodeCard };

function inferKind(nodeType: string): NodeData["kind"] {
  if (nodeType.startsWith("trigger.")) return "trigger";
  if (nodeType.startsWith("check.")) return "check";
  return "action";
}

function fallbackLabel(nodeType: string): string {
  const [, name = nodeType] = nodeType.split(".");
  return name
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

// ---------------------------------------------------------------------------
// Empty / onboarding state overlay
// ---------------------------------------------------------------------------

function EmptyCanvas({ onOpenTemplates }: { onOpenTemplates?: () => void }) {
  return (
    <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center gap-4 px-8 text-center">
      <div className="pointer-events-auto flex h-14 w-14 items-center justify-center rounded-2xl border-2 border-dashed border-line bg-surface shadow-card">
        <Play className="h-6 w-6 text-muted" />
      </div>
      <div>
        <div className="text-sm font-semibold text-ink">
          Start from a workflow template
        </div>
        <div className="mt-0.5 text-xs text-muted">
          Load a proven trigger, check, and action path before saving a new
          automation.
        </div>
      </div>
      {onOpenTemplates && (
        <button
          type="button"
          onClick={onOpenTemplates}
          className="pointer-events-auto rounded-lg border border-line bg-surface px-3 py-1.5 text-xs font-semibold text-ink shadow-card transition-colors hover:border-brand hover:text-brand"
        >
          Browse templates
        </button>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Run summary panel
// ---------------------------------------------------------------------------

interface RunSummaryProps {
  run: WorkflowRun;
  onDismiss: () => void;
}

function RunSummaryPanel({ run, onDismiss }: RunSummaryProps) {
  const ok = run.node_results.filter((r) => r.result === "ok").length;
  const err = run.node_results.filter((r) => r.result === "error").length;

  return (
    <div className="absolute bottom-3 left-1/2 z-10 w-[460px] max-w-[calc(100%-24px)] -translate-x-1/2 rounded-2xl border border-line bg-surface shadow-hero">
      <div className="flex items-center justify-between gap-3 border-b border-line px-4 py-3">
        <div className="flex items-center gap-2">
          {run.result === "ok" ? (
            <CheckCircle2 className="h-4 w-4 text-success-fg" />
          ) : (
            <AlertCircle className="h-4 w-4 text-danger-fg" />
          )}
          <span className="text-sm font-semibold text-ink">
            Run {run.result.toUpperCase()} &middot; v{run.workflow_version}
          </span>
          <span className="text-xs text-muted">
            {ok} passed &middot; {err} failed
          </span>
        </div>
        <button
          type="button"
          onClick={onDismiss}
          aria-label="Dismiss run summary"
          className="rounded p-0.5 text-muted hover:text-ink"
        >
          &times;
        </button>
      </div>

      <div className="grid gap-1 p-3">
        {run.node_results.map((nr, idx) => (
          <div
            key={`${nr.node_id}-${idx}`}
            className="flex items-center gap-2.5 rounded-lg border border-line bg-surfaceMuted px-3 py-1.5"
          >
            {nr.result === "ok" ? (
              <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-success-fg" />
            ) : (
              <AlertCircle className="h-3.5 w-3.5 shrink-0 text-danger-fg" />
            )}
            <code className="min-w-0 truncate text-[11px] text-ink">
              {nr.node_id}
            </code>
            <span className="ml-auto shrink-0 text-[10px] text-muted">
              {nr.node_type}
            </span>
          </div>
        ))}
      </div>

      <div className="border-t border-line px-4 py-2 text-[10px] text-muted">
        {run.started_at} &rarr; {run.finished_at} &middot; actor{" "}
        <b className="text-ink">{run.actor}</b>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// toFlowNode helper (re-exported for page.tsx)
// ---------------------------------------------------------------------------

export function toFlowNode(
  node: WorkflowNode,
  action: ActionSpec | undefined,
): FlowNode {
  const fallbackKind = inferKind(node.node_type);
  return {
    id: node.id,
    type: "trustops",
    position: node.position ?? { x: 0, y: 0 },
    data: {
      label: action?.label ?? fallbackLabel(node.node_type),
      kind: (action?.kind ?? fallbackKind) as NodeData["kind"],
      node_type: node.node_type,
      params: node.params ?? {},
    },
  };
}

// ---------------------------------------------------------------------------
// Props + canvas component
// ---------------------------------------------------------------------------

interface Props {
  nodes: FlowNode[];
  edges: Edge[];
  catalog: ActionSpec[];
  onNodesChange: (nodes: FlowNode[]) => void;
  onEdgesChange: (edges: Edge[]) => void;
  onSelectNode: (id: string | null) => void;
  onDropAction?: (spec: ActionSpec, position: { x: number; y: number }) => void;
  fitTrigger?: number;
  lastRun?: WorkflowRun | null;
  onDismissRun?: () => void;
  onOpenTemplates?: () => void;
}

export function WorkflowCanvas({
  nodes,
  edges,
  catalog,
  onNodesChange,
  onEdgesChange,
  onSelectNode,
  onDropAction,
  fitTrigger,
  lastRun,
  onDismissRun,
  onOpenTemplates,
}: Props) {
  const { resolved: resolvedTheme } = useTheme();
  const instanceRef = useRef<ReactFlowInstance<FlowNode, Edge> | null>(null);

  const handleDragOver = useCallback((event: React.DragEvent) => {
    if (event.dataTransfer.types.includes("application/trustops-action")) {
      event.preventDefault();
      event.dataTransfer.dropEffect = "move";
    }
  }, []);

  const handleDrop = useCallback(
    (event: React.DragEvent) => {
      const raw = event.dataTransfer.getData("application/trustops-action");
      if (!raw || !instanceRef.current || !onDropAction) return;
      event.preventDefault();
      const spec = JSON.parse(raw) as ActionSpec;
      const position = instanceRef.current.screenToFlowPosition({
        x: event.clientX,
        y: event.clientY,
      });
      onDropAction(spec, position);
    },
    [onDropAction],
  );

  const handleNodesChange = useCallback(
    (changes: NodeChange[]) => {
      const next = applyNodeChanges(changes, nodes) as FlowNode[];
      onNodesChange(next);
    },
    [nodes, onNodesChange],
  );

  const handleEdgesChange = useCallback(
    (changes: EdgeChange[]) => {
      onEdgesChange(applyEdgeChanges(changes, edges));
    },
    [edges, onEdgesChange],
  );

  const handleConnect = useCallback(
    (params: Connection) => {
      onEdgesChange(
        addEdge(
          {
            ...params,
            animated: true,
            data: { condition: "always" },
            markerEnd: { type: MarkerType.ArrowClosed, color: "#64748b" },
            style: { stroke: "#64748b", strokeWidth: 2 },
          },
          edges,
        ),
      );
    },
    [edges, onEdgesChange],
  );

  const handleSelection = useCallback<
    NonNullable<ReactFlowProps["onSelectionChange"]>
  >(
    ({ nodes: selected }) => {
      onSelectNode(selected[0]?.id ?? null);
    },
    [onSelectNode],
  );

  // Keep node labels + kinds in sync with catalog updates.
  const decoratedNodes = useMemo(() => {
    const byType = new Map(catalog.map((a) => [a.node_type, a]));
    return nodes.map((node) => ({
      ...node,
      data: {
        ...node.data,
        kind:
          byType.get(node.data.node_type)?.kind ??
          node.data.kind ??
          inferKind(node.data.node_type),
        label:
          byType.get(node.data.node_type)?.label ??
          node.data.label ??
          fallbackLabel(node.data.node_type),
      },
    }));
  }, [nodes, catalog]);

  // `fitView` on the component only fits the nodes present at mount; a
  // workflow that loads afterwards would sit off-centre. Fit once it arrives.
  const hasNodes = nodes.length > 0;
  const fittedRef = useRef(false);
  useEffect(() => {
    if (!hasNodes) {
      fittedRef.current = false;
      return;
    }
    if (fittedRef.current) return;
    fittedRef.current = true;
    window.requestAnimationFrame(() => {
      instanceRef.current?.fitView({ padding: 0.22 });
    });
  }, [hasNodes]);

  useEffect(() => {
    if (fitTrigger) {
      window.requestAnimationFrame(() => {
        instanceRef.current?.fitView({ padding: 0.22, duration: 320 });
      });
    }
  }, [fitTrigger]);

  return (
    <div
      className="relative h-[min(760px,calc(100dvh-245px))] min-h-[560px] overflow-hidden rounded-2xl border border-line bg-surface"
      onDragOver={handleDragOver}
      onDrop={handleDrop}
      role="application"
      aria-label="Workflow canvas"
    >
      <ReactFlow
        colorMode={resolvedTheme}
        nodes={decoratedNodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onInit={(instance) => {
          instanceRef.current = instance;
        }}
        onNodesChange={handleNodesChange}
        onEdgesChange={handleEdgesChange}
        onConnect={handleConnect}
        onSelectionChange={handleSelection}
        fitView
        proOptions={{ hideAttribution: true }}
        defaultEdgeOptions={{
          animated: true,
          markerEnd: { type: MarkerType.ArrowClosed, color: "#64748b" },
          style: { stroke: "#64748b", strokeWidth: 2 },
        }}
      >
        <Background gap={24} color="var(--color-line)" />
        <MiniMap
          pannable
          zoomable
          maskColor="rgba(15,23,42,0.06)"
          nodeColor={(n) => {
            const kind = (n.data as NodeData).kind ?? "action";
            return (
              {
                trigger: "#3b82f6",
                check: "#f59e0b",
                gate: "#8b5cf6",
                action: "#10b981",
              }[kind] ?? "#94a3b8"
            );
          }}
        />
        <Controls position="bottom-left" />
      </ReactFlow>

      {nodes.length === 0 && <EmptyCanvas onOpenTemplates={onOpenTemplates} />}

      {lastRun && onDismissRun && (
        <RunSummaryPanel run={lastRun} onDismiss={onDismissRun} />
      )}
    </div>
  );
}

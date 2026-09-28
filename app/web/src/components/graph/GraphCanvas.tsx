"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTheme } from "@/components/theme/ThemeProvider";
import dagre from "@dagrejs/dagre";
import * as Tooltip from "@radix-ui/react-tooltip";
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes,
} from "@xyflow/react";
import {
  Activity,
  AlertTriangle,
  BookOpen,
  Boxes,
  CheckCircle2,
  ClipboardCheck,
  Code2,
  FileCode2,
  FileText,
  FolderTree,
  GitBranch,
  LockKeyhole,
  Network,
  Package,
  Server,
  ShieldCheck,
  ShieldQuestion,
  UserRound,
  Users,
  Workflow,
  type LucideIcon,
} from "lucide-react";
import "@xyflow/react/dist/style.css";
import { GRAPH_LAYER } from "@/lib/graph-palette";
import { FrameworkBadge } from "@/components/framework/FrameworkBadge";
import type {
  ComplianceGraph,
  GraphNode,
  GraphNodeKind,
} from "@/lib/api/types";

interface GraphNodeData extends Record<string, unknown> {
  label: string;
  subtitle: string;
  kind: GraphNodeKind;
  framework_id?: string;
  owner?: string;
  risk_score?: number;
  /** Render emphasis driven by search / select / path-trace. */
  emphasis: "active" | "dimmed" | "highlight" | "path" | "match";
}

type FlowGraphNode = Node<GraphNodeData, "trustops-graph">;

const KIND_STYLE: Partial<
  Record<GraphNodeKind, { border: string; chip: string }>
> = {
  framework: { border: GRAPH_LAYER.framework, chip: GRAPH_LAYER.framework },
  control: { border: GRAPH_LAYER.control, chip: GRAPH_LAYER.control },
  evidence_type: {
    border: GRAPH_LAYER.evidence_type,
    chip: GRAPH_LAYER.evidence_type,
  },
  asset: { border: GRAPH_LAYER.asset, chip: GRAPH_LAYER.asset },
  repository: { border: "#0ea5e9", chip: "#0369a1" },
  directory: { border: "#64748b", chip: "#475569" },
  language: { border: "#059669", chip: "#047857" },
  evidence_signal: { border: "#ca8a04", chip: "#854d0e" },
  governance_signal: { border: "#2563eb", chip: "#1d4ed8" },
  signal_gap: { border: "#dc2626", chip: "#b91c1c" },
  workflow: { border: "#9333ea", chip: "#7e22ce" },
  dependency_manifest: { border: "#c2410c", chip: "#9a3412" },
  ownership_file: { border: "#0891b2", chip: "#0e7490" },
  security_file: { border: "#047857", chip: "#047857" },
  file: { border: "#71717a", chip: "#52525b" },
  principal: { border: "#be123c", chip: "#9f1239" },
  team: { border: "#4338ca", chip: "#3730a3" },
  review_rule: { border: "#65a30d", chip: "#4d7c0f" },
  status_check: { border: "#15803d", chip: "#166534" },
  workflow_permission: { border: "#ea580c", chip: "#c2410c" },
  evidence: { border: "#475569", chip: "#334155" },
};

const KIND_ICON: Partial<Record<GraphNodeKind, LucideIcon>> = {
  framework: BookOpen,
  control: ShieldCheck,
  evidence_type: FileText,
  asset: Server,
  repository: GitBranch,
  directory: FolderTree,
  language: Code2,
  evidence_signal: Activity,
  governance_signal: ClipboardCheck,
  signal_gap: AlertTriangle,
  workflow: Workflow,
  dependency_manifest: Package,
  ownership_file: Users,
  security_file: LockKeyhole,
  file: FileCode2,
  principal: UserRound,
  team: Users,
  review_rule: ShieldQuestion,
  status_check: CheckCircle2,
  workflow_permission: LockKeyhole,
  evidence: Boxes,
};

function emphasisClass(emphasis: GraphNodeData["emphasis"]): string {
  switch (emphasis) {
    case "dimmed":
      return "opacity-50 saturate-50";
    case "highlight":
      return "opacity-100 shadow-[0_0_0_3px_rgba(15,23,42,0.18)]";
    case "path":
      return "opacity-100 shadow-[0_0_0_3px_rgba(245,158,11,0.55)]";
    case "match":
      return "opacity-100 shadow-[0_0_0_3px_rgba(34,197,94,0.55)]";
    default:
      return "opacity-100";
  }
}

function GraphNodeCard({ data, selected }: NodeProps<FlowGraphNode>) {
  const tone = KIND_STYLE[data.kind] ?? {
    border: "var(--color-line-strong)",
    chip: "var(--color-muted)",
  };
  const Icon = KIND_ICON[data.kind] ?? Network;
  return (
    <Tooltip.Root delayDuration={120}>
      <Tooltip.Trigger asChild>
        <div
          style={{
            borderColor: selected ? "var(--color-ink)" : tone.border,
            background: `color-mix(in srgb, ${tone.border} 8%, var(--color-surface))`,
            borderWidth: selected ? 2 : 1.5,
          }}
          className={`w-[144px] max-w-[144px] rounded-lg px-2 py-1.5 transition-all ${emphasisClass(data.emphasis)}`}
        >
          <div className="flex items-center justify-between gap-2">
            <span
              className="inline-flex min-w-0 items-center gap-1 rounded-full px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide"
              style={{
                color: `color-mix(in srgb, ${tone.chip} 55%, var(--color-ink))`,
                background: "var(--color-surface)",
              }}
            >
              <Icon className="h-3 w-3 shrink-0" />
              <span className="truncate">{data.kind.replace("_", " ")}</span>
            </span>
            {data.kind === "framework" && data.framework_id && (
              <FrameworkBadge
                frameworkId={data.framework_id}
                fallbackLabel={data.label}
                size={24}
              />
            )}
          </div>
          <div className="mt-1 truncate text-xs font-semibold text-ink">
            {data.label}
          </div>
          <div className="truncate text-[10px] text-muted">{data.subtitle}</div>
          {data.owner && (
            <div className="mt-1 truncate text-[10px] text-muted">
              owner {data.owner}
            </div>
          )}
        </div>
      </Tooltip.Trigger>
      <Tooltip.Portal>
        <Tooltip.Content
          side="top"
          sideOffset={8}
          className="z-[80] max-w-[280px] rounded-lg border border-line bg-surface p-3 text-xs text-ink shadow-hero"
        >
          <div className="text-[11px] font-semibold uppercase tracking-wider text-muted">
            {data.kind.replace("_", " ")}
          </div>
          <div className="mt-1 font-semibold">{data.label}</div>
          {data.subtitle && (
            <div className="mt-0.5 text-muted">{data.subtitle}</div>
          )}
          <div className="mt-2 grid gap-0.5 text-[11px]">
            {data.framework_id && (
              <div>
                framework: <code className="text-ink">{data.framework_id}</code>
              </div>
            )}
            {data.owner && (
              <div>
                owner: <b className="text-ink">{data.owner}</b>
              </div>
            )}
            {data.risk_score !== undefined && (
              <div>
                risk: <b className="text-ink">{data.risk_score}</b>
              </div>
            )}
          </div>
          <Tooltip.Arrow className="fill-white" />
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  );
}

const nodeTypes: NodeTypes = { "trustops-graph": GraphNodeCard };

export type LayoutDir = "LR" | "TB" | "BT";

function layoutGraph(
  rfNodes: FlowGraphNode[],
  rfEdges: Edge[],
  rankdir: LayoutDir,
): { nodes: FlowGraphNode[]; edges: Edge[] } {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir, nodesep: 10, ranksep: 26, marginx: 8, marginy: 8 });

  rfNodes.forEach((node) =>
    g.setNode(node.id, { width: NODE_W, height: NODE_H }),
  );
  rfEdges.forEach((edge) => g.setEdge(edge.source, edge.target));
  dagre.layout(g);

  const positions = new Map(
    rfNodes.map((node) => {
      const pos = g.node(node.id);
      return [node.id, { x: pos.x - NODE_W / 2, y: pos.y - NODE_H / 2 }];
    }),
  );
  wrapWideRanks(positions, rankdir);
  const laidOut = rfNodes.map((node) => ({
    ...node,
    position: positions.get(node.id) ?? { x: 0, y: 0 },
  }));
  return { nodes: laidOut, edges: rfEdges };
}

const NODE_W = 144;
const NODE_H = 84;

/**
 * Dagre puts every node of a rank on one line, so a framework with dozens of
 * controls becomes a strip that only fits at minimum zoom. Wrap any rank wider
 * than a sqrt-scaled limit into rows, keeping dagre's within-rank order.
 */
function wrapWideRanks(
  positions: Map<string, { x: number; y: number }>,
  rankdir: LayoutDir,
) {
  const horizontal = rankdir === "LR";
  const limit = Math.min(
    16,
    Math.max(6, Math.round(Math.sqrt(positions.size) * 1.2)),
  );
  const ranks = new Map<number, string[]>();
  positions.forEach((pos, id) => {
    const key = Math.round(horizontal ? pos.x : pos.y);
    ranks.set(key, [...(ranks.get(key) ?? []), id]);
  });
  if (![...ranks.values()].some((ids) => ids.length > limit)) return;

  const crossStep = (horizontal ? NODE_H : NODE_W) + 10;
  const rowStep = (horizontal ? NODE_W : NODE_H) + 14;
  const rankGap = 40;
  const ordered = [...ranks.entries()].sort((a, b) => a[0] - b[0]);
  if (rankdir === "BT") ordered.reverse();
  let cursor = 0;
  for (const [, ids] of ordered) {
    ids.sort((a, b) => {
      const pa = positions.get(a)!;
      const pb = positions.get(b)!;
      return horizontal ? pa.y - pb.y : pa.x - pb.x;
    });
    for (let start = 0; start < ids.length; start += limit) {
      const row = ids.slice(start, start + limit);
      row.forEach((id, i) => {
        const cross = (i - (row.length - 1) / 2) * crossStep;
        const along = rankdir === "BT" ? -cursor : cursor;
        positions.set(
          id,
          horizontal ? { x: along, y: cross } : { x: cross, y: along },
        );
      });
      cursor += rowStep;
    }
    cursor += rankGap;
  }
}

interface Props {
  graph: ComplianceGraph | undefined;
  visibleKinds: Set<GraphNodeKind>;
  layout: LayoutDir;
  filterOwner: string;
  filterEnvironment: string;
  filterFramework: string;
  filterControl: string;
  filterWorkflow: string;
  filterStaleOnly: boolean;
  searchQuery: string;
  focusId?: string | null;
  pathFrom: string | null;
  pathTo: string | null;
  onSelectNode: (node: GraphNode | null) => void;
}

interface ImperativeRef {
  toJSON: () => unknown;
  toSVG: () => string | null;
}

export function GraphCanvas(
  props: Props & { canvasRef?: React.MutableRefObject<ImperativeRef | null> },
) {
  return (
    <ReactFlowProvider>
      <Tooltip.Provider>
        <InnerGraphCanvas {...props} />
      </Tooltip.Provider>
    </ReactFlowProvider>
  );
}

function InnerGraphCanvas({
  graph,
  visibleKinds,
  layout,
  filterOwner,
  filterEnvironment,
  filterFramework,
  filterControl,
  filterWorkflow,
  filterStaleOnly,
  searchQuery,
  focusId = null,
  pathFrom,
  pathTo,
  onSelectNode,
  canvasRef,
}: Props & { canvasRef?: React.MutableRefObject<ImperativeRef | null> }) {
  const { resolved: resolvedTheme } = useTheme();
  const [hydrated, setHydrated] = useState(false);
  const wrapperRef = useRef<HTMLDivElement>(null);
  useEffect(() => setHydrated(true), []);
  const { fitView, setCenter } = useReactFlow();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  useEffect(() => {
    if (focusId) setSelectedId(focusId);
  }, [focusId]);

  const frameworkScopeIds = useMemo(() => {
    if (!graph || !filterFramework) return null;
    const ids = new Set<string>();
    for (const node of graph.nodes) {
      if (
        (node.kind === "framework" && node.framework_id === filterFramework) ||
        (node.kind === "control" && node.framework_id === filterFramework)
      ) {
        ids.add(node.id);
      }
    }
    for (let depth = 0; depth < 2; depth += 1) {
      for (const edge of graph.edges) {
        if (ids.has(edge.source)) ids.add(edge.target);
      }
    }
    return ids;
  }, [graph, filterFramework]);

  const expandScope = useCallback(
    (seed: Set<string>, hops: number) => {
      if (!graph) return seed;
      const ids = new Set(seed);
      for (let depth = 0; depth < hops; depth += 1) {
        for (const edge of graph.edges) {
          if (ids.has(edge.source)) ids.add(edge.target);
          if (ids.has(edge.target)) ids.add(edge.source);
        }
      }
      return ids;
    },
    [graph],
  );

  const controlScopeIds = useMemo(() => {
    if (!graph || !filterControl) return null;
    const seed = new Set<string>();
    for (const node of graph.nodes) {
      if (node.kind === "control" && node.label === filterControl)
        seed.add(node.id);
      if (node.control_ids?.includes(filterControl)) seed.add(node.id);
    }
    return expandScope(seed, 3);
  }, [graph, filterControl, expandScope]);

  const workflowScopeIds = useMemo(() => {
    if (!graph || !filterWorkflow) return null;
    const seed = new Set<string>();
    for (const node of graph.nodes) {
      const isWorkflow =
        node.kind === "workflow" ||
        (node.kind === "evidence_signal" &&
          (node.label.includes("workflow") ||
            node.event_type?.includes("ci_workflow")));
      if (isWorkflow && node.label === filterWorkflow) seed.add(node.id);
    }
    return expandScope(seed, 2);
  }, [graph, filterWorkflow, expandScope]);

  const staleScopeIds = useMemo(() => {
    if (!graph || !filterStaleOnly) return null;
    const staleStatuses = new Set(["stale", "expired", "missing"]);
    const seed = new Set<string>();
    for (const node of graph.nodes) {
      if (
        node.kind === "signal_gap" ||
        (node.freshness_status && staleStatuses.has(node.freshness_status))
      ) {
        seed.add(node.id);
      }
    }
    return expandScope(seed, 2);
  }, [graph, filterStaleOnly, expandScope]);

  // Apply layer + facet filters in one place so the canvas + path-trace + search agree.
  const filteredNodes = useMemo(() => {
    if (!graph) return [];
    return graph.nodes.filter((n) => {
      if (!visibleKinds.has(n.kind)) return false;
      if (filterOwner && (n.owner ?? "") !== filterOwner) return false;
      if (filterEnvironment && (n.environment ?? "") !== filterEnvironment)
        return false;
      if (frameworkScopeIds && !frameworkScopeIds.has(n.id)) return false;
      if (controlScopeIds && !controlScopeIds.has(n.id)) return false;
      if (workflowScopeIds && !workflowScopeIds.has(n.id)) return false;
      if (staleScopeIds && !staleScopeIds.has(n.id)) return false;
      return true;
    });
  }, [
    graph,
    visibleKinds,
    filterOwner,
    filterEnvironment,
    frameworkScopeIds,
    controlScopeIds,
    workflowScopeIds,
    staleScopeIds,
  ]);

  const allowedIds = useMemo(
    () => new Set(filteredNodes.map((n) => n.id)),
    [filteredNodes],
  );

  // Compute neighbor sets for the currently selected node so the canvas can
  // bright-highlight it + its 1-hop neighbors and dim the rest.
  const adjacency = useMemo(() => {
    const out = new Map<string, Set<string>>();
    if (!graph) return out;
    for (const e of graph.edges) {
      if (!allowedIds.has(e.source) || !allowedIds.has(e.target)) continue;
      if (!out.has(e.source)) out.set(e.source, new Set());
      if (!out.has(e.target)) out.set(e.target, new Set());
      out.get(e.source)!.add(e.target);
      out.get(e.target)!.add(e.source);
    }
    return out;
  }, [graph, allowedIds]);

  const highlightSet = useMemo<Set<string> | null>(() => {
    if (!selectedId) return null;
    const out = new Set<string>([selectedId]);
    for (const n of adjacency.get(selectedId) ?? []) out.add(n);
    return out;
  }, [selectedId, adjacency]);

  // Two-click path trace via BFS over the filtered subgraph.
  const pathSet = useMemo<{
    nodes: Set<string>;
    edges: Set<string>;
  } | null>(() => {
    if (!graph || !pathFrom || !pathTo || pathFrom === pathTo) return null;
    if (!allowedIds.has(pathFrom) || !allowedIds.has(pathTo)) return null;
    const visited = new Map<string, string | null>([[pathFrom, null]]);
    const queue: string[] = [pathFrom];
    while (queue.length > 0) {
      const cur = queue.shift()!;
      if (cur === pathTo) break;
      for (const next of adjacency.get(cur) ?? []) {
        if (visited.has(next)) continue;
        visited.set(next, cur);
        queue.push(next);
      }
    }
    if (!visited.has(pathTo)) return null;
    const nodes = new Set<string>();
    let step: string | null = pathTo;
    while (step) {
      nodes.add(step);
      step = visited.get(step) ?? null;
    }
    const edges = new Set<string>();
    for (const e of graph.edges) {
      if (nodes.has(e.source) && nodes.has(e.target)) edges.add(e.id);
    }
    return { nodes, edges };
  }, [graph, pathFrom, pathTo, allowedIds, adjacency]);

  // Search highlight: case-insensitive match against label / subtitle / id.
  const matchSet = useMemo<Set<string> | null>(() => {
    if (!searchQuery.trim()) return null;
    const lower = searchQuery.trim().toLowerCase();
    const out = new Set<string>();
    for (const n of filteredNodes) {
      const hay =
        `${n.label} ${n.subtitle ?? ""} ${n.id} ${n.owner ?? ""}`.toLowerCase();
      if (hay.includes(lower)) out.add(n.id);
    }
    return out;
  }, [searchQuery, filteredNodes]);

  const { nodes: rfNodes, edges: rfEdges } = useMemo(() => {
    if (!graph) return { nodes: [] as FlowGraphNode[], edges: [] as Edge[] };
    const list: FlowGraphNode[] = filteredNodes.map((n) => {
      let emphasis: GraphNodeData["emphasis"] = "active";
      if (matchSet) emphasis = matchSet.has(n.id) ? "match" : "dimmed";
      else if (pathSet) emphasis = pathSet.nodes.has(n.id) ? "path" : "dimmed";
      else if (highlightSet)
        emphasis = highlightSet.has(n.id) ? "highlight" : "dimmed";
      return {
        id: n.id,
        type: "trustops-graph",
        className:
          n.id === focusId
            ? "focused rounded-xl ring-2 ring-brand ring-offset-2 ring-offset-surface"
            : undefined,
        position: { x: 0, y: 0 },
        data: {
          label: n.label,
          subtitle: n.subtitle ?? "",
          kind: n.kind,
          framework_id: n.framework_id,
          owner: n.owner,
          risk_score: n.risk_score,
          emphasis,
        },
      };
    });
    const edges: Edge[] = graph.edges
      .filter((e) => allowedIds.has(e.source) && allowedIds.has(e.target))
      .map((e) => {
        const onPath = pathSet?.edges.has(e.id) ?? false;
        const onHighlight =
          highlightSet &&
          (highlightSet.has(e.source) || highlightSet.has(e.target));
        const dimmed =
          (matchSet && !matchSet.has(e.source) && !matchSet.has(e.target)) ||
          (pathSet && !onPath) ||
          (highlightSet && !onHighlight);
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          animated: e.kind === "evidence_covers_asset" || onPath,
          style: {
            stroke: onPath
              ? "#f59e0b"
              : onHighlight
                ? "var(--color-ink)"
                : "var(--color-line-strong)",
            strokeWidth: onPath ? 2.5 : 1.5,
            opacity: dimmed && !onPath && !onHighlight ? 0.4 : 1,
          },
        };
      });
    return layoutGraph(list, edges, layout);
  }, [
    graph,
    filteredNodes,
    allowedIds,
    layout,
    matchSet,
    pathSet,
    highlightSet,
    focusId,
  ]);

  const focusNode = focusId ? rfNodes.find((n) => n.id === focusId) : null;
  const focusX = focusNode ? focusNode.position.x : null;
  const focusY = focusNode ? focusNode.position.y : null;

  useEffect(() => {
    if (rfNodes.length === 0) return;
    const frame = window.requestAnimationFrame(() => {
      if (focusX !== null && focusY !== null) {
        setCenter(focusX + 73, focusY + 29, { zoom: 0.9, duration: 300 });
      } else {
        fitView({ maxZoom: 0.78, padding: 0.22, duration: 180 });
      }
    });
    return () => window.cancelAnimationFrame(frame);
  }, [
    fitView,
    setCenter,
    focusX,
    focusY,
    rfNodes.length,
    layout,
    filterOwner,
    filterEnvironment,
    filterFramework,
    searchQuery,
  ]);

  // When the search has exactly one match, recentre the viewport on it so the
  // user sees the result immediately.
  useEffect(() => {
    if (!matchSet || matchSet.size !== 1) return;
    const match = rfNodes.find((n) => matchSet.has(n.id));
    if (!match) return;
    setCenter(match.position.x + 73, match.position.y + 29, {
      zoom: 0.9,
      duration: 300,
    });
  }, [matchSet, rfNodes, setCenter]);

  // Expose imperative export helpers to the parent (Export menu).
  useEffect(() => {
    if (!canvasRef) return;
    canvasRef.current = {
      toJSON: () => graph ?? null,
      toSVG: () => {
        const root = wrapperRef.current;
        if (!root) return null;
        const svg = root.querySelector(
          "svg.react-flow__edges",
        ) as SVGSVGElement | null;
        if (!svg) return null;
        const clone = svg.cloneNode(true) as SVGSVGElement;
        clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
        // A standalone SVG cannot resolve theme tokens; inline their values.
        const styles = getComputedStyle(root);
        return new XMLSerializer()
          .serializeToString(clone)
          .replace(
            /var\((--color-[a-z0-9-]+)\)/g,
            (match, name: string) =>
              styles.getPropertyValue(name).trim() || match,
          );
      },
    };
  }, [graph, canvasRef]);

  const handleSelectionChange = useCallback(
    ({ nodes: selected }: { nodes: Node[] }) => {
      const first = selected[0];
      setSelectedId(first?.id ?? null);
      if (!first) return onSelectNode(null);
      const original = graph?.nodes.find((n) => n.id === first.id) ?? null;
      onSelectNode(original);
    },
    [graph, onSelectNode],
  );

  if (!hydrated) {
    return (
      <div className="h-[clamp(400px,calc(100dvh-300px),650px)] min-h-[400px] rounded-xl border border-line bg-surface" />
    );
  }

  return (
    <div
      ref={wrapperRef}
      className="h-[clamp(400px,calc(100dvh-300px),650px)] min-h-[400px] overflow-hidden rounded-xl border border-line bg-surface"
    >
      <ReactFlow
        colorMode={resolvedTheme}
        nodes={rfNodes}
        edges={rfEdges}
        nodeTypes={nodeTypes}
        nodesDraggable
        nodesConnectable={false}
        edgesReconnectable={false}
        fitView
        fitViewOptions={{ maxZoom: 0.78, padding: 0.22 }}
        minZoom={0.16}
        maxZoom={1.6}
        proOptions={{ hideAttribution: true }}
        onSelectionChange={handleSelectionChange}
      >
        <Background gap={20} color="var(--color-line)" />
        <MiniMap
          pannable
          zoomable
          className="!h-20 !w-28 !rounded-lg !border !border-line !bg-surface/90 !shadow-card"
          style={{ width: 112, height: 80 }}
          maskColor="rgba(15,23,42,0.06)"
        />
        <Controls position="bottom-left" />
      </ReactFlow>
    </div>
  );
}

export type { ImperativeRef };

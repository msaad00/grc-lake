"use client";

import { Suspense, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  ArrowDownToLine,
  Activity,
  AlertTriangle,
  BookOpen,
  Boxes,
  CheckCircle2,
  ClipboardCheck,
  Code2,
  Download,
  FileCode2,
  FileText,
  Filter,
  FolderTree,
  GitBranch,
  Layout,
  LockKeyhole,
  Network,
  Package,
  Route,
  Search,
  Server,
  ShieldCheck,
  ShieldQuestion,
  Users,
  UserRound,
  Workflow,
  X,
  type LucideIcon,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { KpiTile } from "@/components/ui/KpiTile";
import { GRAPH_KIND_COLOR, tint } from "@/lib/graph-palette";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { QueryState } from "@/components/QueryState";
import {
  GraphCanvas,
  type ImperativeRef,
  type LayoutDir,
} from "@/components/graph/GraphCanvas";
import { GraphNodeDrawer } from "@/components/graph/GraphNodeDrawer";
import { useComplianceGraph, useRepositoryGraph } from "@/lib/api/hooks";
import type { GraphNode, GraphNodeKind } from "@/lib/api/types";
import { ROUTE_LABELS } from "@/lib/console-copy";
import { formatCount, plural } from "@/lib/format";
import { SM_UP, useMediaQuery } from "@/lib/use-media-query";

const COMPLIANCE_KINDS: GraphNodeKind[] = [
  "framework",
  "control",
  "evidence_type",
  "asset",
];

const REPO_KINDS: GraphNodeKind[] = [
  "repository",
  "directory",
  "language",
  "evidence_signal",
  "governance_signal",
  "signal_gap",
  "workflow",
  "dependency_manifest",
  "ownership_file",
  "security_file",
  "file",
  "principal",
  "team",
  "review_rule",
  "status_check",
  "workflow_permission",
  "evidence",
  "control",
];

const KIND_LABEL: Record<GraphNodeKind, string> = {
  framework: "Frameworks",
  control: "Controls",
  evidence_type: "Evidence types",
  asset: "Assets",
  repository: "Repositories",
  directory: "Directories",
  language: "Languages",
  evidence_signal: "Evidence signals",
  governance_signal: "Governance signals",
  signal_gap: "Signal gaps",
  workflow: "Workflows",
  dependency_manifest: "Dependencies",
  ownership_file: "Ownership files",
  security_file: "Security files",
  file: "Files",
  principal: "Principals",
  team: "Teams",
  review_rule: "Review rules",
  status_check: "Status checks",
  workflow_permission: "Workflow permissions",
  evidence: "Evidence refs",
};

const KIND_SWATCH: Record<GraphNodeKind, string> = GRAPH_KIND_COLOR;

const KIND_ICON: Record<GraphNodeKind, LucideIcon> = {
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

const LAYOUT_LABEL: Record<LayoutDir, string> = {
  LR: "Left → Right",
  TB: "Top → Bottom",
  BT: "Bottom → Top",
};

interface MappingRow {
  control: GraphNode;
  evidenceTypes: GraphNode[];
  assetCount: number;
}

interface RepoMappingRow {
  repository: GraphNode;
  signalCount: number;
  gapCount: number;
  controlIds: string[];
}

function downloadBlob(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

const SEARCH_RESULT_LIMIT = 8;

export default function GraphPage() {
  return (
    <Suspense
      fallback={
        <div className="px-4 py-5 text-sm text-muted">Loading graph…</div>
      }
    >
      <GraphPageContent />
    </Suspense>
  );
}

function GraphPageContent() {
  const searchParams = useSearchParams();
  const focusParam = searchParams.get("focus");
  const complianceGraph = useComplianceGraph();
  const repoGraph = useRepositoryGraph();
  const [graphMode, setGraphMode] = useState<"compliance" | "repository">(
    "compliance",
  );
  const activeKinds =
    graphMode === "compliance" ? COMPLIANCE_KINDS : REPO_KINDS;
  const graph = graphMode === "compliance" ? complianceGraph : repoGraph;
  const [visible, setVisible] = useState<Set<GraphNodeKind>>(
    new Set(activeKinds),
  );
  const [layout, setLayout] = useState<LayoutDir>("TB");
  const [filterOwner, setFilterOwner] = useState("");
  const [filterEnvironment, setFilterEnvironment] = useState("");
  const [filterFramework, setFilterFramework] = useState("");
  const [filterControl, setFilterControl] = useState("");
  const [filterWorkflow, setFilterWorkflow] = useState("");
  const [filterStaleOnly, setFilterStaleOnly] = useState(false);
  const [search, setSearch] = useState("");
  const [pathMode, setPathMode] = useState<null | "from" | "to">(null);
  const [pathFrom, setPathFrom] = useState<string | null>(null);
  const [pathTo, setPathTo] = useState<string | null>(null);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [focusId, setFocusId] = useState<string | null>(null);
  const [focusMissing, setFocusMissing] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  // The compliance graph opens on one control path (framework, control, its
  // evidence types, their assets) so it is readable; the whole framework
  // slice is one click away.
  const [pathRoot, setPathRoot] = useState<string | null>(null);
  const pathRootDefaulted = useRef(false);
  const canvasRef = useRef<ImperativeRef | null>(null);
  const wide = useMediaQuery(SM_UP);

  useEffect(() => {
    setVisible(new Set(activeKinds));
    setSelected(null);
    setFilterFramework("");
    setFilterControl("");
    setFilterWorkflow("");
    setFilterStaleOnly(false);
    setLayout(graphMode === "compliance" ? "TB" : "LR");
    setPathRoot(null);
    pathRootDefaulted.current = false;
    clearPath();
  }, [graphMode, activeKinds]);

  const data = graph.data;
  const counts = useMemo(
    () => (data?.counts ?? {}) as Partial<Record<GraphNodeKind, number>>,
    [data],
  );

  // Facet options derived from graph data so the rail only shows real values.
  const owners = useMemo(
    () =>
      Array.from(
        new Set(
          (data?.nodes ?? []).map((n) => n.owner).filter(Boolean) as string[],
        ),
      ).sort(),
    [data],
  );
  const environments = useMemo(
    () =>
      Array.from(
        new Set(
          (data?.nodes ?? [])
            .map((n) => n.environment)
            .filter(Boolean) as string[],
        ),
      ).sort(),
    [data],
  );
  const frameworks = useMemo(
    () =>
      Array.from(
        new Set(
          (data?.nodes ?? [])
            .map((n) => n.framework_id)
            .filter((id): id is string => Boolean(id)),
        ),
      ).sort(),
    [data],
  );
  const linkedControls = useMemo(
    () =>
      Array.from(
        new Set(
          (data?.nodes ?? []).flatMap((n) => {
            if (n.kind === "control") return [n.label];
            return n.control_ids ?? [];
          }),
        ),
      ).sort(),
    [data],
  );
  const workflowSignals = useMemo(
    () =>
      Array.from(
        new Set(
          (data?.nodes ?? [])
            .filter(
              (n) =>
                n.kind === "workflow" ||
                (n.kind === "evidence_signal" &&
                  (n.label.includes("workflow") ||
                    n.event_type?.includes("ci_workflow"))),
            )
            .map((n) => n.label),
        ),
      ).sort(),
    [data],
  );

  // Default to one framework on first load only; "All frameworks" is a real choice.
  const frameworkDefaulted = useRef(false);
  useEffect(() => {
    if (
      frameworkDefaulted.current ||
      graphMode !== "compliance" ||
      frameworks.length === 0
    )
      return;
    frameworkDefaulted.current = true;
    if (filterFramework) return;
    setFilterFramework(
      frameworks.find((id) => id.toLowerCase() === "soc2") ?? frameworks[0],
    );
  }, [filterFramework, frameworks, graphMode]);

  const graphIndex = useMemo(() => {
    const nodesById = new Map<string, GraphNode>();
    const outgoing = new Map<string, string[]>();
    const incoming = new Map<string, string[]>();
    for (const node of data?.nodes ?? []) nodesById.set(node.id, node);
    for (const edge of data?.edges ?? []) {
      const targets = outgoing.get(edge.source) ?? [];
      targets.push(edge.target);
      outgoing.set(edge.source, targets);
      const sources = incoming.get(edge.target) ?? [];
      sources.push(edge.source);
      incoming.set(edge.target, sources);
    }
    return { nodesById, outgoing, incoming };
  }, [data]);

  const frameworkScopeIds = useMemo(() => {
    if (!data || !filterFramework) return null;
    const ids = new Set<string>();
    for (const node of data.nodes) {
      if (
        (node.kind === "framework" && node.framework_id === filterFramework) ||
        (node.kind === "control" && node.framework_id === filterFramework)
      ) {
        ids.add(node.id);
      }
    }
    for (let depth = 0; depth < 2; depth += 1) {
      for (const edge of data.edges) {
        if (ids.has(edge.source)) ids.add(edge.target);
      }
    }
    return ids;
  }, [data, filterFramework]);

  // A control path: everything downstream of the root (evidence types, then
  // assets) plus the chain upstream of it (control, framework). Upstream walks
  // never turn back down, so sibling controls stay out.
  const pathScopeIds = useMemo(() => {
    if (graphMode !== "compliance" || !pathRoot) return null;
    if (!graphIndex.nodesById.has(pathRoot)) return null;
    const ids = new Set<string>([pathRoot]);
    const walk = (edges: Map<string, string[]>) => {
      let frontier = [pathRoot];
      for (let depth = 0; depth < 3; depth += 1) {
        const next: string[] = [];
        for (const id of frontier)
          for (const other of edges.get(id) ?? [])
            if (!ids.has(other)) {
              ids.add(other);
              next.push(other);
            }
        frontier = next;
      }
    };
    walk(graphIndex.outgoing);
    walk(graphIndex.incoming);
    return ids;
  }, [graphIndex, graphMode, pathRoot]);

  // The richest mapped control in the framework slice: most evidence types,
  // then most covered assets. Ties go to the lower control id.
  const defaultPathRoot = useMemo(() => {
    if (graphMode !== "compliance" || !data || !filterFramework) return null;
    let best: { id: string; label: string; score: number } | null = null;
    for (const node of data.nodes) {
      if (node.kind !== "control" || node.framework_id !== filterFramework)
        continue;
      const evidence = (graphIndex.outgoing.get(node.id) ?? []).filter(
        (id) => graphIndex.nodesById.get(id)?.kind === "evidence_type",
      );
      if (evidence.length === 0) continue;
      const assets = new Set(
        evidence.flatMap((id) =>
          (graphIndex.outgoing.get(id) ?? []).filter(
            (assetId) => graphIndex.nodesById.get(assetId)?.kind === "asset",
          ),
        ),
      );
      const score = evidence.length * 1000 + assets.size;
      if (
        !best ||
        score > best.score ||
        (score === best.score && node.label < best.label)
      )
        best = { id: node.id, label: node.label, score };
    }
    return best?.id ?? null;
  }, [data, filterFramework, graphIndex, graphMode]);

  useEffect(() => {
    if (pathRootDefaulted.current || focusParam || !defaultPathRoot) return;
    pathRootDefaulted.current = true;
    setPathRoot(defaultPathRoot);
  }, [defaultPathRoot, focusParam]);

  // `?focus=<node id>` selects and centres a node. The node's framework slice
  // is chosen so the default single-framework view does not hide it.
  useEffect(() => {
    if (!focusParam || graphMode !== "compliance" || !data) return;
    const node = graphIndex.nodesById.get(focusParam);
    if (!node) {
      setFocusMissing(true);
      return;
    }
    setFocusMissing(false);
    let framework = node.framework_id ?? "";
    if (!framework) {
      const incoming = new Map<string, string[]>();
      for (const edge of data.edges) {
        const sources = incoming.get(edge.target) ?? [];
        sources.push(edge.source);
        incoming.set(edge.target, sources);
      }
      const queue = [node.id];
      const seen = new Set(queue);
      while (queue.length > 0) {
        const current = graphIndex.nodesById.get(queue.shift()!);
        if (current?.kind === "control" && current.framework_id) {
          framework = current.framework_id;
          break;
        }
        for (const next of incoming.get(current?.id ?? "") ?? []) {
          if (!seen.has(next)) {
            seen.add(next);
            queue.push(next);
          }
        }
      }
    }
    if (framework) setFilterFramework(framework);
    setFilterOwner("");
    setFilterEnvironment("");
    setVisible((prev) => new Set([...prev, node.kind]));
    setFocusId(node.id);
    pathRootDefaulted.current = true;
    setPathRoot(node.id);
  }, [focusParam, graphMode, data, graphIndex]);

  const searchResults = useMemo(() => {
    const lower = search.trim().toLowerCase();
    if (!lower || !data) return [];
    return data.nodes
      .filter((n) =>
        `${n.label} ${n.subtitle ?? ""} ${n.id} ${n.owner ?? ""}`
          .toLowerCase()
          .includes(lower),
      )
      .slice(0, SEARCH_RESULT_LIMIT);
  }, [data, search]);

  const visibleSummary = useMemo(() => {
    const nodes = (data?.nodes ?? []).filter((n) => {
      if (!visible.has(n.kind)) return false;
      if (filterOwner && (n.owner ?? "") !== filterOwner) return false;
      if (filterEnvironment && (n.environment ?? "") !== filterEnvironment)
        return false;
      if (frameworkScopeIds && !frameworkScopeIds.has(n.id)) return false;
      if (pathScopeIds && !pathScopeIds.has(n.id)) return false;
      return true;
    });
    const countKind = (kind: GraphNodeKind) =>
      nodes.filter((node) => node.kind === kind).length;
    return {
      nodes: nodes.length,
      edges:
        data?.edges.filter((edge) => {
          const ids = new Set(nodes.map((node) => node.id));
          return ids.has(edge.source) && ids.has(edge.target);
        }).length ?? 0,
      controls: countKind("control"),
      evidenceTypes: countKind("evidence_type"),
      assets: countKind("asset"),
      repositories: countKind("repository"),
      signals:
        countKind("governance_signal") +
        countKind("evidence_signal") +
        countKind("signal_gap"),
    };
  }, [
    data,
    filterEnvironment,
    filterOwner,
    frameworkScopeIds,
    pathScopeIds,
    visible,
  ]);

  const mappingRows = useMemo<MappingRow[]>(() => {
    if (graphMode !== "compliance" || !data) return [];
    return data.nodes
      .filter(
        (node) =>
          node.kind === "control" &&
          (!filterFramework || node.framework_id === filterFramework),
      )
      .slice(0, 10)
      .map((control) => {
        const evidenceTypes = (graphIndex.outgoing.get(control.id) ?? [])
          .map((id) => graphIndex.nodesById.get(id))
          .filter((node): node is GraphNode => node?.kind === "evidence_type");
        const assetIds = new Set<string>();
        for (const evidence of evidenceTypes) {
          for (const assetId of graphIndex.outgoing.get(evidence.id) ?? []) {
            if (graphIndex.nodesById.get(assetId)?.kind === "asset")
              assetIds.add(assetId);
          }
        }
        return { control, evidenceTypes, assetCount: assetIds.size };
      });
  }, [data, filterFramework, graphIndex, graphMode]);

  const repoMappingRows = useMemo<RepoMappingRow[]>(() => {
    if (graphMode !== "repository" || !data) return [];
    const collectLinked = (rootId: string) => {
      const seen = new Set<string>();
      const queue = [rootId];
      let signalCount = 0;
      let gapCount = 0;
      const controlIds = new Set<string>();
      while (queue.length > 0) {
        const nodeId = queue.shift()!;
        if (seen.has(nodeId)) continue;
        seen.add(nodeId);
        const node = graphIndex.nodesById.get(nodeId);
        if (!node) continue;
        if (
          node.kind === "governance_signal" ||
          node.kind === "evidence_signal"
        ) {
          signalCount += 1;
        }
        if (node.kind === "signal_gap") gapCount += 1;
        if (node.kind === "control") controlIds.add(node.label);
        for (const controlId of node.control_ids ?? [])
          controlIds.add(controlId);
        for (const nextId of graphIndex.outgoing.get(nodeId) ?? []) {
          if (!seen.has(nextId)) queue.push(nextId);
        }
      }
      return { signalCount, gapCount, controlIds: [...controlIds].sort() };
    };
    return data.nodes
      .filter((node) => node.kind === "repository")
      .slice(0, 12)
      .map((repository) => {
        const linked = collectLinked(repository.id);
        return { repository, ...linked };
      });
  }, [data, graphIndex, graphMode]);

  const toggle = (kind: GraphNodeKind) => {
    setVisible((prev) => {
      const next = new Set(prev);
      if (next.has(kind)) next.delete(kind);
      else next.add(kind);
      return next;
    });
  };

  // Intercept node selection when path-trace mode is armed, otherwise behave
  // as a normal selection.
  const handleSelect = (node: GraphNode | null) => {
    setSelected(node);
    if (!node) return;
    if (node.id !== focusId) setFocusId(null);
    if (pathMode === "from") {
      setPathFrom(node.id);
      setPathMode("to");
    } else if (pathMode === "to") {
      setPathTo(node.id);
      setPathMode(null);
    }
  };

  // Picking from the search list sets a trace endpoint when trace mode is
  // armed; otherwise it focuses the node in the canvas.
  const pickSearchResult = (node: GraphNode) => {
    if (graphMode === "compliance" && node.framework_id)
      setFilterFramework(node.framework_id);
    setVisible((prev) => new Set([...prev, node.kind]));
    if (pathMode === "from") {
      setPathFrom(node.id);
      setPathMode("to");
    } else if (pathMode === "to") {
      setPathTo(node.id);
      setPathMode(null);
    }
    setFocusId(node.id);
    if (graphMode === "compliance") setPathRoot(node.id);
    setSearch("");
    setSearchOpen(false);
  };

  const clearPath = () => {
    setPathFrom(null);
    setPathTo(null);
    setPathMode(null);
  };

  const exportJSON = () => {
    const payload = canvasRef.current?.toJSON();
    if (!payload) return;
    downloadBlob(
      `trustops-graph-${Date.now()}.json`,
      new Blob([JSON.stringify(payload, null, 2)], {
        type: "application/json",
      }),
    );
  };

  const exportSVG = () => {
    const svg = canvasRef.current?.toSVG();
    if (!svg) return;
    downloadBlob(
      `trustops-graph-${Date.now()}.svg`,
      new Blob([svg], { type: "image/svg+xml" }),
    );
  };

  // Esc cancels path-trace mode.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape" && pathMode) setPathMode(null);
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [pathMode]);

  const pathRootNode = pathScopeIds
    ? graphIndex.nodesById.get(pathRoot ?? "")
    : undefined;
  const focusLabel =
    graphMode !== "compliance"
      ? "Repository"
      : pathRootNode
        ? pathRootNode.label
        : filterFramework || "All frameworks";

  const repoGraphEmpty =
    graphMode === "repository" &&
    !graph.isLoading &&
    !graph.isError &&
    (data?.nodes.length ?? 0) === 0;

  return (
    <div className="page-shell grid gap-3">
      <PageHeader
        title={ROUTE_LABELS["/graph"]}
        description={
          graphMode === "compliance"
            ? "Focused framework slices show the control-to-evidence-to-asset path clearly. Expand to the wide map only when you need every framework at once."
            : "Public repo audit and authenticated governance evidence rendered as repositories, code structure, workflows, owners, required reviews, status checks, controls, and evidence refs. Public-mode gaps stay explicit."
        }
        actions={
          <Badge tone="info">
            <Network className="mr-1 h-3 w-3" />{" "}
            {data
              ? `${formatCount(data.nodes.length)} nodes / ${formatCount(data.edges.length)} edges`
              : "loading"}
          </Badge>
        }
      />

      <QueryState queries={graph} label="compliance graph">
        <Card className="relative z-10">
          <div className="flex flex-wrap items-center gap-2 p-2">
            <div className="inline-flex items-center gap-1 rounded-lg border border-line bg-surface p-0.5">
              {(["compliance", "repository"] as const).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  onClick={() => setGraphMode(mode)}
                  className={[
                    "inline-flex items-center gap-1 rounded-md px-2.5 py-1.5 text-xs font-semibold",
                    graphMode === mode
                      ? "bg-ink text-surface"
                      : "text-muted hover:bg-surfaceMuted",
                  ].join(" ")}
                >
                  {mode === "repository" ? (
                    <GitBranch className="h-3.5 w-3.5" />
                  ) : (
                    <Network className="h-3.5 w-3.5" />
                  )}
                  {mode === "repository" ? "Repository" : "Compliance"}
                </button>
              ))}
            </div>
            <div className="relative min-w-[180px] flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
              <input
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setSearchOpen(true);
                }}
                onFocus={() => setSearchOpen(true)}
                onKeyDown={(e) => {
                  if (e.key === "Escape") setSearchOpen(false);
                  if (e.key === "Enter" && searchResults[0]) {
                    e.preventDefault();
                    pickSearchResult(searchResults[0]);
                  }
                }}
                aria-label="Search graph nodes"
                placeholder={
                  pathMode
                    ? `Search to pick the path ${pathMode === "from" ? "start" : "end"}…`
                    : "Search nodes (label, subtitle, owner)…"
                }
                className="w-full rounded-lg border border-line bg-surface py-2 pl-9 pr-8 text-xs focus:outline-none focus:ring-1 focus:ring-brand"
              />
              {searchOpen && searchResults.length > 0 && (
                <ul
                  role="listbox"
                  aria-label="Matching nodes"
                  className="absolute left-0 right-0 top-full z-20 mt-1 max-h-72 overflow-auto rounded-lg border border-line bg-surface p-1 shadow-card"
                >
                  {searchResults.map((node) => (
                    <li
                      key={node.id}
                      role="option"
                      aria-selected={false}
                      tabIndex={0}
                      onMouseDown={(e) => e.preventDefault()}
                      onClick={() => pickSearchResult(node)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          pickSearchResult(node);
                        }
                      }}
                      className="flex min-w-0 cursor-pointer items-center justify-between gap-2 rounded-md px-2 py-1.5 text-xs hover:bg-surfaceMuted focus:bg-surfaceMuted focus:outline-none"
                    >
                      <span className="min-w-0 truncate font-semibold text-ink">
                        {node.label}
                        {node.subtitle && (
                          <span className="ml-1 font-normal text-muted">
                            {node.subtitle}
                          </span>
                        )}
                      </span>
                      <span className="shrink-0 text-[11px] font-semibold uppercase tracking-wide text-muted">
                        {pathMode === "from"
                          ? "set start"
                          : pathMode === "to"
                            ? "set end"
                            : node.kind.replaceAll("_", " ")}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
              {search && (
                <button
                  type="button"
                  onClick={() => setSearch("")}
                  aria-label="Clear search"
                  className="absolute right-2 top-1/2 grid h-5 w-5 -translate-y-1/2 place-items-center rounded text-muted hover:bg-surfaceMuted"
                >
                  <X className="h-3 w-3" />
                </button>
              )}
            </div>
            <div className="inline-flex items-center gap-1 rounded-lg border border-line bg-surface p-0.5">
              <Layout className="ml-1.5 h-3.5 w-3.5 text-muted" />
              {(["LR", "TB", "BT"] as LayoutDir[]).map((dir) => (
                <button
                  key={dir}
                  type="button"
                  onClick={() => setLayout(dir)}
                  className={[
                    "rounded-md px-2 py-1 text-[11px] font-semibold uppercase tracking-wide",
                    layout === dir
                      ? "bg-ink text-surface"
                      : "text-muted hover:bg-surfaceMuted",
                  ].join(" ")}
                  title={LAYOUT_LABEL[dir]}
                >
                  {dir}
                </button>
              ))}
            </div>
            <Button
              variant={pathMode ? "primary" : "default"}
              size="sm"
              onClick={() => {
                if (pathFrom || pathTo) {
                  clearPath();
                } else {
                  setPathMode("from");
                }
              }}
              title="Click two nodes to highlight the shortest path between them"
            >
              <Route className="h-3.5 w-3.5" />
              {pathFrom && pathTo
                ? "Clear path"
                : pathMode === "from"
                  ? "Pick start node"
                  : pathMode === "to"
                    ? "Pick end node"
                    : "Trace path"}
            </Button>
            <Button variant="default" size="sm" onClick={exportSVG}>
              <ArrowDownToLine className="h-3.5 w-3.5" /> SVG
            </Button>
            <Button variant="default" size="sm" onClick={exportJSON}>
              <Download className="h-3.5 w-3.5" /> JSON
            </Button>
          </div>
        </Card>

        {/* Phones get one summary line so the canvas is on the first screen. */}
        <p
          data-testid="graph-summary-line"
          className="text-xs text-muted sm:hidden"
        >
          <b className="text-ink">{focusLabel}</b> ·{" "}
          {graphMode === "compliance"
            ? `${plural(visibleSummary.controls, "control")} · ${plural(visibleSummary.evidenceTypes, "evidence type")} · ${plural(visibleSummary.assets, "asset")} in view`
            : `${plural(visibleSummary.signals, "signal")} · ${plural(visibleSummary.repositories, "repository", "repositories")} in view`}
        </p>
        <div className="hidden min-w-0 gap-2 sm:grid sm:grid-cols-2 xl:grid-cols-4">
          <KpiTile
            label="Focus"
            value={focusLabel}
            detail={`${formatCount(visibleSummary.nodes)} nodes / ${formatCount(visibleSummary.edges)} edges in view`}
          />
          <KpiTile
            label={
              graphMode === "compliance"
                ? "Controls in view"
                : "Governance signals in view"
            }
            value={
              graphMode === "compliance"
                ? visibleSummary.controls
                : visibleSummary.signals
            }
            detail={
              graphMode === "compliance"
                ? `of ${formatCount(counts.control ?? 0)} requirements in the catalog`
                : "after filters"
            }
          />
          <KpiTile
            label={
              graphMode === "compliance"
                ? "Evidence types in view"
                : "Repositories in view"
            }
            value={
              graphMode === "compliance"
                ? visibleSummary.evidenceTypes
                : visibleSummary.repositories
            }
            detail={
              graphMode === "compliance"
                ? `of ${formatCount(counts.evidence_type ?? 0)} in the catalog`
                : "after filters"
            }
          />
          <KpiTile
            label={
              graphMode === "compliance"
                ? "Covered assets in view"
                : "Signal gaps"
            }
            value={
              graphMode === "compliance"
                ? visibleSummary.assets
                : (counts.signal_gap ?? 0)
            }
            detail={
              graphMode === "compliance"
                ? "with evidence paths"
                : "need authenticated sync"
            }
          />
        </div>

        {repoGraphEmpty && (
          <div className="rounded-xl border border-dashed border-line bg-surfaceMuted p-4 text-sm text-muted">
            <b className="text-ink">No repository graph yet.</b> Run a public
            repo audit or sync GitHub/GitLab governance evidence, then reload
            this workbench. Private signals stay explicit — the graph will show{" "}
            <code>not_available_public_mode</code> gaps instead of inventing
            data.
          </div>
        )}

        <div className="grid min-w-0 gap-3 xl:grid-cols-[220px_minmax(0,1fr)]">
          <Card className="order-last max-h-[clamp(380px,calc(100dvh-260px),620px)] min-h-[340px] overflow-auto xl:order-none">
            <CardHeader className="p-3 pb-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <Filter className="h-4 w-4 text-muted" /> Layers + facets
              </CardTitle>
              <CardDescription className="text-xs leading-5">
                Persistent filters drive every other view.
              </CardDescription>
            </CardHeader>
            <div className="grid gap-2 p-3 pt-0">
              <section>
                <div className="mb-2 flex items-baseline justify-between gap-2 text-[11px] font-semibold uppercase tracking-wide text-muted">
                  Layers
                  <span className="font-medium normal-case tracking-normal">
                    catalog totals
                  </span>
                </div>
                <div className="grid gap-1">
                  {activeKinds.map((kind) => {
                    const on = visible.has(kind);
                    const Icon = KIND_ICON[kind];
                    const color = KIND_SWATCH[kind];
                    return (
                      <button
                        key={kind}
                        type="button"
                        onClick={() => toggle(kind)}
                        className={[
                          "grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-1.5 rounded-lg border px-2 py-1.5 text-left text-[11px] font-semibold",
                          on
                            ? "bg-surface text-ink shadow-sm"
                            : "border-line bg-surfaceMuted text-muted hover:border-brand",
                        ].join(" ")}
                        style={on ? { borderColor: color } : undefined}
                      >
                        <span
                          className="grid h-6 w-6 place-items-center rounded-lg"
                          style={{ background: tint(color), color }}
                        >
                          <Icon className="h-3.5 w-3.5" />
                        </span>
                        <span className="truncate">{KIND_LABEL[kind]}</span>
                        <Badge
                          title={`${formatCount(counts[kind] ?? 0)} ${kind === "control" ? "requirements" : KIND_LABEL[kind].toLowerCase()} in the catalog`}
                        >
                          {formatCount(counts[kind] ?? 0)}
                        </Badge>
                      </button>
                    );
                  })}
                </div>
              </section>

              <section>
                <div className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-muted">
                  Framework
                </div>
                <select
                  aria-label="Filter graph by framework"
                  value={filterFramework}
                  onChange={(e) => {
                    setFilterFramework(e.target.value);
                    setPathRoot(null);
                  }}
                  disabled={graphMode === "repository"}
                  className="w-full rounded-lg border border-line bg-surface px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-brand disabled:bg-surfaceMuted disabled:text-muted"
                >
                  <option value="">All frameworks (wide map)</option>
                  {frameworks.map((f) => (
                    <option key={f} value={f}>
                      {f}
                    </option>
                  ))}
                </select>
              </section>

              {graphMode === "repository" && (
                <>
                  <section>
                    <div className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-muted">
                      Control
                    </div>
                    <select
                      aria-label="Filter graph by control"
                      value={filterControl}
                      onChange={(e) => setFilterControl(e.target.value)}
                      className="w-full rounded-lg border border-line bg-surface px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-brand"
                    >
                      <option value="">All linked controls</option>
                      {linkedControls.map((controlId) => (
                        <option key={controlId} value={controlId}>
                          {controlId}
                        </option>
                      ))}
                    </select>
                  </section>

                  <section>
                    <div className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-muted">
                      Workflow signal
                    </div>
                    <select
                      aria-label="Filter graph by workflow"
                      value={filterWorkflow}
                      onChange={(e) => setFilterWorkflow(e.target.value)}
                      className="w-full rounded-lg border border-line bg-surface px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-brand"
                    >
                      <option value="">All workflows</option>
                      {workflowSignals.map((signal) => (
                        <option key={signal} value={signal}>
                          {signal}
                        </option>
                      ))}
                    </select>
                  </section>

                  <section>
                    <label className="flex items-center gap-2 rounded-lg border border-line bg-surface px-2 py-2 text-xs font-semibold text-ink">
                      <input
                        type="checkbox"
                        checked={filterStaleOnly}
                        onChange={(e) => setFilterStaleOnly(e.target.checked)}
                        className="h-3.5 w-3.5 rounded border-line"
                      />
                      Stale or auth-gap evidence only
                    </label>
                  </section>
                </>
              )}

              <section>
                <div className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-muted">
                  Owner
                </div>
                <select
                  aria-label="Filter graph by owner"
                  value={filterOwner}
                  onChange={(e) => setFilterOwner(e.target.value)}
                  className="w-full rounded-lg border border-line bg-surface px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-brand"
                >
                  <option value="">All owners</option>
                  {owners.map((o) => (
                    <option key={o} value={o}>
                      {o}
                    </option>
                  ))}
                </select>
              </section>

              <section>
                <div className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-muted">
                  Environment
                </div>
                <select
                  aria-label="Filter graph by environment"
                  value={filterEnvironment}
                  onChange={(e) => setFilterEnvironment(e.target.value)}
                  className="w-full rounded-lg border border-line bg-surface px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-brand"
                >
                  <option value="">All environments</option>
                  {environments.map((env) => (
                    <option key={env} value={env}>
                      {env}
                    </option>
                  ))}
                </select>
              </section>

              <section className="rounded-lg border border-line bg-surfaceMuted p-2.5 text-[11px] text-muted">
                <div className="mb-1 font-semibold uppercase tracking-wide text-muted">
                  Legend
                </div>
                <div className="grid gap-1">
                  {activeKinds.map((kind) => (
                    <div key={kind} className="flex items-center gap-2">
                      {(() => {
                        const Icon = KIND_ICON[kind];
                        const color = KIND_SWATCH[kind];
                        return (
                          <span
                            className="grid h-5 w-5 place-items-center rounded-md"
                            style={{ background: tint(color), color }}
                          >
                            <Icon className="h-3 w-3" />
                          </span>
                        );
                      })()}
                      <span className="text-ink">{KIND_LABEL[kind]}</span>
                    </div>
                  ))}
                  <div className="mt-1 border-t border-line pt-1">
                    <div className="flex items-center gap-2">
                      <span className="h-2.5 w-2.5 rounded bg-warning" />
                      <span>path trace</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="h-2.5 w-2.5 rounded bg-success" />
                      <span>search match</span>
                    </div>
                  </div>
                </div>
              </section>
            </div>
          </Card>

          <div className="grid min-w-0 gap-3 overflow-hidden">
            {focusMissing && focusParam && (
              <div
                role="status"
                className="min-w-0 rounded-xl border border-line bg-surfaceMuted p-3 text-xs text-muted"
              >
                <code className="break-all text-ink">{focusParam}</code> is not
                in the current graph.
              </div>
            )}
            {pathFrom && pathTo && (
              <div className="min-w-0 rounded-xl border border-warning/40 bg-warning-bg p-3 text-xs text-warning-fg">
                <b>Path trace:</b>{" "}
                <code className="break-all text-ink">{pathFrom}</code> →{" "}
                <code className="break-all text-ink">{pathTo}</code>. Dimmed
                nodes/edges are outside the shortest path.{" "}
                <button
                  type="button"
                  className="ml-1 underline"
                  onClick={clearPath}
                >
                  clear
                </button>
              </div>
            )}
            {graphMode === "compliance" &&
              (pathRootNode || defaultPathRoot) && (
                <div
                  data-testid="graph-path-scope"
                  className="flex min-w-0 flex-wrap items-center justify-between gap-2 rounded-xl border border-line bg-surface px-3 py-2 text-xs text-muted"
                >
                  <span className="min-w-0 [overflow-wrap:anywhere]">
                    {pathRootNode ? (
                      <>
                        Showing the path through{" "}
                        <b className="text-ink">{pathRootNode.label}</b>
                        {pathRootNode.subtitle
                          ? ` · ${pathRootNode.subtitle}`
                          : ""}{" "}
                        ({formatCount(visibleSummary.nodes)} nodes)
                      </>
                    ) : (
                      <>
                        Showing every node in{" "}
                        <b className="text-ink">
                          {filterFramework || "all frameworks"}
                        </b>{" "}
                        ({formatCount(visibleSummary.nodes)} nodes)
                      </>
                    )}
                  </span>
                  {pathRootNode ? (
                    <Button
                      size="sm"
                      variant="default"
                      onClick={() => setPathRoot(null)}
                    >
                      {filterFramework
                        ? "Show whole framework"
                        : "Show all frameworks"}
                    </Button>
                  ) : defaultPathRoot ? (
                    <Button
                      size="sm"
                      variant="default"
                      onClick={() => setPathRoot(defaultPathRoot)}
                    >
                      Focus one control path
                    </Button>
                  ) : null}
                </div>
              )}
            {pathMode && (
              <div className="rounded-xl border border-info/40 bg-info-bg p-3 text-xs text-info-fg">
                {pathMode === "from"
                  ? "Click a node or search above to set the path start."
                  : "Click a node or search above to set the path end. Esc cancels."}
              </div>
            )}
            <GraphCanvas
              graph={data}
              visibleKinds={visible}
              layout={layout}
              filterOwner={filterOwner}
              filterEnvironment={filterEnvironment}
              filterFramework={filterFramework}
              filterControl={filterControl}
              filterWorkflow={filterWorkflow}
              filterStaleOnly={filterStaleOnly}
              searchQuery={search}
              focusId={focusId}
              scopeIds={pathScopeIds}
              rankLimit={wide ? undefined : 3}
              pathFrom={pathFrom}
              pathTo={pathTo}
              onSelectNode={handleSelect}
              canvasRef={canvasRef}
            />
          </div>
        </div>

        {(graphMode === "compliance" || graphMode === "repository") && (
          <Card className="overflow-hidden">
            <CardHeader>
              <CardTitle>Mapping inspector</CardTitle>
              <CardDescription>
                {graphMode === "compliance"
                  ? "Control paths currently visible in the graph. Select a row to inspect the mapped control and keep the canvas focused."
                  : "Repository governance paths in the graph. Select a row to focus the canvas on repo signals, gaps, and linked controls."}
              </CardDescription>
            </CardHeader>
            <CardContent className="p-4 pt-0">
              {graphMode === "compliance" ? (
                mappingRows.length > 0 ? (
                  <div className="grid gap-2 md:grid-cols-2 2xl:grid-cols-3">
                    {mappingRows.map(
                      ({ control, evidenceTypes, assetCount }) => (
                        <button
                          key={control.id}
                          type="button"
                          onClick={() => {
                            setPathRoot(control.id);
                            handleSelect(control);
                          }}
                          className="min-w-0 rounded-lg border border-line bg-surfaceMuted p-3 text-left transition hover:border-brand hover:bg-surface"
                        >
                          <div className="flex min-w-0 items-start justify-between gap-2">
                            <div className="min-w-0">
                              <div className="truncate text-sm font-semibold text-ink">
                                {control.label}
                              </div>
                              <div className="mt-0.5 truncate text-[11px] text-muted">
                                {control.subtitle}
                              </div>
                            </div>
                            <Badge tone="info">{control.framework_id}</Badge>
                          </div>
                          <div className="mt-2 grid grid-cols-[minmax(0,1fr)_auto] gap-2 text-xs">
                            <span className="truncate text-muted">
                              {evidenceTypes.length > 0
                                ? evidenceTypes.map((e) => e.label).join(", ")
                                : "No evidence type mapped"}
                            </span>
                            <span className="font-semibold text-ink">
                              {assetCount} assets
                            </span>
                          </div>
                        </button>
                      ),
                    )}
                  </div>
                ) : (
                  <div className="rounded-xl border border-dashed border-line bg-surfaceMuted p-4 text-sm text-muted">
                    No mapped control paths match the active filters.
                  </div>
                )
              ) : repoMappingRows.length > 0 ? (
                <div className="grid gap-2 md:grid-cols-2 2xl:grid-cols-3">
                  {repoMappingRows.map(
                    ({ repository, signalCount, gapCount, controlIds }) => (
                      <button
                        key={repository.id}
                        type="button"
                        onClick={() => handleSelect(repository)}
                        className="min-w-0 rounded-lg border border-line bg-surfaceMuted p-3 text-left transition hover:border-brand hover:bg-surface"
                      >
                        <div className="flex min-w-0 items-start justify-between gap-2">
                          <div className="min-w-0">
                            <div className="truncate text-sm font-semibold text-ink">
                              {repository.label}
                            </div>
                            <div className="mt-0.5 truncate text-[11px] text-muted">
                              {repository.subtitle ??
                                repository.owner ??
                                "repository"}
                            </div>
                          </div>
                          {repository.provider && (
                            <Badge>{repository.provider}</Badge>
                          )}
                        </div>
                        <div className="mt-2 flex flex-wrap gap-2 text-xs">
                          <Badge tone="info">{signalCount} signals</Badge>
                          {gapCount > 0 && (
                            <Badge tone="critical">{gapCount} auth gaps</Badge>
                          )}
                          <span className="font-semibold text-ink">
                            {controlIds.length} controls
                          </span>
                        </div>
                      </button>
                    ),
                  )}
                </div>
              ) : (
                <div className="rounded-xl border border-dashed border-line bg-surfaceMuted p-4 text-sm text-muted">
                  Link GitHub or GitLab governance connectors and sync a
                  repository to populate the topology graph.
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </QueryState>

      <GraphNodeDrawer
        node={selected}
        graphMode={graphMode}
        onClose={() => setSelected(null)}
      />
    </div>
  );
}

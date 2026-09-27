"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  createColumnHelper,
  flexRender,
  useTable,
  type SortingState,
} from "@tanstack/react-table";
import { Button } from "@/components/ui/button";
import { ArrowUpDown } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { SavedViewsBar } from "@/components/SavedViewsBar";
import { QueryState } from "@/components/QueryState";
import { TrustPipelineStrip } from "@/components/TrustPipelineStrip";
import { notify } from "@/lib/toast";
import { Toolbar, matchesQuery } from "@/components/Toolbar";
import { TagFilterBar } from "@/components/TagFilterBar";
import { ViolationDrawer } from "@/components/drawers/ViolationDrawer";
import {
  useControls,
  useTagEntityIds,
  useViolations,
  useTags,
} from "@/lib/api/hooks";
import { useToolbar } from "@/lib/state/filters";
import {
  sortableTableFeatures,
  type SortableColumnDefs,
} from "@/lib/table-features";
import type { Severity, Violation } from "@/lib/api/types";
import { ROUTE_LABELS } from "@/lib/console-copy";
import { assetLabel } from "@/lib/format";

const helper = createColumnHelper<typeof sortableTableFeatures, Violation>();

const toneForSeverity = (s: string) =>
  s === "critical" ? "critical" : s === "high" ? "attention" : "info";

const SURFACE = "violations";
const UNASSIGNED = "__unassigned__";

function ViolationsPageContent() {
  const violations = useViolations();
  const controls = useControls();
  const tagsQuery = useTags();
  const searchParams = useSearchParams();
  const router = useRouter();
  const [environment, setEnvironment] = useState("all");

  const { filters, setFilters } = useToolbar();
  const [sorting, setSorting] = useState<SortingState>([
    { id: "severity_score", desc: true },
  ]);
  const [selected, setSelected] = useState<Violation | null>(null);
  const [activeTagId, setActiveTagId] = useState<string | null>(null);

  const ownerFilter = searchParams.get("owner") ?? "all";
  function setOwnerFilter(value: string) {
    const params = new URLSearchParams(searchParams.toString());
    if (value === "all") params.delete("owner");
    else params.set("owner", value);
    router.replace(`/violations${params.size ? `?${params}` : ""}`, {
      scroll: false,
    });
  }
  const deepLinkId = searchParams.get("id");
  useEffect(() => {
    if (!deepLinkId) {
      setSelected(null);
      return;
    }
    if (!violations.data) return;
    const match = violations.data.find((v) => v.violation_id === deepLinkId);
    setSelected(match ?? null);
  }, [deepLinkId, violations.data]);
  function selectFinding(finding: Violation | null) {
    setSelected(finding);
    const params = new URLSearchParams(searchParams.toString());
    if (finding) params.set("id", finding.violation_id);
    else params.delete("id");
    router.replace(`/violations${params.size ? `?${params}` : ""}`, {
      scroll: false,
    });
  }
  const environmentFor = (value: string) =>
    value?.trim().toLowerCase() || "unknown";
  const environments = [
    ...new Set(
      (violations.data ?? []).map((v) => environmentFor(v.environment)),
    ),
  ].sort();
  const owners = [
    ...new Set(
      (violations.data ?? [])
        .map((v) => v.asset_owner?.trim())
        .filter((value): value is string => Boolean(value)),
    ),
  ].sort();
  const controlTitles = useMemo(
    () => new Map((controls.data ?? []).map((c) => [c.control_id, c.title])),
    [controls.data],
  );
  const taggedViolations = useTagEntityIds(activeTagId, "violation");
  const taggedIds = useMemo(
    () => new Set(taggedViolations.data ?? []),
    [taggedViolations.data],
  );

  const frameworks = useMemo(
    () => Array.from(new Set((controls.data ?? []).map((c) => c.framework))),
    [controls.data],
  );

  const controlFramework = useMemo(() => {
    const map = new Map<string, string>();
    (controls.data ?? []).forEach((c) => map.set(c.control_id, c.framework));
    return map;
  }, [controls.data]);

  const filtered = useMemo(
    () =>
      (violations.data ?? []).filter((v) => {
        if (activeTagId && !taggedIds.has(v.violation_id)) return false;
        if (
          environment !== "all" &&
          environmentFor(v.environment) !== environment
        )
          return false;
        if (
          filters.framework !== "all" &&
          controlFramework.get(v.control_id) !== filters.framework
        )
          return false;
        if (filters.severity !== "all" && v.severity !== filters.severity)
          return false;
        if (ownerFilter !== "all") {
          const owner = v.asset_owner?.trim() ?? "";
          if (ownerFilter === UNASSIGNED ? owner !== "" : owner !== ownerFilter)
            return false;
        }
        return matchesQuery(
          { ...v, title: controlTitles.get(v.control_id) },
          filters.query,
        );
      }),
    [
      violations.data,
      filters,
      controlFramework,
      activeTagId,
      taggedIds,
      environment,
      controlTitles,
      ownerFilter,
    ],
  );

  const columns: SortableColumnDefs<Violation> = [
    helper.accessor("control_id", {
      header: "Finding",
      cell: (info) => (
        <div className="max-w-[320px]">
          <div className="font-semibold leading-5 text-ink">
            {controlTitles.get(info.getValue()) ?? info.row.original.event_type}
          </div>
          <div className="mt-1 text-xs text-muted">{info.getValue()}</div>
        </div>
      ),
    }),
    helper.accessor("asset_id", {
      header: "Asset & environment",
      cell: (info) => (
        <div className="max-w-[280px]" title={info.getValue() || undefined}>
          <div className="break-words text-xs leading-5 text-ink [overflow-wrap:anywhere]">
            {assetLabel(info.row.original) || "Unknown asset"}
          </div>
          <Badge
            className="mt-1"
            tone={
              ["prod", "production"].includes(
                environmentFor(info.row.original.environment),
              )
                ? "attention"
                : "default"
            }
          >
            {info.row.original.environment?.trim() || "Unknown"}
          </Badge>
        </div>
      ),
    }),
    helper.accessor("severity_score", {
      header: "Severity",
      cell: (info) => (
        <div>
          <Badge tone={toneForSeverity(info.row.original.severity)}>
            {info.row.original.severity}
          </Badge>
          <div className="mt-1 text-xs text-muted">Score {info.getValue()}</div>
        </div>
      ),
    }),
    helper.accessor("asset_owner", {
      header: "Owner & source",
      cell: (info) => (
        <div className="max-w-[190px] break-words text-xs leading-5">
          <div className="font-medium text-ink">
            {info.getValue()?.trim() || "Unassigned"}
          </div>
          <div className="text-muted">{info.row.original.source}</div>
        </div>
      ),
    }),
    helper.display({
      id: "review",
      header: "Action",
      cell: (info) => (
        <Button
          size="sm"
          aria-label={`Review finding ${info.row.original.violation_id}`}
          onClick={(event) => {
            event.stopPropagation();
            selectFinding(info.row.original);
          }}
        >
          Review
        </Button>
      ),
    }),
  ];

  const table = useTable({
    features: sortableTableFeatures,
    data: filtered,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
  });

  const tags = tagsQuery.data ?? [];

  return (
    <div className="page-shell grid gap-5">
      <PageHeader
        eyebrow="Triage"
        title={ROUTE_LABELS["/violations"]}
        description="Prioritize findings, assign owners, and review evidence."
      />
      <TrustPipelineStrip activeStage="findings" />

      <TagFilterBar
        tags={tags}
        activeTagId={activeTagId}
        onSelect={setActiveTagId}
        onClear={() => setActiveTagId(null)}
      />

      {/* Saved views */}
      <SavedViewsBar
        surface={SURFACE}
        filters={{
          framework: filters.framework,
          severity: filters.severity,
          query: filters.query,
          environment,
        }}
        onApply={(viewFilters) => {
          setEnvironment((viewFilters.environment as string) ?? "all");
          setFilters({
            framework: (viewFilters.framework as string) ?? "all",
            severity: (viewFilters.severity as Severity | "all") ?? "all",
            query: (viewFilters.query as string) ?? "",
          });
        }}
      />

      <Toolbar
        filters={filters}
        frameworks={frameworks}
        onChange={setFilters}
        placeholder="Search findings, assets, sources, owners…"
      />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap gap-2 text-xs">
          <Badge tone="critical">
            {filtered.filter((v) => v.severity === "critical").length} critical
          </Badge>
          <Badge>
            {filtered.filter((v) => !v.asset_owner?.trim()).length} unassigned
          </Badge>
          <Badge>
            {
              filtered.filter(
                (v) => environmentFor(v.environment) === "unknown",
              ).length
            }{" "}
            unknown environment
          </Badge>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <label className="flex items-center gap-2 text-xs font-medium text-muted">
            Owner
            <select
              aria-label="Filter by owner"
              value={ownerFilter}
              onChange={(e) => setOwnerFilter(e.target.value)}
              className="max-w-[12rem] rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink"
            >
              <option value="all">All owners</option>
              <option value={UNASSIGNED}>Unassigned</option>
              {owners.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
              {ownerFilter !== "all" &&
                ownerFilter !== UNASSIGNED &&
                !owners.includes(ownerFilter) && (
                  <option value={ownerFilter}>{ownerFilter}</option>
                )}
            </select>
          </label>
          <label className="flex items-center gap-2 text-xs font-medium text-muted">
            Environment
            <select
              aria-label="Filter by environment"
              value={environment}
              onChange={(e) => setEnvironment(e.target.value)}
              className="rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink"
            >
              <option value="all">All environments</option>
              {environments.map((value) => (
                <option key={value} value={value}>
                  {value === "unknown" ? "Unknown" : value}
                </option>
              ))}
            </select>
          </label>
        </div>
      </div>
      <QueryState queries={violations} label="violations">
        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle>{filtered.length} findings</CardTitle>
          </CardHeader>
          <div
            className="max-h-[640px] overflow-auto"
            role="region"
            aria-label="Findings queue"
            tabIndex={0}
          >
            <table className="min-w-[820px] w-full text-sm">
              <thead>
                {table.getHeaderGroups().map((hg) => (
                  <tr
                    key={hg.id}
                    className="border-y border-line bg-surfaceMuted"
                  >
                    {hg.headers.map((h) => (
                      <th
                        key={h.id}
                        scope="col"
                        className="cursor-pointer px-4 py-3 text-left text-[11px] font-black uppercase tracking-wide text-muted"
                      >
                        <button
                          type="button"
                          onClick={h.column.getToggleSortingHandler()}
                          disabled={!h.column.getCanSort()}
                          className="inline-flex items-center gap-1 text-left"
                        >
                          {flexRender(
                            h.column.columnDef.header,
                            h.getContext(),
                          )}
                          {h.column.getCanSort() && (
                            <ArrowUpDown className="h-3 w-3 opacity-40" />
                          )}
                        </button>
                      </th>
                    ))}
                  </tr>
                ))}
              </thead>
              <tbody>
                {table.getRowModel().rows.map((r) => (
                  <tr
                    key={r.id}
                    tabIndex={0}
                    aria-label={`Open finding ${controlTitles.get(r.original.control_id) ?? r.original.event_type} on ${assetLabel(r.original) || "unknown asset"}`}
                    onClick={() => selectFinding(r.original)}
                    onKeyDown={(event) => {
                      if (event.target !== event.currentTarget) return;
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        selectFinding(r.original);
                      }
                    }}
                    className="cursor-pointer border-b border-line last:border-0 hover:bg-blue-50/40 focus-visible:bg-blue-50/40 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-brand dark:hover:bg-blue-500/10 dark:focus-visible:bg-blue-500/10"
                  >
                    {r.getVisibleCells().map((c) => (
                      <td key={c.id} className="px-4 py-3 align-top">
                        {flexRender(c.column.columnDef.cell, c.getContext())}
                      </td>
                    ))}
                  </tr>
                ))}
                {filtered.length === 0 && (
                  <tr>
                    <td
                      className="px-4 py-8 text-center text-sm text-muted"
                      colSpan={columns.length}
                    >
                      No findings match the current filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      </QueryState>
      <ViolationDrawer
        violation={selected}
        onClose={() => selectFinding(null)}
        onToast={notify.success}
      />
    </div>
  );
}

export default function ViolationsPage() {
  return (
    <Suspense
      fallback={
        <div className="px-4 py-5 text-sm text-muted">Loading findings…</div>
      }
    >
      <ViolationsPageContent />
    </Suspense>
  );
}

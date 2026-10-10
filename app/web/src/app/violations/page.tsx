"use client";

import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  createColumnHelper,
  useTable,
  type SortingState,
} from "@tanstack/react-table";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { DataTable } from "@/components/ui/data-table";
import { FilterDisclosure } from "@/components/ui/filter-disclosure";
import { PageHeader } from "@/components/PageHeader";
import { SavedViewsBar } from "@/components/SavedViewsBar";
import { QueryState, QueryWarning } from "@/components/QueryState";
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
import { severityTone } from "@/lib/severity";
import { displayLabel } from "@/lib/display";

const helper = createColumnHelper<typeof sortableTableFeatures, Violation>();

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
  const selectFinding = useCallback(
    (finding: Violation | null) => {
      setSelected(finding);
      const params = new URLSearchParams(searchParams.toString());
      if (finding) params.set("id", finding.violation_id);
      else params.delete("id");
      router.replace(`/violations${params.size ? `?${params}` : ""}`, {
        scroll: false,
      });
    },
    [router, searchParams],
  );
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

  // Zero-count chips are noise; only show what needs a look.
  const summaryChips = [
    {
      label: "critical",
      tone: "critical" as const,
      count: filtered.filter((v) => v.severity === "critical").length,
    },
    {
      label: "unassigned",
      tone: "default" as const,
      count: filtered.filter((v) => !v.asset_owner?.trim()).length,
    },
    {
      label: "unknown environment",
      tone: "default" as const,
      count: filtered.filter((v) => environmentFor(v.environment) === "unknown")
        .length,
    },
  ].filter((chip) => chip.count > 0);

  const columns = useMemo<SortableColumnDefs<Violation>>(
    () => [
      helper.accessor("control_id", {
        header: "Finding",
        meta: { mobile: "title" },
        cell: (info) => (
          <div className="max-w-[320px]">
            <div
              className="line-clamp-2 font-semibold leading-5 text-ink"
              title={
                controlTitles.get(info.getValue()) ??
                info.row.original.event_type
              }
            >
              {controlTitles.get(info.getValue()) ??
                info.row.original.event_type}
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
            <div className="mt-0.5 text-xs text-muted">
              {info.row.original.environment?.trim() || "Unknown environment"}
            </div>
          </div>
        ),
      }),
      helper.accessor("severity_score", {
        header: "Severity",
        meta: { mobile: "badge" },
        cell: (info) => (
          <div>
            <Badge tone={severityTone(info.row.original.severity)}>
              {displayLabel(info.row.original.severity)}
            </Badge>
            <div className="mt-1 text-xs text-muted">
              Score {info.getValue()}
            </div>
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
        meta: { mobile: "hidden", rowAction: true },
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
    ],
    [controlTitles, selectFinding],
  );

  const table = useTable({
    features: sortableTableFeatures,
    data: filtered,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
  });

  const tags = tagsQuery.data ?? [];
  const activeFilters = [
    Boolean(activeTagId),
    filters.framework !== "all",
    filters.severity !== "all",
    Boolean(filters.query.trim()),
    ownerFilter !== "all",
    environment !== "all",
  ].filter(Boolean).length;

  return (
    <div className="page-shell grid gap-5">
      <PageHeader
        title={ROUTE_LABELS["/violations"]}
        description="Prioritize findings, assign owners, and review evidence."
      />
      <TrustPipelineStrip activeStage="findings" />

      <FilterDisclosure activeCount={activeFilters} className="gap-5">
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
            owner: ownerFilter,
            tag: activeTagId,
          }}
          onApply={(viewFilters) => {
            // A view written before owner/tag were saved resets them, so no
            // filter from the previous view lingers.
            setEnvironment((viewFilters.environment as string) ?? "all");
            setOwnerFilter((viewFilters.owner as string) || "all");
            setActiveTagId((viewFilters.tag as string) || null);
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
            {summaryChips.map((chip) => (
              <Badge key={chip.label} tone={chip.tone}>
                {chip.count} {chip.label}
              </Badge>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <label className="flex items-center gap-2 text-xs font-medium text-muted">
              Owner
              <select
                aria-label="Filter by owner"
                value={ownerFilter}
                onChange={(e) => setOwnerFilter(e.target.value)}
                className="ui-input h-9 max-w-[12rem] text-ink"
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
                className="ui-input h-9 text-ink"
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
      </FilterDisclosure>
      <QueryState queries={violations} label="violations">
        {controls.isError ? (
          <QueryWarning
            query={controls}
            message="Couldn’t load control titles. Findings show control IDs, and the framework filter is empty until controls load."
          />
        ) : null}
        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle>{filtered.length} findings</CardTitle>
          </CardHeader>
          <DataTable
            table={table}
            label="Findings queue"
            scrollClassName="max-h-[640px] overflow-auto"
            emptyLabel="No findings match the current filters."
            onRowSelect={selectFinding}
            rowLabel={(row) =>
              `Open finding ${controlTitles.get(row.control_id) ?? row.event_type} on ${assetLabel(row) || "unknown asset"}`
            }
          />
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

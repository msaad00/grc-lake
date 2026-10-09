"use client";

import Link from "next/link";
import { Suspense, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  createColumnHelper,
  flexRender,
  useTable,
  type SortingState,
} from "@tanstack/react-table";
import {
  AlertTriangle,
  ArrowUpDown,
  Database,
  FileText,
  RefreshCw,
  ShieldCheck,
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
import { SavedViewsBar } from "@/components/SavedViewsBar";
import { TagFilterBar } from "@/components/TagFilterBar";
import { QueryState } from "@/components/QueryState";
import { Toolbar, matchesQuery } from "@/components/Toolbar";
import { EvidenceDrawer } from "@/components/drawers/EvidenceDrawer";
import {
  useControls,
  useEvidence,
  useEvidenceFreshness,
  useTagEntityIds,
  useTags,
} from "@/lib/api/hooks";
import { useToolbar } from "@/lib/state/filters";
import {
  sortableTableFeatures,
  type SortableColumnDefs,
} from "@/lib/table-features";
import type {
  EvidenceFreshness,
  EvidenceFreshnessStatus,
  NormalizedEvent,
  Severity,
} from "@/lib/api/types";
import { ROUTE_LABELS } from "@/lib/console-copy";
import { splitRef } from "@/lib/format";
import { displayLabel } from "@/lib/display";

const SURFACE = "evidence";

type EvidenceRow = NormalizedEvent & { freshness?: EvidenceFreshness };

const helper = createColumnHelper<typeof sortableTableFeatures, EvidenceRow>();
const handoffCards = [
  {
    title: "How evidence flows",
    detail:
      "Raw records are collected, normalized into facts, then scored as posture.",
    note: "This page shows the normalized facts.",
    Icon: Database,
  },
  {
    title: "Schedule ingestion and eval",
    detail: "Connector sync and control eval run on configured schedules.",
    note: "Manage cadence from Connections.",
    href: "/connectors",
    action: "Manage schedules",
    Icon: RefreshCw,
  },
  {
    title: "Reports and proof packs",
    detail: "Audit room exports PDF and proof packs from scored posture.",
    note: "Use these for auditor review.",
    href: "/audit-room",
    action: "Open audit room",
    Icon: FileText,
  },
];

const toneForStatus = (status: string) =>
  status === "passed"
    ? "ready"
    : status === "blocked" || status === "failed"
      ? "critical"
      : "attention";

const toneForFreshness = (status?: string) =>
  status === "fresh"
    ? "ready"
    : status === "stale"
      ? "attention"
      : status === "expired" || status === "missing"
        ? "critical"
        : "default";

function EvidencePageContent() {
  const evidence = useEvidence();
  const freshness = useEvidenceFreshness();
  const controls = useControls();
  const tagsQuery = useTags();
  const { filters, setFilters } = useToolbar();
  const [sorting, setSorting] = useState<SortingState>([
    { id: "event_time", desc: true },
  ]);
  const searchParams = useSearchParams();
  const router = useRouter();
  const controlFilter = searchParams.get("control") ?? "";
  const clearControlFilter = () => {
    const params = new URLSearchParams(searchParams.toString());
    params.delete("control");
    router.replace(`/evidence/${params.size ? `?${params}` : ""}`, {
      scroll: false,
    });
  };
  const [selected, setSelected] = useState<EvidenceRow | null>(null);
  const [activeTagId, setActiveTagId] = useState<string | null>(null);
  const taggedEvidence = useTagEntityIds(activeTagId, "evidence");

  const deepLinkId = searchParams.get("id");
  useEffect(() => {
    if (!deepLinkId || !evidence.data) return;
    const match = evidence.data.find((e) => e.event_id === deepLinkId);
    if (match) setSelected({ ...match, freshness: undefined });
  }, [deepLinkId, evidence.data]);
  const taggedIds = useMemo(
    () => new Set(taggedEvidence.data ?? []),
    [taggedEvidence.data],
  );
  const tags = tagsQuery.data ?? [];

  const frameworks = useMemo(
    () => Array.from(new Set((controls.data ?? []).map((c) => c.framework))),
    [controls.data],
  );

  const controlFramework = useMemo(() => {
    const map = new Map<string, string>();
    (controls.data ?? []).forEach((c) => map.set(c.control_id, c.framework));
    return map;
  }, [controls.data]);

  const freshnessByEvent = useMemo(() => {
    const map = new Map<string, EvidenceFreshness>();
    (freshness.data ?? []).forEach((row) => map.set(row.event_id, row));
    return map;
  }, [freshness.data]);

  const rows = useMemo(
    () =>
      (evidence.data ?? []).map((row) => ({
        ...row,
        freshness: freshnessByEvent.get(row.event_id),
      })),
    [evidence.data, freshnessByEvent],
  );

  const staleCount = useMemo(
    () =>
      (freshness.data ?? []).filter((row) =>
        ["stale", "expired", "missing"].includes(row.status),
      ).length,
    [freshness.data],
  );

  const filtered = useMemo(() => {
    const freshnessFilter = filters.freshness ?? "all";
    return rows.filter((e) => {
      if (activeTagId && !taggedIds.has(e.event_id)) return false;
      if (controlFilter && !e.control_ids.includes(controlFilter)) return false;
      if (filters.framework !== "all") {
        const hit = e.control_ids.some(
          (cid) => controlFramework.get(cid) === filters.framework,
        );
        if (!hit) return false;
      }
      if (filters.severity !== "all" && e.severity !== filters.severity)
        return false;
      if (freshnessFilter !== "all" && e.freshness?.status !== freshnessFilter)
        return false;
      return matchesQuery(e, filters.query);
    });
  }, [rows, filters, controlFramework, activeTagId, taggedIds, controlFilter]);

  const columns: SortableColumnDefs<EvidenceRow> = [
    helper.accessor("event_time", {
      header: "Time",
      cell: (info) => {
        const stamp = String(info.getValue());
        return (
          <code className="block whitespace-nowrap text-xs leading-5 text-ink">
            {stamp.slice(0, 10)}
            <span className="block text-muted">{stamp.slice(11, 19)}</span>
          </code>
        );
      },
    }),
    helper.accessor("source", {
      header: "Source",
      cell: (info) => (
        <span className="font-mono text-xs text-ink">{info.getValue()}</span>
      ),
    }),
    helper.accessor("asset_id", {
      header: "Asset",
      cell: (info) => {
        const [name, scope] = splitRef(info.getValue());
        const displayName = info.row.original.asset_name?.trim();
        return (
          <div className="min-w-[140px] max-w-[220px]" title={info.getValue()}>
            {displayName ? (
              <div className="truncate text-xs font-semibold text-ink">
                {displayName}
              </div>
            ) : (
              <div className="truncate font-mono text-xs font-semibold text-ink">
                {name}
              </div>
            )}
            <div className="truncate text-xs text-muted">
              {info.row.original.asset_owner || scope}
            </div>
          </div>
        );
      },
    }),
    helper.accessor("control_ids", {
      header: "Controls",
      cell: (info) => (
        <div className="grid min-w-[130px] gap-0.5 font-mono text-xs text-ink">
          {(info.getValue() as string[]).map((c) => (
            <span key={c} className="whitespace-nowrap">
              {c}
            </span>
          ))}
        </div>
      ),
    }),
    // The source's own check outcome for this row, not the evaluated
    // control result (that lives on Controls).
    helper.accessor("status", {
      header: "Check result",
      cell: (info) => {
        const v = info.getValue() as string;
        return <Badge tone={toneForStatus(v)}>{displayLabel(v)}</Badge>;
      },
    }),
    helper.accessor((row) => row.freshness, {
      id: "freshness",
      header: "Freshness",
      cell: (info) => {
        const row = info.getValue();
        if (!row) return <Badge>Not scored</Badge>;
        const age =
          row.age_minutes === null
            ? "no age"
            : row.age_minutes >= 1440
              ? `${Math.round(row.age_minutes / 1440)}d old`
              : `${Math.round(row.age_minutes)}m old`;
        return (
          <div className="min-w-[120px] space-y-1">
            <Badge tone={toneForFreshness(row.status)}>
              {displayLabel(row.status)}
            </Badge>
            <div className="whitespace-nowrap text-xs text-muted">
              {age} · SLO {row.freshness_slo_minutes}m
            </div>
          </div>
        );
      },
    }),
    helper.accessor("evidence_ref", {
      header: "Evidence ref",
      cell: (info) => {
        const [file, location] = splitRef(info.getValue());
        return (
          <div className="min-w-[120px] max-w-[180px]" title={info.getValue()}>
            <code className="block truncate text-xs text-ink">{file}</code>
            {location ? (
              <div className="truncate text-[11px] text-muted">{location}</div>
            ) : null}
          </div>
        );
      },
    }),
  ];

  const table = useTable({
    features: sortableTableFeatures,
    data: filtered,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
  });

  return (
    <div className="page-shell grid gap-3">
      <PageHeader
        title={ROUTE_LABELS["/evidence"]}
        description="These rows are evidence facts, not reports. Click a row to verify its SHA-256 hash against the original, unaltered record."
        actions={
          <span className="rounded-full border border-line bg-surface px-3 py-1.5 text-xs font-semibold text-muted">
            {staleCount > 0 ? (
              <AlertTriangle className="mr-1 inline h-3 w-3 text-warning-fg" />
            ) : (
              <ShieldCheck className="mr-1 inline h-3 w-3 text-success-fg" />
            )}
            {staleCount > 0
              ? `${staleCount} freshness issues`
              : `${(evidence.data ?? []).length} normalized`}
          </span>
        }
      />
      <div className="grid gap-2 lg:grid-cols-3">
        {handoffCards.map(({ title, detail, note, href, action, Icon }) => (
          <div
            key={title}
            className="grid min-w-0 gap-2 rounded-xl border border-line bg-surface p-3 shadow-sm sm:grid-cols-[auto_minmax(0,1fr)]"
          >
            <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-line bg-panel text-brand">
              <Icon className="h-4 w-4" />
            </span>
            <div className="min-w-0">
              <div className="text-sm font-semibold text-ink">{title}</div>
              <p className="mt-1 text-sm leading-5 text-muted">{detail}</p>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <span className="text-xs font-semibold text-muted">{note}</span>
                {href && action ? (
                  <Button asChild size="sm" variant="default">
                    <Link href={href}>{action}</Link>
                  </Button>
                ) : null}
              </div>
            </div>
          </div>
        ))}
      </div>
      <TagFilterBar
        tags={tags}
        activeTagId={activeTagId}
        onSelect={setActiveTagId}
        onClear={() => setActiveTagId(null)}
      />
      <SavedViewsBar
        surface={SURFACE}
        filters={{
          framework: filters.framework,
          severity: filters.severity,
          freshness: filters.freshness ?? "all",
          query: filters.query,
        }}
        onApply={(viewFilters) =>
          setFilters({
            ...filters,
            framework: (viewFilters.framework as string) ?? "all",
            severity: (viewFilters.severity as Severity | "all") ?? "all",
            freshness:
              (viewFilters.freshness as
                EvidenceFreshnessStatus | "all" | undefined) ?? "all",
            query: (viewFilters.query as string) ?? "",
          })
        }
      />
      <Toolbar
        filters={filters}
        frameworks={frameworks}
        onChange={setFilters}
        placeholder="Search by source, asset, evidence ref, control…"
        showFreshness
      />
      {controlFilter && (
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="inline-flex max-w-full items-center gap-2 rounded-full border border-line bg-surfaceMuted px-3 py-1 text-ink">
            <span className="[overflow-wrap:anywhere]">
              Control: {controlFilter}
            </span>
            <button
              type="button"
              onClick={clearControlFilter}
              className="font-semibold text-brand hover:underline"
            >
              Show all evidence
            </button>
          </span>
        </div>
      )}
      <QueryState queries={[evidence, freshness]} label="evidence freshness">
        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle>{filtered.length} matching records</CardTitle>
            <CardDescription>
              Every row is an append-only fact normalized from the original,
              unaltered evidence record. Freshness is checked against each
              source&apos;s refresh target.
            </CardDescription>
          </CardHeader>
          {/* tabIndex makes the horizontal scroll reachable by keyboard;
              without it the columns past the fold are mouse-only. */}
          <div className="max-w-full overflow-x-auto" tabIndex={0}>
            <table className="w-full min-w-[760px] text-sm">
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
                        onClick={h.column.getToggleSortingHandler()}
                        className="cursor-pointer whitespace-nowrap px-3 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wide text-muted"
                      >
                        <span className="inline-flex items-center gap-1">
                          {flexRender(
                            h.column.columnDef.header,
                            h.getContext(),
                          )}
                          <ArrowUpDown className="h-3 w-3 opacity-40" />
                        </span>
                      </th>
                    ))}
                  </tr>
                ))}
              </thead>
              <tbody>
                {table.getRowModel().rows.map((r) => (
                  <tr
                    key={r.id}
                    onClick={() => setSelected(r.original)}
                    className="cursor-pointer border-b border-line last:border-0 hover:bg-info-bg"
                  >
                    {r.getVisibleCells().map((c) => (
                      <td key={c.id} className="px-3 py-2.5 align-top">
                        {flexRender(c.column.columnDef.cell, c.getContext())}
                      </td>
                    ))}
                  </tr>
                ))}
                {filtered.length === 0 && (
                  <tr>
                    <td
                      colSpan={columns.length}
                      className="px-3 py-7 text-center text-sm text-muted"
                    >
                      No evidence records match the current filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      </QueryState>
      <EvidenceDrawer evidence={selected} onClose={() => setSelected(null)} />
    </div>
  );
}

export default function EvidencePage() {
  return (
    <Suspense
      fallback={
        <div className="px-4 py-5 text-sm text-muted">Loading evidence…</div>
      }
    >
      <EvidencePageContent />
    </Suspense>
  );
}

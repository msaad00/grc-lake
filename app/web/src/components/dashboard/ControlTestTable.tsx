"use client";

import {
  createColumnHelper,
  flexRender,
  useTable,
  type SortingState,
} from "@tanstack/react-table";
import { useState } from "react";
import {
  sortableTableFeatures,
  type SortableColumnDefs,
} from "@/lib/table-features";
import { ArrowUpDown } from "lucide-react";
import type { ControlTest } from "@/lib/api/types";
import { FrameworkMark } from "@/components/framework/FrameworkMark";
import { frameworkIdFromControlId } from "@/lib/framework-visuals";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { displayLabel } from "@/lib/display";

const helper = createColumnHelper<typeof sortableTableFeatures, ControlTest>();

const toneFor = (result: string) =>
  result === "pass" ? "ready" : result === "fail" ? "critical" : "attention";

const CONFIDENCE_INPUT_LABELS: Record<string, string> = {
  evidence_coverage: "evidence coverage",
  evidence_type_coverage: "evidence type coverage",
  freshness: "freshness",
  source_health: "source health",
  mapping_quality: "mapping quality",
  hash_integrity: "hash integrity",
};

/** Per-row score from the pipeline; the hover text shows what it is made of. */
export function confidenceTitle(test: ControlTest): string {
  const inputs = Object.entries(test.confidence_inputs ?? {});
  if (inputs.length === 0)
    return "Evidence confidence computed by the assessment pipeline for this control.";
  return `Evidence confidence, weighted from: ${inputs
    .map(([key, value]) => `${CONFIDENCE_INPUT_LABELS[key] ?? key} ${value}`)
    .join(", ")}.`;
}

export function ControlTestTable({
  rows,
  onSelect,
  emptyLabel = "No control tests reported by the assessment engine.",
  description = "Sorted by result, freshness, and confidence for reviewer-ready triage.",
}: {
  rows: ControlTest[];
  onSelect?: (controlId: string) => void;
  emptyLabel?: string;
  description?: string;
}) {
  const [sorting, setSorting] = useState<SortingState>([
    { id: "result", desc: false },
  ]);

  const columns: SortableColumnDefs<ControlTest> = [
    helper.accessor("control_id", {
      header: "Program",
      cell: (info) => (
        <FrameworkMark
          frameworkId={frameworkIdFromControlId(info.getValue())}
          size={32}
        />
      ),
    }),
    helper.accessor("name", {
      header: "Test",
      cell: (info) => (
        <div>
          <b className="block">{info.getValue()}</b>
          <span className="block text-xs text-muted">
            {info.row.original.control_id} · {info.row.original.next_action}
          </span>
        </div>
      ),
    }),
    helper.accessor("owner", {
      header: "Owner",
      cell: (info) => (
        <span className="inline-flex items-center gap-2 text-xs font-semibold">
          <span className="grid h-6 w-6 place-items-center rounded-full bg-info-bg text-[11px] font-semibold text-info-fg">
            {info.getValue().slice(0, 1).toUpperCase()}
          </span>
          {info.getValue()}
        </span>
      ),
    }),
    helper.accessor("result", {
      header: "Result",
      cell: (info) => {
        const v = info.getValue();
        return (
          <div>
            <Badge tone={toneFor(v) as "ready" | "critical" | "attention"}>
              {displayLabel(v)}
            </Badge>
            <div
              className="mt-1 whitespace-nowrap text-xs text-muted"
              title={confidenceTitle(info.row.original)}
            >
              {info.row.original.confidence_score}% evidence confidence
            </div>
          </div>
        );
      },
    }),
    helper.accessor("freshness_status", {
      header: "Freshness",
      cell: (info) => (
        <Badge tone="info">{displayLabel(info.getValue())}</Badge>
      ),
    }),
    helper.accessor("agent_skill", {
      header: "Review skill",
      cell: (info) => (
        <code className="whitespace-nowrap text-xs text-ink">
          {info.getValue()}
        </code>
      ),
    }),
  ];

  const table = useTable({
    features: sortableTableFeatures,
    data: rows,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
  });

  return (
    <Card className="overflow-hidden">
      <CardHeader>
        <CardTitle>Latest control test results</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <div
        className="overflow-x-auto"
        role="region"
        aria-label="Latest control test results"
        tabIndex={0}
      >
        <table className="min-w-[820px] w-full text-sm">
          <thead>
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id} className="border-y border-line bg-surfaceMuted">
                {hg.headers.map((h) => (
                  <th
                    key={h.id}
                    onClick={h.column.getToggleSortingHandler()}
                    className="cursor-pointer px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wide text-muted"
                  >
                    <span className="inline-flex items-center gap-1">
                      {flexRender(h.column.columnDef.header, h.getContext())}
                      <ArrowUpDown className="h-3 w-3 opacity-50" />
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
                {...(onSelect
                  ? {
                      tabIndex: 0,
                      "aria-label": `Open control ${r.original.control_id}: ${r.original.name}`,
                      onClick: () => onSelect(r.original.control_id),
                      onKeyDown: (event: React.KeyboardEvent) => {
                        if (event.target !== event.currentTarget) return;
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          onSelect(r.original.control_id);
                        }
                      },
                    }
                  : {})}
                className={`border-b border-line last:border-0 hover:bg-info-bg ${onSelect ? "cursor-pointer focus-visible:bg-info-bg focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-brand " : ""}`}
              >
                {r.getVisibleCells().map((c) => (
                  <td key={c.id} className="px-4 py-3 align-top">
                    {flexRender(c.column.columnDef.cell, c.getContext())}
                  </td>
                ))}
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td
                  className="px-4 py-6 text-center text-sm text-muted"
                  colSpan={columns.length}
                >
                  {emptyLabel}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

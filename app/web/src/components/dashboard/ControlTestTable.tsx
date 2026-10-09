"use client";

import {
  createColumnHelper,
  useTable,
  type SortingState,
} from "@tanstack/react-table";
import { useState } from "react";
import {
  sortableTableFeatures,
  type SortableColumnDefs,
} from "@/lib/table-features";
import type { ControlTest } from "@/lib/api/types";
import { FrameworkMark } from "@/components/framework/FrameworkMark";
import { frameworkIdFromControlId } from "@/lib/framework-visuals";
import { Badge } from "@/components/ui/badge";
import { DataTable } from "@/components/ui/data-table";
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
      meta: { mobile: "badge" },
      cell: (info) => (
        <FrameworkMark
          frameworkId={frameworkIdFromControlId(info.getValue())}
          size={32}
        />
      ),
    }),
    helper.accessor("name", {
      header: "Test",
      meta: { mobile: "title" },
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
      meta: { mobile: "badge" },
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
      meta: { mobile: "badge" },
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
      <DataTable
        table={table}
        label="Latest control test results"
        emptyLabel={emptyLabel}
        onRowSelect={onSelect ? (row) => onSelect(row.control_id) : undefined}
        rowLabel={(row) => `Open control ${row.control_id}: ${row.name}`}
      />
    </Card>
  );
}

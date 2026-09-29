"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Badge } from "@/components/ui/badge";
import { FrameworkBadge } from "@/components/framework/FrameworkBadge";
import { resolveFrameworkId } from "@/lib/framework-visuals";
import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { SavedViewsBar } from "@/components/SavedViewsBar";
import { TagFilterBar } from "@/components/TagFilterBar";
import { TrustPipelineStrip } from "@/components/TrustPipelineStrip";
import { QueryState } from "@/components/QueryState";
import { notify } from "@/lib/toast";
import { Toolbar, matchesQuery } from "@/components/Toolbar";
import { ControlDrawer } from "@/components/drawers/ControlDrawer";
import { ViolationDrawer } from "@/components/drawers/ViolationDrawer";
import {
  useControls,
  useControlTests,
  usePosture,
  useTagEntityIds,
  useTags,
} from "@/lib/api/hooks";
import { useToolbar } from "@/lib/state/filters";
import { cn } from "@/lib/utils";
import { ControlMonitoringSummary } from "@/components/controls/ControlMonitoringSummary";
import { ControlTestTable } from "@/components/dashboard/ControlTestTable";
import type { ControlPosture, Violation } from "@/lib/api/types";
import { ROUTE_LABELS } from "@/lib/console-copy";
import { displayLabel } from "@/lib/display";

const SURFACE = "controls";
const selectClass =
  "max-w-[12rem] rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-brand";

const toneForStatus = (status: string) =>
  status === "pass" ? "ready" : status === "fail" ? "critical" : "attention";

function ControlRow({
  control,
  onSelect,
  confidence,
}: {
  control: ControlPosture;
  onSelect: () => void;
  confidence?: number;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        "block w-full rounded-xl border border-line bg-surface p-3 text-left transition-colors hover:border-brand hover:shadow-card",
      )}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <code className="text-sm font-semibold text-ink">
          {control.control_id}
        </code>
        <Badge tone={toneForStatus(control.status)}>
          {displayLabel(control.status)}
        </Badge>
      </div>
      <div className="mt-1 text-sm text-ink">{control.title}</div>
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        <FrameworkBadge
          frameworkId={resolveFrameworkId(control.framework)}
          fallbackLabel={control.framework}
          variant="compact"
          size={28}
        />
        <Badge>{control.owner}</Badge>
        <Badge tone={Number(control.risk_score) >= 80 ? "critical" : "default"}>
          risk {control.risk_score}
        </Badge>
        <Badge>
          evidence {control.evidence_count}/{control.event_count}
        </Badge>
        {confidence !== undefined && (
          <Badge tone={confidence >= 75 ? "ready" : "attention"}>
            test {confidence}%
          </Badge>
        )}
      </div>
    </button>
  );
}

function ControlsPageContent() {
  const controls = useControls();
  const tests = useControlTests();
  const posture = usePosture();
  const tagsQuery = useTags();
  const searchParams = useSearchParams();
  const { filters, setFilters } = useToolbar();
  const [selected, setSelected] = useState<ControlPosture | null>(null);
  const [violation, setViolation] = useState<Violation | null>(null);
  const [activeTagId, setActiveTagId] = useState<string | null>(null);
  const [resultFilter, setResultFilter] = useState("all");
  const [ownerFilter, setOwnerFilter] = useState("all");
  const [view, setView] = useState<"queue" | "grid">("queue");
  const [pendingControlId, setPendingControlId] = useState<string | null>(null);

  const deepLinkId = searchParams.get("id");
  const deepLinkFramework = searchParams.get("framework");
  // Only evaluated controls have a result here; a catalogued control that
  // this lake has not evaluated (or a mistyped id) gets a notice instead.
  const deepLinkMissing = Boolean(
    deepLinkId &&
    controls.data &&
    !controls.data.some((c) => c.control_id === deepLinkId),
  );
  useEffect(() => {
    if (!deepLinkId || !controls.data) return;
    const match = controls.data.find((c) => c.control_id === deepLinkId);
    if (match) setSelected(match);
  }, [deepLinkId, controls.data]);
  const taggedControls = useTagEntityIds(activeTagId, "control");
  const taggedIds = useMemo(
    () => new Set(taggedControls.data ?? []),
    [taggedControls.data],
  );
  const tags = tagsQuery.data ?? [];

  const frameworks = useMemo(
    () => Array.from(new Set((controls.data ?? []).map((c) => c.framework))),
    [controls.data],
  );

  const testsByControl = useMemo(
    () => new Map((tests.data ?? []).map((t) => [t.control_id, t])),
    [tests.data],
  );
  const controlsById = useMemo(
    () => new Map((controls.data ?? []).map((c) => [c.control_id, c])),
    [controls.data],
  );
  useEffect(() => {
    if (!pendingControlId) return;
    const match = controlsById.get(pendingControlId);
    if (!match) return;
    setSelected(match);
    setPendingControlId(null);
  }, [pendingControlId, controlsById]);
  const results = useMemo(
    () => [...new Set((tests.data ?? []).map((t) => t.result))].sort(),
    [tests.data],
  );
  const owners = useMemo(
    () =>
      [
        ...new Set(
          [...(controls.data ?? []), ...(tests.data ?? [])]
            .map((row) => row.owner?.trim())
            .filter((value): value is string => Boolean(value)),
        ),
      ].sort(),
    [controls.data, tests.data],
  );

  const filtered = useMemo(
    () =>
      (controls.data ?? []).filter((c) => {
        if (activeTagId && !taggedIds.has(c.control_id)) return false;
        if (ownerFilter !== "all" && c.owner !== ownerFilter) return false;
        if (
          resultFilter !== "all" &&
          testsByControl.get(c.control_id)?.result !== resultFilter
        )
          return false;
        return (
          (filters.framework === "all" || c.framework === filters.framework) &&
          matchesQuery(c, filters.query)
        );
      }),
    [
      controls.data,
      filters,
      activeTagId,
      taggedIds,
      ownerFilter,
      resultFilter,
      testsByControl,
    ],
  );

  const filteredTests = useMemo(
    () =>
      (tests.data ?? []).filter((t) => {
        const control = controlsById.get(t.control_id);
        if (activeTagId && !taggedIds.has(t.control_id)) return false;
        if (ownerFilter !== "all" && t.owner !== ownerFilter) return false;
        if (resultFilter !== "all" && t.result !== resultFilter) return false;
        if (
          filters.framework !== "all" &&
          control?.framework !== filters.framework
        )
          return false;
        return matchesQuery({ ...t, title: control?.title }, filters.query);
      }),
    [
      tests.data,
      controlsById,
      activeTagId,
      taggedIds,
      ownerFilter,
      resultFilter,
      filters,
    ],
  );
  const filtersActive =
    Boolean(activeTagId) ||
    ownerFilter !== "all" ||
    resultFilter !== "all" ||
    filters.framework !== "all" ||
    Boolean(filters.query.trim());

  const openViolation = (violationId: string) => {
    const v = (posture.data?.violations ?? []).find(
      (row) => row.violation_id === violationId,
    );
    if (v) setViolation(v);
  };

  return (
    <div className="page-shell grid gap-5">
      <PageHeader
        title={ROUTE_LABELS["/controls"]}
        description="Results, evidence, and owners."
      />
      <TrustPipelineStrip activeStage="controls" />
      {deepLinkMissing ? (
        <p
          role="status"
          className="rounded-lg border border-line bg-surfaceMuted px-4 py-3 text-sm text-muted"
        >
          <code className="font-semibold text-ink">{deepLinkId}</code> has no
          evaluated result in this lake.
          {deepLinkFramework ? (
            <>
              {" "}
              <Link
                href={`/frameworks/?framework=${encodeURIComponent(deepLinkFramework)}&control=${encodeURIComponent(deepLinkId!)}`}
                className="font-semibold text-brand hover:underline"
              >
                View its requirement in Frameworks
              </Link>
            </>
          ) : null}
        </p>
      ) : null}
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
          query: filters.query,
          result: resultFilter,
          owner: ownerFilter,
        }}
        onApply={(viewFilters) => {
          setFilters({
            ...filters,
            framework: (viewFilters.framework as string) ?? "all",
            query: (viewFilters.query as string) ?? "",
          });
          setResultFilter((viewFilters.result as string) ?? "all");
          setOwnerFilter((viewFilters.owner as string) ?? "all");
        }}
      />
      <Toolbar
        filters={filters}
        frameworks={frameworks}
        onChange={setFilters}
        placeholder="Search by control id, title, framework, owner…"
      />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <label className="flex items-center gap-2 text-xs font-medium text-muted">
            Result
            <select
              aria-label="Filter by result"
              value={resultFilter}
              onChange={(e) => setResultFilter(e.target.value)}
              className={selectClass}
            >
              <option value="all">All results</option>
              {results.map((value) => (
                <option key={value} value={value}>
                  {value.replaceAll("_", " ")}
                </option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-2 text-xs font-medium text-muted">
            Owner
            <select
              aria-label="Filter by owner"
              value={ownerFilter}
              onChange={(e) => setOwnerFilter(e.target.value)}
              className={selectClass}
            >
              <option value="all">All owners</option>
              {owners.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
        </div>
        <div
          role="group"
          aria-label="Control view"
          className="inline-flex rounded-lg border border-line bg-surface p-0.5"
        >
          {(
            [
              ["queue", "Test queue"],
              ["grid", "Card grid"],
            ] as const
          ).map(([id, label]) => (
            <button
              key={id}
              type="button"
              aria-pressed={view === id}
              onClick={() => setView(id)}
              className={cn(
                "rounded-md px-3 py-1.5 text-xs font-semibold",
                view === id
                  ? "bg-ink text-surface"
                  : "text-muted hover:bg-surfaceMuted",
              )}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
      <QueryState queries={[tests]} label="control tests">
        <ControlMonitoringSummary rows={tests.data ?? []} />
        {view === "queue" && (
          <ControlTestTable
            rows={filteredTests}
            description={
              filtersActive
                ? `${filteredTests.length} of ${(tests.data ?? []).length} control tests match the filters. Select a row to open the control.`
                : "Sorted by result, freshness, and confidence. Select a row to open the control."
            }
            emptyLabel={
              filtersActive
                ? "No control tests match the current filters."
                : undefined
            }
            onSelect={setPendingControlId}
          />
        )}
      </QueryState>
      {view === "grid" && (
        <QueryState queries={controls} label="controls">
          <Card className="overflow-hidden" data-testid="control-card-grid">
            <CardHeader>
              <CardTitle>{filtered.length} controls</CardTitle>
              <CardDescription>
                Click a control to inspect evidence, violations, owner, and
                API-safe facts.
              </CardDescription>
            </CardHeader>
            <div className="grid gap-2 p-5 pt-0 lg:grid-cols-2">
              {filtered.length === 0 && (
                <div className="col-span-full rounded-lg border border-dashed border-line p-4 text-sm text-muted">
                  No controls match the current filters.
                </div>
              )}
              {filtered.map((c) => (
                <ControlRow
                  key={c.control_id}
                  control={c}
                  onSelect={() => setSelected(c)}
                  confidence={
                    testsByControl.get(c.control_id)?.confidence_score
                  }
                />
              ))}
            </div>
          </Card>
        </QueryState>
      )}
      <ControlDrawer
        control={selected}
        onClose={() => setSelected(null)}
        onOpenViolation={openViolation}
      />
      <ViolationDrawer
        violation={violation}
        onClose={() => setViolation(null)}
        onToast={notify.success}
      />
    </div>
  );
}

export default function ControlsPage() {
  return (
    <Suspense
      fallback={
        <div className="px-4 py-5 text-sm text-muted">Loading controls…</div>
      }
    >
      <ControlsPageContent />
    </Suspense>
  );
}

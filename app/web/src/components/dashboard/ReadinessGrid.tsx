"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { ChevronDown, ChevronUp } from "lucide-react";
import type { FrameworkPosture, FrameworkView } from "@/lib/api/types";
import { CollapsibleCard } from "@/components/ui/collapsible-card";
import { FrameworkBadge } from "@/components/framework/FrameworkBadge";
import { resolveFrameworkId } from "@/lib/framework-visuals";
import { frameworkDetailHref } from "@/lib/framework-links";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { splitFrameworkPacks, stubCountLabel } from "@/lib/framework-packs";

const FRAMEWORK_IDS: Record<string, string> = {
  "SOC 2": "soc2",
  "NIST AI RMF": "nist-ai-rmf",
  "ISO 27001": "iso-27001-2022",
  "ISO 42001": "iso-42001-2023",
  HIPAA: "hipaa-security-rule",
  "PCI DSS": "pci-dss-v4",
  GDPR: "gdpr-2016-679",
  "EU AI Act": "eu-ai-act-2024-1689",
  FedRAMP: "fedramp-moderate",
  "CIS AWS": "cis_aws",
};

function frameworkIdFor(label: string) {
  return resolveFrameworkId(FRAMEWORK_IDS[label] ?? label);
}

function frameworkLabel(framework: FrameworkView) {
  if (framework.framework_id === "soc2") return "SOC 2";
  if (framework.framework_id === "nist-ai-rmf") return "NIST AI RMF";
  if (framework.framework_id === "iso-27001-2022") return "ISO 27001";
  if (framework.framework_id === "iso-42001-2023") return "ISO 42001";
  if (framework.framework_id === "hipaa-security-rule") return "HIPAA";
  if (framework.framework_id === "pci-dss-v4") return "PCI DSS";
  if (framework.framework_id === "gdpr-2016-679") return "GDPR";
  if (framework.framework_id === "eu-ai-act-2024-1689") return "EU AI Act";
  return framework.name;
}

const MIN_COVERAGE = 0.5;

type Coverage = { assessed: number; total: number | null; sufficient: boolean };

// A score over a sliver of the catalog is not a readiness signal, so below
// MIN_COVERAGE the card reports coverage instead of a percentage.
function coverageFor(
  framework: FrameworkPosture,
  catalogById: Map<string, FrameworkView>,
): Coverage {
  const total =
    catalogById.get(frameworkIdFor(framework.framework))?.control_count ?? null;
  const assessed = framework.control_count;
  const sufficient = !total || assessed / total >= MIN_COVERAGE;
  return { assessed, total: total || null, sufficient };
}

function statusFor(framework: FrameworkPosture, coverage: Coverage) {
  if (!coverage.sufficient) {
    return { label: "Insufficient coverage", tone: "default" as const };
  }
  if (framework.state === "ready") {
    return { label: "Ready", tone: "ready" as const };
  }
  if (framework.critical_violation_count > 0 || framework.score < 50) {
    return { label: "Needs attention", tone: "critical" as const };
  }
  return { label: "Review", tone: "attention" as const };
}

function byName(a: FrameworkPosture, b: FrameworkPosture) {
  return a.framework.localeCompare(b.framework, undefined, { numeric: true });
}

function worstFirst(a: FrameworkPosture, b: FrameworkPosture) {
  return (
    a.score - b.score ||
    b.critical_violation_count - a.critical_violation_count ||
    b.failing_control_count - a.failing_control_count ||
    b.stale_control_count - a.stale_control_count ||
    a.framework.localeCompare(b.framework)
  );
}

function FrameworkRow({
  framework,
  coverage,
  unmonitored,
}: {
  framework?: FrameworkPosture;
  coverage?: Coverage;
  unmonitored?: FrameworkView;
}) {
  if (!framework && !unmonitored) return null;
  const id = unmonitored?.framework_id ?? frameworkIdFor(framework!.framework);
  const label = unmonitored
    ? frameworkLabel(unmonitored)
    : framework!.framework;
  const showScore = Boolean(framework && coverage?.sufficient);
  const status = framework
    ? statusFor(framework, coverage!)
    : { label: "Not assessed", tone: "default" as const };
  const assessedShare =
    framework && coverage?.total
      ? Math.min(100, Math.round((coverage.assessed / coverage.total) * 100))
      : null;
  const progress = framework
    ? `${
        coverage?.total
          ? `${coverage.assessed} of ${coverage.total} controls assessed`
          : `${framework.control_count} ${framework.control_count === 1 ? "control" : "controls"} assessed`
      }${framework.failing_control_count ? ` · ${framework.failing_control_count} failing` : ""}`
    : `${unmonitored!.control_count} ${unmonitored!.control_count === 1 ? "control" : "controls"} catalogued`;
  return (
    <Link
      href={frameworkDetailHref(id)}
      className="group flex min-w-0 items-center gap-3 px-4 py-3 transition-colors hover:bg-surfaceMuted focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-brand sm:px-5"
    >
      <FrameworkBadge
        frameworkId={id}
        fallbackLabel={label}
        size={32}
        variant="mark-only"
      />
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-medium text-ink">{label}</div>
        <div className="mt-1 flex min-w-0 items-center gap-2">
          {assessedShare != null ? (
            <span
              aria-hidden="true"
              className="hidden h-1 w-16 shrink-0 overflow-hidden rounded-full bg-surfaceMuted sm:block"
            >
              <span
                className="block h-full rounded-full bg-line-strong"
                style={{ width: `${Math.max(3, assessedShare)}%` }}
              />
            </span>
          ) : null}
          <span className="text-xs text-muted sm:truncate">{progress}</span>
        </div>
      </div>
      {framework && showScore ? (
        <span className="shrink-0 text-sm tabular-nums text-ink">
          {Math.round(framework.score)}
          <span className="text-xs text-muted">/100</span>
          <span className="sr-only"> assessment score</span>
        </span>
      ) : null}
      <Badge tone={status.tone} className="shrink-0">
        {status.label}
      </Badge>
    </Link>
  );
}

const PREVIEW = 4;

export function ReadinessGrid({
  frameworks,
  catalog = [],
  embedded = false,
}: {
  frameworks: FrameworkPosture[];
  catalog?: FrameworkView[];
  embedded?: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const [sort, setSort] = useState<"priority" | "name">("priority");
  const sorted = useMemo(
    () => [...frameworks].sort(sort === "name" ? byName : worstFirst),
    [frameworks, sort],
  );
  const catalogById = useMemo(
    () => new Map(catalog.map((entry) => [entry.framework_id, entry])),
    [catalog],
  );
  const coverageByName = useMemo(
    () =>
      new Map(
        sorted.map((framework) => [
          framework.framework,
          coverageFor(framework, catalogById),
        ]),
      ),
    [sorted, catalogById],
  );
  const monitoredIds = useMemo(
    () =>
      new Set(sorted.map((framework) => frameworkIdFor(framework.framework))),
    [sorted],
  );
  const { packs, stubs } = useMemo(
    () => splitFrameworkPacks(catalog),
    [catalog],
  );
  const unmonitored = useMemo(
    () =>
      packs
        .filter((framework) => !monitoredIds.has(framework.framework_id))
        .sort((a, b) =>
          frameworkLabel(a).localeCompare(frameworkLabel(b), undefined, {
            numeric: true,
          }),
        ),
    [packs, monitoredIds],
  );
  const totalCount = sorted.length + unmonitored.length;
  const visibleLimit = expanded ? totalCount : PREVIEW;
  const visibleFrameworks = sorted.slice(0, visibleLimit);
  const visibleUnmonitored = unmonitored.slice(
    0,
    Math.max(visibleLimit - visibleFrameworks.length, 0),
  );
  const hiddenCount = Math.max(
    totalCount - visibleFrameworks.length - visibleUnmonitored.length,
    0,
  );

  return (
    <CollapsibleCard
      embedded={embedded}
      storageKey="dashboard-framework-readiness"
      defaultOpen
      title="Framework posture"
      contentClassName="p-0"
    >
      {totalCount > 0 ? (
        <>
          <div className="flex items-center justify-end gap-3 px-4 pb-1 pt-3 sm:px-5">
            <label className="inline-flex items-center gap-2 text-xs text-muted">
              Sort
              <select
                value={sort}
                onChange={(event) =>
                  setSort(event.target.value as "priority" | "name")
                }
                className="ui-input h-7 py-0 pr-7 text-xs text-ink"
              >
                <option value="priority">Needs attention first</option>
                <option value="name">Name</option>
              </select>
            </label>
          </div>
          <div
            className={cn(
              "grid min-w-0 divide-y divide-line",
              expanded &&
                "max-h-[420px] overflow-y-auto overscroll-contain [scrollbar-width:thin]",
            )}
            tabIndex={0}
            role="region"
            aria-label="Framework posture list"
          >
            {visibleFrameworks.map((f) => (
              <FrameworkRow
                key={f.framework}
                framework={f}
                coverage={coverageByName.get(f.framework)}
              />
            ))}
            {visibleUnmonitored.map((framework) => (
              <FrameworkRow
                key={framework.framework_id}
                unmonitored={framework}
              />
            ))}
          </div>
          {totalCount > PREVIEW ? (
            <div className="border-t border-line px-2 py-1.5">
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="w-full text-muted hover:text-ink"
                aria-expanded={expanded}
                onClick={() => setExpanded(!expanded)}
              >
                {expanded ? (
                  <ChevronUp aria-hidden="true" className="h-4 w-4" />
                ) : (
                  <ChevronDown aria-hidden="true" className="h-4 w-4" />
                )}
                {expanded
                  ? "Show fewer"
                  : `Show all ${totalCount} framework packs (${hiddenCount} more)`}
              </Button>
            </div>
          ) : null}
          {stubs.length ? (
            <p className="border-t border-line px-4 py-2 text-xs text-muted sm:px-5">
              Not counted: {stubCountLabel(stubs.length)} registry{" "}
              {stubs.length === 1 ? "entry" : "entries"} with no requirements.{" "}
              <Link href="/frameworks" className="ui-link">
                View frameworks
              </Link>
            </p>
          ) : null}
        </>
      ) : (
        <div className="m-4 rounded-md border border-dashed border-line bg-surfaceMuted p-5 text-sm text-muted">
          No framework assessments yet. Connect a source and evaluate controls
          to begin.
        </div>
      )}
    </CollapsibleCard>
  );
}

"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import {
  ArrowUpRight,
  Calendar,
  ChevronDown,
  ExternalLink,
  FileCheck2,
  GitCompareArrows,
  Search,
  ShieldAlert,
  SlidersHorizontal,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { CollapsibleCard } from "@/components/ui/collapsible-card";
import { buttonVariants } from "@/components/ui/button";
import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Drawer } from "@/components/ui/drawer";
import { PageHeader } from "@/components/PageHeader";
import { TrustPipelineStrip } from "@/components/TrustPipelineStrip";
import { FrameworkBadge } from "@/components/framework/FrameworkBadge";
import { FrameworkDrilldownPanel } from "@/components/framework/FrameworkDrilldownPanel";
import { FrameworkRoster } from "@/components/framework/FrameworkRoster";
import { frameworkDetailHref } from "@/lib/framework-links";
import {
  useFrameworkCoverage,
  useCcfAssessment,
  useFrameworkDetail,
  useFrameworks,
  useReadiness,
} from "@/lib/api/hooks";
import type {
  FrameworkCoverageRow,
  FrameworkFreshness,
  FrameworkReadiness,
  FrameworkView,
  ReadinessStage,
} from "@/lib/api/types";
import { MAPPING_REVIEW_GLOSSARY, ROUTE_LABELS } from "@/lib/console-copy";
import { displayLabel } from "@/lib/display";
import { formatCount, formatDate } from "@/lib/format";
import {
  packState,
  splitFrameworkPacks,
  stubCountLabel,
  stubStatusLabel,
} from "@/lib/framework-packs";

const TONE_TEXT: Record<FrameworkFreshness, string> = {
  fresh: "Source pulled recently",
  stale: "Source overdue for re-pull",
  expired: "Source likely outdated",
  never_pulled: "Source never pulled — provenance unverified",
};

function Row({
  framework,
  coverage,
  readiness,
  frameworkNames,
  onSelect,
}: {
  framework: FrameworkView;
  coverage?: FrameworkCoverageRow;
  readiness?: FrameworkReadiness;
  frameworkNames: ReadonlyMap<string, string>;
  onSelect: () => void;
}) {
  const state = packState(framework);
  const isPlanned = state !== "seeded";
  const seededCount = coverage?.seeded_control_count ?? framework.control_count;
  const evaluatableCount = coverage?.evaluatable_requirement_count ?? 0;
  const evaluatablePct = coverage?.evaluatable_coverage_pct ?? 0;
  const attestableCount = coverage?.attestable_requirement_count ?? 0;
  const attestablePct = coverage?.attestable_coverage_pct ?? 0;
  const sourceMappingPct =
    coverage?.seeded_mapping_coverage_pct ?? framework.mapping_coverage_pct;

  return (
    <article className="group grid min-w-0 gap-3 rounded-2xl border border-line bg-surface p-4 shadow-sm transition-all duration-base hover:-translate-y-0.5 hover:border-brand/60 hover:shadow-card">
      <div className="flex min-w-0 items-start justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2.5">
          <FrameworkBadge
            frameworkId={framework.framework_id}
            fallbackLabel={framework.name}
            size={36}
            variant="mark-only"
          />
          <div className="min-w-0">
            <h2 className="truncate text-sm font-semibold text-ink">
              {framework.name}
            </h2>
            <div className="mt-0.5 truncate text-[11px] text-muted">
              {framework.version}
              {framework.effective_date &&
                ` · effective ${framework.effective_date}`}
            </div>
          </div>
        </div>
        <div className="shrink-0">
          <Badge
            tone={
              readiness?.is_ready
                ? "ready"
                : isPlanned
                  ? "default"
                  : "attention"
            }
          >
            {readiness?.is_ready
              ? "Ready"
              : state === "superseded"
                ? "Superseded"
                : isPlanned
                  ? "Planned"
                  : "In progress"}
          </Badge>
        </div>
      </div>

      <div className="grid gap-3">
        <div>
          <div className="flex items-center justify-between gap-3 text-xs">
            <span className="font-semibold text-ink">Mapped</span>
            <span className="text-muted">
              <b className="text-ink">{evaluatablePct}%</b> ·{" "}
              {formatCount(evaluatableCount)}/{formatCount(seededCount)}
            </span>
          </div>
          <div className="mt-1.5 h-2 overflow-hidden rounded-full bg-surfaceMuted">
            <div
              className="h-full rounded-full bg-brand"
              style={{ width: `${evaluatablePct}%` }}
            />
          </div>
        </div>
        <div>
          <div className="flex items-center justify-between gap-3 text-xs">
            <span className="font-semibold text-ink">Reviewed</span>
            <span className="text-muted">
              <b className="text-ink">{attestablePct}%</b> ·{" "}
              {formatCount(attestableCount)}/{formatCount(seededCount)}
            </span>
          </div>
          <div className="mt-1.5 h-2 overflow-hidden rounded-full bg-surfaceMuted">
            <div
              className="h-full rounded-full bg-success"
              style={{ width: `${attestablePct}%` }}
            />
          </div>
        </div>
      </div>

      {isPlanned &&
      (framework.coverage_boundary || framework.evidence_focus?.length) ? (
        <div className="grid gap-2 rounded-xl border border-dashed border-line bg-surfaceMuted/50 p-3 text-[11px] text-muted">
          <div className="font-semibold text-ink">
            {state === "superseded"
              ? stubStatusLabel(framework, frameworkNames)
              : "Planned boundary"}
          </div>
          {framework.coverage_boundary ? (
            <p>{framework.coverage_boundary}</p>
          ) : null}
          {framework.evidence_focus?.length ? (
            <div className="flex flex-wrap gap-1.5">
              {framework.evidence_focus.map((focus) => (
                <span
                  key={focus}
                  className="rounded-full border border-line bg-surface px-2 py-1"
                >
                  {focus}
                </span>
              ))}
            </div>
          ) : null}
        </div>
      ) : null}

      <div className="flex flex-wrap items-end justify-between gap-3 border-t border-line pt-3">
        <div className="min-w-0 text-[11px] text-muted">
          <a
            href={framework.official_source_url}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 font-semibold text-brand hover:underline"
          >
            official source <ExternalLink className="h-3 w-3" />
          </a>
          <div className="mt-1 truncate">
            {sourceMappingPct}% source-cited ·{" "}
            {framework.pulled_age_days === null
              ? "Not yet synced"
              : `${displayLabel(framework.freshness_state)} · pulled ${
                  framework.pulled_age_days === 0
                    ? "today"
                    : `${framework.pulled_age_days}d ago`
                }`}
            {framework.source_sha256
              ? ` · sha ${framework.source_sha256.slice(0, 10)}…`
              : " · hash pending"}
          </div>
        </div>
        <button
          type="button"
          onClick={onSelect}
          aria-label={`Inspect ${framework.name}`}
          className="inline-flex h-9 items-center gap-1.5 rounded-lg border border-line bg-surfaceMuted px-3 text-xs font-semibold text-ink transition-colors hover:border-brand hover:text-brand focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand"
        >
          Inspect <ArrowUpRight className="h-3.5 w-3.5" />
        </button>
      </div>
      {!isPlanned && !readiness?.is_ready ? (
        <div className="-mt-1 text-[11px] font-semibold text-warning-fg">
          Next gate: {STAGE_LABEL[readiness?.stage ?? "mapped"]}
        </div>
      ) : null}
    </article>
  );
}

function Detail({
  framework,
  coverage,
  expandedControlId,
  onExpandedControlChange,
  onClose,
}: {
  framework: FrameworkView | null;
  /** Same safeguard coverage row the roster reads, so both agree. */
  coverage?: FrameworkCoverageRow;
  expandedControlId: string | null;
  onExpandedControlChange: (controlId: string | null) => void;
  onClose: () => void;
}) {
  const detail = useFrameworkDetail(framework?.framework_id ?? null);
  const summary = detail.data?.summary;
  const results = summary
    ? {
        total: summary.control_count,
        pass: summary.passing_control_count,
        fail: summary.failing_control_count,
        notEvaluated: Math.max(
          summary.control_count -
            summary.passing_control_count -
            summary.failing_control_count,
          0,
        ),
      }
    : null;
  const share = (n: number) =>
    results && results.total > 0 ? (n / results.total) * 100 : 0;
  return (
    <Drawer
      open={Boolean(framework)}
      onOpenChange={(o) => !o && onClose()}
      title={framework?.name ?? "Framework"}
      description={framework?.version}
      width="lg"
    >
      {framework && (
        <div className="grid gap-5 text-sm">
          <div className="flex items-center gap-3">
            <FrameworkBadge
              frameworkId={framework.framework_id}
              fallbackLabel={framework.name}
              size={56}
            />
            <div>
              <div className="font-semibold text-ink">{framework.name}</div>
              <div className="text-xs text-muted">{framework.version}</div>
            </div>
          </div>
          <section
            className={[
              "rounded-xl border p-3",
              framework.freshness_state === "fresh"
                ? "border-success/40 bg-success-bg text-success-fg"
                : framework.freshness_state === "stale"
                  ? "border-warning/40 bg-warning-bg text-warning-fg"
                  : framework.freshness_state === "expired"
                    ? "border-danger/40 bg-danger-bg text-danger-fg"
                    : "border-line bg-surfaceMuted text-ink",
            ].join(" ")}
          >
            <div className="flex items-center gap-2 font-semibold">
              {framework.freshness_state === "fresh" ? (
                <FileCheck2 className="h-4 w-4" />
              ) : (
                <ShieldAlert className="h-4 w-4" />
              )}{" "}
              {TONE_TEXT[framework.freshness_state]}
            </div>
            <p className="mt-1 text-xs">{framework.copyright_guardrail}</p>
          </section>

          {packState(framework) !== "seeded" &&
          (framework.coverage_boundary ||
            framework.evidence_focus?.length ||
            framework.next_step) ? (
            <section className="grid gap-2 rounded-xl border border-dashed border-line bg-surfaceMuted/50 p-3">
              <div className="text-xs font-semibold text-muted">
                {packState(framework) === "superseded"
                  ? stubStatusLabel(framework)
                  : "Planned boundary"}
              </div>
              {framework.coverage_boundary ? (
                <p className="text-xs text-ink">
                  {framework.coverage_boundary}
                </p>
              ) : null}
              {framework.evidence_focus?.length ? (
                <ul className="grid gap-1 text-xs text-muted">
                  {framework.evidence_focus.map((focus) => (
                    <li key={focus}>• {focus}</li>
                  ))}
                </ul>
              ) : null}
              {framework.next_step ? (
                <p className="text-xs font-semibold text-ink">
                  Next step: {framework.next_step}
                </p>
              ) : null}
            </section>
          ) : null}

          <dl className="grid grid-cols-[140px_1fr] gap-x-3 gap-y-1.5">
            <dt className="text-muted">Source</dt>
            <dd>
              <a
                href={framework.official_source_url}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 break-all text-brand hover:underline"
              >
                {framework.official_source_name}{" "}
                <ExternalLink className="h-3 w-3" />
              </a>
            </dd>
            <dt className="text-muted">Effective date</dt>
            <dd className="font-semibold">
              <Calendar className="mr-1 inline h-3 w-3" />
              {framework.effective_date ?? "—"}
            </dd>
            <dt className="text-muted">Last pulled</dt>
            <dd className="font-semibold">
              {framework.pulled_at ?? "Not yet synced"}
            </dd>
            <dt className="text-muted">Source sha256</dt>
            <dd>
              <code className="break-all text-xs text-ink">
                {framework.source_sha256 ?? "—"}
              </code>
            </dd>
            <dt className="text-muted">Next pull due</dt>
            <dd className="font-semibold">
              {formatDate(framework.next_pull_due)}
            </dd>
            <dt className="text-muted">Superseded by</dt>
            <dd className="font-semibold">{framework.superseded_by ?? "—"}</dd>
          </dl>

          <section className="rounded-xl border border-line p-3">
            <div className="text-xs font-semibold uppercase tracking-wide text-muted">
              Control results
            </div>
            {results ? (
              <>
                <div className="mt-2 text-base font-semibold text-ink">
                  {results.pass} passing · {results.fail} failing ·{" "}
                  {results.notEvaluated} not evaluated
                </div>
                <div className="text-xs text-muted">
                  of {results.total}{" "}
                  {results.total === 1 ? "control" : "controls"}
                </div>
                <div
                  className="mt-2 flex h-2 overflow-hidden rounded-full bg-surfaceMuted"
                  aria-hidden="true"
                >
                  <div
                    className="h-full bg-success"
                    style={{ width: `${share(results.pass)}%` }}
                  />
                  <div
                    className="h-full bg-danger"
                    style={{ width: `${share(results.fail)}%` }}
                  />
                </div>
              </>
            ) : (
              <p className="mt-2 text-xs text-muted">
                {detail.isError
                  ? "Control results could not be loaded."
                  : "Loading control results…"}
              </p>
            )}
            <div className="mt-3 border-t border-line pt-2 text-xs text-muted">
              <span className="font-semibold text-ink">
                {coverage?.evaluatable_requirement_count ?? 0} of{" "}
                {coverage?.seeded_control_count ?? framework.control_count}{" "}
                controls mapped
              </span>{" "}
              to safeguards; {framework.implemented_control_count} cite their
              official source ({framework.mapping_coverage_pct}%). Mapped means
              a safeguard can evaluate it, not that it is implemented or
              passing.
            </div>
          </section>

          <section className="grid gap-2 rounded-xl border border-line p-3">
            <FrameworkDrilldownPanel
              frameworkId={framework.framework_id}
              expandedControlId={expandedControlId}
              onExpandedControlChange={onExpandedControlChange}
            />
          </section>
        </div>
      )}
    </Drawer>
  );
}

const STAGE_ORDER: ReadinessStage[] = [
  "source_pulled",
  "mapped",
  "evidence_defined",
  "rule_versioned",
  "coverage_verified",
];

const STAGE_LABEL: Record<ReadinessStage, string> = {
  source_pulled: "Source pulled",
  mapped: "Reviewed article mappings",
  evidence_defined: "Evidence defined",
  rule_versioned: "Rule versioned",
  coverage_verified: "Coverage gate passed",
};

function ReadinessRow({ row }: { row: FrameworkReadiness }) {
  const passedGateCount = STAGE_ORDER.filter(
    (stage) => row.gates[stage],
  ).length;
  const progress = (passedGateCount / STAGE_ORDER.length) * 100;

  return (
    <div className="rounded-xl border border-line bg-surface p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="flex items-center gap-2">
          <FrameworkBadge
            frameworkId={row.framework_id}
            fallbackLabel={row.name}
            size={28}
          />
          <code className="text-sm font-semibold text-ink">
            {row.framework_id}
          </code>
        </span>
        <Badge tone={row.is_ready ? "ready" : "attention"}>
          {row.is_ready ? "Ready" : `Blocked: ${STAGE_LABEL[row.stage]}`}
        </Badge>
      </div>
      <div className="mt-1 text-xs text-muted">
        {row.mapped_control_count}/{row.control_count} controls with a reviewed
        article mapping · {row.coverage_pct}%
      </div>
      <div className="mt-3 flex items-center gap-3">
        <div className="h-1.5 min-w-0 flex-1 overflow-hidden rounded-full bg-surfaceMuted">
          <div
            className="h-full rounded-full bg-brand"
            style={{ width: `${progress}%` }}
          />
        </div>
        <span className="shrink-0 text-[11px] font-semibold text-muted">
          {passedGateCount}/{STAGE_ORDER.length} gates
        </span>
      </div>
      {!row.is_ready ? (
        <div className="mt-1.5 truncate text-[11px] text-muted">
          Next: <b className="text-ink">{STAGE_LABEL[row.stage]}</b>
        </div>
      ) : null}
    </div>
  );
}

function SafeguardAssessment() {
  const assessment = useCcfAssessment();
  const data = assessment.data;
  const rows = data?.safeguards ?? [];
  const passed = rows.filter((row) => row.status === "pass").length;
  const failed = rows.filter((row) => row.status === "fail").length;
  return (
    <CollapsibleCard
      title="Safeguard assessment · observed assets"
      defaultOpen={false}
      storageKey="frameworks:safeguard-assessment"
    >
      <p className="text-sm text-muted">
        Explicit safeguard evidence is evaluated against applicable observed
        assets. Mapping coverage alone does not establish a pass. Complete asset
        inventory is not established.
      </p>
      {assessment.isLoading ? (
        <p className="mt-3 text-sm">Loading assessment…</p>
      ) : assessment.isError ? (
        <p role="alert" className="mt-3 text-sm">
          Assessment unavailable. Reload to try again.
        </p>
      ) : rows.length === 0 ? (
        <p className="mt-3 text-sm">
          No safeguard assessment has been published. Run a lake evaluation to
          begin.
        </p>
      ) : (
        <>
          <p className="mt-3 text-sm">
            {passed} passing · {failed} failing ·{" "}
            {rows.length - passed - failed} stale or not evaluated ·{" "}
            {data?.asset_count ?? 0} observed assets
          </p>
          {data?.review_log_verified === false && (
            <p role="alert" className="mt-2 text-sm">
              Mapping review integrity could not be verified. Requirement passes
              are blocked.
            </p>
          )}
          <div className="mt-4 max-h-80 overflow-auto">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">
                Safeguard results in the published assessment
              </caption>
              <thead>
                <tr>
                  <th scope="col" className="p-2">
                    Safeguard
                  </th>
                  <th scope="col" className="p-2">
                    Result
                  </th>
                  <th scope="col" className="p-2">
                    Assets assessed / applicable
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.safeguard_id} className="border-t border-line">
                    <th scope="row" className="p-2 font-normal">
                      <span className="block text-xs text-muted">
                        {row.safeguard_id}
                      </span>
                      {row.title}
                    </th>
                    <td className="p-2">{row.status.replaceAll("_", " ")}</td>
                    <td className="p-2 tabular-nums">
                      {row.assessed_asset_count} / {row.applicable_asset_count}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </CollapsibleCard>
  );
}

function FrameworksPageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const frameworks = useFrameworks();
  const coverage = useFrameworkCoverage();
  const readiness = useReadiness();
  const [selected, setSelected] = useState<FrameworkView | null>(null);
  const [query, setQuery] = useState("");
  const [readinessFilter, setReadinessFilter] = useState("all");
  const [freshnessFilter, setFreshnessFilter] = useState("all");
  const [showFilters, setShowFilters] = useState(false);
  const [showReadiness, setShowReadiness] = useState(false);
  const data = useMemo(() => frameworks.data ?? [], [frameworks.data]);
  const readinessRows = useMemo(() => readiness.data ?? [], [readiness.data]);
  const frameworkParam = searchParams.get("framework");
  const controlParam = searchParams.get("control");
  const readinessById = useMemo(
    () => new Map(readinessRows.map((row) => [row.framework_id, row])),
    [readinessRows],
  );
  const coverageRows = useMemo(
    () => coverage.data?.frameworks ?? [],
    [coverage.data?.frameworks],
  );
  const coverageById = useMemo(
    () => new Map(coverageRows.map((row) => [row.framework_id, row])),
    [coverageRows],
  );
  const coverageSummary = coverage.data?.summary;
  const frameworkNames = useMemo(
    () => new Map(data.map((row) => [row.framework_id, row.name])),
    [data],
  );
  const { packs, stubs } = useMemo(() => splitFrameworkPacks(data), [data]);
  const packReadiness = useMemo(
    () => splitFrameworkPacks(readinessRows).packs,
    [readinessRows],
  );
  const portfolio = useMemo(() => {
    return {
      ready: packReadiness.filter((row) => row.is_ready).length,
      total: packReadiness.length,
    };
  }, [packReadiness]);
  const stubNote = stubCountLabel(stubs.length);
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return data.filter((row) => {
      const readinessRow = readinessById.get(row.framework_id);
      const readinessMatch =
        readinessFilter === "all" ||
        (readinessFilter === "ready" && readinessRow?.is_ready) ||
        (readinessFilter === "needs_work" &&
          packState(row) === "seeded" &&
          !readinessRow?.is_ready) ||
        (readinessFilter === "planned" && packState(row) !== "seeded");
      const freshnessMatch =
        freshnessFilter === "all" || row.freshness_state === freshnessFilter;
      const queryMatch =
        !needle ||
        [row.name, row.framework_id, row.version, row.official_source_name]
          .join(" ")
          .toLowerCase()
          .includes(needle);
      return Boolean(readinessMatch && freshnessMatch && queryMatch);
    });
  }, [data, freshnessFilter, query, readinessById, readinessFilter]);

  useEffect(() => {
    if (!frameworkParam || data.length === 0) return;
    const match = data.find((row) => row.framework_id === frameworkParam);
    if (match) setSelected(match);
  }, [frameworkParam, data]);

  function openFramework(framework: FrameworkView) {
    setSelected(framework);
    router.replace(frameworkDetailHref(framework.framework_id), {
      scroll: false,
    });
  }

  function closeFramework() {
    setSelected(null);
    router.replace("/frameworks", { scroll: false });
  }

  function setExpandedControl(controlId: string | null) {
    if (!selected) return;
    router.replace(frameworkDetailHref(selected.framework_id, controlId), {
      scroll: false,
    });
  }

  return (
    <div className="page-shell grid min-h-full gap-5">
      <PageHeader
        title={ROUTE_LABELS["/frameworks"]}
        description="Review requirement coverage, mapping status, readiness gates, and source records for each framework."
        actions={
          <div className="flex flex-wrap gap-2">
            <Link href="/crosswalk" className={buttonVariants({ size: "sm" })}>
              <GitCompareArrows className="h-3.5 w-3.5" /> Crosswalk
            </Link>
            <Link
              href="/controls"
              className={buttonVariants({ size: "sm", variant: "primary" })}
            >
              Explore controls <ArrowUpRight className="h-3.5 w-3.5" />
            </Link>
          </div>
        }
      />
      <TrustPipelineStrip activeStage="frameworks" />

      <section
        aria-label="Framework coverage summary"
        className="overflow-hidden rounded-lg border border-line bg-surface"
      >
        <div className="flex flex-wrap items-start justify-between gap-3 border-b border-line px-4 py-3 sm:px-5">
          <div className="min-w-0">
            <h2 className="ui-section-title">Requirement coverage</h2>
            <p className="mt-0.5 text-xs text-muted">
              Catalogued, mapped, and reviewed counts are reported separately.
              Proposed mappings stay in the review queue.
            </p>
          </div>
          <Badge
            tone={
              portfolio.total > 0 && portfolio.ready === portfolio.total
                ? "ready"
                : "attention"
            }
          >
            {portfolio.ready}/{portfolio.total} packs ready
          </Badge>
        </div>
        <dl className="grid divide-line sm:grid-cols-2 sm:divide-x xl:grid-cols-4 [&>div]:border-line max-sm:divide-y">
          <div className="px-4 py-4 sm:px-5">
            <dt className="ui-label">Catalogued requirements</dt>
            <dd className="ui-kpi-value mt-1.5">
              {formatCount(coverageSummary?.seeded_control_count)}
            </dd>
            <dd className="mt-1.5 text-xs text-muted">
              Across {coverageSummary?.seeded_framework_count ?? packs.length}{" "}
              framework packs
              {stubNote ? ` · ${stubNote} not counted` : ""}
            </dd>
          </div>
          <div className="px-4 py-4 sm:px-5">
            <dt className="ui-label">Mapped requirements</dt>
            <dd className="ui-kpi-value mt-1.5">
              {coverageSummary
                ? `${coverageSummary.evaluatable_coverage_pct}%`
                : "—"}
            </dd>
            <dd className="mt-1.5 text-xs text-muted">
              {formatCount(coverageSummary?.evaluatable_requirement_count)}{" "}
              mapped to safeguards
            </dd>
            <dd className="mt-2 h-1 overflow-hidden rounded-full bg-surfaceMuted">
              <div
                className="h-full rounded-full bg-line-strong"
                style={{
                  width: `${coverageSummary?.evaluatable_coverage_pct ?? 0}%`,
                }}
              />
            </dd>
          </div>
          <div className="px-4 py-4 sm:px-5">
            <dt className="ui-label">Reviewed requirements</dt>
            <dd className="ui-kpi-value mt-1.5">
              {coverageSummary
                ? `${coverageSummary.attestable_coverage_pct}%`
                : "—"}
            </dd>
            <dd className="mt-1.5 text-xs text-muted">
              {formatCount(coverageSummary?.attestable_requirement_count)}{" "}
              requirements with a reviewed mapping:{" "}
              {formatCount(
                coverageSummary?.maintainer_reviewed_requirement_count ??
                  coverageSummary?.attestable_requirement_count,
              )}{" "}
              {MAPPING_REVIEW_GLOSSARY.maintainer_reviewed.label.toLowerCase()}{" "}
              ·{" "}
              {formatCount(
                coverageSummary?.org_reviewed_requirement_count ?? 0,
              )}{" "}
              {MAPPING_REVIEW_GLOSSARY.org_reviewed.label.toLowerCase()}
            </dd>
          </div>
          <div className="px-4 py-4 sm:px-5">
            <dt className="ui-label">Review backlog</dt>
            <dd className="ui-kpi-value mt-1.5">
              {coverageSummary
                ? formatCount(
                    coverageSummary.evaluatable_requirement_count -
                      coverageSummary.attestable_requirement_count,
                  )
                : "—"}
            </dd>
            <dd className="mt-1.5 text-xs text-muted">
              Requirements with a proposed link awaiting review
              {coverageSummary?.rejected_mapping_count
                ? ` · ${formatCount(coverageSummary.rejected_mapping_count)} mapping(s) rejected by your org`
                : ""}
            </dd>
            <dd className="mt-2">
              <Link href="/mapping-review" className="ui-link text-xs">
                Review mappings
              </Link>
            </dd>
          </div>
        </dl>
      </section>

      <SafeguardAssessment />

      <FrameworkRoster
        frameworks={data}
        coverage={coverageRows}
        readiness={readinessRows}
      />

      <section
        aria-label="Framework catalog"
        className="grid gap-3 rounded-lg border border-line bg-surface p-4 sm:p-5"
      >
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-ink">
              Framework catalog
            </h2>
            <p className="mt-0.5 text-xs text-muted">
              {filtered.length} of {data.length} shown · {packs.length} packs
              {stubNote ? `, ${stubNote}` : ""}
            </p>
          </div>
          <Badge>{filtered.length} shown</Badge>
        </div>

        <div className="grid gap-2 rounded-xl border border-line bg-surfaceMuted p-2">
          <div className="grid min-w-0 gap-2 sm:grid-cols-[minmax(0,1fr)_auto]">
            <label className="flex h-10 min-w-0 items-center gap-2 rounded-lg border border-line bg-surface px-3 text-sm shadow-sm focus-within:border-brand focus-within:ring-2 focus-within:ring-brand/20">
              <Search className="h-4 w-4 shrink-0 text-muted" />
              <input
                type="search"
                aria-label="Search frameworks"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search frameworks"
                className="min-w-0 flex-1 bg-transparent text-ink outline-none placeholder:text-muted"
              />
            </label>
            <button
              type="button"
              aria-expanded={showFilters}
              aria-controls="framework-filters"
              onClick={() => setShowFilters((value) => !value)}
              className="inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-line bg-surface px-3 text-sm font-semibold text-ink shadow-sm transition-colors hover:border-brand hover:text-brand"
            >
              <SlidersHorizontal className="h-4 w-4" />
              {showFilters ? "Hide filters" : "Show filters"}
            </button>
          </div>
          {showFilters ? (
            <div id="framework-filters" className="grid gap-2 sm:grid-cols-2">
              <select
                aria-label="Filter by readiness"
                value={readinessFilter}
                onChange={(event) => setReadinessFilter(event.target.value)}
                className="h-10 min-w-0 rounded-lg border border-line bg-surface px-3 text-sm font-semibold text-ink outline-none focus:border-brand focus:ring-2 focus:ring-brand/20"
              >
                <option value="all">All readiness</option>
                <option value="ready">Ready</option>
                <option value="needs_work">Needs mapping</option>
                <option value="planned">Planned or superseded</option>
              </select>
              <select
                aria-label="Filter by source health"
                value={freshnessFilter}
                onChange={(event) => setFreshnessFilter(event.target.value)}
                className="h-10 min-w-0 rounded-lg border border-line bg-surface px-3 text-sm font-semibold text-ink outline-none focus:border-brand focus:ring-2 focus:ring-brand/20"
              >
                <option value="all">All source health</option>
                <option value="fresh">Fresh</option>
                <option value="stale">Stale</option>
                <option value="expired">Expired</option>
                <option value="never_pulled">Never pulled</option>
              </select>
            </div>
          ) : null}
        </div>

        {data.length === 0 ? (
          <div className="rounded-xl border border-dashed border-line p-5 text-sm text-muted">
            No frameworks registered. Check{" "}
            <code>frameworks/registry.json</code>.
          </div>
        ) : filtered.length === 0 ? (
          <div className="rounded-xl border border-dashed border-line p-5 text-sm text-muted">
            No frameworks match the current filters.
          </div>
        ) : (
          <div className="grid min-w-0 gap-3 xl:grid-cols-2 2xl:grid-cols-3">
            {filtered.map((framework) => (
              <Row
                key={framework.framework_id}
                framework={framework}
                coverage={coverageById.get(framework.framework_id)}
                readiness={readinessById.get(framework.framework_id)}
                frameworkNames={frameworkNames}
                onSelect={() => openFramework(framework)}
              />
            ))}
          </div>
        )}
      </section>

      <Card className="overflow-hidden">
        <CardHeader className="gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="min-w-0">
            <CardTitle>Readiness gates</CardTitle>
            <CardDescription>
              {portfolio.ready} of {portfolio.total} packs pass every gate. Open
              the audit detail only when you need it.
            </CardDescription>
          </div>
          <button
            type="button"
            aria-expanded={showReadiness}
            aria-controls="framework-readiness-details"
            onClick={() => setShowReadiness((value) => !value)}
            className="inline-flex h-9 shrink-0 items-center justify-center gap-1.5 rounded-lg border border-line bg-surfaceMuted px-3 text-xs font-semibold text-ink transition-colors hover:border-brand hover:text-brand"
          >
            {showReadiness
              ? "Hide readiness details"
              : "Show readiness details"}
            <ChevronDown
              className={`h-3.5 w-3.5 transition-transform ${showReadiness ? "rotate-180" : ""}`}
            />
          </button>
        </CardHeader>
        {showReadiness ? (
          <div
            id="framework-readiness-details"
            role="region"
            aria-label="Readiness details"
            className="grid gap-2 px-5 pb-5 xl:grid-cols-2"
          >
            {readinessRows.length === 0 ? (
              <div className="rounded-lg border border-dashed border-line p-3 text-xs text-muted">
                Loading readiness…
              </div>
            ) : (
              packReadiness.map((row) => (
                <ReadinessRow key={row.framework_id} row={row} />
              ))
            )}
          </div>
        ) : null}
      </Card>

      <Detail
        framework={selected}
        coverage={
          selected ? coverageById.get(selected.framework_id) : undefined
        }
        expandedControlId={controlParam}
        onExpandedControlChange={setExpandedControl}
        onClose={closeFramework}
      />
    </div>
  );
}

export default function FrameworksPage() {
  return (
    <Suspense
      fallback={
        <div className="px-4 py-5 text-sm text-muted">Loading frameworks…</div>
      }
    >
      <FrameworksPageContent />
    </Suspense>
  );
}

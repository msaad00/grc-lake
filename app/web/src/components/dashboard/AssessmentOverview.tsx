"use client";

import Link from "next/link";
import { useEffect, useRef, type ReactNode } from "react";
import {
  ArrowUpRight,
  ChartNoAxesCombined,
  ChevronDown,
  CircleCheck,
  Clock3,
  FileCheck2,
  ListChecks,
  ShieldAlert,
} from "lucide-react";
import type { Assessment, IngestionStatus } from "@/lib/api/types";
import { formatDateTime, formatRelative } from "@/lib/format";

type Segment = { label: string; count: number; color: string };

const TILE_SURFACE =
  "group flex min-w-0 flex-col gap-2 rounded-xl border border-line bg-surface p-4 transition-colors hover:border-brand/50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand sm:p-5";

const INLINE_LINK =
  "inline-flex items-center gap-1.5 rounded-sm hover:text-ink focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand";

const STATE_TONE = {
  ready: "text-emerald-600 dark:text-emerald-400",
  attention_required: "text-amber-600 dark:text-amber-400",
  critical: "text-rose-600 dark:text-rose-400",
} as const;

const STATE_BAR = {
  ready: "bg-emerald-500",
  attention_required: "bg-amber-500",
  critical: "bg-rose-500",
} as const;

function StackedBar({
  segments,
  total,
  label,
  omitFromLegend = [],
  progress,
}: {
  segments: Segment[];
  total: number;
  label: string;
  omitFromLegend?: string[];
  /** Render as an accessible progressbar with this 0-100 value. */
  progress?: { label: string; value: number };
}) {
  const visible = segments.filter((item) => item.count > 0);
  const legend = visible.filter((item) => !omitFromLegend.includes(item.label));
  return (
    <>
      <div
        {...(progress
          ? {
              role: "progressbar",
              "aria-label": progress.label,
              "aria-valuemin": 0,
              "aria-valuemax": 100,
              "aria-valuenow": progress.value,
              "aria-valuetext": `${label}: ${visible.map((item) => `${item.count} ${item.label.toLowerCase()}`).join(", ")}`,
            }
          : {
              role: "img",
              "aria-label": `${label}: ${visible.map((item) => `${item.count} ${item.label.toLowerCase()}`).join(", ")}`,
            })}
        className="flex h-1.5 gap-0.5 overflow-hidden rounded-full bg-surfaceMuted"
      >
        {visible.map((item) => (
          <span
            key={item.label}
            className={item.color}
            style={{ width: `${total ? (item.count / total) * 100 : 0}%` }}
          />
        ))}
      </div>
      <div className="flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-muted">
        {legend.map((item) => (
          <span key={item.label} className="inline-flex items-center gap-1">
            <span
              aria-hidden="true"
              className={`h-1.5 w-1.5 rounded-full ${item.color}`}
            />
            <strong className="font-semibold text-ink">{item.count}</strong>{" "}
            {item.label}
          </span>
        ))}
      </div>
    </>
  );
}

function Tile({
  href,
  label,
  icon,
  value,
  suffix,
  valueTone = "text-ink",
  detail,
  children,
}: {
  href: string;
  label: string;
  icon: ReactNode;
  value: ReactNode;
  suffix?: string;
  valueTone?: string;
  detail: ReactNode;
  children?: ReactNode;
}) {
  return (
    <Link href={href} className={TILE_SURFACE}>
      <div className="flex items-center justify-between gap-2 text-xs font-medium text-muted">
        <span>{label}</span>
        <span className="flex items-center gap-1.5">
          {icon}
          <ArrowUpRight
            aria-hidden="true"
            className="h-3.5 w-3.5 opacity-0 transition-opacity group-hover:opacity-100"
          />
        </span>
      </div>
      <div className="flex items-baseline gap-1">
        <span
          className={`text-2xl font-semibold leading-none tracking-tight tabular-nums sm:text-3xl ${valueTone}`}
        >
          {value}
        </span>
        {suffix ? (
          <span className="text-sm font-medium text-muted">{suffix}</span>
        ) : null}
      </div>
      <div className="text-xs text-muted">{detail}</div>
      {children ? <div className="mt-auto grid gap-2">{children}</div> : null}
    </Link>
  );
}

/** Inline disclosure: pushes content down instead of floating over it, and
 * closes on Escape or a click elsewhere like the popovers around it. */
function AssessmentDetails({
  hash,
  evaluatedAt,
}: {
  hash?: string | null;
  evaluatedAt?: string | null;
}) {
  const ref = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    const onPointer = (event: PointerEvent) => {
      const el = ref.current;
      if (el?.open && !el.contains(event.target as Node)) el.open = false;
    };
    const onKey = (event: KeyboardEvent) => {
      const el = ref.current;
      if (event.key === "Escape" && el?.open) {
        el.open = false;
        el.querySelector("summary")?.focus();
      }
    };
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, []);
  return (
    <details ref={ref} className="max-w-full [&[open]_.chevron]:rotate-180">
      <summary
        className={`${INLINE_LINK} w-fit cursor-pointer list-none [&::-webkit-details-marker]:hidden`}
      >
        Assessment details
        <ChevronDown
          aria-hidden="true"
          className="chevron h-3.5 w-3.5 transition-transform"
        />
      </summary>
      <dl className="mt-2 grid max-w-full gap-x-6 gap-y-2 rounded-lg border border-line bg-surface p-3 text-xs sm:w-fit sm:grid-cols-[auto_auto]">
        <div className="min-w-0">
          <dt className="text-muted">Assessment ID</dt>
          <dd className="mt-0.5 break-all font-mono text-ink">
            {hash || "Not available"}
          </dd>
        </div>
        <div className="min-w-0">
          <dt className="text-muted">Time evaluated</dt>
          <dd className="mt-0.5 text-ink">{formatDateTime(evaluatedAt)}</dd>
        </div>
      </dl>
    </details>
  );
}

export function AssessmentOverview({
  assessment,
  ingestion,
  frameworkCount,
}: {
  assessment?: Assessment;
  ingestion?: IngestionStatus;
  frameworkCount: number;
}) {
  const posture = assessment?.posture;
  const state = posture?.state;
  const accuracy = ingestion?.eval_accuracy;
  const evaluated = Boolean(accuracy?.has_tests);
  const rate = accuracy?.pass_rate;
  const passPercent =
    evaluated && rate != null && Number.isFinite(rate)
      ? Math.round(rate * 100)
      : null;
  const status = !posture
    ? "Not assessed"
    : state === "ready"
      ? "Ready for review"
      : state === "critical"
        ? "Needs attention"
        : "Review required";
  const StatusIcon = state === "ready" ? CircleCheck : ShieldAlert;
  const statusTone = state ? STATE_TONE[state] : "text-muted";
  const exportReady = Boolean(ingestion?.proof.proof_pack_exists);

  const total = accuracy?.total_tests ?? 0;
  const passing = accuracy?.passing ?? 0;
  const failing = accuracy?.failing ?? 0;
  const warning = accuracy?.warning ?? 0;
  const needsEvidence = accuracy?.needs_evidence ?? 0;
  const outcomes: Segment[] = [
    { label: "Pass", count: passing, color: "bg-emerald-500" },
    { label: "Fail", count: failing, color: "bg-rose-500" },
    { label: "Warning", count: warning, color: "bg-amber-400" },
    { label: "Needs evidence", count: needsEvidence, color: "bg-sky-400" },
    {
      label: "Other",
      count: Math.max(0, total - passing - failing - warning - needsEvidence),
      color: "bg-slate-400",
    },
  ];

  const findings = posture?.open_violation_count ?? 0;
  const critical = posture?.critical_violation_count ?? 0;
  const high = posture?.high_violation_count ?? 0;
  const severity: Segment[] = [
    { label: "Critical", count: critical, color: "bg-rose-600" },
    { label: "High", count: high, color: "bg-orange-400" },
    {
      label: "Medium or low",
      count: Math.max(0, findings - critical - high),
      color: "bg-slate-400",
    },
  ];

  const assessed = assessment?.frameworks.length ?? 0;
  const staleRows = posture?.stale_evidence_count ?? 0;
  const staleControls = posture?.stale_control_count ?? 0;

  return (
    <section
      aria-labelledby="current-assessment-heading"
      className="grid min-w-0 gap-3"
    >
      <h2 id="current-assessment-heading" className="sr-only">
        Current assessment
      </h2>
      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-2 text-xs text-muted">
        <p
          className={`inline-flex items-center gap-1.5 font-semibold ${statusTone}`}
        >
          <StatusIcon aria-hidden="true" className="h-3.5 w-3.5" />
          {status}
        </p>
        {assessment?.evaluated_at ? (
          <span>Evaluated {formatRelative(assessment.evaluated_at)}</span>
        ) : null}
        <Link href="/audit-room" className={INLINE_LINK}>
          <FileCheck2 aria-hidden="true" className="h-3.5 w-3.5" />
          <span>Assessment export</span>
          <span className="rounded-md border border-line bg-surface px-1.5 py-0.5 text-[11px] font-medium text-ink">
            {exportReady ? "Available" : "Pending"}
          </span>
        </Link>
        {assessment ? (
          <AssessmentDetails
            hash={assessment.assessment_hash}
            evaluatedAt={assessment.evaluated_at}
          />
        ) : null}
      </div>
      <div className="grid grid-cols-2 gap-2 sm:gap-3 xl:grid-cols-4">
        <Tile
          href="/frameworks"
          label="Assessment score"
          icon={<ChartNoAxesCombined aria-hidden="true" className="h-4 w-4" />}
          value={posture ? Math.round(posture.score) : "—"}
          suffix={posture ? "/ 100" : undefined}
          valueTone={statusTone === "text-muted" ? "text-ink" : statusTone}
          detail={
            <>
              <strong className="font-semibold text-ink">
                {assessed} of {frameworkCount}
              </strong>{" "}
              frameworks assessed
            </>
          }
        >
          {posture ? (
            <div
              role="progressbar"
              aria-label="Assessment score"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={Math.round(posture.score)}
              className="h-1.5 overflow-hidden rounded-full bg-surfaceMuted"
            >
              <span
                className={`block h-full rounded-full ${state ? STATE_BAR[state] : "bg-slate-400"}`}
                style={{
                  width: `${Math.max(2, Math.min(100, posture.score))}%`,
                }}
              />
            </div>
          ) : null}
        </Tile>
        <Tile
          href="/controls"
          label="Control pass rate"
          icon={<ListChecks aria-hidden="true" className="h-4 w-4" />}
          value={passPercent ?? "—"}
          suffix={passPercent != null ? "%" : undefined}
          detail={
            passPercent != null ? (
              <>
                <strong className="font-semibold text-ink">
                  {passing} of {total}
                </strong>{" "}
                tests passing
              </>
            ) : (
              "Not evaluated"
            )
          }
        >
          {passPercent != null ? (
            <StackedBar
              segments={outcomes}
              total={total}
              label="Control test results"
              progress={{ label: "Control pass rate", value: passPercent }}
            />
          ) : null}
        </Tile>
        <Tile
          href="/violations"
          label="Open findings"
          icon={<ShieldAlert aria-hidden="true" className="h-4 w-4" />}
          value={posture ? findings : "—"}
          detail={
            posture ? (
              critical > 0 ? (
                <>
                  <span className="font-semibold text-rose-600 dark:text-rose-400">
                    {critical} critical
                  </span>
                  {high > 0 ? ` · ${high} high` : null}
                </>
              ) : (
                "No critical findings"
              )
            ) : (
              "Awaiting assessment"
            )
          }
        >
          {posture && findings > 0 ? (
            <StackedBar
              segments={severity}
              total={findings}
              label="Finding severity"
              omitFromLegend={["Critical", "High"]}
            />
          ) : null}
        </Tile>
        <Tile
          href="/evidence"
          label="Evidence to refresh"
          icon={<Clock3 aria-hidden="true" className="h-4 w-4" />}
          value={posture ? staleRows : "—"}
          valueTone={
            staleRows > 0 ? "text-amber-600 dark:text-amber-400" : "text-ink"
          }
          detail={
            posture ? (
              staleRows > 0 ? (
                <>
                  {staleRows === 1 ? "Record" : "Records"} past the freshness
                  SLA ·{" "}
                  <strong className="font-semibold text-ink">
                    {staleControls}
                  </strong>{" "}
                  {staleControls === 1 ? "control" : "controls"} affected
                </>
              ) : (
                "All evidence within its freshness SLA"
              )
            ) : (
              "Freshness unavailable"
            )
          }
        />
      </div>
    </section>
  );
}

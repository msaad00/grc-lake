"use client";

import Link from "next/link";
import type { ReactNode } from "react";
import {
  ArrowUpRight,
  ChartNoAxesCombined,
  CircleCheck,
  Clock3,
  FileCheck2,
  ListChecks,
  ShieldAlert,
} from "lucide-react";
import type { Assessment, IngestionStatus } from "@/lib/api/types";
import { formatRelative } from "@/lib/format";

type Segment = { label: string; count: number; color: string };

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
}: {
  segments: Segment[];
  total: number;
  label: string;
  omitFromLegend?: string[];
}) {
  const visible = segments.filter((item) => item.count > 0);
  const legend = visible.filter((item) => !omitFromLegend.includes(item.label));
  return (
    <>
      <div
        role="img"
        aria-label={`${label}: ${visible.map((item) => `${item.count} ${item.label.toLowerCase()}`).join(", ")}`}
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
      <div className="hidden flex-wrap gap-x-3 gap-y-1 text-[11px] text-muted sm:flex">
        {legend.map((item) => (
          <span key={item.label} className="inline-flex items-center gap-1">
            <span
              aria-hidden="true"
              className={`h-1.5 w-1.5 rounded-full ${item.color}`}
            />
            <strong className="font-semibold text-ink">{item.count}</strong>
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
    <Link
      href={href}
      className="group flex min-w-0 flex-col gap-2 rounded-xl border border-line bg-surface p-3 transition-colors sm:p-4 hover:border-brand/50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-brand"
    >
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
    <section aria-label="Current assessment" className="grid min-w-0 gap-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-muted">
        <span
          className={`inline-flex items-center gap-1.5 font-semibold ${statusTone}`}
        >
          <StatusIcon aria-hidden="true" className="h-3.5 w-3.5" />
          <h2>{status}</h2>
        </span>
        {assessment?.evaluated_at ? (
          <span title={assessment.assessment_hash || undefined}>
            Evaluated {formatRelative(assessment.evaluated_at)}
          </span>
        ) : null}
        <Link
          href="/audit-room"
          className="inline-flex items-center gap-1.5 hover:text-ink focus-visible:outline focus-visible:outline-2 focus-visible:outline-brand"
        >
          <FileCheck2 aria-hidden="true" className="h-3.5 w-3.5" />
          Assessment export: {exportReady ? "available" : "pending"}
        </Link>
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
              "Not evaluated yet"
            )
          }
        >
          {passPercent != null ? (
            <StackedBar
              segments={outcomes}
              total={total}
              label="Control test results"
              omitFromLegend={["Pass"]}
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
          href="/evidence/"
          label="Stale evidence"
          icon={<Clock3 aria-hidden="true" className="h-4 w-4" />}
          value={posture ? staleRows : "—"}
          valueTone={
            staleRows > 0 ? "text-amber-600 dark:text-amber-400" : "text-ink"
          }
          detail={
            posture ? (
              staleRows > 0 ? (
                <>
                  Past their freshness SLA ·{" "}
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

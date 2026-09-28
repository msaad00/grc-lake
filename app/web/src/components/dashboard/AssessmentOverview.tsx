"use client";

import Link from "next/link";
import { useEffect, useRef, type ReactNode } from "react";
import { ChevronDown, CircleCheck, ShieldAlert } from "lucide-react";
import type { Assessment, IngestionStatus } from "@/lib/api/types";
import { Badge } from "@/components/ui/badge";
import { formatDateTime, formatRelative } from "@/lib/format";

const TILE_SURFACE =
  "flex min-w-0 flex-col gap-1.5 rounded-lg border border-line bg-surface px-4 py-4 transition-colors hover:border-line-strong focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand sm:px-5";

const INLINE_LINK =
  "inline-flex items-center gap-1 rounded-sm hover:text-ink focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand";

const STATE_BADGE = {
  ready: "ready",
  attention_required: "attention",
  critical: "critical",
} as const;

const STATE_BAR = {
  ready: "bg-success",
  attention_required: "bg-warning",
  critical: "bg-danger",
} as const;

function Meter({
  label,
  value,
  tone,
  valueText,
}: {
  label: string;
  value: number;
  tone: string;
  valueText?: string;
}) {
  return (
    <div
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={value}
      aria-valuetext={valueText}
      className="mt-auto h-1 overflow-hidden rounded-full bg-surfaceMuted"
    >
      <span
        className={`block h-full rounded-full ${tone}`}
        style={{ width: `${Math.max(2, Math.min(100, value))}%` }}
      />
    </div>
  );
}

/** A KPI: label, one number, one short line of context, optional meter. */
function Tile({
  href,
  label,
  value,
  suffix,
  detail,
  children,
}: {
  href: string;
  label: string;
  value: ReactNode;
  suffix?: string;
  detail: ReactNode;
  children?: ReactNode;
}) {
  return (
    <Link href={href} className={TILE_SURFACE}>
      <span className="text-xs font-medium text-muted">{label}</span>
      <span className="flex items-baseline gap-1">
        <span className="text-3xl font-semibold leading-none tracking-tight text-ink">
          {value}
        </span>
        {suffix ? <span className="text-sm text-muted">{suffix}</span> : null}
      </span>
      <span className="line-clamp-2 text-xs text-muted sm:truncate">
        {detail}
      </span>
      {children}
    </Link>
  );
}

/** "Evaluated …" doubles as the disclosure for the assessment provenance. It
 * pushes content down instead of floating over it, and closes on Escape or a
 * click elsewhere like the popovers around it. */
function EvaluatedDetails({
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
        Evaluated {formatRelative(evaluatedAt)}
        <span className="sr-only">, assessment details</span>
        <ChevronDown
          aria-hidden="true"
          className="chevron h-3.5 w-3.5 transition-transform"
        />
      </summary>
      <dl className="mt-2 grid max-w-full gap-x-6 gap-y-2 rounded-md border border-line bg-surface p-3 text-xs sm:w-fit sm:grid-cols-[auto_auto]">
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
  const exportReady = Boolean(ingestion?.proof.proof_pack_exists);

  const total = accuracy?.total_tests ?? 0;
  const passing = accuracy?.passing ?? 0;
  const needsEvidence = accuracy?.needs_evidence ?? 0;

  const findings = posture?.open_violation_count ?? 0;
  const critical = posture?.critical_violation_count ?? 0;
  const high = posture?.high_violation_count ?? 0;

  const assessed = assessment?.frameworks.length ?? 0;
  const staleRows = posture?.stale_evidence_count ?? 0;
  const staleControls = posture?.stale_control_count ?? 0;

  return (
    <section
      aria-labelledby="current-assessment-heading"
      className="grid min-w-0 gap-4"
    >
      <h2 id="current-assessment-heading" className="sr-only">
        Current assessment
      </h2>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-muted">
        <Badge tone={state ? STATE_BADGE[state] : "default"}>
          <StatusIcon aria-hidden="true" className="h-3.5 w-3.5" />
          {status}
        </Badge>
        {assessment?.evaluated_at ? (
          <EvaluatedDetails
            hash={assessment.assessment_hash}
            evaluatedAt={assessment.evaluated_at}
          />
        ) : null}
        <Link href="/audit-room" className={INLINE_LINK}>
          <span>Assessment export</span>
          <span className="font-medium text-ink">
            {exportReady ? "available" : "pending"}
          </span>
        </Link>
      </div>
      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
        <Tile
          href="/frameworks"
          label="Assessment score"
          value={posture ? Math.round(posture.score) : "—"}
          suffix={posture ? "/ 100" : undefined}
          detail={`${assessed} of ${frameworkCount} frameworks assessed`}
        >
          {posture ? (
            <Meter
              label="Assessment score"
              value={Math.round(posture.score)}
              tone={state ? STATE_BAR[state] : "bg-line-strong"}
            />
          ) : null}
        </Tile>
        <Tile
          href="/controls"
          label="Control pass rate"
          value={passPercent ?? "—"}
          suffix={passPercent != null ? "%" : undefined}
          detail={
            passPercent != null
              ? `${passing} of ${total} tests passing${needsEvidence ? ` · ${needsEvidence} need evidence` : ""}`
              : "Not evaluated"
          }
        >
          {passPercent != null ? (
            <Meter
              label="Control pass rate"
              value={passPercent}
              tone="bg-success"
              valueText={`${passing} of ${total} tests passing`}
            />
          ) : null}
        </Tile>
        <Tile
          href="/violations"
          label="Open findings"
          value={posture ? findings : "—"}
          detail={
            posture
              ? critical > 0 || high > 0
                ? `${critical} critical · ${high} high`
                : "No critical or high findings"
              : "Awaiting assessment"
          }
        />
        <Tile
          href="/evidence"
          label="Evidence to refresh"
          value={posture ? staleRows : "—"}
          detail={
            posture
              ? staleRows > 0
                ? `Past freshness SLA · ${staleControls} ${staleControls === 1 ? "control" : "controls"}`
                : "All evidence within its freshness SLA"
              : "Freshness unavailable"
          }
        />
      </div>
    </section>
  );
}

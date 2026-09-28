"use client";

import { Clock3, History, PlayCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { QueryState } from "@/components/QueryState";
import { useEvalRuns, useIngestionStatus } from "@/lib/api/hooks";
import { shortDate } from "@/lib/utils";
import { displayLabel } from "@/lib/display";

function toneForResult(result?: string): "ready" | "attention" | "critical" {
  if (result === "ok") return "ready";
  if (result === "error") return "critical";
  return "attention";
}

function formatPassRate(rate: number | null | undefined) {
  if (rate == null) return "—";
  return `${Math.round(rate * 100)}%`;
}

export function EvalRunsStrip({
  limit = 6,
  embedded = false,
}: {
  limit?: number;
  embedded?: boolean;
}) {
  const ingestion = useIngestionStatus();
  const evalRuns = useEvalRuns(limit);
  const scale = ingestion.data?.scale;
  const accuracy = ingestion.data?.eval_accuracy;

  return (
    <QueryState queries={[ingestion, evalRuns]} label="evaluation history">
      {ingestion.data && (
        <Card
          className={embedded ? "rounded-none border-0 shadow-none" : undefined}
        >
          <CardHeader className="flex-row items-start justify-between gap-3">
            <div className="min-w-0">
              <CardTitle className="flex items-center gap-2 text-base">
                <History className="h-4 w-4 text-brand" />
                Lake evaluation runs
              </CardTitle>
              <CardDescription>
                Scheduled materialize-and-evaluate loop separate from connector
                syncs.
              </CardDescription>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {scale?.eval_schedule ? (
                <Badge tone="default">{scale.eval_schedule}</Badge>
              ) : null}
              {scale?.eval_overdue ? (
                <Badge tone="critical">overdue</Badge>
              ) : scale?.next_eval_at ? (
                <Badge tone="ready">on schedule</Badge>
              ) : null}
            </div>
          </CardHeader>
          <CardContent className="grid gap-3">
            <div className="grid gap-2 sm:grid-cols-4">
              <div className="rounded-lg border border-line bg-panel px-3 py-2">
                <div className="text-[11px] font-semibold uppercase tracking-wide text-muted">
                  Last eval
                </div>
                <div className="mt-1 text-sm font-semibold text-ink">
                  {scale?.latest_eval?.occurred_at
                    ? shortDate(scale.latest_eval.occurred_at)
                    : "never"}
                </div>
                <div className="mt-1 text-xs text-muted">
                  {scale?.latest_eval?.mode ?? "—"} ·{" "}
                  {scale?.latest_eval?.result ?? "pending"}
                </div>
              </div>
              <div className="rounded-lg border border-line bg-panel px-3 py-2">
                <div className="text-[11px] font-semibold uppercase tracking-wide text-muted">
                  Pass rate
                </div>
                <div className="mt-1 text-sm font-semibold text-ink">
                  {formatPassRate(accuracy?.pass_rate)}
                </div>
                <div className="mt-1 text-xs text-muted">
                  {accuracy?.has_tests
                    ? `${accuracy.failing} failing · ${accuracy.evidence_source_count} sources`
                    : "awaiting eval materialization"}
                </div>
              </div>
              <div className="rounded-lg border border-line bg-panel px-3 py-2">
                <div className="flex items-center gap-1 text-[11px] font-semibold uppercase tracking-wide text-muted">
                  <Clock3 className="h-3 w-3" />
                  Next eval
                </div>
                <div className="mt-1 text-sm font-semibold text-ink">
                  {scale?.next_eval_at
                    ? shortDate(scale.next_eval_at)
                    : "not scheduled"}
                </div>
                <div className="mt-1 text-xs text-muted">
                  {scale?.eval_overdue
                    ? "due now — scheduler will fire on next tick"
                    : "based on scheduler state"}
                </div>
              </div>
              <div className="rounded-lg border border-line bg-panel px-3 py-2">
                <div className="flex items-center gap-1 text-[11px] font-semibold uppercase tracking-wide text-muted">
                  <PlayCircle className="h-3 w-3" />
                  Recent runs
                </div>
                <div className="mt-1 text-sm font-semibold text-ink">
                  {(evalRuns.data ?? []).length}
                </div>
                <div className="mt-1 text-xs text-muted">
                  newest-first from eval_runs.jsonl
                </div>
              </div>
            </div>

            <div className="divide-y divide-line rounded-lg border border-line">
              {(evalRuns.data ?? []).length > 0 ? (
                evalRuns.data?.map((run, index) => (
                  <div
                    key={`${run.occurred_at}-${index}`}
                    className="grid gap-2 px-3 py-2 sm:grid-cols-[minmax(0,1fr)_120px_100px_90px_80px]"
                  >
                    <div className="min-w-0">
                      <div className="truncate text-sm font-semibold text-ink">
                        {run.mode}
                      </div>
                      <div className="truncate text-xs text-muted">
                        {run.actor} ·{" "}
                        {run.duration_ms != null
                          ? `${run.duration_ms} ms`
                          : "—"}
                        {run.error ? ` · ${run.error}` : ""}
                      </div>
                    </div>
                    <div className="text-xs text-muted">
                      {shortDate(run.occurred_at)}
                    </div>
                    <Badge tone={toneForResult(run.result)}>
                      {displayLabel(run.result)}
                    </Badge>
                    <div className="text-xs text-muted">
                      {run.event_count != null
                        ? `${run.event_count.toLocaleString()} events`
                        : "—"}
                    </div>
                    <div className="text-xs font-semibold text-ink">
                      {formatPassRate(run.pass_rate)}
                    </div>
                  </div>
                ))
              ) : (
                <div className="px-3 py-3 text-sm text-muted">
                  No lake evaluation runs yet. Trigger one from source health or
                  wait for the scheduler.
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </QueryState>
  );
}

"use client";

import Link from "next/link";
import {
  Activity,
  ArrowRight,
  BarChart3,
  Clock3,
  History,
  Layers,
  Play,
  RefreshCw,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { QueryState } from "@/components/QueryState";
import { KpiTile } from "@/components/ui/KpiTile";
import {
  useEvalRuns,
  useIngestionStatus,
  useRunLakeEvalMutation,
  useRunSchedulerTickMutation,
} from "@/lib/api/hooks";
import { shortDate } from "@/lib/utils";
import { notify } from "@/lib/toast";
import { displayLabel } from "@/lib/display";

function toneForState(state?: string): "ready" | "attention" | "critical" {
  if (state === "active") return "ready";
  if (state === "error") return "critical";
  return "attention";
}

function formatPassRate(rate: number | null | undefined) {
  if (rate == null) return "—";
  return `${Math.round(rate * 100)}%`;
}

export function IngestionLoopStrip() {
  const ingestion = useIngestionStatus();
  const evalRuns = useEvalRuns(5);
  const runEval = useRunLakeEvalMutation();
  const runTick = useRunSchedulerTickMutation();
  const summary = ingestion.data?.summary;
  const scale = ingestion.data?.scale;
  const health = ingestion.data?.health;
  const accuracy = ingestion.data?.eval_accuracy;
  const coverage = ingestion.data?.catalog_coverage;

  const handleRunEval = async () => {
    try {
      const result = await runEval.mutateAsync({ actor: "audit-room" });
      if (result.result === "ok") {
        notify.success(
          `Control eval complete (${result.mode}, ${result.duration_ms} ms).`,
        );
      } else {
        notify.error(
          result.error ??
            `Control eval finished with result: ${result.result}.`,
        );
      }
    } catch (err) {
      notify.error(`Control eval failed: ${(err as Error).message}`);
    }
  };

  const handleSchedulerTick = async () => {
    try {
      const result = await runTick.mutateAsync();
      notify.success(
        result.count > 0
          ? `Scheduler tick fired ${result.count} job(s).`
          : "Scheduler tick complete — no jobs due.",
      );
    } catch (err) {
      notify.error(`Scheduler tick failed: ${(err as Error).message}`);
    }
  };

  return (
    <QueryState queries={[ingestion, evalRuns]} label="ingestion loop">
      {ingestion.data && (
        <Card>
          <CardContent className="grid gap-4 p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <Activity className="h-4 w-4 text-brand" />
                  <span className="text-sm font-semibold text-ink">
                    Continuous ingestion loop
                  </span>
                  <Badge tone={toneForState(ingestion.data.state)}>
                    {displayLabel(ingestion.data.state)}
                  </Badge>
                  {scale?.eval_overdue ? (
                    <Badge tone="critical">eval overdue</Badge>
                  ) : null}
                  {accuracy?.has_tests && (accuracy.failing ?? 0) > 0 ? (
                    <Badge tone="attention">
                      {accuracy.failing} failing test
                      {accuracy.failing === 1 ? "" : "s"}
                    </Badge>
                  ) : null}
                </div>
                <p className="mt-1 text-xs leading-5 text-muted">
                  Connector syncs land raw evidence; control eval materializes
                  posture on a separate schedule — same split loop as managed
                  GRC platforms.
                  {coverage
                    ? ` ${coverage.implemented}/${coverage.total} integrations implemented · ${coverage.enabled} enabled.`
                    : ""}
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  size="sm"
                  variant="primary"
                  disabled={runEval.isPending}
                  onClick={handleRunEval}
                >
                  <Play className="mr-1 h-3.5 w-3.5" />
                  Run control eval
                </Button>
                <Button
                  size="sm"
                  variant="default"
                  disabled={runTick.isPending}
                  onClick={handleSchedulerTick}
                >
                  <RefreshCw className="mr-1 h-3.5 w-3.5" />
                  Scheduler tick
                </Button>
                <Link
                  href="/dashboard"
                  className="inline-flex items-center gap-1 text-xs font-semibold text-brand hover:underline"
                >
                  Source health
                  <ArrowRight className="h-3.5 w-3.5" />
                </Link>
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
              <KpiTile
                label="Enabled connectors"
                value={`${summary?.enabled_connectors ?? 0}/${summary?.connector_count ?? 0}`}
                detail={`${summary?.failed_connectors ?? 0} failed · ${summary?.never_synced_connectors ?? 0} never synced`}
                tone={
                  (summary?.failed_connectors ?? 0) > 0
                    ? "attention"
                    : "default"
                }
              />
              <KpiTile
                label="Evidence rows"
                value={(summary?.evidence_count ?? 0).toLocaleString()}
                detail={`${summary?.source_count ?? 0} sources · ${summary?.stale_evidence ?? 0} stale`}
              />
              <KpiTile
                label="Connector health"
                value={
                  health
                    ? `${health.summary.healthy}/${health.summary.enabled}`
                    : "—"
                }
                detail={
                  health
                    ? `${health.summary.silent} silent · ${health.summary.degraded} degraded`
                    : "freshness SLO rollups"
                }
                tone={
                  health && health.summary.unhealthy > 0
                    ? "attention"
                    : "default"
                }
              />
              <KpiTile
                label="Control pass rate"
                value={formatPassRate(accuracy?.pass_rate)}
                detail={
                  accuracy?.has_tests
                    ? `${accuracy.passing}/${accuracy.total_tests} passing · ${accuracy.framework_count} frameworks`
                    : "run control eval to materialize tests"
                }
                tone={
                  accuracy && (accuracy.failing ?? 0) > 0
                    ? "attention"
                    : accuracy?.has_tests
                      ? "ready"
                      : "default"
                }
              />
              <KpiTile
                label="Last eval"
                value={
                  scale?.latest_eval?.occurred_at
                    ? shortDate(scale.latest_eval.occurred_at)
                    : "never"
                }
                detail={`${scale?.latest_eval?.mode ?? "—"} · ${scale?.latest_eval?.result ?? "pending"}`}
              />
              <KpiTile
                label="Next eval"
                value={
                  scale?.next_eval_at
                    ? shortDate(scale.next_eval_at)
                    : (scale?.eval_schedule ?? "—")
                }
                detail={
                  scale?.eval_overdue
                    ? "overdue — scheduler will fire on next tick"
                    : scale?.eval_schedule
                      ? `cadence ${scale.eval_schedule}`
                      : "no eval schedule configured"
                }
                tone={scale?.eval_overdue ? "critical" : "default"}
              />
            </div>

            {(evalRuns.data ?? []).length > 0 && (
              <div className="rounded-lg border border-line bg-panel p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted">
                    <History className="h-3.5 w-3.5" />
                    Recent eval runs
                  </div>
                  {scale?.mode && (
                    <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-muted">
                      <Layers className="h-3 w-3" />
                      {scale.mode.replace(/_/g, " ")}
                    </span>
                  )}
                </div>
                <div className="mt-2 grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
                  {evalRuns.data?.map((run, index) => (
                    <div
                      key={`${run.occurred_at}-${index}`}
                      className="rounded-md border border-line bg-surface px-2.5 py-2"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate text-xs font-semibold text-ink">
                          {run.mode}
                        </span>
                        <Badge
                          tone={run.result === "ok" ? "ready" : "critical"}
                        >
                          {displayLabel(run.result)}
                        </Badge>
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] text-muted">
                        <span className="inline-flex items-center gap-1">
                          <Clock3 className="h-3 w-3" />
                          {shortDate(run.occurred_at)}
                        </span>
                        {run.duration_ms != null && (
                          <span>{run.duration_ms}ms</span>
                        )}
                        {run.pass_rate != null && (
                          <span className="inline-flex items-center gap-0.5 font-semibold text-ink">
                            <BarChart3 className="h-3 w-3" />
                            {formatPassRate(run.pass_rate)}
                          </span>
                        )}
                      </div>
                      {(run.event_count != null ||
                        run.control_tests_total != null) && (
                        <div className="mt-1 text-[10px] text-muted">
                          {run.event_count != null
                            ? `${run.event_count} events`
                            : ""}
                          {run.event_count != null &&
                          run.control_tests_total != null
                            ? " · "
                            : ""}
                          {run.control_tests_total != null
                            ? `${run.control_tests_total} tests`
                            : ""}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </QueryState>
  );
}

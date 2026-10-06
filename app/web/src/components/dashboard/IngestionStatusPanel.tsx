"use client";

import Link from "next/link";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Database,
  FileCheck2,
  Layers,
  RefreshCw,
} from "lucide-react";
import type { IngestionStatus } from "@/lib/api/types";
import { CONNECT_FLOW } from "@/lib/console-copy";
import {
  usePlatformJobs,
  useRunLakeEvalMutation,
  useRunSchedulerTickMutation,
} from "@/lib/api/hooks";
import { shortDate } from "@/lib/utils";
import { notify } from "@/lib/toast";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { displayLabel } from "@/lib/display";

function toneForState(state?: string): "ready" | "attention" | "critical" {
  if (state === "active") return "ready";
  if (state === "error") return "critical";
  return "attention";
}

function labelForState(state?: string) {
  if (state === "active") return "Healthy";
  if (state === "error") return "Needs repair";
  if (state === "needs_configuration") return "Connect a source";
  if (state === "needs_data") return "Run initial sync";
  return "Needs review";
}

function Metric({
  label,
  value,
  detail,
}: {
  label: string;
  value: string | number;
  detail: string;
}) {
  return (
    <div className="rounded-lg border border-line bg-panel px-3 py-2">
      <div className="text-[11px] font-semibold uppercase tracking-wide text-muted">
        {label}
      </div>
      <div className="mt-1 text-xl font-semibold leading-none text-ink">
        {value}
      </div>
      <div className="mt-1 text-xs leading-5 text-muted">{detail}</div>
    </div>
  );
}

function labelForScaleMode(mode?: string) {
  if (mode === "warehouse_required") return "Warehouse required";
  if (mode === "warehouse") return "Warehouse eval";
  if (mode === "local_incremental") return "Changed evidence only";
  if (mode === "local_full") return "Full local";
  return mode?.replace(/_/g, " ") ?? "unknown";
}

function toneForScaleMode(mode?: string): "ready" | "attention" | "critical" {
  if (mode === "warehouse_required") return "critical";
  if (mode === "warehouse") return "attention";
  return "ready";
}

function formatPassRate(rate: number | null | undefined) {
  if (rate == null) return "—";
  return `${Math.round(rate * 100)}%`;
}

function scaleRecommendationCopy(scale: IngestionStatus["scale"]) {
  if (!scale) return "";
  if (scale.mode === "local_incremental") {
    return "Processes only changed raw evidence since the last manifest, so large lakes do not reprocess every row.";
  }
  return scale.recommendation;
}

export function IngestionStatusPanel({
  status,
  embedded = false,
}: {
  status: IngestionStatus | undefined;
  embedded?: boolean;
}) {
  const runEval = useRunLakeEvalMutation();
  const runTick = useRunSchedulerTickMutation();
  const platformJobs = usePlatformJobs(6);
  const summary = status?.summary;
  const scale = status?.scale;
  const health = status?.health;
  const accuracy = status?.eval_accuracy;
  const coverage = status?.catalog_coverage;
  const action = status?.recommended_actions?.[0];
  const recentEvidenceSyncs =
    status?.latest_runs
      ?.filter((run) => run.kind === "sync" || (run.evidence_count ?? 0) > 0)
      .slice(0, 4) ?? [];
  const visibleConnectors =
    status?.connectors
      ?.filter(
        (connector) =>
          connector.last_sync_at ||
          connector.latest_sync.result === "error" ||
          connector.freshness_state === "stale",
      )
      .slice(0, 4) ?? [];
  const proofReady = Boolean(status?.proof?.proof_pack_exists);

  const handleRunEval = async () => {
    try {
      const result = await runEval.mutateAsync({ actor: "console" });
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
    <Card
      className={
        embedded
          ? "rounded-none border-0 border-b border-line shadow-none"
          : undefined
      }
    >
      <CardHeader className="flex-row items-start justify-between gap-3">
        <div className="min-w-0">
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-brand" />
            Source health
          </CardTitle>
          <CardDescription>
            Evidence-producing sources, freshness, and reviewer proof.
          </CardDescription>
        </div>
        <Badge tone={toneForState(status?.state)}>
          {labelForState(status?.state)}
        </Badge>
      </CardHeader>
      <CardContent className="grid gap-3">
        <div className="grid gap-2 md:grid-cols-4">
          <Metric
            label="Evidence"
            value={summary?.evidence_count ?? 0}
            detail={`${summary?.source_count ?? 0} sources`}
          />
          <Metric
            label="Connectors"
            value={`${summary?.enabled_connectors ?? 0}/${summary?.connector_count ?? 0}`}
            detail={`${summary?.failed_connectors ?? 0} failed`}
          />
          <Metric
            label="Freshness"
            value={summary?.stale_evidence ?? 0}
            detail="records need refresh"
          />
          <Metric
            label="Assessment export"
            value={proofReady ? "Available" : "Pending"}
            detail={status?.proof?.scenario ?? "not run"}
          />
        </div>

        {(accuracy || coverage) && (
          <div className="grid gap-2 md:grid-cols-4">
            <Metric
              label="Control pass rate"
              value={formatPassRate(accuracy?.pass_rate)}
              detail={
                accuracy?.has_tests
                  ? `${accuracy.passing}/${accuracy.total_tests} passing`
                  : "run control eval to materialize"
              }
            />
            <Metric
              label="Failing tests"
              value={accuracy?.failing ?? 0}
              detail={`${accuracy?.framework_count ?? 0} frameworks covered`}
            />
            <Metric
              label="Catalog adapters"
              value={
                coverage ? `${coverage.implemented}/${coverage.total}` : "—"
              }
              detail={
                coverage
                  ? `${Math.round(coverage.implementation_rate * 100)}% implemented`
                  : "connector registry"
              }
            />
            <Metric
              label="Enabled adapters"
              value={
                coverage ? `${coverage.enabled}/${coverage.implemented}` : "—"
              }
              detail={
                coverage
                  ? `${Math.round(coverage.enabled_rate * 100)}% of implemented live`
                  : "test-before-enable"
              }
            />
          </div>
        )}

        {scale && (
          <div className="rounded-lg border border-line bg-panel p-3">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <Layers className="h-4 w-4 text-brand" />
                  <span className="text-sm font-semibold text-ink">
                    Processing mode
                  </span>
                  <Badge tone={toneForScaleMode(scale.mode)}>
                    {labelForScaleMode(scale.mode)}
                  </Badge>
                </div>
                <p className="mt-2 text-sm leading-5 text-muted">
                  {(scale.event_count ?? 0).toLocaleString()} events · sync{" "}
                  {scale.default_sync_schedule}
                  {scale.eval_schedule ? ` · eval ${scale.eval_schedule}` : ""}
                </p>
                <p className="mt-1 text-xs leading-5 text-muted">
                  {scaleRecommendationCopy(scale)}
                </p>
                {scale.latest_eval?.occurred_at && (
                  <p className="mt-2 text-xs text-muted">
                    Last eval {shortDate(scale.latest_eval.occurred_at)} ·{" "}
                    {scale.latest_eval.mode} · {scale.latest_eval.result}
                  </p>
                )}
                {scale.next_eval_at && (
                  <p className="mt-1 text-xs text-muted">
                    Next eval {shortDate(scale.next_eval_at)}
                    {scale.eval_overdue ? " · overdue" : ""}
                  </p>
                )}
              </div>
              <div className="flex flex-wrap gap-2">
                {scale.eval_overdue ? (
                  <Badge tone="critical">eval overdue</Badge>
                ) : null}
                <Button
                  size="sm"
                  variant="primary"
                  disabled={runEval.isPending}
                  onClick={handleRunEval}
                >
                  Run control eval
                </Button>
                <Button
                  size="sm"
                  variant="default"
                  disabled={runTick.isPending}
                  onClick={handleSchedulerTick}
                >
                  Scheduler tick
                </Button>
              </div>
            </div>
          </div>
        )}

        {health && (
          <div className="grid gap-2 sm:grid-cols-4">
            <Metric
              label="Healthy"
              value={health.summary.healthy}
              detail={`of ${health.summary.enabled} enabled`}
            />
            <Metric
              label="Degraded"
              value={health.summary.degraded}
              detail="past freshness SLO"
            />
            <Metric
              label="Silent"
              value={health.summary.silent}
              detail="no recent success"
            />
            <Metric
              label="Never synced"
              value={health.summary.never_succeeded}
              detail="awaiting first run"
            />
          </div>
        )}

        {recentEvidenceSyncs.length > 0 && (
          <div className="rounded-lg border border-line">
            <div className="border-b border-line px-3 py-2 text-xs font-semibold uppercase tracking-wide text-muted">
              Recent evidence syncs
            </div>
            <div className="divide-y divide-line">
              {recentEvidenceSyncs.map((run, index) => (
                <div
                  key={`${run.connector_id}-${run.occurred_at}-${index}`}
                  className="grid gap-2 px-3 py-2 sm:grid-cols-[minmax(0,1fr)_120px_90px]"
                >
                  <div className="min-w-0 truncate text-sm font-semibold text-ink">
                    {run.connector_id} ·{" "}
                    {run.evidence_count == null
                      ? "sync attempt"
                      : `${run.evidence_count} evidence rows`}
                  </div>
                  <div className="text-xs text-muted">
                    {shortDate(run.occurred_at)}
                  </div>
                  <Badge
                    tone={
                      run.result === "ok"
                        ? "ready"
                        : run.result === "error"
                          ? "critical"
                          : "attention"
                    }
                  >
                    {displayLabel(run.result)}
                  </Badge>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_320px]">
          <div className="min-w-0 rounded-lg border border-line">
            <div className="flex items-center justify-between border-b border-line px-3 py-2">
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted">
                <Database className="h-3.5 w-3.5" />
                Evidence sources
              </div>
              <span className="text-xs font-semibold text-muted">
                {status?.integrity?.ok === true ? "integrity ok" : "verify"}
              </span>
            </div>
            <div className="flex flex-wrap gap-2 p-3">
              {(status?.sources ?? []).length > 0 ? (
                status?.sources.map((source) => (
                  <span
                    key={source.source}
                    className="inline-flex items-center gap-2 rounded-md border border-line bg-surface px-2.5 py-1 text-xs font-semibold text-muted"
                  >
                    {source.source}
                    <strong className="text-ink">
                      {source.evidence_count}
                    </strong>
                  </span>
                ))
              ) : (
                <span className="text-sm text-muted">
                  {CONNECT_FLOW.emptyEvidence}{" "}
                  <Link
                    href="/connectors?onboarding=1"
                    className="font-semibold text-brand hover:underline"
                  >
                    Connect a source
                  </Link>
                </span>
              )}
            </div>
            <div className="divide-y divide-line border-t border-line">
              {visibleConnectors.length > 0 ? (
                visibleConnectors.map((connector) => (
                  <div
                    key={connector.connector_id}
                    className="grid gap-2 px-3 py-2 sm:grid-cols-[minmax(0,1fr)_160px_110px]"
                  >
                    <div className="min-w-0">
                      <div className="truncate text-sm font-semibold text-ink">
                        {connector.name}
                      </div>
                      <div className="truncate text-xs text-muted">
                        {connector.connector_id}
                      </div>
                    </div>
                    <div className="text-xs text-muted">
                      last sync {shortDate(connector.last_sync_at ?? undefined)}
                    </div>
                    <Badge
                      tone={
                        connector.latest_sync.result === "error"
                          ? "critical"
                          : connector.freshness_state === "fresh"
                            ? "ready"
                            : "attention"
                      }
                    >
                      {displayLabel(
                        connector.latest_sync.result ??
                          connector.freshness_state,
                      )}
                    </Badge>
                  </div>
                ))
              ) : (
                <div className="px-3 py-3 text-sm text-muted">
                  {CONNECT_FLOW.emptyEvidence}
                </div>
              )}
            </div>
          </div>

          <div className="grid gap-3">
            <div className="rounded-lg border border-line bg-panel p-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-ink">
                {proofReady ? (
                  <CheckCircle2 className="h-4 w-4 text-success-fg" />
                ) : (
                  <FileCheck2 className="h-4 w-4 text-warning-fg" />
                )}
                Reviewer proof
              </div>
              <p className="mt-2 text-sm leading-5 text-muted">
                {proofReady
                  ? `${status?.proof?.evidence_count ?? 0} rows in the latest assessment export across ${(status?.proof?.sources ?? []).length} sources.`
                  : "Run a sync to create the first assessment export."}
              </p>
            </div>
            <div className="rounded-lg border border-line bg-surface p-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-ink">
                {action?.priority === "p0" ? (
                  <AlertTriangle className="h-4 w-4 text-danger-fg" />
                ) : (
                  <RefreshCw className="h-4 w-4 text-brand" />
                )}
                Next action
              </div>
              <p className="mt-2 text-sm leading-5 text-muted">
                {action?.reason ?? "No ingestion action is required right now."}
              </p>
            </div>
          </div>
        </div>

        {(platformJobs.data?.jobs.length ?? 0) > 0 && (
          <div className="rounded-lg border border-line bg-surface p-3">
            <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
              <div className="text-xs font-semibold uppercase tracking-wide text-muted">
                Recent platform jobs
              </div>
              <Badge tone="info">
                {platformJobs.data?.running_count ?? 0} running ·{" "}
                {platformJobs.data?.count ?? 0} total
              </Badge>
            </div>
            <div className="grid gap-2">
              {platformJobs.data?.jobs.slice(0, 4).map((job) => (
                <div
                  key={job.id}
                  className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-line bg-panel px-2.5 py-2 text-xs"
                >
                  <div className="min-w-0">
                    <div className="truncate font-semibold text-ink">
                      {job.label}
                    </div>
                    <div className="truncate text-muted">
                      {job.kind.replace(/_/g, " ")} ·{" "}
                      {shortDate(job.started_at ?? undefined)}
                    </div>
                  </div>
                  <Badge
                    tone={
                      job.status === "failed" || job.status === "interrupted"
                        ? "critical"
                        : job.status === "completed" ||
                            job.status === "succeeded"
                          ? "ready"
                          : "attention"
                    }
                  >
                    {displayLabel(job.status)}
                  </Badge>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

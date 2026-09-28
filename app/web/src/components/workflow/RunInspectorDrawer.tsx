"use client";

import { Loader2, RotateCcw, ShieldCheck, XCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import type { WorkflowRun } from "@/lib/api/types";

function runTone(run: WorkflowRun) {
  if (run.result === "ok") return "ready" as const;
  if (run.result === "awaiting_approval") return "attention" as const;
  if (run.result === "rejected") return "critical" as const;
  return "critical" as const;
}

export function RunInspectorDrawer({
  run,
  auditor,
  onClose,
  onRetry,
  onApprove,
  onReject,
  busy,
}: {
  run: WorkflowRun;
  auditor: boolean;
  onClose: () => void;
  onRetry?: () => void;
  onApprove?: () => void;
  onReject?: () => void;
  busy?: boolean;
}) {
  const runKey = run.run_id ?? `${run.started_at}-${run.actor}`;

  return (
    <Card className="border-brand/30 shadow-lg">
      <CardHeader className="flex flex-row items-start justify-between gap-3 space-y-0">
        <div className="grid gap-1">
          <CardTitle className="text-base">Run inspector</CardTitle>
          <CardDescription>
            {run.workflow_id} · v{run.workflow_version}
            {run.dry_run ? " · preview" : ""}
          </CardDescription>
        </div>
        <div className="flex items-center gap-2">
          <Badge tone={runTone(run)}>{run.result}</Badge>
          <Button variant="ghost" size="sm" onClick={onClose}>
            Close
          </Button>
        </div>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="grid gap-1 text-xs text-muted">
          <div>
            <span className="font-semibold text-ink">Run id:</span>{" "}
            <code>{run.run_id ?? "legacy"}</code>
          </div>
          <div>
            actor <b className="text-ink">{run.actor}</b> · started{" "}
            {run.started_at} · finished {run.finished_at}
          </div>
        </div>

        {!auditor && (
          <div className="flex flex-wrap gap-2">
            {run.result === "awaiting_approval" && onApprove && onReject && (
              <>
                <Button
                  variant="primary"
                  size="sm"
                  disabled={busy}
                  onClick={onApprove}
                >
                  {busy ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <ShieldCheck className="h-4 w-4" />
                  )}{" "}
                  Approve
                </Button>
                <Button
                  variant="default"
                  size="sm"
                  disabled={busy}
                  onClick={onReject}
                >
                  <XCircle className="h-4 w-4" /> Reject
                </Button>
              </>
            )}
            {run.result === "error" && onRetry && (
              <Button
                variant="default"
                size="sm"
                disabled={busy}
                onClick={onRetry}
              >
                {busy ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <RotateCcw className="h-4 w-4" />
                )}{" "}
                Retry run
              </Button>
            )}
          </div>
        )}

        <div className="grid max-h-[420px] gap-2 overflow-y-auto">
          {run.node_results.map((node) => (
            <div
              key={`${runKey}-${node.node_id}`}
              className="rounded-lg border border-line bg-surface p-3 text-xs"
            >
              <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                <span className="font-semibold text-ink">
                  {node.node_id} · {node.node_type}
                </span>
                <Badge
                  tone={
                    node.result === "ok"
                      ? "ready"
                      : node.result === "skipped"
                        ? "default"
                        : "critical"
                  }
                >
                  {node.result}
                </Badge>
              </div>
              {node.reason ? (
                <p className="mb-2 text-muted">{node.reason}</p>
              ) : null}
              {node.error ? (
                <pre className="mb-2 overflow-x-auto rounded bg-danger-bg p-2 text-[11px] text-danger-fg">
                  {node.error}
                </pre>
              ) : null}
              {node.output ? (
                <pre className="overflow-x-auto rounded bg-surfaceMuted p-2 text-[11px] text-ink">
                  {JSON.stringify(node.output, null, 2)}
                </pre>
              ) : null}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

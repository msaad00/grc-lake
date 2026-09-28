"use client";

import { Loader2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Drawer } from "@/components/ui/drawer";
import {
  AgentDecisionCard,
  modeLabel,
  modeTone,
} from "@/components/agents/AgentDecisionCard";
import { useAgentRun } from "@/lib/api/hooks";
import { displayLabel } from "@/lib/display";

interface Props {
  runId: string | null;
  onClose: () => void;
}

function toneForStatus(status: string | undefined) {
  if (status === "completed" || status === "executed") return "ready" as const;
  if (status === "failed") return "critical" as const;
  if (status === "proposed") return "attention" as const;
  return "default" as const;
}

function jsonPreview(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

export function AgentRunDrawer({ runId, onClose }: Props) {
  const detail = useAgentRun(runId);
  const run = detail.data;

  return (
    <Drawer
      open={Boolean(runId)}
      onOpenChange={(open) => !open && onClose()}
      title={run?.id ?? "Agent run"}
      description={
        run
          ? `${run.harness.replaceAll("_", " ")} · ${run.status} · ${run.created_at}`
          : "Loading persisted harness evaluation"
      }
    >
      {detail.isLoading ? (
        <div className="flex items-center gap-2 text-sm text-muted">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading run detail…
        </div>
      ) : null}
      {detail.isError ? (
        <div className="rounded-lg border border-danger/40 bg-danger-bg px-3 py-2 text-sm font-semibold text-danger-fg">
          Could not load agent run detail.
        </div>
      ) : null}
      {run ? (
        <div className="grid gap-5">
          <dl className="grid grid-cols-[120px_1fr] gap-x-3 gap-y-1.5 text-sm">
            <dt className="text-muted">Harness</dt>
            <dd className="font-semibold capitalize text-ink">
              {run.harness.replaceAll("_", " ")}
            </dd>
            <dt className="text-muted">Status</dt>
            <dd>
              <Badge tone={toneForStatus(run.status)}>
                {displayLabel(run.status)}
              </Badge>
            </dd>
            <dt className="text-muted">Mode</dt>
            <dd>
              <Badge tone={modeTone(run.mode)}>{modeLabel(run.mode)}</Badge>
            </dd>
            <dt className="text-muted">Confidence</dt>
            <dd>{run.evaluation.confidence ?? "none"}</dd>
            <dt className="text-muted">Score</dt>
            <dd>{run.evaluation.score ?? 0}</dd>
            <dt className="text-muted">Input hash</dt>
            <dd>
              <code className="text-xs">{run.input_hash}</code>
            </dd>
            <dt className="text-muted">Idempotency</dt>
            <dd>
              <code className="text-xs">{run.idempotency_key ?? "—"}</code>
            </dd>
          </dl>

          {run.errors.length > 0 ? (
            <div className="rounded-lg border border-danger/40 bg-danger-bg px-3 py-2 text-sm font-semibold text-danger-fg">
              {run.errors.join(" ")}
            </div>
          ) : null}

          <div className="grid gap-3">
            <span className="text-xs font-semibold uppercase tracking-wide text-muted">
              Evaluation summary
            </span>
            <pre className="max-h-40 overflow-auto rounded-lg bg-surfaceMuted p-3 text-xs text-ink">
              {jsonPreview(run.evaluation)}
            </pre>
          </div>

          {run.state ? (
            <div className="grid gap-3">
              <span className="text-xs font-semibold uppercase tracking-wide text-muted">
                Persisted state
              </span>
              <pre className="max-h-48 overflow-auto rounded-lg bg-surfaceMuted p-3 text-xs text-ink">
                {jsonPreview(run.state)}
              </pre>
            </div>
          ) : null}

          <div className="grid gap-3">
            <span className="text-xs font-semibold uppercase tracking-wide text-muted">
              Proposed decisions
            </span>
            {run.decisions.length === 0 ? (
              <div className="rounded-lg border border-dashed border-line px-4 py-6 text-sm font-semibold text-muted">
                No proposed writes for this run.
              </div>
            ) : (
              run.decisions.map((decision, index) => (
                <AgentDecisionCard
                  key={`${run.id}-${index}`}
                  run={run}
                  decision={decision}
                  decisionIndex={index}
                  compact
                />
              ))
            )}
          </div>
        </div>
      ) : null}
    </Drawer>
  );
}

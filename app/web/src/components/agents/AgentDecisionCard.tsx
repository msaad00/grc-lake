"use client";

import { useState } from "react";
import Link from "next/link";
import { CheckCircle2, Loader2, XCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  useApproveAgentDecisionMutation,
  useRejectAgentDecisionMutation,
} from "@/lib/api/hooks";
import type { AgentDecision, AgentRun } from "@/lib/api/types";
import { notify } from "@/lib/toast";

function toneForStatus(status: string | undefined) {
  if (status === "completed" || status === "executed") return "ready" as const;
  if (status === "failed" || status === "rejected") return "critical" as const;
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

function executionLink(result: Record<string, unknown> | undefined) {
  const kind = String(result?.type ?? result?.resource ?? "");
  const id = String(result?.id ?? result?.task_id ?? result?.request_id ?? "");
  if (!id) return null;
  if (kind.includes("remediation") || kind.includes("task")) {
    return { href: "/remediation", label: "View remediation" };
  }
  if (kind.includes("evidence")) {
    return { href: "/remediation", label: "View evidence request" };
  }
  if (kind.includes("snapshot")) {
    return { href: "/audit-room", label: "View snapshot" };
  }
  return null;
}

interface Props {
  run: AgentRun;
  decision: AgentDecision;
  decisionIndex: number;
  compact?: boolean;
}

export function AgentDecisionCard({
  run,
  decision,
  decisionIndex,
  compact = false,
}: Props) {
  const approveDecision = useApproveAgentDecisionMutation();
  const rejectDecision = useRejectAgentDecisionMutation();
  const [note, setNote] = useState("");
  const [needsReason, setNeedsReason] = useState(false);
  const busy = approveDecision.isPending || rejectDecision.isPending;

  const reject = async () => {
    const reason = note.trim();
    if (!reason) {
      setNeedsReason(true);
      return;
    }
    try {
      await rejectDecision.mutateAsync({
        runId: run.id,
        decisionIndex,
        reason,
      });
      notify.success("Decision rejected; it will not run.");
    } catch (err) {
      notify.error(String((err as Error).message));
    }
  };

  const approve = async () => {
    try {
      await approveDecision.mutateAsync({
        runId: run.id,
        decisionIndex,
        note: note.trim() || "approved from console",
      });
      notify.success("Decision approved and executed.");
    } catch (err) {
      notify.error(String((err as Error).message));
    }
  };

  const link = executionLink(decision.execution_result);

  return (
    <div
      className={[
        "grid min-w-0 gap-3 rounded-lg border border-line bg-surface p-3",
        compact ? "" : "lg:grid-cols-[minmax(0,1fr)_auto]",
      ].join(" ")}
    >
      <div className="min-w-0">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <span className="truncate text-sm font-semibold text-ink">
            {decision.action}
          </span>
          <Badge tone={toneForStatus(decision.status)}>
            {decision.status ?? "proposed"}
          </Badge>
          {decision.requires_approval && (
            <Badge tone="attention">approval</Badge>
          )}
        </div>
        <p className="mt-1 text-sm font-semibold leading-5 text-muted">
          {decision.reason ?? "No reason provided."}
        </p>
        <pre className="mt-2 max-h-32 overflow-auto rounded-lg bg-surfaceMuted p-3 text-xs text-ink">
          {jsonPreview(decision.payload)}
        </pre>
        {decision.execution_result ? (
          <div className="mt-2 rounded-lg border border-success/40 bg-success-bg px-3 py-2 text-xs text-success-fg">
            <div className="font-semibold">Execution result</div>
            <pre className="mt-1 overflow-auto">
              {jsonPreview(decision.execution_result)}
            </pre>
            {link ? (
              <Link
                href={link.href}
                className="mt-2 inline-flex text-xs font-semibold text-brand hover:underline"
              >
                {link.label}
              </Link>
            ) : null}
          </div>
        ) : null}
        {decision.status === "rejected" ? (
          <div className="mt-2 rounded-lg border border-danger/40 bg-danger-bg px-3 py-2 text-xs text-danger-fg">
            <span className="font-semibold">
              Rejected
              {decision.rejected_by ? ` by ${decision.rejected_by}` : ""}:
            </span>{" "}
            {decision.rejection_reason}
          </div>
        ) : null}
      </div>
      <div className="flex min-w-0 flex-col items-stretch gap-2 lg:items-end">
        {decision.status === "proposed" ? (
          <>
            <label className="grid gap-1 text-xs font-semibold uppercase tracking-wide text-muted">
              Note or reason
              <textarea
                value={note}
                onChange={(event) => {
                  setNote(event.target.value);
                  setNeedsReason(false);
                }}
                rows={2}
                aria-invalid={needsReason}
                placeholder="Optional for approval; required to reject"
                className="min-w-[220px] rounded-lg border border-line bg-surface px-3 py-2 text-sm font-semibold text-ink focus:outline-none focus:ring-1 focus:ring-brand aria-[invalid=true]:border-danger"
              />
            </label>
            {needsReason ? (
              <p className="text-xs font-semibold text-danger-fg">
                Add a reason to reject this decision.
              </p>
            ) : null}
            <div className="flex flex-wrap justify-end gap-2">
              <Button
                variant="default"
                size="sm"
                disabled={busy}
                onClick={reject}
              >
                {rejectDecision.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <XCircle className="h-4 w-4" />
                )}
                Reject
              </Button>
              <Button
                variant="primary"
                size="sm"
                disabled={busy}
                onClick={approve}
              >
                {approveDecision.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <CheckCircle2 className="h-4 w-4" />
                )}
                Approve
              </Button>
            </div>
          </>
        ) : (
          <Badge tone={toneForStatus(decision.status)}>
            {decision.status ?? "done"}
          </Badge>
        )}
      </div>
    </div>
  );
}

export function modeLabel(mode: string | undefined) {
  if (mode === "rules_only") return "fixture";
  if (mode === "model_assisted") return "model";
  if (mode === "langgraph") return "langgraph";
  return mode ?? "unknown";
}

export function modeTone(mode: string | undefined) {
  if (mode === "rules_only") return "ready" as const;
  if (mode === "model_assisted") return "info" as const;
  return "default" as const;
}

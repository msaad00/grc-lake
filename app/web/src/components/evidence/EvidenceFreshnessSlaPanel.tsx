"use client";

import Link from "next/link";
import { AlertTriangle, Clock, Loader2, RefreshCw } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { QueryState } from "@/components/QueryState";
import {
  useEscalateStaleEvidenceMutation,
  useEvidenceFreshnessSummary,
} from "@/lib/api/hooks";
import { displayLabel } from "@/lib/display";
import { formatMinutes, plural } from "@/lib/format";
import { notify } from "@/lib/toast";

export function EvidenceFreshnessSlaPanel() {
  const summary = useEvidenceFreshnessSummary();
  const escalate = useEscalateStaleEvidenceMutation();

  const escalateTasks = async () => {
    try {
      const result = await escalate.mutateAsync(10);
      notify.success(
        `Created ${plural(result.created_count, "remediation task")} for SLA breaches`,
      );
    } catch (err) {
      notify.error(String((err as Error).message));
    }
  };

  return (
    <Card data-testid="freshness-sla-panel">
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Clock className="h-5 w-5 text-brand" />
            Evidence freshness SLA
          </CardTitle>
          <CardDescription>
            Each source has a refresh target. Stale, expired, or missing
            evidence is flagged — escalate breaches into owner tasks for audit
            prep.
          </CardDescription>
        </div>
        <Button
          variant="primary"
          size="sm"
          disabled={
            escalate.isPending || (summary.data?.sla_breach_count ?? 0) === 0
          }
          onClick={escalateTasks}
        >
          {escalate.isPending ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <RefreshCw className="h-4 w-4" />
          )}
          Escalate breaches
        </Button>
      </CardHeader>
      <CardContent className="grid gap-3">
        <QueryState queries={[summary]} label="freshness SLA">
          {summary.data && (
            <>
              <p className="text-xs text-muted">
                {plural(summary.data.sources_needing_action, "source")} at risk
                · {plural(summary.data.total, "tracked record")}
              </p>

              {summary.data.sla_breach_count > 0 && (
                <div className="flex items-start gap-2 rounded-lg border border-warning/40 bg-warning-bg p-3 text-sm text-warning-fg">
                  <AlertTriangle className="mt-0.5 h-4 w-4 flex-none" />
                  <p>
                    {summary.data.stale_count} stale ·{" "}
                    {summary.data.expired_count} expired ·{" "}
                    {summary.data.missing_count} missing. Review in{" "}
                    <Link href="/evidence" className="font-semibold underline">
                      Evidence
                    </Link>{" "}
                    or escalate to remediation owners.
                  </p>
                </div>
              )}

              <div className="grid gap-2">
                {(summary.data.sources ?? []).slice(0, 6).map((row) => (
                  <div
                    key={row.source}
                    className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-line bg-surface px-3 py-2"
                  >
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-semibold text-ink">
                          {row.source}
                        </span>
                        <Badge
                          tone={
                            row.state === "action_required"
                              ? "attention"
                              : "ready"
                          }
                        >
                          {displayLabel(row.status)}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted">
                        {plural(row.evidence_count, "record")} · refresh every{" "}
                        {formatMinutes(row.freshness_slo_minutes)}
                      </p>
                    </div>
                    <span className="text-xs font-semibold text-muted">
                      {plural(
                        row.stale_count + row.expired_count + row.missing_count,
                        "breach",
                        "breaches",
                      )}
                    </span>
                  </div>
                ))}
              </div>
            </>
          )}
        </QueryState>
      </CardContent>
    </Card>
  );
}

"use client";

import { useEffect, useState } from "react";
import { CheckCircle2, Loader2, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Drawer } from "@/components/ui/drawer";
import { EntityTagsEditor } from "@/components/EntityTagsEditor";
import { useVerifyMutation } from "@/lib/api/hooks";
import type { NormalizedEvent, VerifyResult } from "@/lib/api/types";
import { assetLabel } from "@/lib/format";

interface Props {
  evidence: NormalizedEvent | null;
  onClose: () => void;
}

export function EvidenceDrawer({ evidence, onClose }: Props) {
  const verify = useVerifyMutation();
  const [result, setResult] = useState<VerifyResult | null>(null);

  useEffect(() => {
    setResult(null);
  }, [evidence?.event_id]);

  const run = async () => {
    if (!evidence) return;
    const r = await verify.mutateAsync(evidence.event_id);
    setResult(r);
  };

  return (
    <Drawer
      open={Boolean(evidence)}
      onOpenChange={(o) => !o && onClose()}
      title={evidence?.event_id ?? "Evidence"}
      description={
        evidence ? `${evidence.source} · ${assetLabel(evidence)}` : undefined
      }
      footer={
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs text-muted">
            Verification recomputes SHA-256 over the bronze raw record
            server-side.
          </span>
          <Button variant="primary" onClick={run} disabled={verify.isPending}>
            {verify.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <ShieldCheck className="h-4 w-4" />
            )}{" "}
            Verify hash
          </Button>
        </div>
      }
    >
      {evidence && (
        <div className="grid gap-5">
          <dl className="grid grid-cols-[140px_1fr] gap-x-3 gap-y-1.5 text-sm">
            <dt className="text-muted">Time</dt>
            <dd>
              <code className="text-xs text-ink">{evidence.event_time}</code>
            </dd>
            <dt className="text-muted">Source</dt>
            <dd>
              <Badge tone="info">{evidence.source}</Badge>
            </dd>
            <dt className="text-muted">Asset</dt>
            <dd>
              {evidence.asset_name ? (
                <div className="font-semibold text-ink">
                  {evidence.asset_name}
                </div>
              ) : null}
              <code className="text-xs text-ink">{evidence.asset_id}</code>
            </dd>
            <dt className="text-muted">Owner</dt>
            <dd className="font-extrabold">{evidence.asset_owner}</dd>
            <dt className="text-muted">Status</dt>
            <dd>
              <Badge>{evidence.status}</Badge>
            </dd>
            <dt className="text-muted">Severity</dt>
            <dd>
              <Badge
                tone={
                  evidence.severity === "critical" ? "critical" : "attention"
                }
              >
                {evidence.severity}
              </Badge>
            </dd>
            <dt className="text-muted">Controls</dt>
            <dd className="flex flex-wrap gap-1">
              {evidence.control_ids.map((c) => (
                <Badge key={c}>{c}</Badge>
              ))}
            </dd>
            <dt className="text-muted">Evidence ref</dt>
            <dd>
              <code className="text-xs text-ink">{evidence.evidence_ref}</code>
            </dd>
            <dt className="text-muted">Evidence id</dt>
            <dd>
              <code className="text-xs text-ink">{evidence.evidence_id}</code>
            </dd>
            <dt className="text-muted">Collected</dt>
            <dd>
              <code className="text-xs text-ink">
                {evidence.evidence_collected_at}
              </code>
            </dd>
          </dl>

          {result && (
            <div
              className={[
                "rounded-xl border p-3 text-sm",
                result.verified
                  ? "border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-300"
                  : "border-rose-200 bg-rose-50 text-rose-900 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-300",
              ].join(" ")}
            >
              <div className="flex items-center gap-2 font-black">
                {result.verified ? (
                  <>
                    <CheckCircle2 className="h-4 w-4" /> Hash matches bronze raw
                    record.
                  </>
                ) : (
                  <>
                    <ShieldAlert className="h-4 w-4" /> Hash mismatch —{" "}
                    {result.reason ?? "details below"}
                  </>
                )}
              </div>
              <dl className="mt-3 grid grid-cols-[120px_1fr] gap-x-3 gap-y-1.5 text-xs">
                <dt>Source layer</dt>
                <dd>
                  <Badge
                    tone={
                      result.source_layer === "bronze" ? "ready" : "critical"
                    }
                  >
                    {result.source_layer}
                  </Badge>
                </dd>
                <dt>Expected</dt>
                <dd className="break-all">
                  <code>{result.expected_sha256 ?? "—"}</code>
                </dd>
                <dt>Computed</dt>
                <dd className="break-all">
                  <code>{result.computed_sha256 ?? "—"}</code>
                </dd>
              </dl>
            </div>
          )}
          <EntityTagsEditor
            entityType="evidence"
            entityId={evidence.event_id}
          />
        </div>
      )}
    </Drawer>
  );
}

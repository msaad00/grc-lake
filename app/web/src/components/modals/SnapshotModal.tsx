"use client";

import { useState } from "react";
import { Camera, Download, Loader2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Modal } from "@/components/ui/modal";
import { useSnapshotMutation, useSnapshots } from "@/lib/api/hooks";

interface Props {
  open: boolean;
  onClose: () => void;
  onToast: (msg: string) => void;
}

const REASONS = [
  "ad_hoc",
  "audit_request",
  "monthly_review",
  "quarterly_review",
  "incident_response",
  "vendor_diligence",
] as const;

export function SnapshotModal({ open, onClose, onToast }: Props) {
  const snapshots = useSnapshots();
  const create = useSnapshotMutation();
  const [reason, setReason] =
    useState<(typeof REASONS)[number]>("audit_request");

  const last = (snapshots.data ?? [])[
    snapshots.data?.length ? snapshots.data.length - 1 : 0
  ];

  const submit = async () => {
    try {
      const r = await create.mutateAsync(reason);
      onToast(`Snapshot frozen: ${r.snapshot_path.split(/[\\/]/).pop()}`);
      onClose();
    } catch (err) {
      onToast(`Snapshot failed: ${(err as Error).message}`);
    }
  };

  const downloadPdf = () => {
    const snapshotId = last?.snapshot_id;
    if (!snapshotId) {
      onToast("No snapshot available to export");
      return;
    }
    window.open(
      `/api/v1/snapshots/${encodeURIComponent(snapshotId)}/export.pdf`,
      "_blank",
      "noopener,noreferrer",
    );
  };

  return (
    <Modal
      open={open}
      onOpenChange={(o) => !o && onClose()}
      title="Freeze assessment snapshot"
      description="A hash-chained point-in-time snapshot is written to gold/snapshots/ and added to the auditor trail."
      footer={
        <div className="flex items-center justify-end gap-2">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            onClick={submit}
            disabled={create.isPending}
          >
            {create.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Camera className="h-4 w-4" />
            )}{" "}
            Freeze snapshot
          </Button>
        </div>
      }
    >
      <div className="grid gap-4 text-sm">
        <label className="grid gap-1 text-xs font-semibold uppercase tracking-wide text-muted">
          Reason
          <select
            value={reason}
            onChange={(e) =>
              setReason(e.target.value as (typeof REASONS)[number])
            }
            className="rounded-lg border border-line bg-surface px-3 py-2 text-sm font-semibold text-ink focus:outline-none focus:ring-1 focus:ring-brand"
          >
            {REASONS.map((r) => (
              <option key={r} value={r}>
                {r.replace("_", " ")}
              </option>
            ))}
          </select>
        </label>
        <div className="rounded-xl border border-line bg-surfaceMuted p-3">
          <div className="text-xs font-semibold uppercase tracking-wide text-muted">
            Latest snapshot
          </div>
          {last ? (
            <div className="mt-1.5 grid gap-1.5">
              <div className="flex flex-wrap items-center gap-2">
                <Badge tone="info">{last.reason}</Badge>
                <Badge>{last.evaluated_at?.slice(0, 19) ?? "—"}</Badge>
                <Badge
                  tone={
                    last.posture_score && last.posture_score >= 80
                      ? "ready"
                      : "attention"
                  }
                >
                  posture {Math.round(Number(last.posture_score ?? 0))}%
                </Badge>
              </div>
              <code className="break-all text-xs text-ink">
                {last.snapshot_id}
              </code>
              <div className="text-xs text-muted">
                open {last.open_violation_count ?? 0} · critical{" "}
                {last.critical_violation_count ?? 0}
              </div>
              <Button
                type="button"
                variant="default"
                className="mt-2 w-full"
                onClick={downloadPdf}
              >
                <Download className="h-4 w-4" />
                Download executive PDF
              </Button>
            </div>
          ) : (
            <div className="mt-1.5 text-xs text-muted">
              No snapshots in the lake yet.
            </div>
          )}
        </div>
      </div>
    </Modal>
  );
}

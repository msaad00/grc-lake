"use client";

import { useState } from "react";
import { Camera, Download, FileJson, Loader2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Modal } from "@/components/ui/modal";
import { QueryState } from "@/components/QueryState";
import {
  useSnapshotDetail,
  useSnapshotMutation,
  useSnapshots,
} from "@/lib/api/hooks";
import { useAuditorMode } from "@/lib/state/auditor";
import { notify } from "@/lib/toast";
import { shortDate } from "@/lib/utils";

function exportPdf(snapshotId: string) {
  window.open(
    `/api/v1/snapshots/${encodeURIComponent(snapshotId)}/export.pdf`,
    "_blank",
    "noopener,noreferrer",
  );
}

function SnapshotDetailDrawer({
  snapshotId,
  open,
  onClose,
}: {
  snapshotId: string | null;
  open: boolean;
  onClose: () => void;
}) {
  const detail = useSnapshotDetail(snapshotId ?? undefined);

  return (
    <Modal
      open={open}
      onOpenChange={(o) => !o && onClose()}
      title="Snapshot detail"
      description="Frozen posture, frameworks, violations, and evidence references."
      footer={
        snapshotId ? (
          <div className="flex justify-end gap-2">
            <Button variant="default" onClick={onClose}>
              Close
            </Button>
            <Button variant="primary" onClick={() => exportPdf(snapshotId)}>
              <Download className="h-4 w-4" />
              Export PDF
            </Button>
          </div>
        ) : null
      }
    >
      <QueryState queries={detail} label="snapshot detail">
        {detail.data && (
          <div className="grid gap-3 text-sm">
            <div className="grid gap-1 rounded-lg border border-line bg-surfaceMuted p-3">
              <div className="font-semibold text-ink">{detail.data.reason}</div>
              <div className="text-muted">
                {detail.data.evaluated_at
                  ? new Date(detail.data.evaluated_at).toLocaleString()
                  : "—"}
              </div>
              <code className="break-all text-xs text-ink">
                {detail.data.assessment_hash}
              </code>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <span className="text-muted">Posture</span>
                <div className="font-semibold text-ink">
                  {typeof detail.data.posture?.score === "number"
                    ? `${detail.data.posture.score}%`
                    : "—"}
                </div>
              </div>
              <div>
                <span className="text-muted">Violations</span>
                <div className="font-semibold text-ink">
                  {detail.data.violation_count}
                </div>
              </div>
            </div>
            <div>
              <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">
                Frameworks ({detail.data.frameworks?.length ?? 0})
              </div>
              <div className="flex flex-wrap gap-1">
                {(detail.data.frameworks ?? []).slice(0, 8).map((fw) => (
                  <Badge key={fw.framework ?? String(fw.score)} tone="default">
                    {fw.framework ?? "framework"}: {fw.score ?? "—"}%
                  </Badge>
                ))}
              </div>
            </div>
            <div>
              <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">
                Top violations
              </div>
              <ul className="max-h-40 space-y-1 overflow-y-auto text-xs">
                {(detail.data.violations ?? []).slice(0, 10).map((v, i) => (
                  <li
                    key={`${v.control_id}-${i}`}
                    className="rounded border border-line px-2 py-1"
                  >
                    <span className="font-semibold text-ink">
                      {v.control_id}
                    </span>
                    <span className="text-muted"> · {v.severity ?? "—"}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div className="flex items-center gap-2 text-xs text-muted">
              <FileJson className="h-3.5 w-3.5" />
              {detail.data.evidence_refs?.length ?? 0} evidence reference(s) —
              reviewer mode hides raw bronze payloads by default.
            </div>
          </div>
        )}
      </QueryState>
    </Modal>
  );
}

export function AuditSnapshotTimeline() {
  const snapshots = useSnapshots();
  const createSnapshot = useSnapshotMutation();
  const auditor = useAuditorMode();
  const takeSnapshot = async () => {
    try {
      await createSnapshot.mutateAsync("audit_request");
      notify.success("Snapshot saved.");
    } catch (err) {
      notify.error(`Snapshot failed: ${(err as Error).message}`);
    }
  };
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const rows = [...(snapshots.data ?? [])].sort(
    (a, b) =>
      new Date(b.evaluated_at).getTime() - new Date(a.evaluated_at).getTime(),
  );

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Snapshot timeline</CardTitle>
          <CardDescription>
            Point-in-time assessment freezes with hash, posture, and export
            actions for auditors.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <QueryState queries={snapshots} label="snapshots">
            {rows.length === 0 ? (
              <div className="grid gap-3 rounded-lg border border-dashed border-line p-4 text-sm">
                <p className="text-muted">
                  No snapshots yet. A snapshot freezes today&apos;s posture,
                  frameworks, and evidence references so auditors can review a
                  fixed point in time.
                </p>
                <div>
                  <Button
                    size="sm"
                    variant="primary"
                    disabled={createSnapshot.isPending || auditor}
                    onClick={takeSnapshot}
                  >
                    {createSnapshot.isPending ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Camera className="h-4 w-4" />
                    )}
                    Take a snapshot
                  </Button>
                </div>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[640px] text-left text-sm">
                  <thead>
                    <tr className="border-b border-line text-xs uppercase tracking-wide text-muted">
                      <th className="py-2 pr-3">When</th>
                      <th className="py-2 pr-3">Reason</th>
                      <th className="py-2 pr-3">Posture</th>
                      <th className="py-2 pr-3">Open</th>
                      <th className="py-2 pr-3">Hash</th>
                      <th className="py-2">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((row) => (
                      <tr
                        key={row.snapshot_id}
                        className="border-b border-line/60 hover:bg-surfaceMuted/50"
                      >
                        <td className="py-2 pr-3 whitespace-nowrap">
                          {shortDate(row.evaluated_at)}
                        </td>
                        <td className="py-2 pr-3">{row.reason}</td>
                        <td className="py-2 pr-3 font-semibold text-ink">
                          {row.posture_score != null
                            ? `${row.posture_score}%`
                            : "—"}
                        </td>
                        <td className="py-2 pr-3">
                          {row.open_violation_count ?? "—"}
                        </td>
                        <td className="max-w-[120px] truncate py-2 pr-3 font-mono text-xs">
                          {row.assessment_hash?.slice(0, 12)}…
                        </td>
                        <td className="py-2">
                          <div className="flex gap-1">
                            <Button
                              size="sm"
                              variant="default"
                              onClick={() => setSelectedId(row.snapshot_id)}
                            >
                              Detail
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => exportPdf(row.snapshot_id)}
                            >
                              <Download className="h-4 w-4" />
                            </Button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {snapshots.isFetching && (
              <div className="mt-2 flex items-center gap-2 text-xs text-muted">
                <Loader2 className="h-3 w-3 animate-spin" />
                Refreshing…
              </div>
            )}
          </QueryState>
        </CardContent>
      </Card>

      <SnapshotDetailDrawer
        snapshotId={selectedId}
        open={selectedId != null}
        onClose={() => setSelectedId(null)}
      />
    </>
  );
}

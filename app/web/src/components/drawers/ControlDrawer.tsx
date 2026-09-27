"use client";

import { Badge } from "@/components/ui/badge";
import Link from "next/link";
import { Drawer } from "@/components/ui/drawer";
import { useControlTests, usePosture } from "@/lib/api/hooks";
import { RemediationGuidance } from "@/components/remediation/RemediationGuidance";
import { controlGraphFocusHref } from "@/lib/finding-links";
import { FrameworkBadge } from "@/components/framework/FrameworkBadge";
import { EntityTagsEditor } from "@/components/EntityTagsEditor";
import { resolveFrameworkId } from "@/lib/framework-visuals";
import type { ControlPosture } from "@/lib/api/types";
import { assetLabel } from "@/lib/format";

interface Props {
  control: ControlPosture | null;
  onClose: () => void;
  onOpenViolation: (violationId: string) => void;
}

const toneFor = (s: string) =>
  s === "pass" ? "ready" : s === "fail" ? "critical" : "attention";

export function ControlDrawer({ control, onClose, onOpenViolation }: Props) {
  const tests = useControlTests();
  const posture = usePosture();

  const test = control
    ? (tests.data ?? []).find((t) => t.control_id === control.control_id)
    : undefined;
  const violations = control
    ? (posture.data?.violations ?? []).filter(
        (v) => v.control_id === control.control_id,
      )
    : [];

  return (
    <Drawer
      open={Boolean(control)}
      onOpenChange={(o) => !o && onClose()}
      title={control?.control_id ?? "Control detail"}
      description={control?.title}
      width="lg"
    >
      {control && (
        <div className="grid min-w-0 gap-5 [overflow-wrap:anywhere]">
          {test && (
            <div className="rounded-xl border border-line bg-surfaceMuted p-3">
              <div className="flex items-center justify-between gap-2">
                <b>{test.name}</b>
                <Badge
                  tone={toneFor(test.result)}
                  className="shrink-0 whitespace-nowrap"
                >
                  {test.status}
                </Badge>
              </div>
              <div className="mt-1 text-xs text-muted">{test.next_action}</div>
              <div className="mt-2 flex flex-wrap gap-1.5">
                <Badge>{test.agent_skill}</Badge>
                <Badge tone="info">{test.freshness_status}</Badge>
                <Badge
                  tone={test.confidence_score >= 75 ? "ready" : "attention"}
                >
                  confidence {test.confidence_score}%
                </Badge>
              </div>
            </div>
          )}
          <dl className="grid grid-cols-[100px_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-sm">
            <dt className="text-muted">Framework</dt>
            <dd>
              <FrameworkBadge
                frameworkId={resolveFrameworkId(control.framework)}
                fallbackLabel={control.framework}
                variant="compact"
                size={28}
              />
            </dd>
            <dt className="text-muted">Owner</dt>
            <dd className="font-extrabold">{control.owner}</dd>
            <dt className="text-muted">Status</dt>
            <dd className="font-extrabold">{control.status}</dd>
            <dt className="text-muted">Risk score</dt>
            <dd className="font-extrabold">{control.risk_score}</dd>
            <dt className="text-muted">Evidence</dt>
            <dd className="font-extrabold">
              <Link
                href={`/evidence/?control=${encodeURIComponent(control.control_id)}`}
                aria-label={`Evidence ${control.evidence_count}/${control.event_count} records`}
                className="text-brand hover:underline"
              >
                {control.evidence_count}/{control.event_count} records →
              </Link>
            </dd>
          </dl>
          <div>
            <div className="mb-2 text-xs font-black uppercase tracking-wide text-muted">
              Open findings · {violations.length}
            </div>
            <div className="grid gap-2">
              {violations.length === 0 && (
                <div className="rounded-lg border border-dashed border-line p-3 text-xs text-muted">
                  No open findings linked to this control.
                </div>
              )}
              {violations.map((v) => (
                <button
                  key={v.violation_id}
                  type="button"
                  onClick={() => onOpenViolation(v.violation_id)}
                  className="rounded-lg border border-line p-3 text-left hover:border-brand hover:bg-blue-50/40 dark:hover:bg-blue-500/10"
                >
                  <div
                    className="text-sm font-semibold text-ink"
                    title={v.asset_id || undefined}
                  >
                    {assetLabel(v) || "Unknown asset"}
                  </div>
                  <div className="mt-1 text-xs text-muted">
                    {v.event_type.replaceAll(/[._]/g, " ")}
                    {v.environment?.trim() ? ` · ${v.environment}` : ""} ·
                    detected {v.detected_at.slice(0, 10)}
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    <Badge
                      tone={
                        v.severity === "critical" ? "critical" : "attention"
                      }
                    >
                      {v.severity}
                    </Badge>
                    <Badge>{v.asset_owner?.trim() || "Unassigned"}</Badge>
                    <Badge tone="info">open triage →</Badge>
                  </div>
                </button>
              ))}
            </div>
          </div>
          <RemediationGuidance controlId={control.control_id} />
          <EntityTagsEditor
            entityType="control"
            entityId={control.control_id}
          />
          <div className="flex flex-wrap gap-2">
            <Link
              className="rounded-lg border border-line px-3 py-2 text-sm font-semibold text-brand hover:bg-surfaceMuted"
              href={`/remediation?tab=evidence&control=${encodeURIComponent(control.control_id)}`}
            >
              Request evidence
            </Link>
            <Link
              className="rounded-lg border border-line px-3 py-2 text-sm font-semibold text-brand hover:bg-surfaceMuted"
              href={`/remediation/?${new URLSearchParams({ tab: "tasks", control: control.control_id, title: control.title, assignee: control.owner })}`}
            >
              Create task
            </Link>
            <Link
              className="rounded-lg border border-line px-3 py-2 text-sm font-semibold text-brand hover:bg-surfaceMuted"
              href={controlGraphFocusHref(control.control_id)}
            >
              Trace in graph
            </Link>
          </div>
        </div>
      )}
    </Drawer>
  );
}

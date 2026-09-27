"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { CheckCircle2, History, Loader2 } from "lucide-react";
import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Drawer } from "@/components/ui/drawer";
import { EntityTagsEditor } from "@/components/EntityTagsEditor";
import { RemediationGuidance } from "@/components/remediation/RemediationGuidance";
import { useControls, useTracking, useTriageMutation } from "@/lib/api/hooks";
import {
  controlGraphFocusHref,
  taskFromFindingHref,
} from "@/lib/finding-links";
import { formatDateTime } from "@/lib/format";
import { useAuditorMode } from "@/lib/state/auditor";
import type { TrackingState, Violation } from "@/lib/api/types";

interface Props {
  violation: Violation | null;
  onClose: () => void;
  onToast: (msg: string) => void;
}

const STATE_TONE: Record<
  TrackingState,
  "default" | "info" | "ready" | "attention" | "critical"
> = {
  open: "critical",
  triaged: "info",
  in_progress: "attention",
  resolved: "ready",
  dismissed: "default",
};

const STATES: TrackingState[] = [
  "open",
  "triaged",
  "in_progress",
  "resolved",
  "dismissed",
];

export function ViolationDrawer({ violation, onClose, onToast }: Props) {
  const auditor = useAuditorMode();
  const tracking = useTracking(violation?.violation_id ?? null);
  const triage = useTriageMutation();
  const controls = useControls();
  const [state, setState] = useState<TrackingState>("open");
  const stateTouched = useRef(false);
  const [actor, setActor] = useState("trust-admin");
  const [assignee, setAssignee] = useState("");
  const [note, setNote] = useState("");
  const [dueAt, setDueAt] = useState("");
  const [saveError, setSaveError] = useState(false);

  useEffect(() => {
    if (!violation) return;
    setSaveError(false);
    stateTouched.current = false;
    setActor("trust-admin");
    setAssignee(violation.asset_owner ?? "");
    setNote("");
    setDueAt("");
  }, [violation]);

  const history = tracking.data?.events ?? [];
  const currentState =
    tracking.data?.current_state ??
    (violation?.state as TrackingState | undefined) ??
    "open";

  useEffect(() => {
    if (!stateTouched.current) setState(currentState as TrackingState);
  }, [currentState, violation]);

  const controlTitle = violation
    ? (controls.data ?? []).find((c) => c.control_id === violation.control_id)
        ?.title
    : undefined;

  const submit = async () => {
    if (!violation) return;
    setSaveError(false);
    try {
      await triage.mutateAsync({
        violationId: violation.violation_id,
        payload: {
          state,
          actor,
          assignee: assignee || undefined,
          note: note || undefined,
          due_at: dueAt ? new Date(dueAt).toISOString() : undefined,
        },
      });
      onToast(`Triage recorded: ${violation.violation_id} → ${state}`);
    } catch {
      setSaveError(true);
    }
  };

  const stateOptions = useMemo(
    () =>
      STATES.map((s) => (
        <option key={s} value={s}>
          {s.replace("_", " ")}
        </option>
      )),
    [],
  );

  return (
    <Drawer
      open={Boolean(violation)}
      onOpenChange={(o) => !o && onClose()}
      title={controlTitle ?? violation?.event_type ?? "Finding"}
      description={
        violation
          ? `${violation.control_id} · ${violation.event_type}`
          : undefined
      }
      width="lg"
      footer={
        !auditor && (
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-xs text-muted">
              Changes are recorded in triage history.
            </span>
            <Button
              variant="primary"
              onClick={submit}
              disabled={triage.isPending}
            >
              {triage.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <CheckCircle2 className="h-4 w-4" />
              )}{" "}
              Save triage
            </Button>
          </div>
        )
      }
    >
      {violation && (
        <div className="grid min-w-0 gap-5 [overflow-wrap:anywhere]">
          <div className="rounded-xl border border-line bg-surfaceMuted p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <Badge
                tone={
                  violation.severity === "critical" ? "critical" : "attention"
                }
              >
                {violation.severity} · {violation.severity_score}
              </Badge>
              <Badge
                tone={STATE_TONE[currentState as TrackingState] ?? "default"}
              >
                {currentState}
              </Badge>
            </div>
            <dl className="mt-3 grid grid-cols-[100px_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-xs">
              <dt className="text-muted">Asset</dt>
              <dd>
                {violation.asset_name ? (
                  <div className="font-semibold text-ink">
                    {violation.asset_name}
                  </div>
                ) : null}
                <code className="text-ink">{violation.asset_id}</code>
              </dd>
              <dt className="text-muted">Owner</dt>
              <dd className="font-medium">
                {violation.asset_owner?.trim() || "Unassigned"}
              </dd>
              <dt className="text-muted">Environment</dt>
              <dd>{violation.environment?.trim() || "Unknown"}</dd>
              <dt className="text-muted">Source</dt>
              <dd className="font-extrabold">{violation.source}</dd>
              <dt className="text-muted">Detected</dt>
              <dd className="font-extrabold" title={violation.detected_at}>
                {formatDateTime(violation.detected_at)}
              </dd>
            </dl>
          </div>

          <div className="flex flex-wrap gap-3 text-sm font-semibold text-brand">
            <Link
              href={taskFromFindingHref(
                violation,
                controlTitle ?? violation.event_type,
              )}
            >
              Create task →
            </Link>
            <Link
              href={`/controls?id=${encodeURIComponent(violation.control_id)}`}
            >
              Review control →
            </Link>
            <Link href={controlGraphFocusHref(violation.control_id)}>
              Trace in graph →
            </Link>
          </div>
          <RemediationGuidance controlId={violation.control_id} />
          {saveError && (
            <p
              role="alert"
              className="rounded-lg bg-rose-50 p-3 text-sm text-rose-700 dark:bg-rose-500/10 dark:text-rose-300"
            >
              Unable to save triage. Your changes are still here. Try again.
            </p>
          )}

          {!auditor && (
            <fieldset className="grid gap-3">
              <legend className="text-xs font-black uppercase tracking-wide text-muted">
                Triage action
              </legend>
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="grid gap-1 text-xs font-black uppercase tracking-wide text-muted">
                  State
                  <select
                    value={state}
                    onChange={(e) => {
                      stateTouched.current = true;
                      setState(e.target.value as TrackingState);
                    }}
                    className="rounded-lg border border-line bg-surface px-3 py-2 text-sm font-extrabold text-ink focus:outline-none focus:ring-1 focus:ring-brand"
                  >
                    {stateOptions}
                  </select>
                </label>
                <label className="grid gap-1 text-xs font-black uppercase tracking-wide text-muted">
                  Actor
                  <input
                    value={actor}
                    onChange={(e) => setActor(e.target.value)}
                    className="rounded-lg border border-line bg-surface px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-brand"
                  />
                </label>
                <label className="grid gap-1 text-xs font-black uppercase tracking-wide text-muted">
                  Assignee
                  <input
                    value={assignee}
                    onChange={(e) => setAssignee(e.target.value)}
                    className="rounded-lg border border-line bg-surface px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-brand"
                  />
                </label>
                <label className="grid gap-1 text-xs font-black uppercase tracking-wide text-muted">
                  Due date
                  <input
                    value={dueAt}
                    onChange={(e) => setDueAt(e.target.value)}
                    type="datetime-local"
                    className="rounded-lg border border-line bg-surface px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-brand"
                  />
                </label>
              </div>
              <label className="grid gap-1 text-xs font-black uppercase tracking-wide text-muted">
                Note
                <textarea
                  rows={3}
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  className="rounded-lg border border-line bg-surface px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-brand"
                />
              </label>
            </fieldset>
          )}

          <details className="rounded-xl border border-line p-3">
            <summary className="cursor-pointer text-sm font-semibold text-ink">
              Evidence & provenance
            </summary>
            <dl className="mt-3 grid grid-cols-[100px_minmax(0,1fr)] gap-2 text-xs">
              <dt className="text-muted">Finding ID</dt>
              <dd>{violation.violation_id}</dd>
              <dt className="text-muted">Evidence ref</dt>
              <dd>
                <code className="text-ink">{violation.evidence_ref}</code>
              </dd>
              <dt className="text-muted">Raw hash</dt>
              <dd>
                <code className="text-ink">
                  {violation.raw_sha256.slice(0, 24)}…
                </code>
              </dd>
            </dl>
          </details>

          <EntityTagsEditor
            entityType="violation"
            entityId={violation.violation_id}
          />

          <div>
            <div className="mb-2 flex items-center gap-2 text-xs font-black uppercase tracking-wide text-muted">
              <History className="h-3 w-3" /> Triage history · {history.length}{" "}
              events
            </div>
            <div className="grid gap-2">
              {history.length === 0 && (
                <div className="rounded-lg border border-dashed border-line p-3 text-xs text-muted">
                  No triage events recorded yet.
                </div>
              )}
              {history.map((event) => (
                <div
                  key={event.tracking_id}
                  className="rounded-lg border border-line p-3 text-xs"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <Badge tone={STATE_TONE[event.state] ?? "default"}>
                      {event.state}
                    </Badge>
                    <span className="text-muted">{event.occurred_at}</span>
                  </div>
                  <div className="mt-1 text-muted">
                    actor <b className="text-ink">{event.actor}</b>
                    {event.assignee && (
                      <>
                        {" "}
                        · assignee <b className="text-ink">{event.assignee}</b>
                      </>
                    )}
                    {event.due_at && (
                      <>
                        {" "}
                        · due <b className="text-ink">{event.due_at}</b>
                      </>
                    )}
                  </div>
                  {event.note && (
                    <div className="mt-1 text-ink">{event.note}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </Drawer>
  );
}

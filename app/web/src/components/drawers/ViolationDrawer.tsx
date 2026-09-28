"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  CheckCircle2,
  History,
  ListPlus,
  Loader2,
  Network,
  ShieldCheck,
} from "lucide-react";
import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Drawer } from "@/components/ui/drawer";
import { EntityTagsEditor } from "@/components/EntityTagsEditor";
import { RemediationGuidance } from "@/components/remediation/RemediationGuidance";
import { severityTone } from "@/lib/severity";
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
  open: "default",
  triaged: "info",
  in_progress: "attention",
  resolved: "ready",
  dismissed: "default",
};

const SECTION_TITLE = "text-sm font-semibold text-ink";
const FIELD_LABEL = "grid gap-1.5 text-xs font-medium text-muted";
const FIELD =
  "rounded-md border border-line bg-surface px-3 py-2 text-sm text-ink focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/30";

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
        <div className="grid min-w-0 gap-6 [overflow-wrap:anywhere]">
          <section aria-label="Summary" className="grid gap-2">
            <div className="flex flex-wrap items-center gap-2">
              <Badge
                tone={severityTone(violation.severity)}
                className="capitalize"
              >
                {violation.severity} · {violation.severity_score}
              </Badge>
              <Badge
                tone={STATE_TONE[currentState as TrackingState] ?? "default"}
                className="capitalize"
              >
                {currentState.replace("_", " ")}
              </Badge>
              <span
                className="text-xs text-muted"
                title={violation.detected_at}
              >
                Detected {formatDateTime(violation.detected_at)}
              </span>
            </div>
          </section>

          <section aria-labelledby="finding-details" className="grid gap-2">
            <h3 id="finding-details" className={SECTION_TITLE}>
              Details
            </h3>
            <dl className="grid grid-cols-[7rem_minmax(0,1fr)] gap-x-3 gap-y-2 rounded-lg border border-line p-3 text-sm">
              <dt className="text-muted">Asset</dt>
              <dd className="min-w-0">
                {violation.asset_name ? (
                  <div className="font-medium text-ink">
                    {violation.asset_name}
                  </div>
                ) : null}
                <code className="text-xs text-muted">{violation.asset_id}</code>
              </dd>
              <dt className="text-muted">Owner</dt>
              <dd className="text-ink">
                {violation.asset_owner?.trim() || "Unassigned"}
              </dd>
              <dt className="text-muted">Environment</dt>
              <dd className="text-ink">
                {violation.environment?.trim() || "Unknown"}
              </dd>
              <dt className="text-muted">Source</dt>
              <dd className="font-mono text-xs leading-5 text-ink">
                {violation.source}
              </dd>
            </dl>
          </section>

          <section aria-labelledby="finding-remediation" className="grid gap-2">
            <h3 id="finding-remediation" className={SECTION_TITLE}>
              Remediation
            </h3>
            <RemediationGuidance controlId={violation.control_id} />
            <div className="flex flex-wrap gap-2">
              <Button asChild size="sm">
                <Link
                  href={taskFromFindingHref(
                    violation,
                    controlTitle ?? violation.event_type,
                  )}
                >
                  <ListPlus aria-hidden="true" className="h-4 w-4" />
                  Create task
                </Link>
              </Button>
              <Button asChild size="sm">
                <Link
                  href={`/controls?id=${encodeURIComponent(violation.control_id)}`}
                >
                  <ShieldCheck aria-hidden="true" className="h-4 w-4" />
                  Review control
                </Link>
              </Button>
              <Button asChild size="sm">
                <Link href={controlGraphFocusHref(violation.control_id)}>
                  <Network aria-hidden="true" className="h-4 w-4" />
                  Trace in graph
                </Link>
              </Button>
            </div>
          </section>

          {saveError && (
            <p
              role="alert"
              className="rounded-lg bg-danger-bg p-3 text-sm text-danger-fg"
            >
              Unable to save triage. Your changes are still here. Try again.
            </p>
          )}

          {!auditor && (
            <fieldset className="grid gap-3">
              <legend className={`${SECTION_TITLE} mb-2`}>Triage</legend>
              <div className="grid gap-3 sm:grid-cols-2">
                <label className={FIELD_LABEL}>
                  State
                  <select
                    value={state}
                    onChange={(e) => {
                      stateTouched.current = true;
                      setState(e.target.value as TrackingState);
                    }}
                    className={FIELD}
                  >
                    {stateOptions}
                  </select>
                </label>
                <label className={FIELD_LABEL}>
                  Assignee
                  <input
                    value={assignee}
                    onChange={(e) => setAssignee(e.target.value)}
                    className={FIELD}
                  />
                </label>
                <label className={FIELD_LABEL}>
                  Due date
                  <input
                    value={dueAt}
                    onChange={(e) => setDueAt(e.target.value)}
                    type="datetime-local"
                    className={FIELD}
                  />
                </label>
                <label className={FIELD_LABEL}>
                  Actor
                  <input
                    value={actor}
                    onChange={(e) => setActor(e.target.value)}
                    className={FIELD}
                  />
                </label>
              </div>
              <label className={FIELD_LABEL}>
                Note
                <textarea
                  rows={2}
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  className={FIELD}
                />
              </label>
            </fieldset>
          )}

          <details className="rounded-lg border border-line p-3">
            <summary className="cursor-pointer text-sm font-medium text-ink">
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
            <h3 className={`${SECTION_TITLE} mb-2 flex items-center gap-2`}>
              <History aria-hidden="true" className="h-3.5 w-3.5 text-muted" />
              Triage history
              <span className="font-normal text-muted">{history.length}</span>
            </h3>
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
                    actor <b className="font-medium text-ink">{event.actor}</b>
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

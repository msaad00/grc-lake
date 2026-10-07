"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Modal } from "@/components/ui/modal";
import { PageHeader } from "@/components/PageHeader";
import { QueryState } from "@/components/QueryState";
import {
  useAuthWhoami,
  useApproveControlExceptionMutation,
  useVerifyTaskMutation,
  useControlExceptions,
  useCreateControlExceptionMutation,
  useCreateEvidenceRequestMutation,
  useCreateTaskMutation,
  useEvidenceRequests,
  useRemediationTasks,
  useRevokeControlExceptionMutation,
  useSetEvidenceRequestStatusMutation,
  useUpdateTaskMutation,
} from "@/lib/api/hooks";
import type {
  ControlExceptionItem,
  EvidenceRequestItem,
  RemediationTask,
} from "@/lib/api/types";
import { findingHref, safeHttpUrl } from "@/lib/finding-links";
import { ROUTE_LABELS } from "@/lib/console-copy";
import { formatDate as fmtDate } from "@/lib/format";
import { displayLabel } from "@/lib/display";

const inputClass =
  "rounded-lg border border-line bg-surface px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-brand";

const STATUS_TONE: Record<
  string,
  "default" | "info" | "attention" | "ready" | "critical"
> = {
  pending: "attention",
  open: "info",
  in_progress: "info",
  blocked: "attention",
  resolved: "ready",
  dismissed: "default",
  fulfilled: "ready",
  cancelled: "default",
  active: "ready",
  revoked: "default",
  expired: "attention",
};

const PRIORITY_TONE: Record<
  string,
  "default" | "info" | "attention" | "critical"
> = {
  low: "default",
  medium: "info",
  high: "attention",
  critical: "critical",
};

const TASK_PRIORITIES: RemediationTask["priority"][] = [
  "low",
  "medium",
  "high",
  "critical",
];

function ResolutionNote({ note }: { note: string }) {
  const href = safeHttpUrl(note);
  return (
    <div className="mt-1 text-xs leading-5 text-muted [overflow-wrap:anywhere]">
      <span className="font-semibold text-ink">Resolution note:</span>{" "}
      {href ? (
        <a
          href={href}
          target="_blank"
          rel="noopener noreferrer"
          className="text-brand hover:underline"
        >
          {note}
        </a>
      ) : (
        note
      )}
    </div>
  );
}

function ResolveTaskModal({
  task,
  pending,
  failed,
  onCancel,
  onConfirm,
}: {
  task: RemediationTask | null;
  pending: boolean;
  failed: boolean;
  onCancel: () => void;
  onConfirm: (note: string) => void;
}) {
  const [note, setNote] = useState("");
  useEffect(() => setNote(""), [task?.id]);
  return (
    <Modal
      open={Boolean(task)}
      onOpenChange={(open) => !open && onCancel()}
      title="Resolve task"
      description={task?.title}
      footer={
        <div className="flex flex-wrap items-center justify-end gap-2">
          <Button variant="ghost" size="sm" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            variant="primary"
            size="sm"
            disabled={pending}
            onClick={() => onConfirm(note.trim())}
          >
            {task?.control_id || task?.violation_id
              ? "Verify and resolve"
              : "Mark resolved"}
          </Button>
        </div>
      }
    >
      <label className="grid gap-1 text-xs font-semibold uppercase tracking-wide text-muted">
        Evidence link or note
        <textarea
          rows={3}
          value={note}
          maxLength={4000}
          onChange={(e) => setNote(e.target.value)}
          placeholder="https://… pull request, change ticket, or what was fixed"
          className={`${inputClass} font-normal normal-case tracking-normal text-ink`}
        />
      </label>
      <p className="mt-2 text-xs text-muted">
        Optional, but reviewers and auditors use it as proof of the fix.
      </p>
      {failed && (
        <p
          role="alert"
          className="mt-3 rounded-lg bg-danger-bg p-3 text-sm text-danger-fg"
        >
          Unable to resolve task. A control manager must verify fresh passing
          evidence collected after task creation. Your note is still here.
        </p>
      )}
    </Modal>
  );
}

function TasksSection() {
  const canWrite = useAuthWhoami().data?.scopes.includes("write") === true;
  const searchParams = useSearchParams();
  const router = useRouter();
  const selectedOwner = searchParams.get("owner") ?? "";
  const controlFilter = searchParams.get("control") ?? "";
  const listQuery = new URLSearchParams();
  if (selectedOwner) listQuery.set("owner", selectedOwner);
  if (controlFilter) listQuery.set("control_id", controlFilter);
  const tasks = useRemediationTasks(listQuery.size ? `?${listQuery}` : "");
  const allTasks = useRemediationTasks("");
  const create = useCreateTaskMutation();
  const update = useUpdateTaskMutation();
  const resolveMutation = useUpdateTaskMutation();
  const verifyMutation = useVerifyTaskMutation();
  const requestedPriority = searchParams.get("priority");
  const [title, setTitle] = useState(searchParams.get("title") ?? "");
  const [controlId, setControlId] = useState(controlFilter);
  const [owner, setOwner] = useState(searchParams.get("assignee") ?? "");
  const [findingId, setFindingId] = useState(searchParams.get("finding") ?? "");
  const [priority, setPriority] = useState<string>(
    TASK_PRIORITIES.includes(requestedPriority as RemediationTask["priority"])
      ? (requestedPriority as string)
      : "medium",
  );
  const [dueAt, setDueAt] = useState("");
  const [resolving, setResolving] = useState<RemediationTask | null>(null);

  const ownerOptions = useMemo(() => {
    const set = new Set<string>();
    for (const task of allTasks.data ?? []) {
      const value = task.owner?.trim();
      if (value) set.add(value);
    }
    if (selectedOwner) set.add(selectedOwner);
    return [...set].sort();
  }, [allTasks.data, selectedOwner]);

  const setParam = (key: string, value: string) => {
    const params = new URLSearchParams(searchParams.toString());
    if (value) params.set(key, value);
    else params.delete(key);
    router.replace(`/remediation/?${params}`, { scroll: false });
  };

  const submit = () => {
    if (!title.trim()) return;
    create.mutate(
      {
        title,
        control_id: controlId || null,
        violation_id: findingId || null,
        owner,
        priority: priority as RemediationTask["priority"],
        due_at: dueAt ? new Date(dueAt).toISOString() : null,
      },
      {
        onSuccess: () => {
          setTitle("");
          setOwner("");
          setDueAt("");
          setFindingId("");
          if (!controlFilter) setControlId("");
        },
      },
    );
  };

  const confirmResolve = (note: string) => {
    if (!resolving) return;
    if (resolving.control_id || resolving.violation_id) {
      verifyMutation.mutate(
        { id: resolving.id, note },
        { onSuccess: () => setResolving(null) },
      );
      return;
    }
    resolveMutation.mutate(
      {
        id: resolving.id,
        payload: note
          ? { status: "resolved", resolution_note: note }
          : { status: "resolved" },
      },
      { onSuccess: () => setResolving(null) },
    );
  };

  const rows = tasks.data ?? [];
  return (
    <Card className="overflow-hidden">
      <CardHeader>
        <CardTitle>Remediation tasks</CardTitle>
        <CardDescription>
          Owners, priorities, and due dates.
          {selectedOwner ? ` Filtered to ${selectedOwner}.` : ""}
        </CardDescription>
      </CardHeader>
      {!canWrite && (
        <p className="px-5 pb-3 text-sm text-muted">
          Your role can view these records. An authorized team member can change
          them.
        </p>
      )}
      <div className="flex flex-wrap items-center gap-2 px-5 pb-3">
        <label className="flex items-center gap-2 text-xs font-medium text-muted">
          Owner
          <select
            aria-label="Filter tasks by owner"
            className={inputClass}
            value={selectedOwner}
            onChange={(e) => setParam("owner", e.target.value)}
          >
            <option value="">All owners</option>
            {ownerOptions.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
        {controlFilter && (
          <span className="inline-flex max-w-full items-center gap-2 rounded-full border border-line bg-surfaceMuted px-3 py-1 text-xs text-ink">
            <span className="[overflow-wrap:anywhere]">
              Showing tasks for {controlFilter}
            </span>
            <button
              type="button"
              className="font-semibold text-brand hover:underline"
              onClick={() => setParam("control", "")}
            >
              Show all
            </button>
          </span>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-2 px-5 pb-4">
        {findingId && (
          <span className="inline-flex w-full flex-wrap items-center gap-2 text-xs text-muted">
            Linked to finding
            <Link
              href={findingHref(findingId)}
              className="font-semibold text-brand hover:underline [overflow-wrap:anywhere]"
            >
              {findingId}
            </Link>
            <button
              type="button"
              className="text-muted hover:text-ink hover:underline"
              onClick={() => setFindingId("")}
            >
              Unlink
            </button>
          </span>
        )}
        <input
          className={`${inputClass} min-w-0 flex-1 basis-full sm:min-w-[220px] sm:basis-auto`}
          aria-label="Task title"
          placeholder="Task title"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
        />
        <input
          className={`${inputClass} w-40`}
          aria-label="Control ID"
          placeholder="Control ID"
          value={controlId}
          onChange={(e) => setControlId(e.target.value)}
        />
        <input
          className={`${inputClass} w-36`}
          aria-label="Owner"
          placeholder="Owner"
          value={owner}
          onChange={(e) => setOwner(e.target.value)}
        />
        <select
          aria-label="Task priority"
          className={inputClass}
          value={priority}
          onChange={(e) => setPriority(e.target.value)}
        >
          {TASK_PRIORITIES.map((p) => (
            <option key={p} value={p}>
              {displayLabel(p)}
            </option>
          ))}
        </select>
        <input
          aria-label="Task due date (UTC)"
          className={inputClass}
          type="date"
          value={dueAt}
          onChange={(e) => setDueAt(e.target.value)}
        />
        <Button
          variant="primary"
          size="sm"
          onClick={submit}
          disabled={!canWrite || create.isPending || !title.trim()}
        >
          Add task
        </Button>
      </div>
      {(create.isError || update.isError) && (
        <p
          role="alert"
          className="mx-5 mb-4 rounded-lg bg-danger-bg p-3 text-sm text-danger-fg"
        >
          Unable to save task. Try again.
        </p>
      )}
      <QueryState queries={tasks} label="remediation tasks">
        <div className="max-h-[520px] divide-y divide-line overflow-y-auto border-t border-line">
          {rows.length === 0 && (
            <div className="px-5 py-6 text-sm text-muted">
              {selectedOwner || controlFilter
                ? "No tasks match these filters."
                : "No tasks yet."}
            </div>
          )}
          {rows.map((task: RemediationTask) => (
            <div
              key={task.id}
              data-testid={`task-${task.id}`}
              className="flex flex-wrap items-center gap-3 px-5 py-3"
            >
              <div className="min-w-0 flex-1 basis-48">
                <div className="text-sm font-semibold text-ink [overflow-wrap:anywhere]">
                  {task.title}
                </div>
                <div className="text-xs leading-5 text-muted [overflow-wrap:anywhere]">
                  {task.control_id ?? "no control"} ·{" "}
                  {task.owner || "unassigned"} · due{" "}
                  {fmtDate(task.due_at?.slice(0, 10))}
                </div>
                {task.violation_id && (
                  <Link
                    href={findingHref(task.violation_id)}
                    className="text-xs font-semibold text-brand hover:underline [overflow-wrap:anywhere]"
                  >
                    From finding {task.violation_id} →
                  </Link>
                )}
                {task.status === "resolved" &&
                task.verification_history?.length ? (
                  <p className="text-xs text-muted">
                    Verified against generation{" "}
                    {
                      task.verification_history[
                        task.verification_history.length - 1
                      ].generation.generation_id
                    }
                  </p>
                ) : null}
                {task.status === "resolved" && task.resolution_note && (
                  <ResolutionNote note={task.resolution_note} />
                )}
              </div>
              <Badge tone={PRIORITY_TONE[task.priority]}>
                {displayLabel(task.priority)}
              </Badge>
              {task.status !== "open" ? (
                <Badge tone={STATUS_TONE[task.status]}>
                  {displayLabel(task.status)}
                </Badge>
              ) : null}
              {task.overdue && <Badge tone="critical">Overdue</Badge>}
              {task.status !== "resolved" && task.status !== "dismissed" && (
                <div className="flex gap-1.5">
                  <Button
                    size="sm"
                    disabled={!canWrite}
                    onClick={() => {
                      resolveMutation.reset();
                      verifyMutation.reset();
                      setResolving(task);
                    }}
                  >
                    Resolve
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={!canWrite}
                    className="font-medium text-muted hover:text-ink"
                    onClick={() =>
                      update.mutate({
                        id: task.id,
                        payload: { status: "dismissed" },
                      })
                    }
                  >
                    Dismiss
                  </Button>
                </div>
              )}
            </div>
          ))}
        </div>
      </QueryState>
      <ResolveTaskModal
        task={resolving}
        pending={resolveMutation.isPending || verifyMutation.isPending}
        failed={resolveMutation.isError || verifyMutation.isError}
        onCancel={() => setResolving(null)}
        onConfirm={confirmResolve}
      />
    </Card>
  );
}

function EvidenceRequestsSection() {
  const canWrite =
    useAuthWhoami().data?.scopes.includes("evidence_request") === true;
  const searchParams = useSearchParams();
  const requests = useEvidenceRequests();
  const create = useCreateEvidenceRequestMutation();
  const setStatus = useSetEvidenceRequestStatusMutation();
  const [controlId, setControlId] = useState(searchParams.get("control") ?? "");
  const [from, setFrom] = useState("");

  const submit = () => {
    if (!controlId.trim()) return;
    create.mutate(
      { control_id: controlId, requested_from: from },
      {
        onSuccess: () => {
          setControlId("");
          setFrom("");
        },
      },
    );
  };

  const rows = requests.data ?? [];
  return (
    <Card className="overflow-hidden">
      <CardHeader>
        <CardTitle>Evidence requests</CardTitle>
        <CardDescription>Owners and fulfillment status.</CardDescription>
      </CardHeader>
      {!canWrite && (
        <p className="px-5 pb-3 text-sm text-muted">
          Your role can view these records. An authorized team member can change
          them.
        </p>
      )}
      <div className="flex flex-wrap items-center gap-2 px-5 pb-4">
        <input
          className={`${inputClass} w-44`}
          aria-label="Control ID"
          placeholder="Control ID"
          value={controlId}
          onChange={(e) => setControlId(e.target.value)}
        />
        <input
          className={`${inputClass} min-w-[200px] flex-1`}
          aria-label="Requested from"
          placeholder="Requested from"
          value={from}
          onChange={(e) => setFrom(e.target.value)}
        />
        <Button
          variant="primary"
          size="sm"
          onClick={submit}
          disabled={!canWrite || create.isPending || !controlId.trim()}
        >
          Request evidence
        </Button>
      </div>
      {(create.isError || setStatus.isError) && (
        <p
          role="alert"
          className="mx-5 mb-4 rounded-lg bg-danger-bg p-3 text-sm text-danger-fg"
        >
          Unable to save evidence request. Your entries are still here. Try
          again.
        </p>
      )}
      {create.isSuccess && (
        <p role="status" className="px-5 pb-4 text-sm text-success-fg">
          Evidence request saved.
        </p>
      )}
      <QueryState queries={requests} label="evidence requests">
        <div className="max-h-[520px] divide-y divide-line overflow-y-auto border-t border-line">
          {rows.length === 0 && (
            <div className="px-5 py-6 text-sm text-muted">
              No evidence requests.
            </div>
          )}
          {rows.map((req: EvidenceRequestItem) => (
            <div
              key={req.id}
              className="flex flex-wrap items-center gap-3 px-5 py-3"
            >
              <div className="min-w-[12rem] flex-1">
                <div className="text-sm font-semibold text-ink [overflow-wrap:anywhere]">
                  {req.control_id}
                </div>
                <div className="text-xs leading-5 text-muted">
                  from {req.requested_from || "—"} · created{" "}
                  {fmtDate(req.created_at)}
                </div>
              </div>
              <Badge tone={STATUS_TONE[req.status]}>
                {displayLabel(req.status)}
              </Badge>
              {req.status === "open" && (
                <div className="flex gap-1.5">
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={!canWrite}
                    onClick={() =>
                      setStatus.mutate({ id: req.id, status: "fulfilled" })
                    }
                  >
                    Fulfill
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={!canWrite}
                    onClick={() =>
                      setStatus.mutate({ id: req.id, status: "cancelled" })
                    }
                  >
                    Cancel
                  </Button>
                </div>
              )}
            </div>
          ))}
        </div>
      </QueryState>
    </Card>
  );
}

function ExceptionsSection() {
  const identity = useAuthWhoami();
  const canWrite = identity.data?.scopes.includes("control_manage") === true;
  const humanReviewer =
    ["session:oidc", "session:saml"].includes(
      identity.data?.auth_method ?? "",
    ) && (identity.data?.scopes ?? []).includes("control_manage");
  const exceptions = useControlExceptions();
  const create = useCreateControlExceptionMutation();
  const revoke = useRevokeControlExceptionMutation();
  const approve = useApproveControlExceptionMutation();
  const [controlId, setControlId] = useState("");
  const [reason, setReason] = useState("");
  const [expiresAt, setExpiresAt] = useState("");

  const submit = () => {
    if (!controlId.trim() || !reason.trim() || !expiresAt) return;
    create.mutate(
      {
        control_id: controlId,
        reason,
        expires_at: new Date(expiresAt).toISOString(),
      },
      {
        onSuccess: () => {
          setControlId("");
          setReason("");
          setExpiresAt("");
        },
      },
    );
  };

  const rows = exceptions.data ?? [];
  return (
    <Card className="overflow-hidden">
      <CardHeader>
        <CardTitle>Control exceptions</CardTitle>
        <CardDescription>
          Time-limited risk acceptance requires a different authorized reviewer.
          Accepted risk does not make a control pass.
        </CardDescription>
      </CardHeader>
      {!canWrite && (
        <p className="px-5 pb-3 text-sm text-muted">
          Your role can view these records. An authorized team member can change
          them.
        </p>
      )}
      <div className="flex flex-wrap items-center gap-2 px-5 pb-4">
        <input
          className={`${inputClass} w-44`}
          aria-label="Control ID"
          placeholder="Control ID"
          value={controlId}
          onChange={(e) => setControlId(e.target.value)}
        />
        <input
          className={`${inputClass} min-w-[200px] flex-1`}
          aria-label="Reason"
          placeholder="Reason"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
        <input
          aria-label="Exception expiry date (UTC)"
          className={inputClass}
          type="date"
          value={expiresAt}
          onChange={(e) => setExpiresAt(e.target.value)}
        />
        <Button
          variant="primary"
          size="sm"
          onClick={submit}
          disabled={
            !canWrite ||
            create.isPending ||
            !controlId.trim() ||
            !reason.trim() ||
            !expiresAt
          }
        >
          Request exception
        </Button>
      </div>
      <p className="px-5 pb-3 text-sm text-muted">
        Signed in as {identity.data?.email ?? "unknown"}.{" "}
        {humanReviewer
          ? "A different authorized reviewer must approve requests you created."
          : "Approval requires an independent reviewer signed in through OIDC or SAML SSO with control-management permission."}
      </p>
      {(create.isError || revoke.isError || approve.isError) && (
        <p
          role="alert"
          className="mx-5 mb-4 rounded-lg bg-danger-bg p-3 text-sm text-danger-fg"
        >
          Unable to save exception. Provide a reason and future expiry; approval
          requires a different authorized user.
        </p>
      )}
      <QueryState queries={exceptions} label="control exceptions">
        <div className="max-h-[520px] divide-y divide-line overflow-y-auto border-t border-line">
          {rows.length === 0 && (
            <div className="px-5 py-6 text-sm text-muted">No exceptions.</div>
          )}
          {rows.map((exc: ControlExceptionItem) => (
            <div
              key={exc.id}
              className="flex flex-wrap items-center gap-3 px-5 py-3"
            >
              <div className="min-w-[12rem] flex-1">
                <div className="text-sm font-semibold text-ink [overflow-wrap:anywhere]">
                  {exc.control_id}
                </div>
                <div className="text-xs leading-5 text-muted">
                  {exc.reason || "no reason"} · by {exc.approved_by || "—"} ·
                  expires {fmtDate(exc.expires_at?.slice(0, 10))}
                </div>
              </div>
              <Badge tone={exc.active ? "ready" : STATUS_TONE[exc.status]}>
                {exc.active ? "active" : exc.status}
              </Badge>
              {exc.status === "pending" && (
                <Button
                  size="sm"
                  disabled={
                    approve.isPending ||
                    !humanReviewer ||
                    exc.created_by.toLowerCase() ===
                      identity.data?.email.toLowerCase()
                  }
                  title={
                    !humanReviewer
                      ? "An independent human SSO reviewer is required"
                      : exc.created_by.toLowerCase() ===
                          identity.data?.email.toLowerCase()
                        ? "Another reviewer must approve your request"
                        : "Approve this exception"
                  }
                  onClick={() => approve.mutate(exc.id)}
                >
                  Approve
                </Button>
              )}
              {(exc.active || exc.status === "pending") && (
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={!canWrite}
                  onClick={() => {
                    if (
                      window.confirm(
                        `Revoke the exception for ${exc.control_id}? Its approval history will be retained.`,
                      )
                    )
                      revoke.mutate(exc.id);
                  }}
                >
                  Revoke
                </Button>
              )}
            </div>
          ))}
        </div>
      </QueryState>
    </Card>
  );
}

const TABS = [
  { id: "tasks", label: "Tasks" },
  { id: "evidence", label: "Evidence requests" },
  { id: "exceptions", label: "Exceptions" },
];

function RemediationContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const requestedTab = searchParams.get("tab") ?? "tasks";
  const tab = TABS.some((item) => item.id === requestedTab)
    ? requestedTab
    : "tasks";
  return (
    <div className="page-shell grid gap-4">
      <PageHeader
        title={ROUTE_LABELS["/remediation"]}
        description="Tasks, evidence requests, and exceptions."
      />
      <div
        role="tablist"
        aria-label="Remediation view"
        className="flex flex-wrap gap-5 border-b border-line"
      >
        {TABS.map((item) => (
          <button
            key={item.id}
            type="button"
            role="tab"
            aria-selected={tab === item.id}
            className={`-mb-px border-b-2 py-2.5 text-[13px] font-medium focus-visible:outline focus-visible:outline-2 focus-visible:outline-brand ${tab === item.id ? "border-ink text-ink" : "border-transparent text-muted hover:text-ink"}`}
            onClick={() => {
              const params = new URLSearchParams(searchParams.toString());
              params.set("tab", item.id);
              router.replace(`/remediation?${params}`, { scroll: false });
            }}
          >
            {item.label}
          </button>
        ))}
      </div>
      {tab === "tasks" && <TasksSection />}
      {tab === "evidence" && <EvidenceRequestsSection />}
      {tab === "exceptions" && <ExceptionsSection />}
    </div>
  );
}

export default function RemediationPage() {
  return (
    <Suspense
      fallback={
        <div className="p-5 text-sm text-muted">Loading remediation…</div>
      }
    >
      <RemediationContent />
    </Suspense>
  );
}

"use client";

import { Suspense, useDeferredValue, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { ExternalLink, History, Search } from "lucide-react";
import { PageHeader } from "@/components/PageHeader";
import { QueryState } from "@/components/QueryState";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Drawer } from "@/components/ui/drawer";
import {
  useAuthWhoami,
  useMappingReviewHistory,
  useMappingReviewQueue,
  useMappingReviewSummary,
  useRecordMappingReviewMutation,
} from "@/lib/api/hooks";
import type {
  MappingReviewDecisionKind,
  MappingReviewItem,
  MappingReviewProgressRow,
  MappingReviewState,
  MappingReviewSummary,
} from "@/lib/api/types";
import { MAPPING_REVIEW_GLOSSARY, ROUTE_LABELS } from "@/lib/console-copy";
import { formatCount, formatDateTime } from "@/lib/format";
import { notify } from "@/lib/toast";
import { cn } from "@/lib/utils";

const PAGE_SIZE = 50;
const PROGRESS_PREVIEW = 6;

type BadgeTone = "default" | "brand" | "ready" | "attention" | "critical";

const STATE_TONE: Record<MappingReviewState, BadgeTone> = {
  maintainer_reviewed: "ready",
  org_reviewed: "brand",
  proposed: "default",
  needs_changes: "attention",
  rejected: "critical",
};

const DECISION_TONE: Record<MappingReviewDecisionKind, BadgeTone> = {
  approve: "brand",
  needs_changes: "attention",
  reject: "critical",
};

const DECISION_LABEL: Record<MappingReviewDecisionKind, string> = {
  approve: "Approved",
  needs_changes: "Needs changes",
  reject: "Rejected",
};

// Progress segments, in the order an auditor reads them. Fills are status
// tokens so they swap with the theme; pending stays neutral.
const SEGMENTS: Array<{
  key: keyof Omit<MappingReviewProgressRow, "framework_id" | "mapped">;
  label: string;
  fill: string;
}> = [
  {
    key: "maintainer_reviewed",
    label: MAPPING_REVIEW_GLOSSARY.maintainer_reviewed.label,
    fill: "bg-success",
  },
  {
    key: "org_reviewed",
    label: MAPPING_REVIEW_GLOSSARY.org_reviewed.label,
    fill: "bg-brand",
  },
  {
    key: "needs_changes",
    label: MAPPING_REVIEW_GLOSSARY.needs_changes.label,
    fill: "bg-warning",
  },
  {
    key: "rejected",
    label: MAPPING_REVIEW_GLOSSARY.rejected.label,
    fill: "bg-danger",
  },
  { key: "pending", label: "Pending", fill: "bg-line-strong" },
];

const STATUS_OPTIONS: Array<{ value: string; label: string }> = [
  { value: "pending", label: "Pending review" },
  {
    value: "needs_changes",
    label: MAPPING_REVIEW_GLOSSARY.needs_changes.label,
  },
  { value: "org_reviewed", label: MAPPING_REVIEW_GLOSSARY.org_reviewed.label },
  {
    value: "maintainer_reviewed",
    label: MAPPING_REVIEW_GLOSSARY.maintainer_reviewed.label,
  },
  { value: "rejected", label: MAPPING_REVIEW_GLOSSARY.rejected.label },
  { value: "all", label: "All mappings" },
];

// Opaque so sticky columns hide what scrolls beneath them.
const ROW_BG = "bg-surface";
const SELECTED_BG =
  "bg-[color-mix(in_srgb,var(--color-brand)_6%,var(--color-surface))]";
const STICKY_SELECT = "sticky left-0 z-[1] w-12 min-w-12";
const STICKY_REQUIREMENT =
  "sticky left-12 z-[1] shadow-[1px_0_0_var(--color-line)] sm:shadow-none";

const ANCHOR_PREVIEW = 8;

const selectClass = "ui-input h-9 w-full min-w-0";

function mappingKey(item: { safeguard_id: string; control_id: string }) {
  return `${item.safeguard_id}|${item.control_id}`;
}

function basisLabel(item: MappingReviewItem): string {
  if (item.mapping_basis === "title_theme") return "Title theme";
  if (item.mapping_source) return "Published crosswalk";
  if (item.shipped_review_status === "reviewed") return "Maintainer review";
  return "Proposed equivalence";
}

function ProgressBar({ row }: { row: MappingReviewProgressRow }) {
  return (
    <div
      className="flex h-2 w-full overflow-hidden rounded-full bg-surfaceMuted"
      aria-hidden="true"
    >
      {SEGMENTS.map((segment) =>
        row[segment.key] > 0 ? (
          <div
            key={segment.key}
            className={segment.fill}
            style={{ width: `${(row[segment.key] / row.mapped) * 100}%` }}
          />
        ) : null,
      )}
    </div>
  );
}

function ReviewProgress({
  summary,
  onPickFramework,
}: {
  summary: MappingReviewSummary;
  onPickFramework: (frameworkId: string) => void;
}) {
  const [showAll, setShowAll] = useState(false);
  const rows = useMemo(
    () =>
      [...summary.frameworks].sort(
        (a, b) => b.pending + b.needs_changes - (a.pending + a.needs_changes),
      ),
    [summary.frameworks],
  );
  const visible = showAll ? rows : rows.slice(0, PROGRESS_PREVIEW);
  const totals = summary.totals;
  return (
    <section
      aria-label="Review progress"
      className="min-w-0 overflow-hidden rounded-lg border border-line bg-surface"
    >
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-line px-4 py-3 sm:px-5">
        <div className="min-w-0">
          <h2 className="ui-section-title">Review progress</h2>
          <p className="mt-0.5 text-xs text-muted">
            {formatCount(totals.org_reviewed)}{" "}
            {MAPPING_REVIEW_GLOSSARY.org_reviewed.label.toLowerCase()} ·{" "}
            {formatCount(totals.maintainer_reviewed)}{" "}
            {MAPPING_REVIEW_GLOSSARY.maintainer_reviewed.label.toLowerCase()} ·{" "}
            {formatCount(totals.pending + totals.needs_changes)} awaiting a
            decision, of {formatCount(totals.mapped)} mappings.
          </p>
        </div>
        <Badge tone={summary.decision_log.ok ? "ready" : "critical"}>
          {summary.decision_log.ok
            ? `Decision log verified · ${formatCount(summary.decision_log.length ?? 0)}`
            : "Decision log failed verification"}
        </Badge>
      </div>
      <details className="group border-b border-line px-4 py-2 text-xs text-muted sm:px-5">
        <summary className="flex cursor-pointer list-none flex-wrap items-center gap-x-4 gap-y-1 rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand [&::-webkit-details-marker]:hidden">
          {SEGMENTS.map((segment) => (
            <span key={segment.key} className="flex items-center gap-1.5">
              <span
                className={cn("h-2 w-2 rounded-full", segment.fill)}
                aria-hidden="true"
              />
              <span>{segment.label}</span>
            </span>
          ))}
          <span className="ui-link">
            <span className="group-open:hidden">What these mean</span>
            <span className="hidden group-open:inline">Hide definitions</span>
          </span>
        </summary>
        <dl className="mt-2 grid gap-x-6 gap-y-1 sm:grid-cols-2">
          {Object.entries(MAPPING_REVIEW_GLOSSARY).map(([key, entry]) => (
            <div key={key} className="flex gap-1.5">
              <dt className="shrink-0 font-semibold text-ink">{entry.label}</dt>
              <dd>{entry.definition}</dd>
            </div>
          ))}
        </dl>
      </details>
      <ul className="grid gap-x-6 px-4 sm:grid-cols-2 sm:px-5 xl:grid-cols-3">
        {visible.map((row) => (
          <li key={row.framework_id} className="border-b border-line py-3">
            <button
              type="button"
              onClick={() => onPickFramework(row.framework_id)}
              className="grid w-full min-w-0 gap-1.5 rounded-md text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand"
              aria-label={`Show ${summary.framework_names[row.framework_id] ?? row.framework_id} mappings`}
            >
              <span className="flex min-w-0 items-baseline justify-between gap-2">
                <span className="truncate text-sm font-semibold text-ink">
                  {summary.framework_names[row.framework_id] ??
                    row.framework_id}
                </span>
                <span className="shrink-0 text-xs tabular-nums text-muted">
                  {MAPPING_REVIEW_GLOSSARY.org_reviewed.label.toLowerCase()}{" "}
                  {formatCount(row.org_reviewed)} of {formatCount(row.mapped)}{" "}
                  mapped
                </span>
              </span>
              <ProgressBar row={row} />
              <span className="text-xs text-muted">
                {formatCount(row.maintainer_reviewed)} maintainer ·{" "}
                {formatCount(row.pending)} pending
                {row.needs_changes
                  ? ` · ${formatCount(row.needs_changes)} needs changes`
                  : ""}
                {row.rejected ? ` · ${formatCount(row.rejected)} rejected` : ""}
              </span>
            </button>
          </li>
        ))}
      </ul>
      {rows.length > PROGRESS_PREVIEW ? (
        <div className="px-4 py-2 sm:px-5">
          <Button
            variant="ghost"
            size="sm"
            aria-expanded={showAll}
            onClick={() => setShowAll((value) => !value)}
          >
            {showAll ? "Show fewer frameworks" : `Show all ${rows.length}`}
          </Button>
        </div>
      ) : null}
    </section>
  );
}

function DecisionForm({
  items,
  canDecide,
  onDone,
  compact = false,
}: {
  items: MappingReviewItem[];
  canDecide: boolean;
  onDone: () => void;
  compact?: boolean;
}) {
  const record = useRecordMappingReviewMutation();
  const [rationale, setRationale] = useState("");
  const [evidenceRef, setEvidenceRef] = useState("");
  const ready = canDecide && items.length > 0 && rationale.trim().length > 0;

  const submit = (decision: MappingReviewDecisionKind) => {
    if (!ready) return;
    if (
      items.length > 1 &&
      decision === "approve" &&
      !window.confirm(
        `Approve ${items.length} selected mappings with this rationale?`,
      )
    )
      return;
    record.mutate(
      {
        decision,
        rationale: rationale.trim(),
        evidence_ref: evidenceRef.trim() || undefined,
        items: items.map((item) => ({
          safeguard_id: item.safeguard_id,
          control_id: item.control_id,
          framework_id: item.framework_id,
        })),
      },
      {
        onSuccess: (records) => {
          notify.success(
            `Recorded ${records.length} decision${records.length === 1 ? "" : "s"}`,
          );
          setRationale("");
          setEvidenceRef("");
          onDone();
        },
        onError: (error) => notify.error(error.message),
      },
    );
  };

  if (!canDecide) {
    return (
      <p className="break-words text-xs leading-5 text-muted">
        You can review the queue, but recording a decision needs the{" "}
        <code>mapping_review</code> scope (admin or compliance reviewer) in a
        signed-in console session. API keys and agents can read but never
        decide. Headless equivalent:{" "}
        <code>
          security-lakehouse frameworks review approve --lake … --safeguard …
          --framework … --control … --rationale … --reviewer …
        </code>
      </p>
    );
  }

  const idPrefix = compact ? "drawer" : "bulk";
  return (
    <div className="grid gap-2">
      <label className="grid gap-1" htmlFor={`${idPrefix}-rationale`}>
        <span className="ui-label">Rationale</span>
        <textarea
          id={`${idPrefix}-rationale`}
          required
          rows={compact ? 3 : 2}
          maxLength={4000}
          value={rationale}
          onChange={(event) => setRationale(event.target.value)}
          placeholder="Why this mapping does or does not satisfy the requirement"
          className="ui-input min-h-[2.5rem] w-full resize-y"
        />
      </label>
      <label className="grid gap-1" htmlFor={`${idPrefix}-evidence`}>
        <span className="ui-label">
          Evidence or ticket reference (optional)
        </span>
        <input
          id={`${idPrefix}-evidence`}
          value={evidenceRef}
          maxLength={1000}
          onChange={(event) => setEvidenceRef(event.target.value)}
          className="ui-input h-9 w-full"
        />
      </label>
      <div className="flex flex-wrap gap-2">
        <Button
          variant="primary"
          size="sm"
          disabled={!ready || record.isPending}
          onClick={() => submit("approve")}
        >
          Approve
        </Button>
        <Button
          size="sm"
          disabled={!ready || record.isPending}
          onClick={() => submit("needs_changes")}
        >
          Request changes
        </Button>
        <Button
          size="sm"
          disabled={!ready || record.isPending}
          onClick={() => submit("reject")}
        >
          Reject
        </Button>
      </div>
    </div>
  );
}

function SourceAnchor({ item }: { item: MappingReviewItem }) {
  if (!item.mapping_source) {
    return <span className="text-muted">—</span>;
  }
  return (
    <a
      href={item.mapping_source.url}
      target="_blank"
      rel="noreferrer"
      className="ui-link inline-flex max-w-full items-center gap-1"
      title={`${item.mapping_source.name} · sha256 ${item.mapping_source.sha256.slice(0, 12)}…`}
    >
      <span className="truncate">{item.mapping_source.locator}</span>
      <ExternalLink className="h-3 w-3 shrink-0" aria-hidden="true" />
      <span className="sr-only">(opens {item.mapping_source.name})</span>
    </a>
  );
}

function HistoryDrawer({
  item,
  canDecide,
  onClose,
}: {
  item: MappingReviewItem | null;
  canDecide: boolean;
  onClose: () => void;
}) {
  const history = useMappingReviewHistory(item);
  const rows = [...(history.data ?? [])].reverse();
  return (
    <Drawer
      open={item !== null}
      onOpenChange={(open) => (open ? null : onClose())}
      title={item ? `${item.safeguard_id} → ${item.control_id}` : ""}
      description={item?.control_title ?? undefined}
      width="lg"
    >
      {item ? (
        <div className="grid gap-5 text-sm">
          <dl className="grid gap-3 sm:grid-cols-2">
            <div>
              <dt className="ui-label">Status</dt>
              <dd className="mt-1">
                <Badge tone={STATE_TONE[item.review_state]}>
                  {MAPPING_REVIEW_GLOSSARY[item.review_state].label}
                </Badge>
                <p className="mt-1 text-xs text-muted">
                  {MAPPING_REVIEW_GLOSSARY[item.review_state].definition}
                </p>
              </dd>
            </div>
            <div>
              <dt className="ui-label">Basis</dt>
              <dd className="mt-1 text-ink">{basisLabel(item)}</dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="ui-label">Safeguard</dt>
              <dd className="mt-1 text-ink">{item.safeguard_title}</dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="ui-label">Source anchor</dt>
              <dd className="mt-1">
                <SourceAnchor item={item} />
              </dd>
            </div>
            {item.reviewed_anchors.length ? (
              <div className="sm:col-span-2">
                <dt className="ui-label">
                  Already confirmed on this safeguard (
                  {formatCount(item.reviewed_anchors.length)})
                </dt>
                <dd className="mt-1 text-xs text-muted">
                  {item.reviewed_anchors.slice(0, ANCHOR_PREVIEW).join(", ")}
                  {item.reviewed_anchors.length > ANCHOR_PREVIEW ? (
                    <details className="mt-1">
                      <summary className="cursor-pointer rounded-sm text-brand focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand">
                        Show{" "}
                        {formatCount(
                          item.reviewed_anchors.length - ANCHOR_PREVIEW,
                        )}{" "}
                        more
                      </summary>
                      <p className="mt-1 max-h-40 overflow-auto">
                        {item.reviewed_anchors.slice(ANCHOR_PREVIEW).join(", ")}
                      </p>
                    </details>
                  ) : null}
                </dd>
              </div>
            ) : null}
          </dl>

          <section
            aria-labelledby="mapping-history-title"
            className="grid gap-2"
          >
            <h3 id="mapping-history-title" className="ui-section-title">
              Decision history
            </h3>
            <QueryState queries={history} label="decision history">
              {rows.length === 0 ? (
                <p className="text-xs text-muted">
                  No org decisions yet. The shipped status is{" "}
                  {item.shipped_review_status}.
                </p>
              ) : (
                <ol className="grid gap-2">
                  {rows.map((row, index) => (
                    <li
                      key={row.decision_id}
                      className="rounded-md border border-line bg-surfaceMuted p-3"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge tone={DECISION_TONE[row.decision]}>
                          {DECISION_LABEL[row.decision]}
                        </Badge>
                        {index === 0 ? (
                          <Badge tone="default">In force</Badge>
                        ) : (
                          <Badge tone="outline">Superseded</Badge>
                        )}
                        <span className="text-xs text-muted">
                          {formatDateTime(row.decided_at)}
                        </span>
                      </div>
                      <p className="mt-2 whitespace-pre-wrap text-ink">
                        {row.rationale}
                      </p>
                      <p className="mt-1 text-xs text-muted">
                        {row.reviewer}
                        {row.reviewer_role
                          ? ` · ${row.reviewer_role}`
                          : ""} · {row.auth_method}
                        {row.evidence_ref ? ` · ${row.evidence_ref}` : ""}
                      </p>
                    </li>
                  ))}
                </ol>
              )}
            </QueryState>
          </section>

          <section
            aria-labelledby="mapping-decide-title"
            className="grid gap-2"
          >
            <h3 id="mapping-decide-title" className="ui-section-title">
              Decide this mapping
            </h3>
            <DecisionForm
              items={[item]}
              canDecide={canDecide}
              onDone={onClose}
              compact
            />
          </section>
        </div>
      ) : null}
    </Drawer>
  );
}

function MappingReviewContent() {
  const searchParams = useSearchParams();
  const [framework, setFramework] = useState(
    () => searchParams.get("framework") ?? "",
  );
  const [family, setFamily] = useState(() => searchParams.get("family") ?? "");
  const [status, setStatus] = useState("pending");
  const [query, setQuery] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [historyItem, setHistoryItem] = useState<MappingReviewItem | null>(
    null,
  );
  const deferredQuery = useDeferredValue(query.trim());

  const whoami = useAuthWhoami();
  const canDecide = Boolean(whoami.data?.scopes.includes("mapping_review"));
  const summary = useMappingReviewSummary();
  const queue = useMappingReviewQueue({
    framework_id: framework || undefined,
    family: family || undefined,
    status,
    q: deferredQuery || undefined,
    limit: PAGE_SIZE,
    offset,
  });
  const items = queue.data?.items ?? [];
  const count = queue.data?.count ?? 0;
  const summaryFamilies = summary.data?.families;
  const familyGroups = useMemo(() => {
    const groups = new Map<string, NonNullable<typeof summaryFamilies>>();
    for (const row of summaryFamilies ?? []) {
      const key = row.category_label || "Other";
      groups.set(key, [...(groups.get(key) ?? []), row]);
    }
    return [...groups.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [summaryFamilies]);
  const selectedItems = items.filter((item) => selected.has(mappingKey(item)));
  const allOnPageSelected =
    items.length > 0 && items.every((item) => selected.has(mappingKey(item)));

  const resetPaging = () => {
    setOffset(0);
    setSelected(new Set());
  };
  const toggle = (key: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  const toggleAll = () =>
    setSelected(allOnPageSelected ? new Set() : new Set(items.map(mappingKey)));

  const frameworkNames = summary.data?.framework_names ?? {};
  const frameworkOptions = Object.entries(frameworkNames).sort((a, b) =>
    a[1].localeCompare(b[1]),
  );

  return (
    <div className="page-shell grid min-h-full grid-cols-[minmax(0,1fr)] gap-5">
      <PageHeader
        title={ROUTE_LABELS["/mapping-review"]}
        description="Approve, reject, or send back safeguard-to-requirement mappings; every decision is attributed and logged."
      />

      <QueryState queries={summary} label="review progress">
        {summary.data ? (
          <ReviewProgress
            summary={summary.data}
            onPickFramework={(id) => {
              setFramework(id);
              resetPaging();
            }}
          />
        ) : null}
      </QueryState>

      <section
        aria-labelledby="mapping-queue-title"
        className="min-w-0 overflow-hidden rounded-lg border border-line bg-surface"
      >
        <div className="grid gap-3 border-b border-line px-4 py-3 sm:px-5">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h2 id="mapping-queue-title" className="ui-section-title">
              Review queue
            </h2>
            <p className="text-xs text-muted" aria-live="polite">
              {queue.isPending
                ? "Loading…"
                : count === 0
                  ? "No mappings match these filters"
                  : `${formatCount(offset + 1)}–${formatCount(Math.min(offset + PAGE_SIZE, count))} of ${formatCount(count)}`}
            </p>
          </div>
          <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-[minmax(0,2fr)_repeat(3,minmax(0,1fr))]">
            <label className="flex h-9 min-w-0 items-center gap-2 rounded-md border border-line bg-surface px-2.5 text-sm focus-within:border-brand focus-within:ring-2 focus-within:ring-brand/40">
              <Search
                className="h-4 w-4 shrink-0 text-muted"
                aria-hidden="true"
              />
              <input
                type="search"
                aria-label="Search mappings"
                placeholder="Search requirement or safeguard"
                value={query}
                onChange={(event) => {
                  setQuery(event.target.value);
                  resetPaging();
                }}
                className="min-w-0 flex-1 bg-transparent text-ink outline-none placeholder:text-muted"
              />
            </label>
            <select
              aria-label="Filter by framework"
              className={selectClass}
              value={framework}
              onChange={(event) => {
                setFramework(event.target.value);
                resetPaging();
              }}
            >
              <option value="">All frameworks</option>
              {frameworkOptions.map(([id, name]) => (
                <option key={id} value={id}>
                  {name}
                </option>
              ))}
            </select>
            <select
              aria-label="Filter by family"
              className={selectClass}
              value={family}
              onChange={(event) => {
                setFamily(event.target.value);
                resetPaging();
              }}
            >
              <option value="">All families</option>
              {familyGroups.map(([category, rows]) => (
                <optgroup key={category} label={category}>
                  {rows.map((row) => (
                    <option key={row.family_id} value={row.family_id}>
                      {row.label}
                    </option>
                  ))}
                </optgroup>
              ))}
            </select>
            <select
              aria-label="Filter by review status"
              className={selectClass}
              value={status}
              onChange={(event) => {
                setStatus(event.target.value);
                resetPaging();
              }}
            >
              {STATUS_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        <section
          aria-label="Record a decision"
          className={cn(
            "border-b border-line bg-surfaceMuted px-4 py-3 sm:px-5",
            selectedItems.length === 0 && canDecide && "hidden",
          )}
        >
          {selectedItems.length > 0 ? (
            <p className="mb-2 text-xs font-semibold text-ink">
              {selectedItems.length} selected
            </p>
          ) : null}
          <DecisionForm
            items={selectedItems}
            canDecide={canDecide}
            onDone={() => setSelected(new Set())}
          />
        </section>

        <QueryState queries={queue} label="review queue">
          <div
            className="relative overflow-x-auto"
            tabIndex={0}
            role="region"
            aria-label="Review queue table"
          >
            <table
              aria-label="Mappings to review"
              className="w-full min-w-[760px] border-collapse text-left text-sm"
            >
              <thead className="border-b border-line text-xs text-muted">
                <tr>
                  <th
                    scope="col"
                    className={cn(STICKY_SELECT, ROW_BG, "px-4 py-2 sm:px-5")}
                  >
                    <input
                      type="checkbox"
                      aria-label="Select all mappings on this page"
                      checked={allOnPageSelected}
                      onChange={toggleAll}
                      disabled={items.length === 0}
                      className="h-4 w-4 accent-brand"
                    />
                  </th>
                  <th
                    scope="col"
                    className={cn(
                      STICKY_REQUIREMENT,
                      ROW_BG,
                      "px-2 py-2 font-medium",
                    )}
                  >
                    Requirement
                  </th>
                  <th scope="col" className="px-2 py-2 font-medium">
                    Safeguard
                  </th>
                  <th scope="col" className="px-2 py-2 font-medium">
                    Basis
                  </th>
                  <th scope="col" className="px-2 py-2 font-medium">
                    Source anchor
                  </th>
                  <th scope="col" className="px-2 py-2 font-medium">
                    Status
                  </th>
                  <th scope="col" className="px-4 py-2 sm:px-5">
                    <span className="sr-only">History</span>
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {items.map((item) => {
                  const key = mappingKey(item);
                  const rowBg = selected.has(key) ? SELECTED_BG : ROW_BG;
                  return (
                    <tr
                      key={key}
                      data-mapping={key}
                      className={cn("align-top", rowBg)}
                    >
                      <td
                        className={cn(
                          STICKY_SELECT,
                          rowBg,
                          "px-4 py-3 sm:px-5",
                        )}
                      >
                        <input
                          type="checkbox"
                          aria-label={`Select ${item.safeguard_id} ${item.control_id}`}
                          checked={selected.has(key)}
                          onChange={() => toggle(key)}
                          className="h-4 w-4 accent-brand"
                        />
                      </td>
                      <td
                        className={cn(
                          STICKY_REQUIREMENT,
                          rowBg,
                          "w-[11rem] min-w-[11rem] max-w-[18rem] px-2 py-3 sm:w-auto",
                        )}
                      >
                        <div className="font-semibold text-ink">
                          {item.control_id}
                        </div>
                        <div className="line-clamp-2 text-xs text-muted">
                          {item.control_title ?? "—"}
                        </div>
                        <div className="mt-0.5 text-xs text-muted">
                          {frameworkNames[item.framework_id] ??
                            item.framework_id}
                        </div>
                      </td>
                      <td className="max-w-[16rem] px-2 py-3">
                        <div className="font-medium text-ink">
                          {item.safeguard_id}
                        </div>
                        <div className="line-clamp-2 text-xs text-muted">
                          {item.safeguard_title}
                        </div>
                      </td>
                      <td className="px-2 py-3 text-xs text-ink">
                        {basisLabel(item)}
                        {item.role === "primary" ? (
                          <div className="text-muted">Primary</div>
                        ) : null}
                      </td>
                      <td className="max-w-[14rem] px-2 py-3 text-xs">
                        <SourceAnchor item={item} />
                      </td>
                      <td className="px-2 py-3">
                        <Badge tone={STATE_TONE[item.review_state]}>
                          {MAPPING_REVIEW_GLOSSARY[item.review_state].label}
                        </Badge>
                        {item.latest_decision ? (
                          <div className="mt-1 text-xs text-muted">
                            {item.latest_decision.reviewer}
                          </div>
                        ) : null}
                      </td>
                      <td className="px-4 py-3 text-right sm:px-5">
                        <Button
                          variant="ghost"
                          size="sm"
                          aria-label={`History for ${item.safeguard_id} ${item.control_id}`}
                          onClick={() => setHistoryItem(item)}
                        >
                          <History className="h-3.5 w-3.5" aria-hidden="true" />
                          {item.decision_count ? item.decision_count : null}
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {items.length === 0 && !queue.isPending ? (
              <p className="m-5 rounded-lg border border-dashed border-line p-6 text-center text-sm text-muted">
                Nothing matches these filters.{" "}
                {status === "pending"
                  ? "Every mapping in scope has a decision."
                  : "Try another status or framework."}
              </p>
            ) : null}
          </div>
        </QueryState>

        {count > PAGE_SIZE ? (
          <div className="flex items-center justify-end gap-2 border-t border-line px-4 py-2 sm:px-5">
            <Button
              size="sm"
              disabled={offset === 0}
              onClick={() => {
                setOffset(Math.max(0, offset - PAGE_SIZE));
                setSelected(new Set());
              }}
            >
              Previous
            </Button>
            <Button
              size="sm"
              disabled={offset + PAGE_SIZE >= count}
              onClick={() => {
                setOffset(offset + PAGE_SIZE);
                setSelected(new Set());
              }}
            >
              Next
            </Button>
          </div>
        ) : null}
      </section>

      <HistoryDrawer
        item={historyItem}
        canDecide={canDecide}
        onClose={() => setHistoryItem(null)}
      />
    </div>
  );
}

export default function MappingReviewPage() {
  return (
    <Suspense
      fallback={
        <div className="px-4 py-5 text-sm text-muted">
          Loading mapping review…
        </div>
      }
    >
      <MappingReviewContent />
    </Suspense>
  );
}

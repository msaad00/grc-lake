"use client";

import { useState } from "react";
import { Activity, ChevronDown, ChevronRight } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { QueryState } from "@/components/QueryState";
import { useAuditLog } from "@/lib/api/hooks";
import type { AuditLogEntry } from "@/lib/api/types";
import { formatDateTime, plural } from "@/lib/format";
import { ROUTE_LABELS } from "@/lib/console-copy";
import { displayLabel } from "@/lib/display";

const PAGE_LIMIT = 200;

type Category = AuditLogEntry["category"];

const CATEGORIES: Array<Category | "all"> = [
  "all",
  "triage",
  "connector",
  "snapshot",
  "workflow",
  "trust_share",
  "request",
];

const CATEGORY_LABEL: Record<Category | "all", string> = {
  all: "All",
  triage: "Triage",
  connector: "Connectors",
  snapshot: "Snapshots",
  workflow: "Workflows",
  trust_share: "Trust shares",
  request: "API requests",
};

const CATEGORY_BADGE: Record<Category, string> = {
  triage: "Triage",
  connector: "Connector",
  snapshot: "Snapshot",
  workflow: "Workflow",
  trust_share: "Trust share",
  request: "API request",
};

const CATEGORY_TONE: Record<
  Category,
  "info" | "ready" | "attention" | "critical" | "default"
> = {
  triage: "attention",
  connector: "info",
  snapshot: "ready",
  workflow: "ready",
  trust_share: "critical",
  request: "default",
};

function Row({ entry }: { entry: AuditLogEntry }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-xl border border-line bg-surface">
      <button
        type="button"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className="grid w-full grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3 p-3 text-left"
      >
        {open ? (
          <ChevronDown className="h-4 w-4 text-muted" />
        ) : (
          <ChevronRight className="h-4 w-4 text-muted" />
        )}
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={CATEGORY_TONE[entry.category]}>
              {CATEGORY_BADGE[entry.category] ?? entry.category}
            </Badge>
            <span className="min-w-0 font-semibold text-ink [overflow-wrap:anywhere]">
              {entry.summary}
            </span>
          </div>
          <div className="mt-1 text-xs text-muted [overflow-wrap:anywhere]">
            <time dateTime={entry.occurred_at}>
              {formatDateTime(entry.occurred_at)}
            </time>{" "}
            · by <b className="text-ink">{entry.actor}</b> · on{" "}
            <code className="text-ink">{entry.subject}</code>
          </div>
          <div className="mt-0.5 text-[10px] text-muted">
            Event <code className="break-all">{entry.event_id}</code>
          </div>
        </div>
        {entry.result && <Badge>{displayLabel(entry.result)}</Badge>}
      </button>
      {open && (
        <div className="border-t border-line bg-surfaceMuted/40 p-3">
          <pre className="overflow-auto rounded bg-surface p-3 font-mono text-[11px] text-ink">
            {JSON.stringify(entry.payload, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

export default function AuditLogPage() {
  const [category, setCategory] = useState<(typeof CATEGORIES)[number]>("all");
  const log = useAuditLog({
    category: category === "all" ? undefined : category,
    limit: PAGE_LIMIT,
  });
  // Chip counts come from the unfiltered stream so switching categories does
  // not zero the others out.
  const all = useAuditLog({ limit: PAGE_LIMIT });

  const entries = log.data ?? [];
  const allEntries = all.data ?? [];
  const totals = allEntries.reduce<Record<string, number>>((acc, e) => {
    acc[e.category] = (acc[e.category] ?? 0) + 1;
    return acc;
  }, {});
  const truncated = entries.length >= PAGE_LIMIT;

  return (
    <div className="page-shell grid gap-5">
      <PageHeader
        title={ROUTE_LABELS["/audit-log"]}
        description="Every posture-changing event in one stream: triage decisions, connector setup and tests, snapshots, workflow runs, and trust-share links. Entries are append-only and cannot be edited."
        actions={
          <Badge tone="info">
            <Activity className="mr-1 h-3 w-3" />{" "}
            {plural(entries.length, "entry", "entries")}
          </Badge>
        }
      />

      <Card className="overflow-hidden">
        <div
          role="group"
          aria-label="Filter by category"
          className="flex flex-wrap items-center gap-2 p-3"
        >
          {CATEGORIES.map((c) => (
            <button
              key={c}
              type="button"
              aria-pressed={category === c}
              onClick={() => setCategory(c)}
              className={[
                "rounded-full border px-3 py-1.5 text-xs font-semibold",
                category === c
                  ? "border-ink bg-ink text-surface"
                  : "border-line bg-surface text-muted hover:border-brand",
              ].join(" ")}
            >
              {CATEGORY_LABEL[c]} (
              {c === "all" ? allEntries.length : (totals[c] ?? 0)})
            </button>
          ))}
        </div>
      </Card>

      <QueryState queries={log} label="audit log">
        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle>{plural(entries.length, "event")}</CardTitle>
            <CardDescription>
              Newest first
              {truncated ? `, latest ${PAGE_LIMIT} shown` : ""}. Click any row
              to see its full record.
            </CardDescription>
          </CardHeader>
          <div className="grid gap-2 p-5 pt-0">
            {entries.length === 0 && (
              <div className="rounded-lg border border-dashed border-line p-4 text-sm text-muted">
                No events in this category yet. Configure a connector, triage a
                violation, or run a workflow.
              </div>
            )}
            {entries.map((entry, index) => (
              <Row key={`${entry.event_id}-${index}`} entry={entry} />
            ))}
          </div>
        </Card>
      </QueryState>
    </div>
  );
}

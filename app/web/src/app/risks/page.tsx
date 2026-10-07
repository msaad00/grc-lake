"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { QueryState } from "@/components/QueryState";
import {
  useAuthWhoami,
  useCreateRiskMutation,
  useDeleteRiskMutation,
  useRisks,
  useUpdateRiskMutation,
} from "@/lib/api/hooks";
import type { Risk, RiskLevel, RiskStatus } from "@/lib/api/types";
import { ROUTE_LABELS } from "@/lib/console-copy";
import { formatDate as fmtDate } from "@/lib/format";
import { displayLabel } from "@/lib/display";

const inputClass =
  "rounded-lg border border-line bg-surface px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-brand";

const LEVELS: RiskLevel[] = ["low", "medium", "high", "critical"];

const LEVEL_TONE: Record<
  RiskLevel,
  "ready" | "info" | "attention" | "critical"
> = {
  low: "ready",
  medium: "info",
  high: "attention",
  critical: "critical",
};

const STATUS_TONE: Record<
  RiskStatus,
  "default" | "info" | "attention" | "ready"
> = {
  open: "attention",
  mitigating: "info",
  accepted: "ready",
  closed: "default",
};

// open → mitigating → accepted → closed. Each status advances to the next.
const NEXT_STATUS: Record<RiskStatus, RiskStatus | null> = {
  open: "mitigating",
  mitigating: "accepted",
  accepted: "closed",
  closed: null,
};

function CreateRiskForm() {
  const canWrite = useAuthWhoami().data?.scopes.includes("write") === true;
  const create = useCreateRiskMutation();
  const [title, setTitle] = useState("");
  const [category, setCategory] = useState("");
  const [owner, setOwner] = useState("");
  const [severity, setSeverity] = useState<RiskLevel>("medium");
  const [likelihood, setLikelihood] = useState<RiskLevel>("medium");
  const [impact, setImpact] = useState<RiskLevel>("medium");

  const submit = () => {
    if (!title.trim()) return;
    create.mutate(
      { title, category, owner, severity, likelihood, impact },
      {
        onSuccess: () => {
          setTitle("");
          setCategory("");
          setOwner("");
          setSeverity("medium");
          setLikelihood("medium");
          setImpact("medium");
        },
      },
    );
  };

  return (
    <div className="flex flex-wrap items-center gap-2 px-5 pb-4">
      <input
        className={`${inputClass} min-w-[220px] flex-1`}
        placeholder="Risk title"
        value={title}
        onChange={(e) => setTitle(e.target.value)}
      />
      <input
        className={`${inputClass} w-40`}
        placeholder="category"
        value={category}
        onChange={(e) => setCategory(e.target.value)}
      />
      <input
        className={`${inputClass} w-36`}
        placeholder="owner"
        value={owner}
        onChange={(e) => setOwner(e.target.value)}
      />
      <label className="flex items-center gap-1 text-[11px] font-semibold uppercase text-muted">
        sev
        <select
          aria-label="Risk severity"
          className={inputClass}
          value={severity}
          onChange={(e) => setSeverity(e.target.value as RiskLevel)}
        >
          {LEVELS.map((l) => (
            <option key={l} value={l}>
              {l}
            </option>
          ))}
        </select>
      </label>
      <label className="flex items-center gap-1 text-[11px] font-semibold uppercase text-muted">
        likely
        <select
          aria-label="Risk likelihood"
          className={inputClass}
          value={likelihood}
          onChange={(e) => setLikelihood(e.target.value as RiskLevel)}
        >
          {LEVELS.map((l) => (
            <option key={l} value={l}>
              {l}
            </option>
          ))}
        </select>
      </label>
      <label className="flex items-center gap-1 text-[11px] font-semibold uppercase text-muted">
        impact
        <select
          aria-label="Risk impact"
          className={inputClass}
          value={impact}
          onChange={(e) => setImpact(e.target.value as RiskLevel)}
        >
          {LEVELS.map((l) => (
            <option key={l} value={l}>
              {l}
            </option>
          ))}
        </select>
      </label>
      {!canWrite && (
        <p className="w-full text-sm text-muted">
          Your role can view risks. A contributor or administrator can change
          them.
        </p>
      )}
      {create.isError && (
        <p role="alert" className="w-full text-sm text-danger-fg">
          Risk could not be saved. Check your permission and try again.
        </p>
      )}
      <Button
        variant="primary"
        size="sm"
        onClick={submit}
        disabled={!canWrite || create.isPending || !title.trim()}
      >
        Add risk
      </Button>
    </div>
  );
}

function RiskRow({ risk }: { risk: Risk }) {
  const canWrite = useAuthWhoami().data?.scopes.includes("write") === true;
  const update = useUpdateRiskMutation();
  const del = useDeleteRiskMutation();
  const next = NEXT_STATUS[risk.status];

  return (
    <div className="flex flex-wrap items-center gap-3 px-5 py-3">
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-semibold text-ink">
          {risk.title}
        </div>
        <div className="text-[11px] text-muted">
          {risk.category || "uncategorized"} · {risk.owner || "unassigned"} ·
          due {fmtDate(risk.due_at)}
        </div>
      </div>
      <Badge tone={LEVEL_TONE[risk.severity]}>
        {displayLabel(risk.severity)} severity
      </Badge>
      <Badge tone={LEVEL_TONE[risk.likelihood]}>likely {risk.likelihood}</Badge>
      <Badge tone={LEVEL_TONE[risk.impact]}>impact {risk.impact}</Badge>
      <Badge tone={STATUS_TONE[risk.status]}>{displayLabel(risk.status)}</Badge>
      {(update.isError || del.isError) && (
        <p role="alert" className="text-sm text-danger-fg">
          Risk change failed. Refresh the record and check your permission.
        </p>
      )}
      <div className="flex gap-1.5">
        {next && (
          <Button
            size="sm"
            variant="ghost"
            disabled={!canWrite || update.isPending}
            onClick={() =>
              update.mutate({ id: risk.id, payload: { status: next } })
            }
          >
            → {next}
          </Button>
        )}
        {risk.status !== "closed" && (
          <Button
            size="sm"
            variant="ghost"
            disabled={!canWrite || update.isPending}
            onClick={() =>
              update.mutate({ id: risk.id, payload: { status: "closed" } })
            }
          >
            Close
          </Button>
        )}
        <Button
          size="sm"
          variant="ghost"
          disabled={!canWrite || del.isPending}
          onClick={() => {
            if (window.confirm(`Delete risk “${risk.title}”?`))
              del.mutate(risk.id);
          }}
        >
          Delete
        </Button>
      </div>
    </div>
  );
}

export default function RisksPage() {
  const risks = useRisks();
  const rows = risks.data ?? [];

  return (
    <div className="page-shell space-y-6">
      <PageHeader
        title={ROUTE_LABELS["/risks"]}
        description="Track identified risks scored by severity, likelihood, and impact. Assign an owner, link a mitigating control, and walk each risk through the open → mitigating → accepted → closed lifecycle."
      />
      <Card className="overflow-hidden">
        <CardHeader>
          <CardTitle>Risks</CardTitle>
          <CardDescription>
            The risk register is a load-bearing GRC pillar. Every entry is
            tenant-scoped and audit-logged.
          </CardDescription>
        </CardHeader>
        <CreateRiskForm />
        <QueryState queries={risks} label="risk register">
          <div className="divide-y divide-line border-t border-line">
            {rows.length === 0 ? (
              <div className="m-5 rounded-lg border border-dashed border-line p-6 text-center text-sm text-muted">
                No risks recorded yet. Add the first entry above to start the
                register.
              </div>
            ) : (
              rows.map((risk) => <RiskRow key={risk.id} risk={risk} />)
            )}
          </div>
        </QueryState>
      </Card>
    </div>
  );
}

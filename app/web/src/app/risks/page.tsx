"use client";

import { useState } from "react";
import { ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/empty-state";
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
  "w-full min-w-0 rounded-lg border border-line bg-surface px-3 py-2 text-sm font-normal text-ink focus:outline-none focus:ring-1 focus:ring-brand";
const fieldLabel = "grid min-w-0 gap-1 text-xs font-medium text-muted";

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

  const levelSelect = (
    label: string,
    value: RiskLevel,
    onChange: (next: RiskLevel) => void,
  ) => (
    <label className={fieldLabel}>
      {label}
      <select
        className={inputClass}
        value={value}
        onChange={(e) => onChange(e.target.value as RiskLevel)}
      >
        {LEVELS.map((l) => (
          <option key={l} value={l}>
            {displayLabel(l)}
          </option>
        ))}
      </select>
    </label>
  );

  return (
    <div className="grid gap-3 px-5 pb-4 sm:grid-cols-2 lg:grid-cols-[minmax(220px,2fr)_repeat(2,minmax(140px,1fr))_repeat(3,minmax(110px,0.8fr))_auto] lg:items-end">
      <label className={`${fieldLabel} sm:col-span-2 lg:col-span-1`}>
        Title
        <input
          className={inputClass}
          placeholder="e.g. Unreviewed vendor access"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
        />
      </label>
      <label className={fieldLabel}>
        Category
        <input
          className={inputClass}
          placeholder="e.g. Third party"
          value={category}
          onChange={(e) => setCategory(e.target.value)}
        />
      </label>
      <label className={fieldLabel}>
        Owner
        <input
          className={inputClass}
          placeholder="e.g. security-team"
          value={owner}
          onChange={(e) => setOwner(e.target.value)}
        />
      </label>
      {levelSelect("Severity", severity, setSeverity)}
      {levelSelect("Likelihood", likelihood, setLikelihood)}
      {levelSelect("Impact", impact, setImpact)}
      {!canWrite && (
        <p className="text-sm text-muted sm:col-span-2 lg:col-span-full">
          Your role can view risks. A contributor or administrator can change
          them.
        </p>
      )}
      {create.isError && (
        <p
          role="alert"
          className="text-sm text-danger-fg sm:col-span-2 lg:col-span-full"
        >
          Risk could not be saved. Check your permission and try again.
        </p>
      )}
      <Button
        variant="primary"
        onClick={submit}
        className="justify-self-start lg:row-start-1 lg:col-start-7"
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
          {risk.category || "Uncategorized"} · {risk.owner || "Unassigned"} ·
          due {fmtDate(risk.due_at)}
        </div>
      </div>
      <Badge tone={LEVEL_TONE[risk.severity]}>
        {displayLabel(risk.severity)} severity
      </Badge>
      <Badge tone={LEVEL_TONE[risk.likelihood]}>
        {displayLabel(risk.likelihood)} likelihood
      </Badge>
      <Badge tone={LEVEL_TONE[risk.impact]}>
        {displayLabel(risk.impact)} impact
      </Badge>
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
            Move to {displayLabel(next).toLowerCase()}
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
            Record a risk, score it, and assign an owner. Entries stay in this
            workspace and every change is audit-logged.
          </CardDescription>
        </CardHeader>
        <CreateRiskForm />
        <QueryState queries={risks} label="risk register">
          <div className="divide-y divide-line border-t border-line">
            {rows.length === 0 ? (
              <EmptyState icon={ShieldAlert} className="m-5">
                No risks recorded yet. Add the first entry above to start the
                register.
              </EmptyState>
            ) : (
              rows.map((risk) => <RiskRow key={risk.id} risk={risk} />)
            )}
          </div>
        </QueryState>
      </Card>
    </div>
  );
}

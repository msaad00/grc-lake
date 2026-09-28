"use client";

import { useMemo, useState } from "react";
import { Cpu, GitFork, GripVertical, Search, Shield, Zap } from "lucide-react";
import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { ActionSpec } from "@/lib/api/types";

interface Props {
  catalog: ActionSpec[];
  onAdd: (spec: ActionSpec) => void;
}

const KIND_ORDER: ActionSpec["kind"][] = ["trigger", "check", "gate", "action"];

const KIND_META: Record<
  ActionSpec["kind"],
  {
    label: string;
    Icon: React.ElementType;
    iconBg: string;
    iconFg: string;
    pillBg: string;
    pillFg: string;
    borderHover: string;
  }
> = {
  trigger: {
    label: "Triggers",
    Icon: Zap,
    iconBg: "bg-info-bg",
    iconFg: "text-brand",
    pillBg: "bg-info-bg",
    pillFg: "text-brand",
    borderHover: "hover:border-info",
  },
  check: {
    label: "Checks",
    Icon: GitFork,
    iconBg: "bg-warning-bg",
    iconFg: "text-warning-fg",
    pillBg: "bg-warning-bg",
    pillFg: "text-warning-fg",
    borderHover: "hover:border-warning",
  },
  gate: {
    label: "Gates",
    Icon: Shield,
    iconBg: "bg-info-bg",
    iconFg: "text-brand",
    pillBg: "bg-info-bg",
    pillFg: "text-brand",
    borderHover: "hover:border-info",
  },
  action: {
    label: "Actions",
    Icon: Cpu,
    iconBg: "bg-success-bg",
    iconFg: "text-success-fg",
    pillBg: "bg-success-bg",
    pillFg: "text-success-fg",
    borderHover: "hover:border-success",
  },
};

export function ActionPalette({ catalog, onAdd }: Props) {
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    if (!query.trim()) return catalog;
    const lower = query.toLowerCase();
    return catalog.filter((a) =>
      `${a.label} ${a.description} ${a.node_type}`
        .toLowerCase()
        .includes(lower),
    );
  }, [catalog, query]);

  const byKind = (kind: ActionSpec["kind"]) =>
    filtered.filter((a) => a.kind === kind);

  const hasResults = KIND_ORDER.some((k) => byKind(k).length > 0);

  return (
    <Card className="flex max-h-[min(760px,calc(100dvh-245px))] min-h-[560px] flex-col overflow-hidden">
      <CardHeader className="shrink-0">
        <CardTitle>Action library</CardTitle>
        <CardDescription>
          Drag onto canvas, or click to add at center.
        </CardDescription>
      </CardHeader>

      <div className="shrink-0 px-5 pb-3">
        <div className="relative">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search actions..."
            aria-label="Search action library"
            className="w-full rounded-lg border border-line bg-surface py-2 pl-9 pr-3 text-xs focus:outline-none focus:ring-1 focus:ring-brand"
          />
        </div>
      </div>

      <div className="flex-1 overflow-y-auto px-5 pb-5">
        {!hasResults ? (
          <div className="rounded-lg border border-dashed border-line p-4 text-center text-xs text-muted">
            No actions match &quot;{query}&quot;
          </div>
        ) : (
          <div className="grid gap-5">
            {KIND_ORDER.map((kind) => {
              const items = byKind(kind);
              if (items.length === 0) return null;
              const meta = KIND_META[kind];
              const Icon = meta.Icon;
              return (
                <section key={kind} aria-label={meta.label}>
                  <div className="mb-2 flex items-center gap-1.5">
                    <span
                      className={cn(
                        "grid h-4 w-4 place-items-center rounded",
                        meta.pillBg,
                      )}
                    >
                      <Icon className={cn("h-2.5 w-2.5", meta.pillFg)} />
                    </span>
                    <span className="text-[11px] font-semibold uppercase tracking-widest text-muted">
                      {meta.label}
                    </span>
                    <span className="ml-auto text-[10px] text-muted">
                      {items.length}
                    </span>
                  </div>

                  <div className="grid gap-1.5">
                    {items.map((action) => (
                      <button
                        key={action.node_type}
                        type="button"
                        draggable
                        aria-label={`Add ${action.label}`}
                        onDragStart={(e) => {
                          e.dataTransfer.setData(
                            "application/trustops-action",
                            JSON.stringify(action),
                          );
                          e.dataTransfer.effectAllowed = "move";
                        }}
                        onClick={() => onAdd(action)}
                        className={cn(
                          "grid cursor-grab grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-2.5 rounded-lg border border-line bg-surface px-3 py-2 text-left transition-colors hover:shadow-card active:cursor-grabbing",
                          meta.borderHover,
                        )}
                      >
                        <span
                          className={cn(
                            "mt-0.5 grid h-7 w-7 place-items-center rounded-md",
                            meta.iconBg,
                          )}
                        >
                          <Icon className={cn("h-3.5 w-3.5", meta.iconFg)} />
                        </span>
                        <span className="min-w-0">
                          <span className="block truncate text-xs font-semibold text-ink">
                            {action.label}
                          </span>
                          <span className="mt-0.5 block truncate text-[11px] text-muted">
                            {action.description}
                          </span>
                        </span>
                        <GripVertical className="mt-0.5 h-4 w-4 text-muted opacity-40" />
                      </button>
                    ))}
                  </div>
                </section>
              );
            })}
          </div>
        )}
      </div>
    </Card>
  );
}

"use client";

import { useMemo } from "react";
import Link from "next/link";
import { ArrowRight } from "lucide-react";
import type { Violation } from "@/lib/api/types";
import { Badge } from "@/components/ui/badge";
import { CollapsibleCard } from "@/components/ui/collapsible-card";
import { useControls } from "@/lib/api/hooks";
import { assetLabel } from "@/lib/format";

const SEVERITY_TONE: Record<
  string,
  "critical" | "attention" | "info" | "default"
> = {
  critical: "critical",
  high: "attention",
  medium: "info",
  low: "default",
  info: "default",
};

export function FixNext({
  violations,
  embedded = false,
}: {
  violations: Violation[];
  embedded?: boolean;
}) {
  const controls = useControls();
  const titles = useMemo(
    () =>
      new Map(
        (controls.data ?? []).map((control) => [
          control.control_id,
          control.title,
        ]),
      ),
    [controls.data],
  );
  const top = [...violations]
    .sort((a, b) => b.severity_score - a.severity_score)
    .slice(0, 6);

  return (
    <CollapsibleCard
      embedded={embedded}
      storageKey="dashboard-priority-findings"
      defaultOpen
      title="Priority findings"
      description="Highest severity"
      contentClassName="p-0"
    >
      <div
        className="max-h-[360px] divide-y divide-line overflow-y-auto overscroll-contain"
        role="region"
        aria-label="Findings to triage"
        tabIndex={0}
      >
        {top.length === 0 && (
          <div className="px-5 py-6 text-sm text-muted">No open findings.</div>
        )}
        {top.map((v) => {
          const title = titles.get(v.control_id);
          // Show a named asset; hide a bare demo ID that would read as noise.
          const showAsset =
            Boolean(v.asset_name?.trim()) ||
            (Boolean(v.asset_id) && !v.asset_id.startsWith("golden:"));
          return (
            <Link
              key={v.violation_id}
              href={`/violations?id=${encodeURIComponent(v.violation_id)}`}
              className="flex items-center gap-3 px-5 py-3 transition-colors hover:bg-surfaceMuted"
            >
              <Badge tone={SEVERITY_TONE[v.severity] ?? "default"}>
                {v.severity}
              </Badge>
              <div className="min-w-0 flex-1">
                <div
                  className="line-clamp-2 text-sm font-black leading-5 text-ink"
                  title={title ?? v.control_id}
                >
                  {title ?? v.control_id}
                </div>
                {title ? (
                  <div className="mt-0.5 truncate font-mono text-[11px] text-muted">
                    {v.control_id}
                  </div>
                ) : null}
                <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted">
                  <span
                    className={`rounded px-1.5 py-0.5 font-semibold ${["prod", "production"].includes(v.environment?.toLowerCase()) ? "bg-amber-50 text-amber-800 dark:bg-amber-500/10 dark:text-amber-300" : "bg-surfaceMuted text-muted"}`}
                  >
                    {v.environment || "Environment unknown"}
                  </span>
                  <span>{v.source}</span>
                  <span className="truncate">
                    Owner: {v.asset_owner || "Unassigned"}
                  </span>
                </div>
                {showAsset ? (
                  <div
                    className="mt-1 truncate text-xs text-muted"
                    title={v.asset_id}
                  >
                    {assetLabel(v)}
                  </div>
                ) : null}
              </div>
              <ArrowRight className="h-4 w-4 shrink-0 text-muted" />
            </Link>
          );
        })}
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line px-5 py-3">
        <span className="text-xs text-muted">
          Highest risk first · {top.length} of {violations.length}
        </span>
        <Link
          href="/violations"
          className="text-sm font-semibold text-brand hover:underline"
        >
          Triage all findings →
        </Link>
      </div>
    </CollapsibleCard>
  );
}

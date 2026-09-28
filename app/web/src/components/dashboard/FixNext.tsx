"use client";

import { useMemo } from "react";
import Link from "next/link";
import type { Violation } from "@/lib/api/types";
import { Badge } from "@/components/ui/badge";
import { CollapsibleCard } from "@/components/ui/collapsible-card";
import { useControls } from "@/lib/api/hooks";
import { severityTone } from "@/lib/severity";
import { displayLabel } from "@/lib/display";

/** Fixed-length preview: rows never scroll or clip inside the card. */
const PREVIEW = 5;

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
    .slice(0, PREVIEW);

  return (
    <CollapsibleCard
      embedded={embedded}
      storageKey="dashboard-priority-findings"
      defaultOpen
      title="Priority findings"
      contentClassName="p-0"
    >
      <div role="region" aria-label="Findings to triage">
        <ul className="divide-y divide-line">
          {top.length === 0 && (
            <li className="px-5 py-6 text-sm text-muted">No open findings.</li>
          )}
          {top.map((v) => {
            const title = titles.get(v.control_id);
            return (
              <li key={v.violation_id}>
                <Link
                  href={`/violations?id=${encodeURIComponent(v.violation_id)}`}
                  className="grid grid-cols-[4.75rem_minmax(0,1fr)] items-start gap-3 px-4 py-3 transition-colors hover:bg-surfaceMuted focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-brand sm:px-5"
                >
                  <Badge
                    tone={severityTone(v.severity)}
                    className="justify-center capitalize"
                  >
                    {displayLabel(v.severity)}
                  </Badge>
                  <span className="min-w-0">
                    <span
                      className="block truncate text-sm font-medium text-ink"
                      title={title ?? v.control_id}
                    >
                      {title ?? v.control_id}
                    </span>
                    {title ? (
                      <span className="mt-0.5 block truncate font-mono text-[11px] text-muted">
                        {v.control_id}
                      </span>
                    ) : null}
                  </span>
                </Link>
              </li>
            );
          })}
        </ul>
      </div>
      <div className="flex items-center justify-end border-t border-line px-4 py-2.5 sm:px-5">
        <Link href="/violations" className="ui-link text-sm">
          View all findings →
        </Link>
      </div>
    </CollapsibleCard>
  );
}

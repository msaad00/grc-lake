"use client";

import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export type KpiTone = "default" | "critical" | "attention" | "ready" | "brand";

const TONE_VALUE: Record<KpiTone, string> = {
  default: "text-ink",
  critical: "text-rose-700 dark:text-rose-300",
  attention: "text-amber-800 dark:text-amber-300",
  ready: "text-emerald-700 dark:text-emerald-300",
  brand: "text-brand",
};

// Accents double as icon-chip fills behind white glyphs, so each clears 4.5:1.
const TONE_ACCENT: Record<KpiTone, string> = {
  default: "#64748b",
  critical: "#d92d20",
  attention: "#b54708",
  ready: "#067647",
  brand: "#3b5bdb",
};

export function KpiTile({
  label,
  value,
  detail,
  tone = "default",
  icon,
  className,
}: {
  label: string;
  value: string | number;
  detail?: string;
  tone?: KpiTone;
  icon?: ReactNode;
  delay?: number;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "relative min-w-0 overflow-hidden rounded-lg border border-line bg-surface px-3 py-2.5",
        className,
      )}
    >
      <div
        className="absolute inset-y-0 left-0 w-0.5"
        style={{ background: TONE_ACCENT[tone] }}
      />
      <div className="flex items-start justify-between gap-2 pl-1.5">
        <div className="min-w-0 flex-1">
          <div className="ui-label">{label}</div>
          <div className={cn("ui-kpi-value mt-0.5", TONE_VALUE[tone])}>
            {value}
          </div>
          {detail ? (
            <div className="mt-1 line-clamp-2 text-xs leading-4 text-muted">
              {detail}
            </div>
          ) : null}
        </div>
        {icon ? (
          <div
            className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-white"
            style={{ background: TONE_ACCENT[tone] }}
          >
            {icon}
          </div>
        ) : null}
      </div>
    </div>
  );
}

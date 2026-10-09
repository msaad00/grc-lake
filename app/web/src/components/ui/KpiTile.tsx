"use client";

import { cn } from "@/lib/utils";

export type KpiTone = "default" | "critical" | "attention" | "ready" | "brand";

// Only the number carries tone; the tile itself stays neutral.
const TONE_VALUE: Record<KpiTone, string> = {
  default: "text-ink",
  critical: "text-danger-fg",
  attention: "text-warning-fg",
  ready: "text-success-fg",
  brand: "text-ink",
};

export function KpiTile({
  label,
  value,
  detail,
  tone = "default",
  className,
}: {
  label: string;
  value: string | number;
  detail?: string;
  tone?: KpiTone;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "min-w-0 rounded-lg border border-line bg-surface px-4 py-3",
        className,
      )}
    >
      <div className="ui-label">{label}</div>
      <div className={cn("ui-kpi-value mt-1.5", TONE_VALUE[tone])}>{value}</div>
      {detail ? (
        <div className="mt-1.5 line-clamp-2 text-xs text-muted" title={detail}>
          {detail}
        </div>
      ) : null}
    </div>
  );
}

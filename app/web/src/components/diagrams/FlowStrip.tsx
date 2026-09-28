"use client";

import { ArrowRight } from "lucide-react";
import { cn } from "@/lib/utils";

export interface FlowStep {
  step: string;
  title: string;
  detail: string;
  tone?: "brand" | "lake" | "assess" | "share" | "neutral";
}

const TONE: Record<NonNullable<FlowStep["tone"]>, string> = {
  brand: "bg-brand/10 text-brand ring-brand/20",
  lake: "bg-info-bg text-info-fg ring-info/40",
  assess: "bg-warning-bg text-warning-fg ring-warning/40",
  share: "bg-info-bg text-info-fg ring-info/40",
  neutral: "bg-panel text-ink ring-line",
};

export function FlowStrip({
  steps,
  className,
}: {
  steps: FlowStep[];
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex min-w-0 flex-col gap-2 lg:flex-row lg:items-stretch",
        className,
      )}
    >
      {steps.map((item, index) => (
        <div
          key={item.step}
          className="flex min-w-0 flex-1 items-stretch gap-2"
        >
          <div className="grid min-h-0 min-w-0 flex-1 grid-cols-[auto_minmax(0,1fr)] gap-3 overflow-hidden rounded-xl border border-line bg-surface p-3 shadow-card">
            <span
              className={cn(
                "grid h-9 w-9 shrink-0 place-items-center rounded-lg text-[10px] font-semibold ring-1",
                TONE[item.tone ?? "neutral"],
              )}
            >
              {item.step}
            </span>
            <span className="min-w-0 overflow-hidden">
              <span className="block line-clamp-2 text-sm font-semibold text-ink">
                {item.title}
              </span>
              <span className="mt-0.5 line-clamp-2 text-xs leading-5 text-muted">
                {item.detail}
              </span>
            </span>
          </div>
          {index < steps.length - 1 && (
            <ArrowRight
              className="hidden shrink-0 self-center text-muted lg:block lg:h-4 lg:w-4"
              aria-hidden
            />
          )}
        </div>
      ))}
    </div>
  );
}

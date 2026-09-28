"use client";

import { frameworkVisual } from "@/lib/framework-visuals";
import { FrameworkMark } from "@/components/framework/FrameworkMark";
import { cn } from "@/lib/utils";

interface FrameworkBadgeProps {
  frameworkId: string;
  fallbackLabel?: string;
  size?: number;
  className?: string;
  variant?: "default" | "compact" | "mark-only";
}

export function FrameworkBadge({
  frameworkId,
  fallbackLabel,
  size = 32,
  className,
  variant = "default",
}: FrameworkBadgeProps) {
  const visual = frameworkVisual(frameworkId, fallbackLabel);
  const markSize = variant === "compact" ? Math.max(28, size - 4) : size;
  const identityNote = `${visual.label} framework identity`;

  if (variant === "mark-only") {
    return (
      <FrameworkMark
        frameworkId={frameworkId}
        fallbackLabel={fallbackLabel}
        size={markSize}
        className={className}
      />
    );
  }

  return (
    <span
      className={cn(
        "inline-flex min-w-0 items-center gap-2.5 rounded-xl border border-line bg-surface px-2.5 py-1.5 text-left shadow-sm",
        variant === "compact" && "gap-2 rounded-lg px-2 py-1",
        className,
      )}
      role="img"
      aria-label={identityNote}
      title={identityNote}
    >
      <FrameworkMark
        frameworkId={frameworkId}
        fallbackLabel={fallbackLabel}
        size={markSize}
      />
      {variant !== "compact" && (
        <span className="min-w-0">
          <span className="block text-xs font-semibold leading-tight text-ink">
            {visual.label}
          </span>
        </span>
      )}
      {variant === "compact" && (
        <span className="text-xs font-semibold text-ink">{visual.label}</span>
      )}
    </span>
  );
}

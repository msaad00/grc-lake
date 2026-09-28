"use client";

import type { CSSProperties } from "react";
import { authVisual } from "@/lib/auth-visuals";

interface AuthMarkProps {
  providerKind?: string;
  methodId?: string;
  size?: "sm" | "md" | "lg";
  showProtocol?: boolean;
  providerLabel?: string;
  className?: string;
}

const SIZE: Record<
  NonNullable<AuthMarkProps["size"]>,
  { box: number; mark: string }
> = {
  sm: { box: 32, mark: "text-[9px]" },
  md: { box: 40, mark: "text-[10px]" },
  lg: { box: 48, mark: "text-[11px]" },
};

export function AuthMark({
  providerKind,
  methodId,
  size = "md",
  showProtocol = false,
  providerLabel,
  className,
}: AuthMarkProps) {
  const visual = authVisual(providerKind, methodId);
  const dim = SIZE[size];
  const boxStyle: CSSProperties = {
    width: dim.box,
    height: dim.box,
    color: visual.accent,
    background: visual.bg,
  };

  return (
    <span
      className={["inline-flex min-w-0 items-center gap-2", className]
        .filter(Boolean)
        .join(" ")}
      role="img"
      aria-label={`${providerLabel ?? visual.protocol} identity mark; not an official logo`}
      title={`${providerLabel ?? visual.protocol} — neutral identity mark`}
    >
      <span
        className={[
          "grid shrink-0 place-items-center rounded-lg font-semibold tracking-wide ring-1 ring-line",
          dim.mark,
        ].join(" ")}
        style={boxStyle}
      >
        {visual.mark}
      </span>
      {showProtocol && (
        <span className="min-w-0 truncate text-[10px] font-semibold text-muted">
          {visual.protocol}
          {providerLabel ? ` · ${providerLabel}` : ""}
        </span>
      )}
    </span>
  );
}

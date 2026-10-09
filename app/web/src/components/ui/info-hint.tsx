"use client";

import * as Tooltip from "@radix-ui/react-tooltip";
import { Info } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

/**
 * A small "i" button that explains a metric. It is a real button so keyboard
 * and touch users reach it, and its accessible name carries the full text.
 * Place it outside any link or other interactive element.
 */
export function InfoHint({
  label,
  text,
  children,
  className,
}: {
  /** The metric being explained, e.g. "Assessment score". */
  label: string;
  /** Plain-text explanation; also the accessible name. */
  text: string;
  /** Optional richer tooltip body; defaults to `text`. */
  children?: ReactNode;
  className?: string;
}) {
  return (
    <Tooltip.Provider delayDuration={150}>
      <Tooltip.Root>
        <Tooltip.Trigger asChild>
          <button
            type="button"
            aria-label={`About ${label}: ${text}`}
            onClick={(event) => event.stopPropagation()}
            className={cn(
              "inline-grid h-5 w-5 shrink-0 place-items-center rounded-full text-muted hover:text-ink focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-brand",
              className,
            )}
          >
            <Info aria-hidden="true" className="h-3.5 w-3.5" />
          </button>
        </Tooltip.Trigger>
        <Tooltip.Portal>
          <Tooltip.Content
            side="top"
            sideOffset={6}
            className="z-[80] max-w-[300px] rounded-md border border-line bg-surface px-3 py-2 text-xs leading-5 text-ink shadow-card"
          >
            {children ?? text}
          </Tooltip.Content>
        </Tooltip.Portal>
      </Tooltip.Root>
    </Tooltip.Provider>
  );
}

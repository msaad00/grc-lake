"use client";

import * as Tooltip from "@radix-ui/react-tooltip";
import { PREVIEW_COPY } from "@/lib/console-copy";
import { cn } from "@/lib/utils";

/**
 * "Preview" release-stage badge. It is a real button so keyboard and touch
 * users can reach the explanation; hovering or focusing it opens the tooltip.
 * Place it outside any other interactive element.
 */
export function PreviewBadge({ className }: { className?: string }) {
  return (
    <Tooltip.Provider delayDuration={150}>
      <Tooltip.Root>
        <Tooltip.Trigger asChild>
          <button
            type="button"
            aria-label={`${PREVIEW_COPY.label}: ${PREVIEW_COPY.definition}`}
            onClick={(event) => event.stopPropagation()}
            className={cn(
              "inline-flex items-center rounded-full bg-transparent px-2 py-0.5 text-xs font-medium leading-4 text-muted ring-1 ring-inset ring-line-strong/60 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand",
              className,
            )}
          >
            {PREVIEW_COPY.label}
          </button>
        </Tooltip.Trigger>
        <Tooltip.Portal>
          <Tooltip.Content
            side="top"
            sideOffset={6}
            className="z-[80] max-w-[260px] rounded-md border border-line bg-surface px-3 py-2 text-xs text-ink shadow-card"
          >
            {PREVIEW_COPY.definition}
          </Tooltip.Content>
        </Tooltip.Portal>
      </Tooltip.Root>
    </Tooltip.Provider>
  );
}

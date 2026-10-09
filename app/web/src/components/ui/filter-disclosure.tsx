"use client";

import { useId, useState, type ReactNode } from "react";
import { ChevronDown, SlidersHorizontal, type LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * Below `sm`, folds a page's filter bands behind one "Filters" toggle so the
 * data is the first thing on a phone. From `sm` up the wrapper is
 * `display: contents`: the bands sit in the page grid exactly as before.
 */
export function FilterDisclosure({
  children,
  activeCount = 0,
  label = "Filters",
  icon: Icon = SlidersHorizontal,
  open: openProp,
  onOpenChange,
  className,
}: {
  children: ReactNode;
  /** Filters currently narrowing the view; shown on the collapsed toggle. */
  activeCount?: number;
  label?: string;
  icon?: LucideIcon;
  /** Controlled mode, for pages with filters outside the panel. */
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  /** Layout for the open panel on phones; match the page's own grid gap. */
  className?: string;
}) {
  const [localOpen, setLocalOpen] = useState(false);
  const open = openProp ?? localOpen;
  const setOpen = onOpenChange ?? setLocalOpen;
  const panelId = useId();
  return (
    <>
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen(!open)}
        className="flex h-10 w-full items-center gap-2 rounded-lg border border-line bg-surface px-3 text-sm font-semibold text-ink focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand sm:hidden"
      >
        <Icon aria-hidden="true" className="h-4 w-4 text-muted" />
        {label}
        {activeCount > 0 ? (
          <span className="rounded-full bg-info-bg px-2 py-0.5 text-xs font-semibold text-info-fg">
            {activeCount} active
          </span>
        ) : null}
        <ChevronDown
          aria-hidden="true"
          className={cn(
            "ml-auto h-4 w-4 text-muted transition-transform",
            open && "rotate-180",
          )}
        />
      </button>
      <div
        id={panelId}
        className={cn(open ? "grid" : "hidden", "gap-3 sm:contents", className)}
      >
        {children}
      </div>
    </>
  );
}

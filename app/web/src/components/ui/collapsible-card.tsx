"use client";

import { useState, type ReactNode } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { Card } from "./card";
import { usePersistentState } from "@/lib/state/preferences";
import { cn } from "@/lib/utils";

interface Props {
  title: ReactNode;
  embedded?: boolean;
  description?: ReactNode;
  actions?: ReactNode;
  /**
   * Stable identifier used to persist open/closed state across reloads.
   * Pages should pass a deterministic key per section.
   */
  storageKey?: string;
  defaultOpen?: boolean;
  children: ReactNode;
  className?: string;
  contentClassName?: string;
}

export function CollapsibleCard({
  title,
  embedded = false,
  description,
  actions,
  storageKey,
  defaultOpen = true,
  children,
  className,
  contentClassName,
}: Props) {
  const [localOpen, setLocalOpen] = useState(defaultOpen);
  const [persistedOpen, setPersistedOpen] = usePersistentState(
    storageKey ? `trustops:section:${storageKey}` : "trustops:section:_unused",
    defaultOpen,
  );
  const open = storageKey ? persistedOpen : localOpen;
  const setOpen = storageKey ? setPersistedOpen : setLocalOpen;

  if (embedded) {
    return (
      <div className="min-w-0">
        {actions && <div className="flex justify-end px-4 pt-3">{actions}</div>}
        <div className={cn("p-3", contentClassName)}>{children}</div>
      </div>
    );
  }

  return (
    <Card className={cn("overflow-hidden", className)}>
      <div className="flex w-full items-start justify-between gap-2 px-4 py-3">
        <button
          type="button"
          onClick={() => setOpen(!open)}
          aria-expanded={open}
          className="flex min-w-0 flex-1 items-start gap-2 rounded-sm text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand"
        >
          {open ? (
            <ChevronDown className="mt-0.5 h-4 w-4 shrink-0 text-muted" />
          ) : (
            <ChevronRight className="mt-0.5 h-4 w-4 shrink-0 text-muted" />
          )}
          <span className="grid min-w-0 gap-0.5">
            <span className="ui-section-title block">{title}</span>
            {description && (
              <span className="block text-xs leading-5 text-muted">
                {description}
              </span>
            )}
          </span>
        </button>
        {actions && (
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            {actions}
          </div>
        )}
      </div>
      {open && (
        <div className={cn("border-t border-line p-4", contentClassName)}>
          {children}
        </div>
      )}
    </Card>
  );
}

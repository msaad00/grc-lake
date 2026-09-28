"use client";

import { useMemo } from "react";
import Link from "next/link";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { Bell } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { useAuditLog } from "@/lib/api/hooks";
import { usePersistentState } from "@/lib/state/preferences";
import type { AuditLogEntry } from "@/lib/api/types";
import { CONNECT_FLOW } from "@/lib/console-copy";
import { displayLabel } from "@/lib/display";

const CATEGORY_TONE: Record<
  AuditLogEntry["category"],
  "info" | "ready" | "attention" | "critical" | "default"
> = {
  triage: "attention",
  connector: "info",
  snapshot: "ready",
  workflow: "ready",
  trust_share: "critical",
  mapping_review: "attention",
  request: "default",
};

export function NotificationBell() {
  const log = useAuditLog({ limit: 8 });
  const [seenAt, setSeenAt] = usePersistentState<string>(
    "trustops:audit-log:seen-at",
    "",
  );

  const entries = useMemo(() => log.data ?? [], [log.data]);
  const unread = useMemo(
    () =>
      entries.filter(
        (e) => !seenAt || (e.occurred_at && e.occurred_at > seenAt),
      ).length,
    [entries, seenAt],
  );

  const markSeen = () => {
    if (entries[0]?.occurred_at) setSeenAt(entries[0].occurred_at);
  };

  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button
          type="button"
          aria-label="Notifications"
          className="relative inline-flex h-8 w-8 items-center justify-center rounded-md text-muted hover:bg-rail-hover hover:text-ink focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand"
        >
          <Bell className="h-4 w-4" />
          {unread > 0 && (
            <span className="absolute -right-1 -top-1 grid h-4 min-w-[16px] place-items-center rounded-full bg-danger-bg px-1 text-[10px] font-semibold text-danger-fg">
              {unread > 9 ? "9+" : unread}
            </span>
          )}
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          align="end"
          sideOffset={6}
          onCloseAutoFocus={markSeen}
          className="z-[60] grid min-w-[360px] max-w-[480px] gap-0.5 rounded-xl border border-line bg-surface p-1.5 shadow-hero"
        >
          <DropdownMenu.Label className="flex items-center justify-between gap-2 px-2 py-2 text-[11px] font-semibold uppercase tracking-wider text-muted">
            <span>Audit activity</span>
            <Link
              href="/audit-log"
              className="text-[11px] font-semibold uppercase tracking-wider text-brand hover:underline"
            >
              View all →
            </Link>
          </DropdownMenu.Label>
          {entries.length === 0 && (
            <div className="px-3 py-6 text-center text-xs text-muted">
              No activity yet. {CONNECT_FLOW.emptyActivity}
            </div>
          )}
          {entries.map((entry) => (
            <DropdownMenu.Item
              key={entry.occurred_at + entry.subject + entry.category}
              asChild
            >
              <Link
                href="/audit-log"
                className="grid cursor-pointer grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-2 rounded-md px-2 py-2 text-xs outline-none data-[highlighted]:bg-surfaceMuted"
              >
                <Badge tone={CATEGORY_TONE[entry.category]}>
                  {displayLabel(entry.category)}
                </Badge>
                <span className="min-w-0">
                  <span className="block truncate text-ink">
                    {entry.summary}
                  </span>
                  <span className="block truncate text-[10px] text-muted">
                    {entry.actor} · {entry.occurred_at}
                  </span>
                </span>
                {entry.result && <Badge>{displayLabel(entry.result)}</Badge>}
              </Link>
            </DropdownMenu.Item>
          ))}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

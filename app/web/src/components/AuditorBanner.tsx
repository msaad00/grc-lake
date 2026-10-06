"use client";

import { ShieldCheck } from "lucide-react";
import { useAuditorMode } from "@/lib/state/auditor";

export function AuditorBanner() {
  const auditor = useAuditorMode();
  if (!auditor) return null;
  return (
    <div className="flex min-w-0 flex-wrap items-center justify-between gap-3 border-b border-warning/40 bg-warning-bg px-4 py-2 text-sm text-warning-fg sm:px-5 lg:px-7">
      <span className="inline-flex items-center gap-2 font-semibold">
        <ShieldCheck className="h-4 w-4" />
        Auditor view — read-only. Owners, assignees, and remediation notes are
        redacted.
      </span>
      <a
        href="?role=default"
        className="rounded-md border border-warning/40 bg-surface px-2.5 py-1 text-xs font-semibold text-warning-fg hover:bg-warning-bg"
      >
        Exit auditor mode
      </a>
    </div>
  );
}

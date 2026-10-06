"use client";

import { useQueryClient } from "@tanstack/react-query";
import { useSyncExternalStore } from "react";
import { ApiError } from "@/lib/api/client";

/**
 * Surfaces a clear warning when one or more API queries have failed.
 *
 * Without this, list pages fall back to `?? []` on a failed fetch and render
 * their cheerful empty state ("No violations", "0 open"), so a down backend
 * looks like a clean compliance posture. This subscribes to the query cache and
 * tells the user the data is incomplete — not an all-clear.
 */
export function ApiHealthBanner() {
  const cache = useQueryClient().getQueryCache();
  const message = useSyncExternalStore(
    (onChange) => cache.subscribe(onChange),
    () => {
      const errors = cache
        .getAll()
        .filter(
          (q) =>
            q.state.status === "error" &&
            !/\b501\b/.test(String(q.state.error?.message ?? "")),
        )
        .map((q) => q.state.error);
      if (!errors.length) return "";
      const statuses = errors.map((error) =>
        error instanceof ApiError ? error.status : undefined,
      );
      if (statuses.includes(401))
        return "Your session has ended. Sign in again to restore access.";
      if (statuses.includes(403))
        return "Some data requires additional permission. Ask a workspace administrator for access.";
      if (statuses.includes(429))
        return "Too many requests. Some data is unavailable until the request limit resets.";
      if (
        statuses.every(
          (status) => status !== undefined && status >= 400 && status < 500,
        )
      )
        return "Some requests were rejected. Check the selected filters and request details.";
      return "Can't reach the assessment API — some data failed to load. What you see may be incomplete, not an all-clear. Check that the server is reachable and use Refresh to retry.";
    },
    () => "",
  );
  if (!message) return null;

  return (
    <div
      role="alert"
      className="mx-3 mt-2 rounded-lg border border-danger/40 bg-danger-bg px-3 py-2 text-sm font-semibold text-danger-fg sm:mx-4"
    >
      {message}
    </div>
  );
}

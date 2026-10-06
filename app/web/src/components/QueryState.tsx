import * as React from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { ApiError } from "@/lib/api/client";
import { Skeleton } from "@/components/ui/skeleton";
import { TrustOpsMark } from "@/components/brand/TrustOpsMark";

/**
 * Minimal shape of a TanStack query result this component depends on. Accepting
 * a structural type keeps it usable with any `useQuery` hook without importing
 * the full generic.
 */
export interface QueryLike {
  isError: boolean;
  error?: unknown;
  isPending: boolean;
  refetch: () => unknown;
}

function ErrorState({
  label,
  onRetry,
  error,
}: {
  label: string;
  onRetry: () => void;
  error?: unknown;
}) {
  const status = error instanceof ApiError ? error.status : undefined;
  const permission = status === 403;
  const message = permission
    ? `You do not have permission to view ${label}. Ask a workspace administrator for access.`
    : status === 401
      ? "Your session has ended. Sign in again to continue."
      : status === 429
        ? "Too many requests. Wait a moment, then retry."
        : `Couldn’t load ${label}. The API is unavailable or returned an error.`;
  return (
    <div
      role="alert"
      className="m-5 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-danger/40 bg-danger-bg px-4 py-3 text-sm text-danger-fg"
    >
      <span className="flex items-center gap-2">
        <AlertTriangle className="h-4 w-4 flex-none" />
        {message}
      </span>
      {!permission && (
        <button
          type="button"
          onClick={onRetry}
          className="inline-flex items-center gap-1.5 rounded-md border border-danger/40 bg-surface px-2.5 py-1 font-semibold text-danger-fg outline-none hover:bg-danger-bg focus-visible:ring-2 focus-visible:ring-danger"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Retry
        </button>
      )}
    </div>
  );
}

function DefaultSkeleton({ label }: { label: string }) {
  return (
    <div className="grid gap-3 p-5" role="status" aria-live="polite">
      <div className="flex items-center gap-3 rounded-xl border border-line bg-surface px-4 py-3 shadow-card">
        <TrustOpsMark size="sm" gradientId="trustops-query-state-gradient" />
        <div className="min-w-0">
          <p className="text-sm font-semibold text-ink">Loading {label}…</p>
          <p className="text-xs text-muted">
            Connecting to the security data lake and checking the latest trust
            state.
          </p>
        </div>
        <span className="ml-auto h-2 w-2 shrink-0 animate-pulse rounded-full bg-brand" />
      </div>
      <Skeleton className="h-24 w-full" />
      <Skeleton className="h-24 w-full" />
    </div>
  );
}

/**
 * Gate content on one or more queries. Renders a retryable error banner when
 * any query failed and a skeleton while any is still loading, so a failed fetch
 * never renders as zero-filled "everything is fine" UI. Queries with `retry`
 * disabled (the console default) surface the failure immediately.
 */
export function QueryState({
  queries,
  label = "data",
  skeleton,
  children,
}: {
  queries: QueryLike | QueryLike[];
  label?: string;
  skeleton?: React.ReactNode;
  children: React.ReactNode;
}) {
  const list = Array.isArray(queries) ? queries : [queries];
  if (list.some((q) => q.isError)) {
    return (
      <ErrorState
        label={label}
        error={list.find((q) => q.isError)?.error}
        onRetry={() => list.forEach((q) => q.refetch())}
      />
    );
  }
  if (list.some((q) => q.isPending)) {
    return <>{skeleton ?? <DefaultSkeleton label={label} />}</>;
  }
  return <>{children}</>;
}

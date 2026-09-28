"use client";

import { useEffect } from "react";
import { Camera, Menu, RefreshCw, Search } from "lucide-react";
import { TrustOpsLogo } from "@/components/brand/TrustOpsLogo";
import { NotificationBell } from "./NotificationBell";
import { UserMenu } from "./UserMenu";
import { useHealth } from "@/lib/api/hooks";

interface Props {
  onRefresh: () => void;
  onSnapshot: () => void;
  onOpenPalette: () => void;
  onOpenNav: () => void;
}

export function TopBar({
  onRefresh,
  onSnapshot,
  onOpenPalette,
  onOpenNav,
}: Props) {
  const { data, isError } = useHealth();
  const live = isError ? false : (data?.ok ?? null);
  const statusLabel =
    live === null
      ? "Connecting to API"
      : live
        ? "API connected"
        : "API unavailable";

  // cmd/ctrl + K opens the palette anywhere in the app.
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      const isPalette =
        (event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k";
      if (isPalette) {
        event.preventDefault();
        onOpenPalette();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onOpenPalette]);

  const actionClass =
    "inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-muted transition-colors hover:bg-rail-hover hover:text-ink focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand";

  return (
    <header className="sticky top-0 z-40 flex h-[var(--topbar-h)] min-w-0 items-center gap-3 border-b border-rail-line bg-rail px-3 text-ink sm:gap-5 sm:px-5">
      <button
        type="button"
        onClick={onOpenNav}
        aria-label="Open navigation"
        className={`${actionClass} -mr-1 md:hidden`}
      >
        <Menu aria-hidden="true" className="h-5 w-5" />
      </button>
      <TrustOpsLogo
        href="/dashboard"
        markSize="md"
        showWordmark
        wordmarkClassName="hidden lg:block"
        className="flex-none"
        gradientId="trustops-topbar-gradient"
      />
      <button
        type="button"
        onClick={onOpenPalette}
        aria-label="Open command palette"
        className="flex h-8 min-w-0 flex-1 items-center gap-2 rounded-md border border-line bg-surfaceMuted px-2.5 text-left text-xs text-muted transition-colors hover:border-line-strong focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand lg:max-w-[480px]"
      >
        <Search aria-hidden="true" className="h-3.5 w-3.5 shrink-0" />
        <span className="truncate sm:hidden">Search…</span>
        <span className="hidden flex-1 truncate sm:block">
          Search controls, findings, evidence…
        </span>
        <kbd className="ml-auto hidden rounded border border-line bg-surface px-1 py-0.5 text-[10px] leading-none text-muted md:block">
          ⌘ K
        </kbd>
      </button>
      <div className="ml-auto flex shrink-0 items-center gap-1 sm:gap-2">
        <span
          role="status"
          aria-label={statusLabel}
          title={statusLabel}
          className="mr-1 inline-flex items-center gap-1.5 text-[11px] text-muted sm:mr-2"
        >
          <span
            aria-hidden="true"
            className={`h-2 w-2 rounded-full ${live ? "bg-success" : "bg-warning"}`}
          />
          <span aria-hidden="true" className="hidden xl:inline">
            {statusLabel}
          </span>
        </span>
        <button
          type="button"
          onClick={onRefresh}
          aria-label="Refresh data"
          title="Refresh data"
          className={actionClass}
        >
          <RefreshCw aria-hidden="true" className="h-4 w-4" />
        </button>
        <div className="hidden sm:block">
          <NotificationBell />
        </div>
        <button
          type="button"
          onClick={onSnapshot}
          aria-label="Capture snapshot"
          title="Capture snapshot"
          className="inline-flex h-8 shrink-0 items-center justify-center gap-2 rounded-md border border-line bg-surface px-2 text-xs font-medium text-ink transition-colors hover:bg-surfaceMuted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand sm:px-3"
        >
          <Camera aria-hidden="true" className="h-4 w-4" />
          <span className="hidden md:inline">Snapshot</span>
        </button>
        <div className="ml-1 border-l border-rail-line pl-2 sm:ml-2 sm:pl-3">
          <UserMenu compact />
        </div>
      </div>
    </header>
  );
}

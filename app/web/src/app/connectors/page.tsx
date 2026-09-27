"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Search } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { QueryState } from "@/components/QueryState";
import { ConnectorDrawer } from "@/components/drawers/ConnectorDrawer";
import { ConnectorMark } from "@/components/connectors/ConnectorMark";
import { EvidencePathPanel } from "@/components/connectors/EvidencePathPanel";
import { OnboardingGuideBanner } from "@/components/onboarding/OnboardingGuideBanner";
import { connectorNotify } from "@/lib/connector-notify";
import { CONNECT_FLOW } from "@/lib/console-copy";
import { useConnectors } from "@/lib/api/hooks";
import type { ConnectorView } from "@/lib/api/types";

const isRunnableConnector = (connector: ConnectorView) =>
  Boolean(connector.is_implemented);

const PREVIEW_TITLE =
  "Implemented and fixture-tested; not yet verified against a live tenant.";

const toneForState = (state: string) =>
  state === "enabled" ? "ready" : "default";

type Health = {
  label: string;
  tone: "ready" | "attention" | "critical" | "default";
};

type ViewFilter = "all" | "connected" | "setup" | "attention";
type CategoryFilter = "all" | "cloud" | "identity" | "data" | "dev" | "ops";

const VIEW_TABS: Array<{ id: ViewFilter; label: string }> = [
  { id: "all", label: "All" },
  { id: "connected", label: "Connected" },
  { id: "setup", label: "Needs setup" },
  { id: "attention", label: "Needs attention" },
];

const CATEGORY_OPTIONS: Array<{ id: CategoryFilter; label: string }> = [
  { id: "all", label: "All categories" },
  { id: "cloud", label: "Cloud" },
  { id: "identity", label: "Identity" },
  { id: "data", label: "Data lakes" },
  { id: "dev", label: "Dev tools" },
  { id: "ops", label: "Ops" },
];

function connectorCategory(connector: ConnectorView): CategoryFilter {
  if (connector.category === "cloud") return "cloud";
  if (connector.category === "identity") return "identity";
  if (connector.category === "developer_platform") return "dev";
  if (
    connector.category === "analytics_lake" ||
    connector.category === "warehouse" ||
    connector.category === "evidence_store" ||
    connector.category === "starter_mode"
  ) {
    return "data";
  }
  return "ops";
}

function syncHealth(connector: ConnectorView): Health | null {
  if (connector.state !== "enabled") return null;

  const freshness = connector.freshness_state;
  if (freshness === "fresh") return { label: "healthy", tone: "ready" };
  if (freshness === "stale") return { label: "stale sync", tone: "attention" };
  if (freshness === "never_synced") {
    const failedAttempt =
      connector.last_sync?.result === "error" &&
      connector.last_successful_sync?.result === "ok";
    if (failedAttempt) {
      return { label: "last sync failed", tone: "attention" };
    }
    return { label: "never synced", tone: "attention" };
  }

  const successAt =
    connector.last_sync_at ??
    connector.last_successful_sync?.occurred_at ??
    (connector.last_sync?.result === "ok"
      ? connector.last_sync.occurred_at
      : null);
  if (!successAt) {
    if (connector.last_sync?.result === "error") {
      return { label: "last sync failed", tone: "attention" };
    }
    return { label: "never synced", tone: "attention" };
  }
  const ageMinutes = (Date.now() - Date.parse(successAt)) / 60000;
  const slo = connector.freshness_slo_minutes || 1440;
  if (ageMinutes <= slo) return { label: "healthy", tone: "ready" };
  if (ageMinutes <= slo * 3) return { label: "stale sync", tone: "attention" };
  return { label: "silent", tone: "critical" };
}

function needsAttention(connector: ConnectorView) {
  const health = syncHealth(connector);
  return (
    (health !== null && health.tone !== "ready") ||
    connector.last_probe?.result === "error" ||
    connector.last_sync?.result === "error"
  );
}

const toneForProbe = (result?: string) =>
  result === "ok"
    ? "ready"
    : result === "error"
      ? "critical"
      : result === "skipped"
        ? "attention"
        : "default";

function ConnectorRow({
  connector,
  onSelect,
}: {
  connector: ConnectorView;
  onSelect: () => void;
}) {
  const probe = connector.last_probe;
  const health = syncHealth(connector);
  const runnable = isRunnableConnector(connector);
  return (
    <button
      type="button"
      onClick={onSelect}
      className={`grid w-full min-w-0 grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3 overflow-hidden rounded-lg border bg-white p-3 text-left transition-colors hover:border-brand hover:shadow-card ${
        runnable
          ? "border-line"
          : "border-dashed border-amber-200/80 bg-amber-50/30 dark:border-amber-500/30 dark:bg-amber-500/10"
      }`}
    >
      <span className="grid h-10 w-10 shrink-0 place-items-center rounded-lg">
        <ConnectorMark
          connectorId={connector.connector_id}
          name={connector.name}
          category={connector.category}
          size="md"
        />
      </span>
      <span className="min-w-0 overflow-hidden">
        <span className="flex flex-wrap items-center gap-2">
          <span className="truncate font-black text-ink">{connector.name}</span>
          <Badge tone={toneForState(connector.state)}>{connector.state}</Badge>
          {connector.release_stage === "preview" && (
            <Badge tone="info" title={PREVIEW_TITLE}>
              Preview
            </Badge>
          )}
          {health && <Badge tone={health.tone}>{health.label}</Badge>}
        </span>
        <span className="mt-1 block truncate text-xs text-muted">
          {connector.setup_hint ?? `Read-only ${connector.category} evidence`}
        </span>
      </span>
      <span className="shrink-0 text-right">
        <Badge tone={probe ? toneForProbe(probe.result) : "default"}>
          {probe ? `Probe ${probe.result}` : "Connect"}
        </Badge>
      </span>
    </button>
  );
}

export default function ConnectorsPage() {
  const connectors = useConnectors();
  const [connectId, setConnectId] = useState<string | null>(null);
  const [linkSessionId, setLinkSessionId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [viewFilter, setViewFilter] = useState<ViewFilter>("all");
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>("all");
  const [selected, setSelected] = useState<ConnectorView | null>(null);
  const [onboarding, setOnboarding] = useState(false);

  const data = useMemo(() => connectors.data ?? [], [connectors.data]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    setConnectId(params.get("connect"));
    setLinkSessionId(params.get("link_session"));
    setOnboarding(params.get("onboarding") === "1");
  }, []);

  useEffect(() => {
    if (!connectId || data.length === 0) return;
    const match = data.find((c) => c.connector_id === connectId);
    if (match) setSelected(match);
  }, [connectId, data]);

  useEffect(() => {
    if (!onboarding || !connectId) return;
    document.getElementById("connector-drawer-anchor")?.scrollIntoView({
      behavior: "smooth",
      block: "nearest",
    });
  }, [onboarding, connectId, selected]);

  const filtered = useMemo(
    () =>
      data.filter((c) => {
        if (!isRunnableConnector(c)) return false;
        if (viewFilter === "connected" && c.state !== "enabled") return false;
        if (viewFilter === "setup" && c.state === "enabled") return false;
        if (viewFilter === "attention" && !needsAttention(c)) return false;
        if (categoryFilter !== "all" && connectorCategory(c) !== categoryFilter)
          return false;
        if (!query) return true;
        return JSON.stringify(c).toLowerCase().includes(query.toLowerCase());
      }),
    [categoryFilter, data, query, viewFilter],
  );

  const totals = {
    runnable: data.filter((c) => isRunnableConnector(c)).length,
    enabled: data.filter((c) => c.state === "enabled").length,
    unhealthy: data.filter((c) => {
      const h = syncHealth(c);
      return h !== null && h.tone !== "ready";
    }).length,
  };

  const selectedLive = selected
    ? (data.find((c) => c.connector_id === selected.connector_id) ?? selected)
    : null;

  const clearDeepLinkParams = () => {
    if (typeof window === "undefined") return;
    const url = new URL(window.location.href);
    if (
      !url.searchParams.has("connect") &&
      !url.searchParams.has("link_session")
    ) {
      return;
    }
    url.searchParams.delete("connect");
    url.searchParams.delete("link_session");
    const next = `${url.pathname}${url.search}${url.hash}`;
    window.history.replaceState({}, "", next);
    setConnectId(null);
    setLinkSessionId(null);
  };

  return (
    <div className="page-shell grid gap-2">
      {onboarding && (
        <OnboardingGuideBanner
          step={1}
          title="Connect a read-only source"
          detail="Pick a connector, test access, enable, then sync evidence — the same probe → enable → sync loop as MCP and CI."
        />
      )}
      <PageHeader
        eyebrow="Sources"
        title="Connect evidence"
        description="Connect a source, test access, then sync evidence. You can also read an existing lake, normalize evidence, then evaluate it."
        actions={
          totals.unhealthy > 0 ? (
            <span className="rounded-full border border-rose-200 bg-rose-50 px-3 py-1.5 text-xs font-black text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-300">
              {totals.unhealthy} need attention
            </span>
          ) : null
        }
      />

      <EvidencePathPanel />

      <div className="grid min-w-0 gap-2 overflow-hidden rounded-lg border border-line bg-surface p-2 shadow-card">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <div className="relative min-w-[min(100%,260px)] flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search sources..."
              className="w-full rounded-lg border border-line bg-surface py-2.5 pl-10 pr-3 text-sm focus:outline-none focus:ring-1 focus:ring-brand"
            />
          </div>
          <div
            aria-label="Connection view"
            className="flex max-w-full gap-1 overflow-x-auto rounded-lg border border-line bg-panel p-1"
            role="tablist"
          >
            {VIEW_TABS.map((tab) => (
              <button
                key={tab.id}
                type="button"
                role="tab"
                aria-selected={viewFilter === tab.id}
                className={`shrink-0 rounded-md px-3 py-2 text-xs font-black ${
                  viewFilter === tab.id
                    ? "bg-brand text-white"
                    : "text-muted hover:bg-surface"
                }`}
                onClick={() => setViewFilter(tab.id)}
              >
                {tab.label}
              </button>
            ))}
          </div>
          <label className="sr-only" htmlFor="connector-category-filter">
            Category
          </label>
          <select
            id="connector-category-filter"
            aria-label="Category filter"
            value={categoryFilter}
            onChange={(event) =>
              setCategoryFilter(event.target.value as CategoryFilter)
            }
            className="min-w-[150px] rounded-lg border border-line bg-panel px-3 py-2.5 text-xs font-black text-ink focus:outline-none focus:ring-1 focus:ring-brand"
          >
            {CATEGORY_OPTIONS.map((option) => (
              <option key={option.id} value={option.id}>
                {option.label}
              </option>
            ))}
          </select>
          <span className="rounded-full border border-line bg-surface px-3 py-2 text-xs font-black text-muted">
            {totals.runnable} available
          </span>
        </div>
      </div>

      <QueryState queries={connectors} label="connectors">
        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle>{filtered.length} sources</CardTitle>
            <CardDescription>
              Pick a source to configure or review.
            </CardDescription>
          </CardHeader>
          <div className="grid gap-2 p-3 pt-0 md:grid-cols-2 xl:grid-cols-3">
            {filtered.length === 0 && (
              <div className="rounded-lg border border-dashed border-line p-4 text-sm text-muted">
                {totals.enabled === 0 ? (
                  <div className="grid gap-3">
                    <p>{CONNECT_FLOW.emptySources}</p>
                    <Button asChild size="sm" className="w-fit">
                      <Link href="/onboarding">Open setup guide</Link>
                    </Button>
                  </div>
                ) : (
                  "No connectors match the current filter."
                )}
              </div>
            )}
            {filtered.map((c) => (
              <ConnectorRow
                key={c.connector_id}
                connector={c}
                onSelect={() => setSelected(c)}
              />
            ))}
          </div>
        </Card>
      </QueryState>

      <div id="connector-drawer-anchor" />
      <ConnectorDrawer
        connector={selectedLive}
        linkSessionId={linkSessionId}
        onboarding={onboarding}
        onClose={() => {
          setSelected(null);
          clearDeepLinkParams();
        }}
        onToast={connectorNotify}
      />
    </div>
  );
}

"use client";

import { useState } from "react";
import Link from "next/link";
import {
  ArrowRight,
  CircleAlert,
  ClipboardCheck,
  ExternalLink,
  ShieldCheck,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { EvidenceFreshnessSlaPanel } from "@/components/evidence/EvidenceFreshnessSlaPanel";
import { AuditSnapshotTimeline } from "@/components/audit-room/AuditSnapshotTimeline";
import { IngestionLoopStrip } from "@/components/audit-room/IngestionLoopStrip";
import { PageHeader } from "@/components/PageHeader";
import { QueryState } from "@/components/QueryState";
import { KpiTile } from "@/components/ui/KpiTile";
import { useAuditReadiness, usePlatformStream } from "@/lib/api/hooks";
import { ROUTE_LABELS, SCORE_COPY } from "@/lib/console-copy";
import { displayLabel } from "@/lib/display";

const AUDIT_ROOM_TABS = ["Freshness", "Runs", "Snapshots", "Gaps"] as const;
type AuditRoomTab = (typeof AUDIT_ROOM_TABS)[number];

function consoleHref(href: string) {
  return href.startsWith("/console") ? href.replace(/^\/console/, "") : href;
}

const STATE_COPY: Record<
  string,
  { label: string; tone: "ready" | "attention" | "critical" }
> = {
  audit_ready: { label: "Audit ready", tone: "ready" },
  on_track: { label: "On track", tone: "attention" },
  needs_work: { label: "Needs attention", tone: "attention" },
};

export default function AuditRoomPage() {
  const audit = useAuditReadiness();
  const { connected } = usePlatformStream();
  const [activeAuditTab, setActiveAuditTab] =
    useState<AuditRoomTab>("Freshness");

  return (
    <div className="page-shell grid gap-2">
      <PageHeader
        title={ROUTE_LABELS["/audit-room"]}
        description="Review posture, freshness, snapshots, and proof gaps without leaving the trust workflow."
      />

      <QueryState queries={audit} label="audit readiness">
        {audit.data && (
          <>
            <Card>
              <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3 pb-2">
                <div>
                  <CardTitle className="text-base">Readiness summary</CardTitle>
                  <CardDescription>
                    Proof view from the latest deterministic evaluation.
                  </CardDescription>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Badge
                    tone={STATE_COPY[audit.data.state]?.tone ?? "attention"}
                  >
                    {STATE_COPY[audit.data.state]?.label ??
                      displayLabel(audit.data.state)}
                  </Badge>
                  {connected ? <Badge tone="ready">Live</Badge> : null}
                  <span className="text-xs font-semibold text-muted">
                    {new Date(audit.data.evaluated_at).toLocaleString()}
                  </span>
                </div>
              </CardHeader>
              <CardContent className="grid gap-3">
                <p className="text-xs text-muted">
                  <b className="font-semibold text-ink">
                    {SCORE_COPY.auditReadiness.label}
                  </b>
                  : {SCORE_COPY.auditReadiness.definition}{" "}
                  <b className="font-semibold text-ink">
                    {SCORE_COPY.assessment.label}
                  </b>
                  : {SCORE_COPY.assessment.definition}
                </p>
                <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
                  <KpiTile
                    label={SCORE_COPY.auditReadiness.label}
                    value={`${audit.data.audit_score}/100`}
                    detail={`${SCORE_COPY.assessment.label} ${audit.data.posture.score}/100`}
                  />
                  <KpiTile
                    label="Control tests"
                    value={`${audit.data.control_tests.passing}/${audit.data.control_tests.total}`}
                    detail={`${audit.data.control_tests.failing} failing`}
                  />
                  <KpiTile
                    label="Frameworks ready"
                    value={`${audit.data.posture.frameworks_ready}/${audit.data.posture.frameworks_total}`}
                    detail="of assessed framework packs"
                  />
                  <KpiTile
                    label="Evidence fresh rate"
                    value={
                      audit.data.evidence_freshness
                        ? `${audit.data.evidence_freshness.fresh_rate_pct}%`
                        : "—"
                    }
                    detail={
                      audit.data.evidence_freshness
                        ? `${audit.data.evidence_freshness.stale_count} ${audit.data.evidence_freshness.stale_count === 1 ? "item" : "items"} past SLA`
                        : "freshness rollup"
                    }
                  />
                </div>

                <div className="flex flex-wrap gap-2">
                  <Button asChild size="sm" variant="primary">
                    <Link href="/trust-center">
                      <ShieldCheck className="h-4 w-4" />
                      Trust center
                    </Link>
                  </Button>
                  <Button asChild size="sm" variant="default">
                    <Link href="/access-reviews">
                      <ClipboardCheck className="h-4 w-4" />
                      Access reviews
                    </Link>
                  </Button>
                  <Button asChild size="sm" variant="default">
                    <a
                      href="https://github.com/msaad00/trustops-security-data-lake/blob/main/docs/AUDIT_READINESS.md"
                      target="_blank"
                      rel="noreferrer"
                    >
                      Readiness doc
                      <ExternalLink className="h-4 w-4" />
                    </a>
                  </Button>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="grid gap-3 p-3">
                <div
                  aria-label="Audit room view"
                  className="grid grid-cols-2 gap-1 rounded-lg border border-line bg-panel p-1 md:grid-cols-4"
                  role="tablist"
                >
                  {AUDIT_ROOM_TABS.map((tab) => (
                    <button
                      key={tab}
                      aria-selected={activeAuditTab === tab}
                      className={`rounded-md px-3 py-2 text-sm font-semibold transition ${
                        activeAuditTab === tab
                          ? "bg-surface text-ink shadow-card ring-1 ring-line"
                          : "text-muted hover:bg-surface hover:text-ink"
                      }`}
                      onClick={() => setActiveAuditTab(tab)}
                      role="tab"
                      type="button"
                    >
                      {tab}
                    </button>
                  ))}
                </div>

                {activeAuditTab === "Freshness" && (
                  <EvidenceFreshnessSlaPanel></EvidenceFreshnessSlaPanel>
                )}

                {activeAuditTab === "Runs" && (
                  <IngestionLoopStrip></IngestionLoopStrip>
                )}

                {activeAuditTab === "Snapshots" && (
                  <AuditSnapshotTimeline></AuditSnapshotTimeline>
                )}

                {activeAuditTab === "Gaps" && (
                  <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_minmax(320px,0.45fr)]">
                    <Card className="overflow-hidden">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-base">
                          Blocking gaps
                        </CardTitle>
                        <CardDescription>
                          Auditor-facing items to close before sign-off.
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="grid max-h-[320px] gap-2 overflow-y-auto">
                        {audit.data.gaps.length > 0 ? (
                          audit.data.gaps.map((gap) => (
                            <Link
                              key={gap.id}
                              href={consoleHref(gap.href)}
                              className="flex items-center justify-between rounded-lg border border-line bg-surface px-3 py-2 text-sm hover:bg-surfaceMuted"
                            >
                              <span className="flex items-center gap-2 font-semibold text-ink">
                                <CircleAlert className="h-4 w-4 text-serious-fg" />
                                {gap.label}
                              </span>
                              <ArrowRight className="h-4 w-4 text-muted" />
                            </Link>
                          ))
                        ) : (
                          <div className="rounded-lg border border-line bg-surfaceMuted px-3 py-2 text-sm text-muted">
                            No blocking gaps from the latest assessment.
                          </div>
                        )}
                      </CardContent>
                    </Card>

                    <div className="grid gap-3">
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-base">
                            Evidence &amp; access
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="grid gap-2 text-sm text-muted">
                          <div className="flex justify-between">
                            <span>Evidence requests</span>
                            <b className="text-ink">
                              {audit.data.evidence_requests.open}
                            </b>
                          </div>
                          <div className="flex justify-between">
                            <span>Access reviews</span>
                            <b className="text-ink">
                              {audit.data.access_reviews.active}
                            </b>
                          </div>
                          <div className="flex justify-between">
                            <span>Auditor shares</span>
                            <b className="text-ink">
                              {audit.data.trust_shares.auditor}
                            </b>
                          </div>
                          <div className="flex justify-between">
                            <span>Connectors / rows</span>
                            <b className="text-ink">
                              {audit.data.connectors.enabled} /{" "}
                              {audit.data.connectors.evidence_count}
                            </b>
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </>
        )}
      </QueryState>
    </div>
  );
}

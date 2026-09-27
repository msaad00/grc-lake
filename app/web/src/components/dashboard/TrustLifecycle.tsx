"use client";

import Link from "next/link";
import {
  ArrowRight,
  Database,
  FileSearch,
  GitBranch,
  ListChecks,
  Share2,
  ShieldCheck,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { PostureBlock } from "@/lib/api/types";

interface Props {
  posture?: PostureBlock;
  assessmentHash?: string;
}

export function TrustLifecycle({ posture, assessmentHash }: Props) {
  const failedTests = posture?.failed_control_test_count ?? 0;
  const staleEvidence = posture?.stale_evidence_count ?? 0;
  const openViolations = posture?.open_violation_count ?? 0;
  const criticalViolations = posture?.critical_violation_count ?? 0;

  const lanes = [
    {
      label: "Sources",
      href: "/connectors",
      Icon: Database,
      detail: "Connect cloud, identity, code, vendor, or lake sources.",
      state:
        staleEvidence > 0
          ? `${staleEvidence} ${staleEvidence === 1 ? "record needs" : "records need"} refresh`
          : "within freshness SLA",
      tone: staleEvidence > 0 ? "attention" : "ready",
    },
    {
      label: "Evidence",
      href: "/evidence",
      Icon: FileSearch,
      detail: "Normalize proof, verify hashes, and track freshness.",
      state: `${staleEvidence} to refresh`,
      tone: staleEvidence > 0 ? "attention" : "ready",
    },
    {
      label: "Controls",
      href: "/controls",
      Icon: ShieldCheck,
      detail: "Evaluate mapped controls with deterministic rules.",
      state: `${failedTests} failing`,
      tone: failedTests > 0 ? "critical" : "ready",
    },
    {
      label: "Risk queue",
      href: "/violations",
      Icon: ListChecks,
      detail: "Turn failed checks into owned remediation.",
      state:
        criticalViolations > 0
          ? `${criticalViolations} critical`
          : `${openViolations} open`,
      tone:
        criticalViolations > 0
          ? "critical"
          : openViolations > 0
            ? "attention"
            : "ready",
    },
    {
      label: "Workflow",
      href: "/automation",
      Icon: GitBranch,
      detail: "Route approvals, tickets, snapshots, and alerts.",
      state: "designer",
      tone: "info",
    },
    {
      label: "Trust share",
      href: "/trust-center",
      Icon: Share2,
      detail: "Share scoped, hashed assurance views.",
      state: assessmentHash ? assessmentHash.slice(0, 8) : "not cut",
      tone: assessmentHash ? "ready" : "default",
    },
  ] as const;

  return (
    <section className="grid gap-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-sm font-black text-ink">How trust flows</h2>
          <p className="mt-0.5 text-xs leading-5 text-muted">
            From source connection to control result, remediation, and shareable
            proof.
          </p>
        </div>
        <Badge tone="info">operating map</Badge>
      </div>
      <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-6">
        {lanes.map(({ label, href, Icon, detail, state, tone }, idx) => (
          <Link
            key={label}
            href={href}
            className="group relative grid min-h-[138px] grid-rows-[auto_1fr_auto] rounded-lg border border-line bg-surface p-3 transition-colors hover:border-brand"
          >
            {idx < lanes.length - 1 && (
              <span className="pointer-events-none absolute -right-2 top-1/2 z-10 hidden h-px w-4 bg-line xl:block" />
            )}
            <span className="flex items-center justify-between gap-2">
              <span className="grid h-8 w-8 place-items-center rounded-lg bg-panel text-brand ring-1 ring-line">
                <Icon className="h-4 w-4" />
              </span>
              <ArrowRight className="h-4 w-4 text-muted transition-transform group-hover:translate-x-0.5 group-hover:text-brand" />
            </span>
            <span className="mt-3 min-w-0">
              <span className="block text-[11px] font-black uppercase tracking-wide text-muted">
                {label}
              </span>
              <span className="mt-1 block text-xs leading-5 text-muted">
                {detail}
              </span>
            </span>
            <Badge tone={tone} className="mt-2 justify-self-start">
              {state}
            </Badge>
          </Link>
        ))}
      </div>
    </section>
  );
}

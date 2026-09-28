"use client";

import Link from "next/link";
import {
  ArrowRight,
  ChevronRight,
  Database,
  FileCheck2,
  Gavel,
  Shield,
} from "lucide-react";
import type { FrameworkControlDetail } from "@/lib/api/types";
import { Badge } from "@/components/ui/badge";
import { frameworkDetailHref } from "@/lib/framework-links";

function ChainStep({
  icon: Icon,
  label,
  value,
  detail,
  href,
}: {
  icon: typeof Shield;
  label: string;
  value: string;
  detail?: string;
  href?: string;
}) {
  const body = (
    <div className="min-w-[120px] flex-1 rounded-lg border border-line bg-surface p-2.5">
      <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted">
        <Icon className="h-3 w-3" />
        {label}
      </div>
      <div className="mt-1 text-xs font-semibold text-ink">{value}</div>
      {detail && <div className="mt-0.5 text-[11px] text-muted">{detail}</div>}
    </div>
  );

  if (!href) return body;

  return (
    <Link
      href={href}
      className="group min-w-[120px] flex-1 transition-colors hover:text-brand"
    >
      {body}
      <span className="mt-1 inline-flex items-center gap-0.5 text-[10px] font-semibold text-brand opacity-0 transition-opacity group-hover:opacity-100">
        Open <ArrowRight className="h-3 w-3" />
      </span>
    </Link>
  );
}

export function FrameworkEvidenceChain({
  control,
  frameworkId,
}: {
  control: FrameworkControlDetail;
  frameworkId: string;
}) {
  const primarySource = control.evidence.sources[0];
  const sourceLabel =
    control.evidence.sources.length === 0
      ? "No datasource"
      : control.evidence.sources.length === 1
        ? primarySource.source
        : `${primarySource.source} +${control.evidence.sources.length - 1}`;

  return (
    <div className="flex flex-wrap items-stretch gap-1.5">
      <ChainStep
        icon={Shield}
        label="Control"
        value={control.control_id}
        detail={control.title}
        href={frameworkDetailHref(frameworkId, control.control_id)}
      />
      <ChevronRight className="mt-6 hidden h-4 w-4 shrink-0 text-muted sm:block" />
      <ChainStep
        icon={Gavel}
        label="Rule"
        value={control.evaluation_rule}
        detail={
          control.posture.rule_reasons[0] ??
          control.evidence_requirement.slice(0, 72)
        }
      />
      <ChevronRight className="mt-6 hidden h-4 w-4 shrink-0 text-muted sm:block" />
      <ChainStep
        icon={FileCheck2}
        label="Evidence"
        value={`${control.evidence.count} facts`}
        detail={
          control.test.freshness_status
            ? `${control.test.freshness_status} · ${control.test.confidence_score ?? 0}% confidence`
            : "Freshness not evaluated"
        }
        href="/evidence"
      />
      <ChevronRight className="mt-6 hidden h-4 w-4 shrink-0 text-muted sm:block" />
      <ChainStep
        icon={Database}
        label="Datasource"
        value={sourceLabel}
        detail={
          primarySource
            ? `${primarySource.event_count} events · ${primarySource.fresh_count} fresh`
            : "Connect a source to collect proof"
        }
        href="/connectors"
      />
      {control.posture.status === "fail" && (
        <div className="flex w-full items-center gap-2 pt-1">
          <Badge tone="critical">Gap detected</Badge>
          {control.test.next_action && (
            <span className="text-xs text-muted">
              {control.test.next_action}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

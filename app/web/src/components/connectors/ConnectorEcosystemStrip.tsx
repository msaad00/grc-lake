"use client";

import Link from "next/link";
import { ArrowRight } from "lucide-react";
import { ConnectorMark } from "@/components/connectors/ConnectorMark";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";

const LIVE_CONNECTORS = [
  { id: "aws-posture", label: "AWS" },
  { id: "azure-posture", label: "Azure" },
  { id: "gcp-posture", label: "GCP" },
  { id: "snowflake-evidence-lake", label: "Snowflake" },
  { id: "github-security", label: "GitHub" },
  { id: "gitlab-security", label: "GitLab" },
  { id: "okta-identity", label: "Okta" },
] as const;

export function ConnectorEcosystemStrip({
  showLink = true,
  compact = false,
}: {
  showLink?: boolean;
  compact?: boolean;
}) {
  return (
    <Card
      className={
        compact
          ? "border-line bg-surface p-3"
          : "overflow-hidden border-line bg-surface"
      }
    >
      <div
        className={compact ? "flex flex-wrap items-center gap-3" : "p-4 sm:p-5"}
      >
        {!compact && (
          <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wide text-brand">
                Read-only integrations
              </div>
              <h2 className="mt-1 text-lg font-semibold text-ink">
                Connect AWS, Azure, GCP, Snowflake, and identity sources
              </h2>
              <p className="mt-1 max-w-[720px] text-sm text-muted">
                Every source follows the same probe → discover → test → enable →
                sync flow, and its evidence lands in your own lake.
              </p>
            </div>
            {showLink && (
              <Link
                href="/connectors"
                className="inline-flex items-center gap-1 text-sm font-semibold text-brand hover:underline"
              >
                Open connectors
                <ArrowRight className="h-4 w-4" />
              </Link>
            )}
          </div>
        )}
        <div className="flex flex-wrap items-center gap-2">
          {compact && (
            <span className="text-[11px] font-semibold uppercase tracking-wide text-muted">
              Live sources
            </span>
          )}
          {LIVE_CONNECTORS.map(({ id, label }) => (
            <Link
              key={id}
              href={`/connectors/?connect=${id}`}
              className="inline-flex items-center gap-2 rounded-xl border border-line bg-surface px-2.5 py-2 shadow-sm transition-colors hover:border-brand"
              title={`Link ${label}`}
            >
              <ConnectorMark connectorId={id} name={label} size="sm" />
              {!compact && (
                <span className="pr-1 text-xs font-semibold text-ink">
                  {label}
                </span>
              )}
            </Link>
          ))}
          <Badge tone="info">read-only</Badge>
        </div>
      </div>
    </Card>
  );
}

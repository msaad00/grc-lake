"use client";

import { Link2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { getIntegrationPreset } from "@/lib/integration-presets";

interface Props {
  connectorId: string;
}

export function IntegrationPresetPanel({ connectorId }: Props) {
  const preset = getIntegrationPreset(connectorId);
  if (!preset) return null;

  return (
    <section className="rounded-lg border border-brand/20 bg-brand/5 p-2.5">
      <div className="flex flex-wrap items-center gap-1.5">
        <Link2 className="h-4 w-4 text-brand" />
        <span className="text-xs font-semibold uppercase tracking-wide text-muted">
          Integration wizard
        </span>
        <span className="text-sm font-semibold text-ink">{preset.title}</span>
        <Badge tone="ready">{preset.authLabel}</Badge>
        {preset.badges
          .filter((badge) => badge !== preset.authLabel)
          .slice(0, 1)
          .map((badge) => (
            <Badge key={badge}>{badge}</Badge>
          ))}
      </div>
      <p className="mt-1 text-xs leading-5 text-muted">{preset.summary}</p>
      <div className="mt-2 grid gap-2 md:grid-cols-2">
        <div className="rounded-lg border border-line bg-surface px-2.5 py-2">
          <div className="text-xs font-semibold uppercase tracking-wide text-muted">
            Provider setup
          </div>
          <p className="mt-1 text-xs leading-5 text-muted">
            {preset.providerSetup}
          </p>
        </div>
        <div className="rounded-lg border border-line bg-surface px-2.5 py-2">
          <div className="text-xs font-semibold uppercase tracking-wide text-muted">
            TrustOps needs
          </div>
          <p className="mt-1 text-xs leading-5 text-muted">
            {preset.trustOpsInput}
          </p>
        </div>
      </div>
      <details className="mt-2 text-xs text-muted">
        <summary className="cursor-pointer list-none font-semibold text-brand">
          Advanced provider details
        </summary>
        <ul className="mt-2 grid gap-1.5 border-t border-line pt-2">
          {preset.advancedDetails.map((detail) => (
            <li key={detail} className="leading-5">
              {detail}
            </li>
          ))}
        </ul>
      </details>
    </section>
  );
}

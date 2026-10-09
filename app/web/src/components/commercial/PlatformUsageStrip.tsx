"use client";

import Link from "next/link";
import { Gauge } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { QueryState } from "@/components/QueryState";
import { KpiTile } from "@/components/ui/KpiTile";
import { useCommercialFeature, usePlatformUsage } from "@/lib/api/hooks";

function usageTone(ok: boolean): "ready" | "attention" | "critical" {
  return ok ? "ready" : "critical";
}

export function PlatformUsageStrip() {
  const feature = useCommercialFeature("plan_usage");
  const usage = usePlatformUsage(feature.enabled);

  if (!feature.enabled) return null;
  if (usage.isError && String(usage.error?.message).includes("501")) {
    return null;
  }

  return (
    <QueryState queries={usage} label="plan usage">
      {usage.data && (
        <Card>
          <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 space-y-0 pb-2">
            <div>
              <CardTitle className="flex items-center gap-2 text-base">
                <Gauge className="h-4 w-4 text-brand" />
                Hosted plan usage
              </CardTitle>
              <p className="mt-1 text-xs text-muted">
                Live counters against this workspace&apos;s plan limits.
              </p>
            </div>
            <Badge tone="info">{usage.data.plan_name}</Badge>
          </CardHeader>
          <CardContent className="grid gap-3 sm:grid-cols-3">
            <KpiTile
              label="Users"
              value={`${usage.data.usage.users}/${usage.data.limits.max_users}`}
              detail={
                usage.data.within_limits.users
                  ? "Within plan"
                  : "At or over limit"
              }
              tone={usageTone(usage.data.within_limits.users)}
            />
            <KpiTile
              label="API keys"
              value={`${usage.data.usage.api_keys}/${usage.data.limits.max_api_keys}`}
              detail={
                usage.data.within_limits.api_keys
                  ? "Within plan"
                  : "At or over limit"
              }
              tone={usageTone(usage.data.within_limits.api_keys)}
            />
            <KpiTile
              label="Pending invites"
              value={`${usage.data.usage.invites_pending}/${usage.data.limits.max_invites_pending}`}
              detail={`${usage.data.limits.max_connectors} connector cap · SCIM ${usage.data.limits.scim ? "on" : "off"}`}
              tone={usageTone(usage.data.within_limits.invites_pending)}
            />
          </CardContent>
          <CardContent className="border-t border-line pt-3">
            <Link
              href="/deploy"
              className="text-xs font-semibold text-brand hover:underline"
            >
              Deployment models →
            </Link>
          </CardContent>
        </Card>
      )}
    </QueryState>
  );
}

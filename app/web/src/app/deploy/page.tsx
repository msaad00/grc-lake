"use client";

import Link from "next/link";
import { ArrowRight, Cloud, GitBranch, Server } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { ConnectionCompareDiagram } from "@/components/diagrams/ConnectionCompareDiagram";
import { CollapsibleCard } from "@/components/ui/collapsible-card";
import { BRAND } from "@/lib/brand";
import { ROUTE_LABELS } from "@/lib/console-copy";

const DEPLOYMENT_MODELS = [
  {
    title: "OSS local",
    detail: "Fixtures + console on laptop or CI.",
    icon: GitBranch,
    badge: "Available",
  },
  {
    title: "Self-hosted",
    detail: "Helm in your VPC; evidence in your lake.",
    icon: Server,
    badge: "Available",
  },
  {
    title: "Managed cloud",
    detail: "Operator-run workspace (future).",
    icon: Cloud,
    badge: "Future",
  },
] as const;

const EDITIONS = [
  {
    name: "OSS",
    deploy: "Local / CI",
    console: "Full console",
    support: "Community",
  },
  {
    name: "Self-hosted",
    deploy: "Your cluster",
    console: "Console + OIDC",
    support: "Your ops",
  },
  {
    name: "Managed cloud",
    deploy: "Operator URL",
    console: "Console + SSO",
    support: "Commercial",
  },
] as const;

export default function DeployPage() {
  return (
    <div className="page-shell grid gap-2">
      <PageHeader
        eyebrow="Platform"
        title={ROUTE_LABELS["/deploy"]}
        description={`${BRAND.name} is open source. Run locally or self-host in your VPC.`}
        actions={
          <>
            <Button asChild variant="default" size="sm">
              <Link href="/connectors">Connectors</Link>
            </Button>
            <Button asChild variant="primary" size="sm">
              <Link href="/poc">
                Launch checklist
                <ArrowRight className="h-4 w-4" />
              </Link>
            </Button>
          </>
        }
      />

      <div className="grid gap-2 sm:grid-cols-3">
        {DEPLOYMENT_MODELS.map(({ title, detail, icon: Icon, badge }) => (
          <Card key={title} className="overflow-hidden">
            <CardContent className="grid grid-cols-[auto_minmax(0,1fr)] gap-2.5 p-3">
              <span className="grid h-8 w-8 shrink-0 place-items-center rounded-md bg-panel text-brand ring-1 ring-line">
                <Icon className="h-3.5 w-3.5" />
              </span>
              <span className="min-w-0">
                <span className="flex flex-wrap items-center gap-1.5">
                  <span className="ui-section-title truncate">{title}</span>
                  <Badge tone={badge === "Available" ? "ready" : "default"}>
                    {badge}
                  </Badge>
                </span>
                <span className="mt-0.5 block text-xs leading-4 text-muted">
                  {detail}
                </span>
              </span>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card className="overflow-hidden">
        <CardContent className="overflow-x-auto p-0">
          <table className="w-full min-w-[480px] text-left text-sm">
            <thead>
              <tr className="border-b border-line bg-surfaceMuted">
                <th className="ui-label px-3 py-2">Edition</th>
                <th className="ui-label px-3 py-2">Deploy</th>
                <th className="ui-label px-3 py-2">Console</th>
                <th className="ui-label px-3 py-2">Support</th>
              </tr>
            </thead>
            <tbody>
              {EDITIONS.map((row) => (
                <tr key={row.name} className="border-b border-line/60">
                  <td className="px-3 py-2 font-medium text-ink">{row.name}</td>
                  <td className="px-3 py-2 text-muted">{row.deploy}</td>
                  <td className="px-3 py-2 text-muted">{row.console}</td>
                  <td className="px-3 py-2 text-muted">{row.support}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>

      <CollapsibleCard
        storageKey="deploy-evidence-boundary"
        defaultOpen={false}
        title="Evidence boundary"
        description="Read-only sources and where evidence is stored"
        contentClassName="p-3"
      >
        <ConnectionCompareDiagram />
      </CollapsibleCard>
    </div>
  );
}

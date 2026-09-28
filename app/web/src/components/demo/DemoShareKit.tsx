"use client";

import Link from "next/link";
import { ClipboardCopy, ExternalLink, Link2, Plug } from "lucide-react";
import { ConnectorMark } from "@/components/connectors/ConnectorMark";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { notify } from "@/lib/toast";
import type { DemoAccountLink, DemoKit, DemoShareLink } from "@/lib/api/types";

function copyUrl(url: string, label: string) {
  void navigator.clipboard.writeText(url).then(
    () => notify.success(`Copied ${label}`),
    () => notify.error("Could not copy link"),
  );
}

function accountStatusTone(status: string) {
  if (status === "ingesting") return "ready" as const;
  if (status === "connected" || status === "enabled") return "info" as const;
  if (status === "error") return "critical" as const;
  return "attention" as const;
}

function accountStatusLabel(status: string) {
  if (status === "ingesting") return "live ingestion";
  if (status === "connected") return "connected";
  if (status === "enabled") return "enabled";
  if (status === "error") return "error";
  return "not linked";
}

function ShareLinkRow({ link }: { link: DemoShareLink }) {
  const external = link.url.startsWith("http");
  return (
    <div className="grid gap-3 rounded-xl border border-line bg-surface p-4 sm:grid-cols-[minmax(0,1fr)_auto]">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-semibold text-ink">{link.label}</span>
          <Badge tone="info">{link.audience}</Badge>
        </div>
        <p className="mt-1 text-xs leading-5 text-muted">{link.description}</p>
        <code className="mt-2 block truncate rounded-md bg-panel px-2 py-1 text-[11px] text-ink">
          {link.url}
        </code>
      </div>
      <div className="flex flex-wrap items-start gap-2 sm:justify-end">
        <Button
          type="button"
          size="sm"
          variant="default"
          onClick={() => copyUrl(link.url, link.label)}
        >
          <ClipboardCopy className="h-4 w-4" />
          Copy
        </Button>
        {external ? (
          <Button asChild size="sm" variant="default">
            <a href={link.url} target="_blank" rel="noreferrer">
              <ExternalLink className="h-4 w-4" />
              Open
            </a>
          </Button>
        ) : (
          <Button asChild size="sm" variant="default">
            <Link href={link.url}>
              <ExternalLink className="h-4 w-4" />
              Open
            </Link>
          </Button>
        )}
      </div>
    </div>
  );
}

function AccountLinkRow({ row }: { row: DemoAccountLink }) {
  const href = row.connect_url.startsWith("http")
    ? row.connect_url
    : row.connect_url.replace(/^\/console/, "") ||
      `/connectors/?connect=${row.connector_id}`;
  return (
    <div className="grid gap-3 rounded-xl border border-line bg-surface p-4 sm:grid-cols-[minmax(0,1fr)_auto]">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <ConnectorMark connectorId={row.connector_id} size="sm" />
          <span className="text-sm font-semibold text-ink">{row.label}</span>
          <Badge tone={accountStatusTone(row.status)}>
            {accountStatusLabel(row.status)}
          </Badge>
          {row.evidence_count > 0 && (
            <Badge tone="ready">{row.evidence_count} evidence</Badge>
          )}
        </div>
        <p className="mt-1 text-xs leading-5 text-muted">{row.setup_hint}</p>
      </div>
      <div className="flex items-start sm:justify-end">
        <Button
          asChild
          size="sm"
          variant={row.status === "not_linked" ? "primary" : "default"}
        >
          <Link href={href}>
            <Plug className="h-4 w-4" />
            {row.status === "not_linked" ? "Link account" : "Review"}
          </Link>
        </Button>
      </div>
    </div>
  );
}

export function DemoShareKit({ kit }: { kit: DemoKit }) {
  const summary = kit.account_linking_summary;
  return (
    <div className="grid gap-3">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Link2 className="h-5 w-5 text-brand" />
            Shareable demo links
          </CardTitle>
          <CardDescription>
            Copy invite, sign-in, and connect URLs for evaluators — similar to
            hosted GRC demo workspaces. Set{" "}
            <code className="text-ink">TRUSTOPS_PUBLIC_URL</code> on the server
            to generate absolute links.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3">
          {kit.share_links.map((link) => (
            <ShareLinkRow key={`${link.kind}-${link.url}`} link={link} />
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Account linking</CardTitle>
          <CardDescription>
            Connect read-only cloud, identity, and evidence-lake accounts. True
            ingestion starts after probe, enable, and first sync.
            {summary.live_ingestion > 0 && (
              <span className="mt-1 block font-semibold text-success-fg">
                {summary.live_ingestion} source(s) actively ingesting evidence.
              </span>
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3">
          {kit.account_linking.map((row) => (
            <AccountLinkRow key={row.connector_id} row={row} />
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

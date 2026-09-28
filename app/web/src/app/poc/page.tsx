"use client";

import Link from "next/link";
import {
  ArrowRight,
  Bot,
  CheckCircle2,
  CircleAlert,
  CircleDot,
  Database,
  ExternalLink,
  Globe2,
  KeyRound,
  ListChecks,
  Plug,
  Share2,
  ShieldCheck,
  UserRoundCheck,
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
import { PageHeader } from "@/components/PageHeader";
import { DemoShareKit } from "@/components/demo/DemoShareKit";
import { usePocReadiness } from "@/lib/api/hooks";
import type { PocReadinessStep } from "@/lib/api/types";

const stateCopy: Record<
  string,
  { label: string; tone: "ready" | "attention" }
> = {
  ready: { label: "Ready to share", tone: "ready" },
  internal_ready: { label: "Internal POC ready", tone: "attention" },
  needs_setup: { label: "Needs setup", tone: "attention" },
};

function stepTone(status: string) {
  if (status === "ready") return "ready";
  if (status === "skipped") return "default";
  return "attention";
}

function stepBadgeLabel(status: string) {
  if (status === "ready") return "ready";
  if (status === "skipped") return "skipped";
  return "setup";
}

function stepIcon(step: PocReadinessStep) {
  if (step.id === "public_url") return Globe2;
  if (step.id === "human_access") return UserRoundCheck;
  if (step.id === "headless_access") return KeyRound;
  if (step.id === "source_sync") return Plug;
  if (step.id === "trust_share") return Share2;
  if (step.id === "agent_review") return Bot;
  return step.status === "ready" ? CheckCircle2 : CircleAlert;
}

function internalHref(href: string | null) {
  if (!href) return null;
  return href.startsWith("/console") ? href.replace(/^\/console/, "") : href;
}

function actionLabel(step: PocReadinessStep) {
  if (step.status === "ready") {
    if (step.id === "source_sync") return "Review sources";
    if (step.id === "trust_share") return "Review shares";
    if (step.id === "agent_review") return "Review runs";
    return "Review";
  }
  if (step.status === "skipped") return "Review";
  if (step.id === "public_url") return "Configure URL";
  if (step.id === "human_access") return "Set up login";
  if (step.id === "headless_access") return "Issue API key";
  if (step.id === "source_sync") return "Connect source";
  if (step.id === "trust_share") return "Create share";
  if (step.id === "agent_review") return "Run review";
  return "Open";
}

function titleFromAction(action: string) {
  return action
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function LaunchStep({
  step,
  index,
  active,
}: {
  step: PocReadinessStep;
  index: number;
  active: boolean;
}) {
  const Icon = stepIcon(step);
  const href = step.console_href ?? internalHref(step.href);
  const ready = step.status === "ready";
  const content = (
    <div
      className={[
        "grid gap-4 rounded-xl border bg-surface p-4 transition-colors sm:grid-cols-[44px_minmax(0,1fr)_auto]",
        active ? "border-brand shadow-sm" : "border-line",
      ].join(" ")}
    >
      <div className="flex items-start gap-3 sm:block">
        <span
          className={[
            "grid h-11 w-11 shrink-0 place-items-center rounded-xl ring-1",
            ready
              ? "bg-success-bg text-success-fg ring-success/40"
              : active
                ? "bg-info-bg text-brand ring-info/40"
                : "bg-panel text-muted ring-line",
          ].join(" ")}
        >
          {ready ? (
            <CheckCircle2 className="h-5 w-5" />
          ) : (
            <Icon className="h-5 w-5" />
          )}
        </span>
        <div className="sm:hidden">
          <div className="text-xs font-semibold uppercase tracking-wide text-muted">
            Step {index + 1}
          </div>
          <Badge tone={stepTone(step.status)}>
            {stepBadgeLabel(step.status)}
          </Badge>
        </div>
      </div>

      <div className="min-w-0">
        <div className="hidden text-xs font-semibold uppercase tracking-wide text-muted sm:block">
          Step {index + 1}
        </div>
        <div className="mt-1 flex flex-wrap items-center gap-2">
          <div className="text-base font-semibold text-ink">{step.label}</div>
          <Badge tone={stepTone(step.status)}>
            {stepBadgeLabel(step.status)}
          </Badge>
          {!step.blocking && <Badge tone="info">optional</Badge>}
        </div>
        <p className="mt-1 max-w-3xl text-sm leading-6 text-muted">
          {step.detail}
        </p>
      </div>

      <div className="flex items-center sm:justify-end">
        {href ? (
          <Button
            asChild
            variant={active && !ready ? "primary" : "default"}
            size="sm"
          >
            <Link href={href}>
              {actionLabel(step)}
              <ArrowRight className="h-4 w-4" />
            </Link>
          </Button>
        ) : (
          <Badge tone={ready ? "ready" : "attention"}>
            {ready ? "complete" : "admin"}
          </Badge>
        )}
      </div>
    </div>
  );
  return content;
}

function Metric({
  label,
  value,
  detail,
}: {
  label: string;
  value: string | number;
  detail: string;
}) {
  return (
    <div className="rounded-lg border border-line bg-panel p-3">
      <div className="text-[11px] font-semibold uppercase tracking-wide text-muted">
        {label}
      </div>
      <div className="mt-1 truncate text-2xl font-semibold leading-none text-ink">
        {value}
      </div>
      <div className="mt-1 truncate text-xs text-muted">{detail}</div>
    </div>
  );
}

function Signal({
  icon: Icon,
  label,
  value,
  detail,
  tone = "default",
}: {
  icon: typeof ShieldCheck;
  label: string;
  value: string | number;
  detail: string;
  tone?: "default" | "ready" | "attention" | "critical" | "info";
}) {
  return (
    <div className="flex min-w-0 items-start gap-3 rounded-xl border border-line bg-surface p-4">
      <span className="grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-panel text-brand ring-1 ring-line">
        <Icon className="h-4 w-4" />
      </span>
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <div className="min-w-0 text-sm font-semibold text-ink">{label}</div>
          <Badge tone={tone}>{value}</Badge>
        </div>
        <p className="mt-1 line-clamp-2 text-xs leading-5 text-muted">
          {detail}
        </p>
      </div>
    </div>
  );
}

export default function PocPage() {
  const readiness = usePocReadiness();
  const data = readiness.data;
  const state = data
    ? (stateCopy[data.state] ?? stateCopy.needs_setup)
    : stateCopy.needs_setup;
  const readySteps =
    data?.steps.filter((step) => step.status === "ready").length ?? 0;
  const totalSteps = data?.steps.length ?? 0;
  const activeStepId = data?.next_step?.id ?? null;

  return (
    <div className="page-shell grid gap-3">
      <PageHeader
        title="First-run launch"
        description="Connect a source, prove the sync path, and prepare a shareable trust workspace."
        actions={
          data && (
            <Badge tone={state.tone}>
              {data.shareable ? "shareable" : state.label}
            </Badge>
          )
        }
      />

      {readiness.isLoading && (
        <Card>
          <CardContent className="p-6 text-sm font-semibold text-muted">
            Checking launch readiness...
          </CardContent>
        </Card>
      )}

      {readiness.isError && (
        <Card>
          <CardContent className="p-6">
            <div className="flex items-start gap-3">
              <CircleAlert className="mt-0.5 h-5 w-5 text-warning-fg" />
              <div>
                <div className="font-semibold text-ink">
                  Admin access is required.
                </div>
                <p className="mt-1 text-sm leading-6 text-muted">
                  POC readiness includes auth, tenant, and connector state, so
                  it is only available to admins.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {data && (
        <>
          <Card className="overflow-hidden">
            <CardContent className="grid gap-0 p-0 lg:grid-cols-[340px_minmax(0,1fr)]">
              <div className="border-b border-line bg-panel p-5 lg:border-b-0 lg:border-r">
                <div className="flex items-center justify-between gap-3">
                  <div className="text-[11px] font-semibold uppercase tracking-wide text-muted">
                    Launch state
                  </div>
                  <Badge tone={state.tone}>
                    {data.shareable ? "shareable" : state.label}
                  </Badge>
                </div>
                <div className="mt-4 text-3xl font-semibold leading-none text-ink">
                  {state.label}
                </div>
                <p className="mt-3 text-sm leading-6 text-muted">
                  {data.shareable
                    ? "The workspace has the core gates needed for an evaluator."
                    : "Finish the active gate before sharing this workspace externally."}
                </p>
                <div className="mt-5">
                  <div className="flex items-center justify-between text-xs font-semibold text-muted">
                    <span>Progress</span>
                    <span>
                      {readySteps}/{totalSteps}
                    </span>
                  </div>
                  <div className="mt-2 h-2 overflow-hidden rounded-full bg-line">
                    <div
                      className="h-full rounded-full bg-brand"
                      style={{
                        width: totalSteps
                          ? `${Math.round((readySteps / totalSteps) * 100)}%`
                          : "0%",
                      }}
                    />
                  </div>
                </div>
              </div>

              <div className="grid gap-3 p-5 sm:grid-cols-2">
                <Signal
                  icon={ShieldCheck}
                  label="Auth"
                  value={
                    data.access.browser_sso_configured
                      ? "SSO"
                      : data.access.require_auth
                        ? "setup"
                        : "local"
                  }
                  detail={
                    data.access.require_auth
                      ? "Browser access is gated."
                      : "Local access mode is active."
                  }
                  tone={
                    data.access.browser_sso_configured ||
                    !data.access.require_auth
                      ? "ready"
                      : "attention"
                  }
                />
                <Signal
                  icon={Database}
                  label="Evidence"
                  value={data.connectors.evidence_count}
                  detail={`${data.connectors.enabled} enabled connector(s), ${data.connectors.source_count} source(s).`}
                  tone={
                    data.connectors.evidence_count > 0 ? "ready" : "attention"
                  }
                />
                <Signal
                  icon={CircleDot}
                  label="Posture"
                  value={data.ingestion.posture_score ?? "none"}
                  detail={`${data.ingestion.open_violations ?? 0} open violation(s).`}
                  tone={
                    (data.ingestion.open_violations ?? 0) > 0
                      ? "attention"
                      : "ready"
                  }
                />
                <Signal
                  icon={Share2}
                  label="Trust share"
                  value={data.trust_shares.active}
                  detail="Scoped reviewer links issued from Trust Center."
                  tone={data.trust_shares.active > 0 ? "ready" : "attention"}
                />
              </div>
            </CardContent>
          </Card>

          <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_360px]">
            <Card>
              <CardHeader>
                <CardTitle>Launch sequence</CardTitle>
                <CardDescription>
                  Complete these gates in order. Only browser login, source
                  sync, and public URL block an external POC.
                </CardDescription>
              </CardHeader>
              <CardContent className="grid gap-3">
                {data.steps.map((step, index) => (
                  <LaunchStep
                    key={step.id}
                    step={step}
                    index={index}
                    active={step.id === activeStepId}
                  />
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Next action</CardTitle>
                <CardDescription>
                  The shortest path to a shareable workspace.
                </CardDescription>
              </CardHeader>
              <CardContent className="grid gap-4">
                <div className="rounded-xl border border-line bg-panel p-4">
                  <div className="text-lg font-semibold text-ink">
                    {data.next_step?.label ?? "Ready for review"}
                  </div>
                  <p className="mt-2 text-sm leading-6 text-muted">
                    {data.next_step?.detail ??
                      "Keep scheduled syncs healthy and review trust shares before expiry."}
                  </p>
                  {data.next_step?.href && (
                    <Button asChild className="mt-4" variant="primary">
                      <Link href={internalHref(data.next_step.href) ?? "#"}>
                        {actionLabel(data.next_step)}
                        <ArrowRight className="h-4 w-4" />
                      </Link>
                    </Button>
                  )}
                </div>

                <div className="grid gap-2">
                  {data.ingestion.recommended_actions
                    .slice(0, 3)
                    .map((action) => (
                      <div
                        key={String(action.action)}
                        className="rounded-lg border border-line bg-surface p-3"
                      >
                        <div className="text-sm font-semibold text-ink">
                          {titleFromAction(String(action.action))}
                        </div>
                        <p className="mt-1 line-clamp-2 text-xs leading-5 text-muted">
                          {String(action.reason ?? "Review ingestion health.")}
                        </p>
                      </div>
                    ))}
                  {data.ingestion.recommended_actions.length === 0 && (
                    <div className="rounded-lg border border-line bg-surface p-3 text-sm font-semibold text-muted">
                      No ingestion actions are currently recommended.
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="grid gap-3 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Access and sharing</CardTitle>
                <CardDescription>
                  Human login, headless access, and external assurance links.
                </CardDescription>
              </CardHeader>
              <CardContent className="grid gap-2 sm:grid-cols-2">
                <Metric
                  label="Browser login"
                  value={data.access.browser_sso_configured ? "SSO" : "not set"}
                  detail={
                    data.access.require_auth ? "auth required" : "local mode"
                  }
                />
                <Metric
                  label="API keys"
                  value={data.access.active_api_keys}
                  detail="active headless keys"
                />
                <Metric
                  label="Trust shares"
                  value={data.trust_shares.active}
                  detail="active external links"
                />
                <Metric
                  label="Agent reviews"
                  value={data.agents.completed}
                  detail={`${data.agents.pending_decisions} pending decision(s)`}
                />
                <Metric
                  label="Public URL"
                  value={data.public_url ? "set" : "missing"}
                  detail={data.public_url ?? "Not configured"}
                />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Source readiness</CardTitle>
                <CardDescription>
                  Connected evidence sources and current ingestion health.
                </CardDescription>
              </CardHeader>
              <CardContent className="grid gap-2 sm:grid-cols-2">
                <Metric
                  label="Sources"
                  value={data.connectors.enabled}
                  detail={`${data.connectors.source_count} evidence source(s)`}
                />
                <Metric
                  label="Evidence"
                  value={data.connectors.evidence_count}
                  detail="normalized rows"
                />
                <Metric
                  label="Failed"
                  value={data.connectors.failed}
                  detail="connector errors"
                />
                <Metric
                  label="Silent"
                  value={data.connectors.silent}
                  detail="missed sync SLO"
                />
              </CardContent>
            </Card>
          </div>

          {data.demo_kit && <DemoShareKit kit={data.demo_kit} />}

          <div className="flex flex-wrap gap-2">
            <Button asChild variant="default">
              <Link href="/connectors">
                <Plug className="h-4 w-4" />
                Connect sources
              </Link>
            </Button>
            <Button asChild variant="default">
              <Link href="/dashboard">
                <ListChecks className="h-4 w-4" />
                Review posture
              </Link>
            </Button>
            <Button asChild variant="default">
              <Link href="/trust-center">
                <Share2 className="h-4 w-4" />
                Share trust
              </Link>
            </Button>
            <Button asChild variant="default">
              <Link href="/agents">
                <Bot className="h-4 w-4" />
                Run agent review
              </Link>
            </Button>
            <Button asChild variant="default">
              <Link href="/demo">
                <Globe2 className="h-4 w-4" />
                Demo landing
              </Link>
            </Button>
            {data.public_url && (
              <Button asChild variant="dark">
                <a href={data.public_url} target="_blank" rel="noreferrer">
                  Open public URL
                  <ExternalLink className="h-4 w-4" />
                </a>
              </Button>
            )}
          </div>
        </>
      )}
    </div>
  );
}

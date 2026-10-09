"use client";

import Link from "next/link";
import {
  ArrowRight,
  CheckCircle2,
  Circle,
  Plug,
  RefreshCw,
  ShieldCheck,
  Share2,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { GrcLakeMark } from "@/components/brand/GrcLakeMark";
import { usePocReadiness } from "@/lib/api/hooks";
import type { PocReadinessStep } from "@/lib/api/types";

const STAGES = [
  {
    id: "connect",
    label: "Connect",
    icon: Plug,
    href: "/connectors/?connect=aws-posture",
  },
  { id: "sync", label: "Sync", icon: RefreshCw, href: "/connectors" },
  { id: "evaluate", label: "Evaluate", icon: ShieldCheck, href: "/dashboard" },
  { id: "share", label: "Share", icon: Share2, href: "/trust-center" },
] as const;

interface Props {
  progress: number;
  shareable: boolean;
  completedBlocking: number;
  blockingTotal: number;
  currentStep: PocReadinessStep | null;
  currentHref: string | null;
}

export function OnboardingProgressHero({
  progress,
  shareable,
  completedBlocking,
  blockingTotal,
  currentStep,
  currentHref,
}: Props) {
  const readiness = usePocReadiness().data;
  // A fixture-loaded local demo has posture but no live setup; say so rather
  // than let "0% ready" read as a broken evaluation.
  const fixtureDemo =
    readiness?.access.require_auth === false &&
    readiness.connectors.enabled === 0;
  const stageIndex = Math.min(
    STAGES.length - 1,
    Math.floor((progress / 100) * STAGES.length),
  );

  return (
    <Card className="overflow-hidden text-ink">
      <div className="grid gap-5 p-5 sm:p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex min-w-0 items-center gap-3">
            <GrcLakeMark size="lg" gradientId="onboarding-mark-gradient" />
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wide text-brand">
                First-run setup
              </div>
              <div className="text-xl font-semibold tracking-tight">
                Launch your trust workspace
              </div>
              <p className="mt-1 max-w-xl text-sm font-medium text-muted">
                Connect read-only sources (no lake build required), sync
                evidence, and share auditor-ready proof — same loop agents run
                headlessly.
              </p>
            </div>
          </div>
          <Badge tone={shareable ? "ready" : "attention"}>
            {shareable ? "shareable" : `${progress}% ready`}
          </Badge>
        </div>

        {fixtureDemo && !shareable ? (
          <p
            role="note"
            data-testid="onboarding-demo-note"
            className="rounded-lg border border-line bg-info-bg px-3 py-2 text-sm text-info-fg"
          >
            Setup readiness counts live setup only: a synced connector, a public
            URL, and a trust share. This local demo&apos;s evidence was loaded
            from a sample fixture, so it is evaluated but does not count here,
            and browser sign-in is off, so the demo cannot become shareable.
          </p>
        ) : null}

        <div className="grid gap-3 sm:grid-cols-4">
          {STAGES.map((stage, index) => {
            const Icon = stage.icon;
            const done = index < stageIndex || shareable;
            const active = index === stageIndex && !shareable;
            const href =
              active && currentHref
                ? currentHref
                : stage.id === "connect"
                  ? "/connectors?onboarding=1"
                  : stage.id === "sync"
                    ? "/connectors?onboarding=1"
                    : stage.href;
            return (
              <Link
                key={stage.id}
                href={href}
                className={`rounded-xl border p-3 transition-colors ${
                  active
                    ? "border-brand bg-brand/5"
                    : done
                      ? "border-success/40 bg-success-bg"
                      : "border-line bg-surface hover:border-line-strong"
                }`}
              >
                <div className="flex items-center gap-2">
                  {done ? (
                    <CheckCircle2 className="h-4 w-4 text-success-fg" />
                  ) : (
                    <Circle
                      className={`h-4 w-4 ${active ? "text-brand" : "text-muted"}`}
                    />
                  )}
                  <Icon
                    className={`h-4 w-4 ${active ? "text-brand" : "text-muted"}`}
                  />
                  <span className="text-sm font-semibold">{stage.label}</span>
                </div>
              </Link>
            );
          })}
        </div>

        <div>
          <div className="mb-2 flex items-center justify-between text-[11px] font-semibold uppercase tracking-wide text-muted">
            <span>Blocking progress</span>
            <span>
              {completedBlocking}/{blockingTotal}
            </span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-surfaceMuted">
            <div
              className="h-full rounded-full bg-brand"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>

        {currentStep && (
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line bg-surfaceMuted p-4">
            <div className="min-w-0">
              <div className="text-[11px] font-semibold uppercase tracking-wide text-brand">
                Current step
              </div>
              <div className="font-semibold text-ink">{currentStep.label}</div>
              <p className="mt-1 text-sm text-muted">{currentStep.detail}</p>
            </div>
            {currentHref ? (
              <Button asChild variant="primary">
                <Link href={currentHref}>
                  Continue setup
                  <ArrowRight className="h-4 w-4" />
                </Link>
              </Button>
            ) : null}
          </div>
        )}
      </div>
    </Card>
  );
}

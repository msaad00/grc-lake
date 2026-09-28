"use client";

import Link from "next/link";
import {
  ArrowRight,
  CheckCircle2,
  CircleAlert,
  ListChecks,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { OnboardingProgressHero } from "@/components/onboarding/OnboardingProgressHero";
import { OnboardingQuickConnect } from "@/components/onboarding/OnboardingQuickConnect";
import { OnboardingEvidencePaths } from "@/components/onboarding/OnboardingEvidencePaths";
import { usePocReadiness } from "@/lib/api/hooks";
import type { PocReadinessStep } from "@/lib/api/types";
import { ROUTE_LABELS } from "@/lib/console-copy";

function stepHref(step: PocReadinessStep) {
  return step.console_href ?? step.href?.replace(/^\/console/, "") ?? null;
}

export default function OnboardingPage() {
  const readiness = usePocReadiness();
  const data = readiness.data;
  const onboarding = data?.onboarding;
  const progress = onboarding?.progress_percent ?? 0;
  const current = data?.next_step ?? null;

  return (
    <div className="mx-auto grid w-full max-w-3xl min-w-0 gap-2 px-3 py-2 sm:px-4">
      <PageHeader
        title={ROUTE_LABELS["/onboarding"]}
        description="Connect sources, prove sync, reach a shareable workspace."
      />

      <OnboardingEvidencePaths />

      {readiness.isLoading && (
        <Card>
          <CardContent className="p-4 text-sm text-muted">
            Loading progress…
          </CardContent>
        </Card>
      )}

      {readiness.isError && (
        <Card>
          <CardContent className="p-4 text-sm text-muted">
            Admin access is required to view onboarding progress.
          </CardContent>
        </Card>
      )}

      {data && onboarding && (
        <>
          <OnboardingProgressHero
            progress={progress}
            shareable={data.shareable}
            completedBlocking={onboarding.completed_blocking}
            blockingTotal={onboarding.blocking_total}
            currentStep={current}
            currentHref={current ? stepHref(current) : null}
          />

          <OnboardingQuickConnect />

          <Card>
            <CardHeader className="p-3 pb-2">
              <CardTitle className="ui-section-title">Checklist</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-1.5 p-3 pt-0">
              {onboarding.steps.map((step) => {
                const ready = step.status === "ready";
                const skipped = step.status === "skipped";
                const href = stepHref(step);
                return (
                  <div
                    key={step.id}
                    className="flex items-start gap-2 rounded-md border border-line bg-surface px-2.5 py-2"
                  >
                    {ready || skipped ? (
                      <CheckCircle2
                        className={`mt-0.5 h-4 w-4 shrink-0 ${ready ? "text-success-fg" : "text-muted"}`}
                      />
                    ) : (
                      <CircleAlert className="mt-0.5 h-4 w-4 shrink-0 text-warning-fg" />
                    )}
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="text-sm font-medium text-ink">
                          {step.label}
                        </span>
                        <Badge
                          tone={
                            ready ? "ready" : skipped ? "default" : "attention"
                          }
                        >
                          {ready ? "done" : skipped ? "skipped" : "todo"}
                        </Badge>
                        {!step.blocking ? (
                          <Badge tone="info">optional</Badge>
                        ) : null}
                      </div>
                      <p className="mt-0.5 text-xs leading-4 text-muted">
                        {step.detail}
                      </p>
                    </div>
                    {href && !ready ? (
                      <Button asChild variant="default" size="sm">
                        <Link href={href}>Open</Link>
                      </Button>
                    ) : null}
                  </div>
                );
              })}
            </CardContent>
          </Card>

          <div className="flex flex-wrap gap-2">
            <Button asChild variant="default" size="sm">
              <Link href="/poc">
                <ListChecks className="h-4 w-4" />
                Full checklist
              </Link>
            </Button>
            {data.shareable ? (
              <Button asChild variant="primary" size="sm">
                <Link href="/demo">
                  Demo landing
                  <ArrowRight className="h-4 w-4" />
                </Link>
              </Button>
            ) : null}
          </div>
        </>
      )}
    </div>
  );
}

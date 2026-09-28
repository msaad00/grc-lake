"use client";

import Link from "next/link";
import { ArrowRight, Database, Plug } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

const PATHS = [
  {
    icon: Plug,
    title: "Connect sources directly",
    description:
      "Use a read-only cloud, identity, SIEM, or source connector. TrustOps probes access, syncs raw observations, normalizes them, and evaluates controls.",
    href: "/connectors/?onboarding=1",
    action: "Choose a connector",
  },
  {
    icon: Database,
    title: "Bring an existing lake",
    description:
      "Read an existing Snowflake or ClickHouse lake, or normalize pre-landed raw JSONL with the CLI before evaluation.",
    href: "/connectors/?connect=snowflake-evidence-lake&onboarding=1",
    action: "Open lake path",
  },
] as const;

export function OnboardingEvidencePaths() {
  return (
    <Card className="overflow-hidden border-brand/20 bg-surfaceMuted">
      <CardHeader className="p-3 pb-2">
        <CardTitle className="text-base">
          Choose how evidence enters TrustOps
        </CardTitle>
        <p className="text-sm text-muted">
          Both paths end in the same normalized evidence → control evaluation →
          audit proof loop.
        </p>
      </CardHeader>
      <CardContent className="grid gap-2 p-3 pt-1 sm:grid-cols-2">
        {PATHS.map(({ icon: Icon, title, description, href, action }) => (
          <section
            key={title}
            className="flex min-w-0 flex-col rounded-lg border border-line bg-surface p-3"
          >
            <div className="flex items-center gap-2">
              <Icon className="h-4 w-4 text-brand" aria-hidden="true" />
              <h2 className="text-sm font-semibold text-ink">{title}</h2>
            </div>
            <p className="mt-2 flex-1 text-xs leading-5 text-muted">
              {description}
            </p>
            <Button asChild size="sm" variant="default" className="mt-3 w-fit">
              <Link href={href}>
                {action}
                <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </Button>
          </section>
        ))}
      </CardContent>
      <div className="border-t border-brand/10 px-3 py-2 text-xs text-muted">
        No local paths or raw secrets are accepted in the console. Use the CLI
        for local raw files, then connect the resulting lake through a read-only
        connector.
      </div>
    </Card>
  );
}

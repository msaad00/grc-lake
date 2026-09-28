"use client";

import Link from "next/link";
import {
  ArrowRight,
  Cloud,
  Link2,
  LogIn,
  Plug,
  Share2,
  ShieldCheck,
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
import { ConnectorEcosystemStrip } from "@/components/connectors/ConnectorEcosystemStrip";
import { useAuthMethods, usePocReadiness } from "@/lib/api/hooks";
import { resolveSignInTarget } from "@/lib/auth/sign-in";
import { BRAND } from "@/lib/brand";

const STEPS = [
  {
    title: "Sign in",
    detail:
      "Use your company SSO or the workspace sign-in link your host shared.",
    icon: LogIn,
    href: "/login",
  },
  {
    title: "Link accounts",
    detail:
      "Connect AWS, Azure, GCP, Snowflake, GitHub, or Okta with read-only scope.",
    icon: Plug,
    href: "/connectors",
  },
  {
    title: "Prove ingestion",
    detail:
      "Run probe, enable, and sync so posture updates from live evidence.",
    icon: Cloud,
    href: "/connectors",
  },
  {
    title: "Share trust",
    detail: "Issue a scoped trust-center link for auditors and customers.",
    icon: Share2,
    href: "/trust-center",
  },
] as const;

export default function DemoLandingPage() {
  const auth = useAuthMethods();
  const readiness = usePocReadiness();
  const kit = readiness.data?.demo_kit;
  const signIn = resolveSignInTarget(auth.data);

  return (
    <div className="page-shell grid gap-3">
      <PageHeader
        title={`${BRAND.name} live demo`}
        description="Evaluate continuous compliance with real account linking and evidence ingestion — not a static screenshot tour."
        actions={
          readiness.data?.shareable ? (
            <Badge tone="ready">Live workspace</Badge>
          ) : (
            <Badge tone="attention">Setup in progress</Badge>
          )
        }
      />

      <Card className="overflow-hidden">
        <CardContent className="grid gap-0 p-0 lg:grid-cols-[minmax(0,1fr)_320px]">
          <div className="border-b border-line p-6 lg:border-b-0 lg:border-r">
            <div className="flex items-center gap-2 text-brand">
              <ShieldCheck className="h-5 w-5" />
              <span className="text-sm font-semibold uppercase tracking-wide">
                Enterprise GRC-style flow
              </span>
            </div>
            <h2 className="mt-3 text-2xl font-semibold text-ink">
              Link accounts, ingest evidence, share proof
            </h2>
            <p className="mt-3 max-w-2xl text-sm leading-6 text-muted">
              {BRAND.name} keeps evidence in your boundary. Connect read-only
              sources, evaluate controls deterministically, and share redacted
              trust links without handing auditors raw lake access.
            </p>
            <div className="mt-5 flex flex-wrap gap-2">
              {signIn.external ? (
                <Button asChild variant="primary">
                  <a href={signIn.href}>
                    <LogIn className="h-4 w-4" />
                    {signIn.label}
                  </a>
                </Button>
              ) : (
                <Button asChild variant="primary">
                  <Link href={signIn.href}>
                    <LogIn className="h-4 w-4" />
                    {signIn.label}
                  </Link>
                </Button>
              )}
              <Button asChild variant="default">
                <Link href="/connectors">
                  <Plug className="h-4 w-4" />
                  Connect accounts
                </Link>
              </Button>
              <Button asChild variant="default">
                <Link href="/dashboard">
                  View posture
                  <ArrowRight className="h-4 w-4" />
                </Link>
              </Button>
            </div>
          </div>
          <div className="grid gap-3 bg-panel p-6">
            {STEPS.map(({ title, detail, icon: Icon, href }) => (
              <Link
                key={title}
                href={href}
                className="grid grid-cols-[auto_minmax(0,1fr)] gap-3 rounded-xl border border-line bg-surface p-3 transition-colors hover:border-brand"
              >
                <span className="grid h-10 w-10 place-items-center rounded-lg bg-panel text-brand ring-1 ring-line">
                  <Icon className="h-4 w-4" />
                </span>
                <span>
                  <span className="text-sm font-semibold text-ink">
                    {title}
                  </span>
                  <span className="mt-0.5 block text-xs leading-5 text-muted">
                    {detail}
                  </span>
                </span>
              </Link>
            ))}
          </div>
        </CardContent>
      </Card>

      <ConnectorEcosystemStrip />

      {readiness.isError && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Link2 className="h-5 w-5" />
              Operator links
            </CardTitle>
            <CardDescription>
              Sign in as an admin to copy hosted invite and account-linking URLs
              from the launch checklist.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button asChild variant="primary">
              <Link href="/poc">Open launch checklist</Link>
            </Button>
          </CardContent>
        </Card>
      )}

      {kit && <DemoShareKit kit={kit} />}
    </div>
  );
}

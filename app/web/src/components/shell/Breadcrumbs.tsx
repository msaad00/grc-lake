"use client";

import Link from "next/link";
import { useMemo } from "react";
import { usePathname } from "next/navigation";
import { ChevronRight } from "lucide-react";

const LABEL: Record<string, string> = {
  dashboard: "Dashboard",
  controls: "Controls",
  violations: "Findings",
  evidence: "Evidence",
  automation: "Workflows",
  graph: "Graph",
  "audit-log": "Audit log",
  connectors: "Connections",
  frameworks: "Frameworks",
  crosswalk: "Crosswalk",
  "trust-center": "Trust center",
  agents: "Agent API",
  "ai-governance": "AI governance",
  "audit-room": "Audit room",
  remediation: "Remediation",
  policies: "Policies",
  "vendor-risk": "Vendor risk",
  onboarding: "Onboarding",
  poc: "Launch",
  demo: "Demo",
  insights: "Insights",
  login: "Sign in",
  signup: "Sign up",
  invite: "Accept invite",
  "access-reviews": "Access reviews",
  risks: "Risk register",
  auth: "Access",
  deploy: "Deploy",
};

export function Breadcrumbs() {
  const pathname = usePathname() ?? "/";

  const crumbs = useMemo(() => {
    const segments = pathname.split("/").filter(Boolean);
    return segments.map((segment, idx) => ({
      segment,
      label: LABEL[segment] ?? segment,
      href: "/" + segments.slice(0, idx + 1).join("/"),
    }));
  }, [pathname]);

  // A top-level page's only crumb would repeat its own heading.
  if (crumbs.length < 2) return null;

  return (
    <nav
      aria-label="Breadcrumb"
      className="flex min-w-0 items-center gap-1.5 border-b border-line bg-surface/90 px-4 py-2 text-xs text-muted backdrop-blur sm:px-5 lg:px-7"
    >
      <Link
        href="/dashboard"
        className="inline-flex items-center gap-1.5 rounded px-1 py-0.5 font-extrabold text-muted hover:bg-surfaceMuted hover:text-ink"
      >
        Overview
      </Link>
      {crumbs.map((crumb, idx) => (
        <span key={crumb.href} className="inline-flex items-center gap-1.5">
          <ChevronRight className="h-3 w-3 text-muted/60" />
          {idx === crumbs.length - 1 ? (
            <span className="font-black text-ink">{crumb.label}</span>
          ) : (
            <Link
              href={crumb.href}
              className="rounded px-1 py-0.5 font-extrabold hover:bg-surfaceMuted hover:text-ink"
            >
              {crumb.label}
            </Link>
          )}
        </span>
      ))}
    </nav>
  );
}

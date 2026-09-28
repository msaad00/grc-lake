"use client";

import { FlowStrip, type FlowStep } from "./FlowStrip";

const STEPS: FlowStep[] = [
  {
    step: "01",
    title: "IdP sign-in",
    detail: "OIDC or SAML with Okta, Entra ID, Google, or generic IdP.",
    tone: "brand",
  },
  {
    step: "02",
    title: "Map to tenant user",
    detail: "Verified email → tenant → role (or API key for headless).",
    tone: "neutral",
  },
  {
    step: "03",
    title: "Issue session",
    detail: "HttpOnly cookie or API key hash — no parallel auth silo.",
    tone: "lake",
  },
  {
    step: "04",
    title: "Enforce RBAC",
    detail: "Scopes gate console, connectors, snapshots, and agents.",
    tone: "assess",
  },
  {
    step: "05",
    title: "Audit every request",
    detail:
      "Actor, tenant, route, decision — same boundary as hosted SSO workspaces.",
    tone: "share",
  },
];

export function AuthIdentityDiagram() {
  return (
    <div className="grid gap-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-xs font-semibold uppercase tracking-wide text-muted">
          Identity boundary
        </span>
        <span className="text-[11px] font-semibold text-muted">
          Browser SSO + API keys share one tenant and audit model
        </span>
      </div>
      <FlowStrip steps={STEPS} />
    </div>
  );
}

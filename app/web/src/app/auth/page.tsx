"use client";

import Link from "next/link";
import {
  BookOpen,
  KeyRound,
  LogIn,
  ShieldCheck,
  UserRound,
} from "lucide-react";
import { AuthMark } from "@/components/auth/AuthMark";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { AuthIdentityDiagram } from "@/components/diagrams/AuthIdentityDiagram";
import { ApiKeysPanel } from "@/components/auth/ApiKeysPanel";
import { InvitesPanel } from "@/components/auth/InvitesPanel";
import { UsersPanel } from "@/components/auth/UsersPanel";
import { BillingPanel } from "@/components/commercial/BillingPanel";
import { PlatformUsageStrip } from "@/components/commercial/PlatformUsageStrip";
import { ScimTokensPanel } from "@/components/commercial/ScimTokensPanel";
import { PageHeader } from "@/components/PageHeader";
import { QueryState } from "@/components/QueryState";
import { useAuthMethods, useAuthWhoami } from "@/lib/api/hooks";
import type { AuthMethod } from "@/lib/api/types";
import { docsUrl } from "@/lib/format";
import { ROUTE_LABELS } from "@/lib/console-copy";

function MethodRow({ method }: { method: AuthMethod }) {
  const externalLogin = method.id !== "api_key";
  return (
    <div className="grid gap-3 rounded-xl border border-line bg-surface p-4 sm:grid-cols-[auto_minmax(0,1fr)_auto] sm:items-center">
      <AuthMark
        providerKind={method.provider_kind}
        methodId={method.id}
        size="md"
      />
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-black text-ink">{method.label}</span>
          <Badge tone={method.configured ? "ready" : "attention"}>
            {method.configured ? "live" : "setup needed"}
          </Badge>
          {method.protocol && <Badge tone="info">{method.protocol}</Badge>}
        </div>
        {method.setup_hint && (
          <p className="mt-1 text-xs leading-5 text-muted">
            {method.setup_hint}
          </p>
        )}
        {method.issuer_host && (
          <p className="mt-1 truncate text-[11px] text-muted">
            Host: <code className="text-ink">{method.issuer_host}</code>
            {method.tenant_slug ? ` · tenant ${method.tenant_slug}` : ""}
          </p>
        )}
      </div>
      <div className="flex flex-wrap gap-2 sm:justify-end">
        {method.configured && externalLogin && (
          <Button asChild size="sm" variant="primary">
            <a href={method.login_url}>
              <LogIn className="h-4 w-4" />
              Sign in
            </a>
          </Button>
        )}
        {!method.configured && externalLogin && (
          <Button asChild size="sm" variant="default">
            <a
              href={docsUrl("SERVER_AUTH.md")}
              target="_blank"
              rel="noopener noreferrer"
            >
              <BookOpen className="h-4 w-4" />
              Setup guide
            </a>
          </Button>
        )}
        {method.id === "api_key" && (
          <Button asChild size="sm" variant="default">
            <a href="#api-keys">
              <KeyRound className="h-4 w-4" />
              Manage keys
            </a>
          </Button>
        )}
      </div>
    </div>
  );
}

export default function AuthPage() {
  const methods = useAuthMethods();
  const whoami = useAuthWhoami();

  return (
    <div className="page-shell grid gap-3">
      <PageHeader
        eyebrow="Access"
        title={ROUTE_LABELS["/auth"]}
        description="OIDC, SAML, and API keys share one tenant, role, and audit boundary — the same identity model as hosted enterprise GRC workspaces."
        actions={<Badge tone="ready">Server auth</Badge>}
      />

      <AuthIdentityDiagram />

      <QueryState queries={[whoami]} label="session">
        {whoami.data && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <UserRound className="h-5 w-5" />
                Current session
              </CardTitle>
            </CardHeader>
            <CardContent className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
              <div className="rounded-lg border border-line bg-panel p-3">
                <div className="text-[10px] font-black uppercase text-muted">
                  User
                </div>
                <div className="mt-1 truncate text-sm font-black text-ink">
                  {whoami.data.email}
                </div>
              </div>
              <div className="rounded-lg border border-line bg-panel p-3">
                <div className="text-[10px] font-black uppercase text-muted">
                  Role
                </div>
                <div className="mt-1 text-sm font-black text-ink">
                  {whoami.data.role}
                </div>
              </div>
              <div className="rounded-lg border border-line bg-panel p-3">
                <div className="text-[10px] font-black uppercase text-muted">
                  Tenant
                </div>
                <div className="mt-1 truncate text-sm font-black text-ink">
                  {whoami.data.tenant_id}
                </div>
              </div>
              <div className="rounded-lg border border-line bg-panel p-3">
                <div className="text-[10px] font-black uppercase text-muted">
                  Scopes
                </div>
                <div className="mt-1 text-sm font-black text-ink">
                  {whoami.data.scopes.length}
                </div>
              </div>
            </CardContent>
          </Card>
        )}
      </QueryState>

      {whoami.data?.role === "admin" ? <PlatformUsageStrip /> : null}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-brand" />
            Login methods
          </CardTitle>
          <CardDescription>
            Browser SSO uses your company IdP. API keys serve agents, CI, and
            MCP clients with the same RBAC envelope.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3">
          <QueryState queries={[methods]} label="auth methods">
            {(methods.data?.methods ?? []).map((method) => (
              <MethodRow key={method.id} method={method} />
            ))}
          </QueryState>
          <div className="flex flex-wrap gap-2">
            <Button asChild variant="default">
              <Link href="/login">Open sign-in page</Link>
            </Button>
            <Button asChild variant="default">
              <Link href="/poc">POC readiness</Link>
            </Button>
          </div>
        </CardContent>
      </Card>

      <div id="users">
        <UsersPanel />
      </div>

      <div id="invites">
        <InvitesPanel />
      </div>
      <ScimTokensPanel />
      <BillingPanel />

      <div id="api-keys">
        <ApiKeysPanel />
      </div>
    </div>
  );
}

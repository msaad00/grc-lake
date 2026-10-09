"use client";

import { useState } from "react";
import { KeyRound, Loader2, LogIn, ShieldCheck, Terminal } from "lucide-react";
import { AuthMark } from "@/components/auth/AuthMark";
import { GrcLakeLogo } from "@/components/brand/GrcLakeLogo";
import { BRAND } from "@/lib/brand";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuthMethods, useSessionFromKeyMutation } from "@/lib/api/hooks";
import type { AuthMethod } from "@/lib/api/types";
import { notify } from "@/lib/toast";
import { docsUrl } from "@/lib/format";

const SESSION_GUARANTEES = [
  {
    label: "Tenant scoped",
    detail: "A session reads and writes only its own workspace.",
  },
  {
    label: "RBAC enforced",
    detail: "Your role's scopes gate every page and API call.",
  },
  {
    label: "Audit logged",
    detail: "Sign-ins and changes land in the append-only request audit.",
  },
] as const;

function BrowserMethodCard({ method }: { method: AuthMethod }) {
  return (
    <div className="grid gap-3 rounded-xl border border-line bg-surface p-4">
      <div className="flex flex-wrap items-center gap-3">
        <AuthMark
          providerKind={method.provider_kind}
          methodId={method.id}
          size="lg"
          providerLabel={method.provider_label}
        />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-black text-ink">{method.label}</span>
            <Badge tone={method.configured ? "ready" : "attention"}>
              {method.configured ? "configured" : "not configured"}
            </Badge>
            {method.protocol && <Badge tone="info">{method.protocol}</Badge>}
          </div>
          {method.issuer_host && (
            <p className="mt-1 truncate text-xs text-muted">
              IdP host: <code className="text-ink">{method.issuer_host}</code>
            </p>
          )}
        </div>
      </div>
      {method.configured && method.setup_hint && (
        <p className="text-xs leading-5 text-muted">{method.setup_hint}</p>
      )}
      <div className="flex flex-wrap gap-2 text-[11px] text-muted">
        {method.tenant_slug && (
          <span className="rounded-full border border-line bg-panel px-2 py-0.5">
            tenant: {method.tenant_slug}
          </span>
        )}
        <span className="rounded-full border border-line bg-panel px-2 py-0.5">
          auto-provision: {method.auto_provision ? "on" : "off"}
        </span>
        {method.metadata_url && (
          <a
            href={method.metadata_url}
            className="rounded-full border border-line bg-panel px-2 py-0.5 font-bold text-brand hover:underline"
          >
            metadata
          </a>
        )}
      </div>
      {method.configured && method.id !== "api_key" && (
        <Button asChild variant="primary" size="lg">
          <a href={method.login_url}>
            <LogIn className="h-4 w-4" />
            {method.label}
          </a>
        </Button>
      )}
    </div>
  );
}

export default function LoginPage() {
  const auth = useAuthMethods();
  const sessionFromKey = useSessionFromKeyMutation();
  const [apiKey, setApiKey] = useState("");
  const data = auth.data;
  const browserMethods =
    data?.methods.filter(
      (method) => method.id === "oidc" || method.id === "saml",
    ) ?? [];
  const configured = browserMethods.filter((method) => method.configured);
  const apiKeyMethod = data?.methods.find((method) => method.id === "api_key");

  const redirectAfterLogin = () => {
    const params = new URLSearchParams(window.location.search);
    const raw = params.get("return_to");
    if (!raw || !raw.startsWith("/console")) return "/console/dashboard";
    return raw;
  };

  const submitApiKey = async () => {
    const token = apiKey.trim();
    if (!token) {
      notify.error("Paste your API key");
      return;
    }
    try {
      await sessionFromKey.mutateAsync(token);
      notify.success("Signed in with API key");
      window.location.assign(redirectAfterLogin());
    } catch (err) {
      notify.error(String((err as Error).message));
    }
  };

  return (
    <section className="grid min-h-screen place-items-center p-4 sm:p-6">
      <div className="grid w-full max-w-[980px] gap-5 lg:grid-cols-[1fr_420px]">
        <div className="order-last flex flex-col rounded-2xl border border-code-fg/15 bg-code p-8 text-code-fg shadow-hero lg:order-none">
          <GrcLakeLogo
            href="/dashboard"
            inverted
            markSize="lg"
            subtitle={BRAND.consoleSubtitle}
            className="mb-6"
            gradientId="grc-lake-login-gradient"
          />
          <Badge tone="info" className="mb-5 self-start">
            Server mode
          </Badge>
          <h1 className="max-w-[680px] text-4xl font-black leading-[1.04]">
            Sign in with your company identity provider.
          </h1>
          <p className="mt-4 max-w-[620px] text-base leading-7 text-code-fg/80">
            Browser sessions use the same tenant, RBAC scopes, and request audit
            trail as API keys. OIDC and SAML resolve to one local user record —
            no parallel auth silo.
          </p>
          <ul className="mt-8 grid gap-3 lg:mt-auto lg:pt-8">
            {SESSION_GUARANTEES.map(({ label, detail }) => (
              <li
                key={label}
                className="grid grid-cols-[auto_minmax(0,1fr)] gap-3 rounded-lg border border-code-fg/15 bg-code-fg/5 p-3"
              >
                <ShieldCheck
                  aria-hidden="true"
                  className="mt-0.5 h-4 w-4 text-info"
                />
                <span>
                  <span className="block text-sm font-extrabold text-code-fg">
                    {label}
                  </span>
                  <span className="mt-0.5 block text-sm leading-5 text-code-fg/75">
                    {detail}
                  </span>
                </span>
              </li>
            ))}
          </ul>
        </div>

        <Card className="self-stretch">
          <CardHeader>
            <CardTitle>Identity providers</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-3">
            {auth.isPending && (
              <div className="rounded-lg border border-line bg-surfaceMuted p-4 text-sm font-bold text-muted">
                Checking identity providers...
              </div>
            )}

            {!auth.isPending &&
              configured.map((method) => (
                <BrowserMethodCard key={method.id} method={method} />
              ))}

            {!auth.isPending && configured.length === 0 && (
              <div className="rounded-lg border border-line bg-surfaceMuted p-4">
                <div className="flex items-start gap-3">
                  <Terminal className="mt-0.5 h-5 w-5 text-muted" />
                  <div>
                    <div className="font-black text-ink">
                      No browser SSO provider is configured.
                    </div>
                    <p className="mt-1 text-sm leading-6 text-muted">
                      Ask your admin to enable SSO, or sign in below with an API
                      key.{" "}
                      <a
                        href={docsUrl("SERVER_AUTH.md")}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-bold text-brand hover:underline"
                      >
                        SSO setup guide
                      </a>
                    </p>
                  </div>
                </div>
                {browserMethods.map((method) => (
                  <div key={method.id} className="mt-3">
                    <BrowserMethodCard method={method} />
                  </div>
                ))}
              </div>
            )}

            {apiKeyMethod && (
              <div
                id="api-key"
                className="rounded-xl border border-dashed border-line bg-panel p-4"
              >
                <div className="flex items-center gap-2 text-sm font-black text-ink">
                  <KeyRound className="h-4 w-4 text-brand" />
                  Sign in with API key
                </div>
                <p className="mt-2 text-xs leading-5 text-muted">
                  {apiKeyMethod.setup_hint}
                </p>
                <label className="mt-3 grid gap-1.5 text-xs font-black uppercase tracking-wide text-muted">
                  Bearer token
                  <input
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    type="password"
                    autoComplete="off"
                    placeholder="tops_…"
                    className="rounded-lg border border-line bg-surface px-3 py-2 text-sm font-bold text-ink focus:outline-none focus:ring-1 focus:ring-brand"
                  />
                </label>
                <Button
                  variant="primary"
                  size="sm"
                  className="mt-3"
                  disabled={sessionFromKey.isPending}
                  onClick={submitApiKey}
                >
                  {sessionFromKey.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <KeyRound className="h-4 w-4" />
                  )}
                  Open console session
                </Button>
              </div>
            )}

            {auth.isError && (
              <div className="rounded-lg border border-warning/40 bg-warning-bg p-4 text-sm font-bold text-warning-fg">
                Auth discovery is unavailable on this server.
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </section>
  );
}

"use client";

import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ClipboardCopy,
  KeyRound,
  Loader2,
  Plus,
  Trash2,
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
import { Modal } from "@/components/ui/modal";
import { QueryState } from "@/components/QueryState";
import { BRAND } from "@/lib/brand";
import {
  useAuthKeys,
  useAuthWhoami,
  useCreateAuthKeyMutation,
  useRevokeAuthKeyMutation,
} from "@/lib/api/hooks";
import type { AuthApiKey, CreatedAuthApiKey } from "@/lib/api/types";
import { notify } from "@/lib/toast";
import { formatWhen } from "@/lib/utils";
import { displayLabel } from "@/lib/display";

const EXPIRY_OPTIONS = [
  { label: "Never", value: "" },
  { label: "30 days", value: "30" },
  { label: "90 days", value: "90" },
  { label: "365 days", value: "365" },
] as const;

function mcpConfigSnippet(apiUrl: string, token: string): string {
  return JSON.stringify(
    {
      mcpServers: {
        "grc-lake": {
          command: "grc-lake-mcp",
          env: {
            GRC_LAKE_API_URL: apiUrl,
            GRC_LAKE_API_KEY: token,
          },
        },
      },
    },
    null,
    2,
  );
}

function KeyStatusBadge({ keyRow }: { keyRow: AuthApiKey }) {
  if (keyRow.revoked) return <Badge tone="critical">revoked</Badge>;
  if (keyRow.expires_at && new Date(keyRow.expires_at) <= new Date()) {
    return <Badge tone="attention">expired</Badge>;
  }
  return <Badge tone="ready">active</Badge>;
}

export function ApiKeysPanel() {
  const whoami = useAuthWhoami();
  const keys = useAuthKeys({
    enabled: Boolean(
      whoami.data?.scopes.includes("auth_admin") ||
      whoami.data?.role === "admin",
    ),
  });
  const createKey = useCreateAuthKeyMutation();
  const revokeKey = useRevokeAuthKeyMutation();

  const [createOpen, setCreateOpen] = useState(false);
  const [revealed, setRevealed] = useState<CreatedAuthApiKey | null>(null);
  const [name, setName] = useState("cursor-mcp");
  const [userEmail, setUserEmail] = useState("");
  const [expiresDays, setExpiresDays] = useState("90");

  const isAdmin = useMemo(
    () =>
      Boolean(
        whoami.data?.role === "admin" ||
        whoami.data?.scopes.includes("auth_admin"),
      ),
    [whoami.data],
  );

  useEffect(() => {
    if (whoami.data?.email && !userEmail) {
      setUserEmail(whoami.data.email);
    }
  }, [whoami.data?.email, userEmail]);

  const apiBaseUrl =
    typeof window !== "undefined" ? window.location.origin : "";

  const copy = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      notify.success(`${label} copied`);
    } catch {
      notify.error("Clipboard unavailable");
    }
  };

  const submitCreate = async () => {
    const email = userEmail.trim();
    if (!email) {
      notify.error("User email is required");
      return;
    }
    try {
      const created = await createKey.mutateAsync({
        user_email: email,
        name: name.trim() || "api-key",
        expires_in_days: expiresDays ? Number(expiresDays) : null,
      });
      setCreateOpen(false);
      setRevealed(created);
      notify.success("API key created — copy the token now");
    } catch (err) {
      notify.error(String((err as Error).message));
    }
  };

  const revoke = async (keyRow: AuthApiKey) => {
    if (keyRow.revoked) return;
    if (
      !window.confirm(
        `Revoke key ${keyRow.prefix}? Agents and MCP clients using it will stop working.`,
      )
    ) {
      return;
    }
    try {
      await revokeKey.mutateAsync(keyRow.id);
      notify.success("API key revoked");
    } catch (err) {
      notify.error(String((err as Error).message));
    }
  };

  if (whoami.isPending) {
    return null;
  }

  if (!isAdmin) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="h-5 w-5 text-brand" />
            API keys
          </CardTitle>
          <CardDescription>
            Headless credentials for MCP, CI, and agents inherit a user role and
            RBAC scopes.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="rounded-lg border border-line bg-surfaceMuted p-4 text-sm text-muted">
            Only workspace admins can mint or revoke API keys. Your current role
            is{" "}
            <span className="font-semibold text-ink">{whoami.data?.role}</span>.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <>
      <Card>
        <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <KeyRound className="h-5 w-5 text-brand" />
              API keys
            </CardTitle>
            <CardDescription>
              Mint bearer tokens for MCP, CI, and agents. The secret is shown
              once — {BRAND.name} stores only a hash.
            </CardDescription>
          </div>
          <Button
            variant="primary"
            size="sm"
            onClick={() => setCreateOpen(true)}
          >
            <Plus className="h-4 w-4" />
            Create key
          </Button>
        </CardHeader>
        <CardContent className="grid gap-3">
          <QueryState queries={[keys]} label="API keys">
            {keys.data && keys.data.length === 0 ? (
              <div className="rounded-xl border border-dashed border-line px-4 py-8 text-center text-sm font-semibold text-muted">
                No API keys yet. Create one for Cursor MCP or CI gates.
              </div>
            ) : (
              <div className="grid gap-2">
                {(keys.data ?? []).map((keyRow) => (
                  <div
                    key={keyRow.id}
                    className="grid gap-3 rounded-xl border border-line bg-surface p-4 lg:grid-cols-[minmax(0,1fr)_auto]"
                  >
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <code className="text-sm font-semibold text-ink">
                          {keyRow.prefix}…
                        </code>
                        <KeyStatusBadge keyRow={keyRow} />
                        {keyRow.name && (
                          <Badge tone="info">{keyRow.name}</Badge>
                        )}
                        <Badge tone="default">
                          {displayLabel(keyRow.role)}
                        </Badge>
                      </div>
                      <p className="mt-1 text-xs text-muted">
                        User{" "}
                        <span className="font-semibold text-ink">
                          {keyRow.user_email}
                        </span>
                        {" · "}
                        Created {formatWhen(keyRow.created_at)}
                        {keyRow.last_used_at
                          ? ` · Last used ${formatWhen(keyRow.last_used_at)}`
                          : ""}
                        {keyRow.expires_at
                          ? ` · Expires ${formatWhen(keyRow.expires_at)}`
                          : ""}
                      </p>
                    </div>
                    <div className="flex items-start justify-end">
                      <Button
                        variant="default"
                        size="sm"
                        disabled={keyRow.revoked || revokeKey.isPending}
                        onClick={() => revoke(keyRow)}
                      >
                        {revokeKey.isPending ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <Trash2 className="h-4 w-4" />
                        )}
                        Revoke
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </QueryState>
          <p className="text-xs leading-5 text-muted">
            Keys inherit the target user&apos;s role. Use{" "}
            <code className="text-ink">contributor</code> or higher for MCP
            harness approvals. Test with{" "}
            <code className="text-ink">GET /api/v1/auth/whoami</code>.
          </p>
        </CardContent>
      </Card>

      <Modal
        open={createOpen}
        onOpenChange={setCreateOpen}
        title="Create API key"
        description="The token acts as the selected user and inherits their RBAC role."
        footer={
          <div className="flex justify-end gap-2">
            <Button variant="default" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              disabled={createKey.isPending}
              onClick={submitCreate}
            >
              {createKey.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <KeyRound className="h-4 w-4" />
              )}
              Mint key
            </Button>
          </div>
        }
      >
        <div className="grid gap-4">
          <label className="grid gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
            User email
            <input
              value={userEmail}
              onChange={(e) => setUserEmail(e.target.value)}
              className="rounded-lg border border-line bg-surface px-3 py-2 text-sm font-semibold text-ink focus:outline-none focus:ring-1 focus:ring-brand"
              placeholder="you@company.com"
            />
          </label>
          <label className="grid gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
            Label
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="rounded-lg border border-line bg-surface px-3 py-2 text-sm font-semibold text-ink focus:outline-none focus:ring-1 focus:ring-brand"
              placeholder="cursor-mcp"
            />
          </label>
          <label className="grid gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
            Expires
            <select
              value={expiresDays}
              onChange={(e) => setExpiresDays(e.target.value)}
              className="rounded-lg border border-line bg-surface px-3 py-2 text-sm font-semibold text-ink focus:outline-none focus:ring-1 focus:ring-brand"
            >
              {EXPIRY_OPTIONS.map((opt) => (
                <option key={opt.label} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </label>
        </div>
      </Modal>

      <Modal
        open={revealed !== null}
        onOpenChange={(open) => {
          if (!open) setRevealed(null);
        }}
        title="Copy your API key now"
        description="This is the only time the full token is shown. Store it in your password manager or MCP config."
        size="lg"
        footer={
          <div className="flex justify-end">
            <Button variant="primary" onClick={() => setRevealed(null)}>
              I saved the key
            </Button>
          </div>
        }
      >
        {revealed && (
          <div className="grid gap-4">
            <div className="flex items-start gap-3 rounded-xl border border-warning/40 bg-warning-bg p-3 text-sm text-warning-fg">
              <AlertTriangle className="mt-0.5 h-4 w-4 flex-none" />
              <p>
                Prefix <code className="font-semibold">{revealed.prefix}</code>{" "}
                for listings only. The bearer token below cannot be recovered
                later.
              </p>
            </div>
            <div className="grid gap-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold uppercase tracking-wide text-muted">
                  Bearer token
                </span>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => copy(revealed.token, "API key")}
                >
                  <ClipboardCopy className="h-3.5 w-3.5" />
                  Copy
                </Button>
              </div>
              <pre className="overflow-x-auto rounded-lg bg-code p-3 text-xs text-code-fg">
                {revealed.token}
              </pre>
            </div>
            <div className="grid gap-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold uppercase tracking-wide text-muted">
                  Cursor MCP config
                </span>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() =>
                    copy(
                      mcpConfigSnippet(apiBaseUrl, revealed.token),
                      "MCP config",
                    )
                  }
                >
                  <ClipboardCopy className="h-3.5 w-3.5" />
                  Copy
                </Button>
              </div>
              <pre className="max-h-48 overflow-auto rounded-lg bg-code p-3 text-xs text-code-fg">
                {mcpConfigSnippet(apiBaseUrl, revealed.token)}
              </pre>
            </div>
          </div>
        )}
      </Modal>
    </>
  );
}

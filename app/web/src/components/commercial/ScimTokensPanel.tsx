"use client";

import { useMemo, useState } from "react";
import { Copy, KeyRound, Loader2, Plus, ShieldOff } from "lucide-react";
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
import {
  useAuthWhoami,
  useCreateScimTokenMutation,
  useRevokeScimTokenMutation,
  useScimTokens,
} from "@/lib/api/hooks";
import type { CreatedScimToken, ScimToken } from "@/lib/api/types";
import { notify } from "@/lib/toast";
import { formatWhen } from "@/lib/utils";

function isNotImplemented(error: unknown): boolean {
  return String((error as Error | null)?.message ?? "").includes("501");
}

function TokenRow({
  row,
  onRevoke,
}: {
  row: ScimToken;
  onRevoke: (row: ScimToken) => void;
}) {
  const revoked = Boolean(row.revoked_at);
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-surface p-4">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-semibold text-ink">{row.name}</span>
          <code className="rounded bg-surfaceMuted px-1.5 py-0.5 text-xs text-muted">
            {row.token_prefix}…
          </code>
          <Badge tone={revoked ? "default" : "ready"}>
            {revoked ? "revoked" : "active"}
          </Badge>
        </div>
        <p className="mt-1 text-xs text-muted">
          Created {formatWhen(row.created_at)} by {row.created_by || "—"} · last
          used {formatWhen(row.last_used_at)}
        </p>
      </div>
      {!revoked ? (
        <Button size="sm" variant="default" onClick={() => onRevoke(row)}>
          <ShieldOff className="h-4 w-4" />
          Revoke
        </Button>
      ) : null}
    </div>
  );
}

export function ScimTokensPanel() {
  const whoami = useAuthWhoami();
  const isAdmin = useMemo(
    () => Boolean(whoami.data?.scopes.includes("auth_admin")),
    [whoami.data],
  );
  const tokens = useScimTokens({ enabled: isAdmin, retry: false });
  const createToken = useCreateScimTokenMutation();
  const revokeToken = useRevokeScimTokenMutation();
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("okta");
  const [revealed, setRevealed] = useState<CreatedScimToken | null>(null);
  const [pendingRevoke, setPendingRevoke] = useState<ScimToken | null>(null);

  if (!isAdmin || (tokens.isError && isNotImplemented(tokens.error))) {
    return null;
  }

  const submitCreate = async () => {
    if (!name.trim()) {
      notify.error("Token name is required");
      return;
    }
    try {
      const created = await createToken.mutateAsync(name.trim());
      setCreateOpen(false);
      setRevealed(created);
    } catch (err) {
      notify.error(String((err as Error).message));
    }
  };

  const confirmRevoke = async () => {
    if (!pendingRevoke) return;
    try {
      await revokeToken.mutateAsync(pendingRevoke.id);
      notify.success(`Revoked ${pendingRevoke.name}`);
      setPendingRevoke(null);
    } catch (err) {
      notify.error(String((err as Error).message));
    }
  };

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      notify.success("SCIM token copied");
    } catch {
      notify.error("Clipboard unavailable");
    }
  };

  const active = (tokens.data ?? []).filter((row) => !row.revoked_at);
  const revoked = (tokens.data ?? []).filter((row) => row.revoked_at);

  return (
    <>
      <Card>
        <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
          <div className="min-w-[16rem] flex-1">
            <CardTitle className="flex items-center gap-2">
              <KeyRound className="h-5 w-5 text-brand" />
              SCIM provisioning
            </CardTitle>
            <CardDescription>
              Tokens your identity provider uses to create, update, and
              deactivate users and groups. Each token only reaches this
              workspace. Rotate by creating a new token, updating the IdP, then
              revoking the old one.
            </CardDescription>
          </div>
          <Button
            variant="primary"
            size="sm"
            className="shrink-0"
            onClick={() => setCreateOpen(true)}
          >
            <Plus className="h-4 w-4" />
            New token
          </Button>
        </CardHeader>
        <CardContent className="grid gap-2">
          <QueryState queries={[tokens]} label="SCIM tokens">
            {active.length === 0 ? (
              <div className="rounded-xl border border-dashed border-line px-4 py-8 text-center text-sm font-semibold text-muted">
                No active SCIM tokens. Create one to connect Okta or Entra ID.
              </div>
            ) : (
              active.map((row) => (
                <TokenRow key={row.id} row={row} onRevoke={setPendingRevoke} />
              ))
            )}
            {revoked.length > 0 ? (
              <details className="text-xs text-muted">
                <summary className="cursor-pointer font-semibold">
                  {revoked.length} revoked
                </summary>
                <div className="mt-2 grid gap-2">
                  {revoked.map((row) => (
                    <TokenRow
                      key={row.id}
                      row={row}
                      onRevoke={setPendingRevoke}
                    />
                  ))}
                </div>
              </details>
            ) : null}
          </QueryState>
        </CardContent>
      </Card>

      <Modal
        open={createOpen}
        onOpenChange={setCreateOpen}
        title="New SCIM token"
        description="Name it after the identity provider that will use it."
        footer={
          <div className="flex justify-end gap-2">
            <Button variant="default" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              disabled={createToken.isPending}
              onClick={submitCreate}
            >
              {createToken.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Plus className="h-4 w-4" />
              )}
              Create token
            </Button>
          </div>
        }
      >
        <label className="grid gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
          Name
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="rounded-lg border border-line bg-surface px-3 py-2 text-sm font-semibold text-ink focus:outline-none focus:ring-1 focus:ring-brand"
            placeholder="okta"
          />
        </label>
      </Modal>

      <Modal
        open={revealed !== null}
        onOpenChange={(open) => {
          if (!open) setRevealed(null);
        }}
        title="Copy the SCIM token now"
        description="It is shown once and never stored. Paste it into your identity provider's SCIM app as the bearer token."
        footer={
          <div className="flex justify-end">
            <Button variant="primary" onClick={() => setRevealed(null)}>
              Done
            </Button>
          </div>
        }
      >
        {revealed ? (
          <div className="grid gap-3">
            <div className="flex items-center gap-2 rounded-lg border border-line bg-surfaceMuted p-3">
              <code className="min-w-0 flex-1 break-all text-xs text-ink">
                {revealed.token}
              </code>
              <Button
                size="sm"
                variant="default"
                onClick={() => copy(revealed.token)}
              >
                <Copy className="h-4 w-4" />
                Copy
              </Button>
            </div>
            <p className="text-xs text-muted">
              SCIM base URL:{" "}
              <code className="text-ink">
                {typeof window === "undefined" ? "" : window.location.origin}
                /api/v1/scim/v2
              </code>
            </p>
          </div>
        ) : null}
      </Modal>

      <Modal
        open={pendingRevoke !== null}
        onOpenChange={(open) => {
          if (!open) setPendingRevoke(null);
        }}
        title={`Revoke ${pendingRevoke?.name ?? "token"}?`}
        description="Provisioning calls with this token stop working immediately."
        footer={
          <div className="flex justify-end gap-2">
            <Button variant="default" onClick={() => setPendingRevoke(null)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              disabled={revokeToken.isPending}
              onClick={confirmRevoke}
            >
              {revokeToken.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <ShieldOff className="h-4 w-4" />
              )}
              Revoke
            </Button>
          </div>
        }
      >
        {null}
      </Modal>
    </>
  );
}

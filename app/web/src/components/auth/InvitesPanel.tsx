"use client";

import { useMemo, useState } from "react";
import { Loader2, MailPlus, UserPlus } from "lucide-react";
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
  useCreateInviteMutation,
  useInvites,
} from "@/lib/api/hooks";
import type { TenantInvite } from "@/lib/api/types";
import { notify } from "@/lib/toast";

const ROLES = [
  "contributor",
  "read_only",
  "auditor",
  "compliance_reviewer",
  "security_admin",
  "admin",
] as const;

function InviteStatusBadge({ row }: { row: TenantInvite }) {
  const tone =
    row.status === "pending"
      ? "attention"
      : row.status === "accepted"
        ? "ready"
        : "default";
  return <Badge tone={tone}>{row.status}</Badge>;
}

export function InvitesPanel() {
  const whoami = useAuthWhoami();
  const isAdmin = useMemo(
    () =>
      Boolean(
        whoami.data?.role === "admin" ||
        whoami.data?.scopes.includes("auth_admin"),
      ),
    [whoami.data],
  );
  const invites = useInvites({ enabled: isAdmin, retry: false });
  const createInvite = useCreateInviteMutation();
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<string>("contributor");

  const commercialUnavailable =
    invites.isError && String(invites.error?.message ?? "").includes("501");

  const submit = async () => {
    const normalized = email.trim();
    if (!normalized) {
      notify.error("Email is required");
      return;
    }
    try {
      await createInvite.mutateAsync({ email: normalized, role });
      setOpen(false);
      setEmail("");
      notify.success("Invite sent");
    } catch (err) {
      notify.error(String((err as Error).message));
    }
  };

  if (whoami.isPending) return null;

  if (!isAdmin) return null;

  return (
    <>
      <Card>
        <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <UserPlus className="h-5 w-5 text-brand" />
              Invites
            </CardTitle>
            <CardDescription>
              Invite teammates by email. Available on hosted workspaces.
            </CardDescription>
          </div>
          <Button
            variant="primary"
            size="sm"
            disabled={commercialUnavailable}
            onClick={() => setOpen(true)}
          >
            <MailPlus className="h-4 w-4" />
            Invite user
          </Button>
        </CardHeader>
        <CardContent className="grid gap-3">
          {commercialUnavailable ? (
            <p className="rounded-lg border border-line bg-surfaceMuted p-4 text-sm text-muted">
              Invites require commercial hosted mode. Provision users via CLI{" "}
              <code className="text-ink">auth create-user</code> or SSO
              auto-provision instead.
            </p>
          ) : (
            <QueryState queries={[invites]} label="invites">
              {invites.data && invites.data.length === 0 ? (
                <div className="rounded-xl border border-dashed border-line px-4 py-8 text-center text-sm font-semibold text-muted">
                  No pending invites. Invite teammates by email.
                </div>
              ) : (
                <div className="grid gap-2">
                  {(invites.data ?? []).map((row) => (
                    <div
                      key={row.id}
                      className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-line bg-surface p-4"
                    >
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-sm font-semibold text-ink">
                            {row.email}
                          </span>
                          <InviteStatusBadge row={row} />
                          <Badge tone="default">{row.role}</Badge>
                        </div>
                        <p className="mt-1 text-xs text-muted">
                          Invited by {row.invited_by}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </QueryState>
          )}
        </CardContent>
      </Card>

      <Modal
        open={open}
        onOpenChange={setOpen}
        title="Invite user"
        description="Sends an email with a one-time accept link when outbound mail is configured."
        footer={
          <div className="flex justify-end gap-2">
            <Button variant="default" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              disabled={createInvite.isPending}
              onClick={submit}
            >
              {createInvite.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <MailPlus className="h-4 w-4" />
              )}
              Send invite
            </Button>
          </div>
        }
      >
        <div className="grid gap-4">
          <label className="grid gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
            Email
            <input
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="rounded-lg border border-line bg-surface px-3 py-2 text-sm font-semibold text-ink focus:outline-none focus:ring-1 focus:ring-brand"
              placeholder="alice@company.com"
            />
          </label>
          <label className="grid gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
            Role
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="rounded-lg border border-line bg-surface px-3 py-2 text-sm font-semibold text-ink focus:outline-none focus:ring-1 focus:ring-brand"
            >
              {ROLES.map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </select>
          </label>
        </div>
      </Modal>
    </>
  );
}

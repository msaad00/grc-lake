"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import {
  useAuthWhoami,
  useAccessReview,
  useAccessReviewCoverage,
  useAccessReviewItems,
  useAccessReviews,
  useCreateAccessReviewMutation,
  useDecideAccessReviewItemMutation,
  useSeedAccessReviewMutation,
  useSetAccessReviewStatusMutation,
} from "@/lib/api/hooks";
import type {
  AccessReviewCampaign,
  AccessReviewDecision,
  AccessReviewStatus,
} from "@/lib/api/types";
import { ROUTE_LABELS } from "@/lib/console-copy";
import { QueryState } from "@/components/QueryState";
import { displayLabel } from "@/lib/display";
import { formatDate } from "@/lib/format";

const inputClass =
  "rounded-lg border border-line bg-surface px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-brand";

const STATUS_TONE: Record<
  AccessReviewStatus,
  "default" | "info" | "ready" | "attention"
> = {
  draft: "default",
  active: "info",
  completed: "ready",
  cancelled: "default",
};

// draft → active → completed; a campaign advances to the next step.
const NEXT_STATUS: Record<AccessReviewStatus, AccessReviewStatus | null> = {
  draft: "active",
  active: "completed",
  completed: null,
  cancelled: null,
};

const DECISION_TONE: Record<
  AccessReviewDecision,
  "default" | "ready" | "critical" | "attention"
> = {
  pending: "default",
  certified: "ready",
  revoked: "critical",
  flagged: "attention",
};

const DECISIONS: AccessReviewDecision[] = ["certified", "revoked", "flagged"];

function fmtDate(value: string | null): string {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "—" : parsed.toLocaleDateString();
}

function CreateCampaignForm() {
  const create = useCreateAccessReviewMutation();
  const canManage =
    useAuthWhoami().data?.scopes.includes("control_manage") === true;
  const [name, setName] = useState("");
  const [scope, setScope] = useState("all");
  const [controlId, setControlId] = useState("");

  return (
    <form
      className="flex flex-wrap items-end gap-3"
      onSubmit={(e) => {
        e.preventDefault();
        if (!canManage || !name.trim()) return;
        create.mutate(
          {
            name: name.trim(),
            scope: scope.trim() || "all",
            control_id: controlId.trim() || null,
          },
          { onSuccess: () => setName("") },
        );
      }}
    >
      <label className="flex flex-col gap-1 text-xs text-muted">
        Campaign name
        <input
          className={inputClass}
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Q3 access review"
        />
      </label>
      <label className="flex flex-col gap-1 text-xs text-muted">
        Scope (connector or all)
        <input
          className={inputClass}
          value={scope}
          onChange={(e) => setScope(e.target.value)}
          placeholder="okta-identity"
        />
      </label>
      <label className="flex flex-col gap-1 text-xs text-muted">
        Control id (optional)
        <input
          className={inputClass}
          value={controlId}
          onChange={(e) => setControlId(e.target.value)}
          placeholder="SOC2-CC6.1"
        />
      </label>
      {create.error && (
        <p role="alert" className="text-sm text-danger">
          {create.error.message}
        </p>
      )}
      <Button
        type="submit"
        variant="primary"
        disabled={!canManage || create.isPending || !name.trim()}
      >
        {create.isPending ? "Creating…" : "New campaign"}
      </Button>
    </form>
  );
}

function CampaignRow({
  campaign,
  selected,
  onSelect,
}: {
  campaign: AccessReviewCampaign;
  selected: boolean;
  onSelect: () => void;
}) {
  const setStatus = useSetAccessReviewStatusMutation();
  const canManage =
    useAuthWhoami().data?.scopes.includes("control_manage") === true;
  const next = NEXT_STATUS[campaign.status];
  return (
    <div
      className={`flex flex-wrap items-center justify-between gap-3 rounded-lg border px-4 py-3 ${
        selected ? "border-brand bg-surfaceMuted" : "border-line bg-surface"
      }`}
    >
      <button
        className="flex flex-col items-start text-left"
        onClick={onSelect}
      >
        <span className="text-sm font-medium text-ink">{campaign.name}</span>
        <span className="text-xs text-muted">
          {campaign.control_id ?? "no control"} · scope {campaign.scope} · due{" "}
          {campaign.due_at
            ? `${formatDate(campaign.due_at.slice(0, 10))} (UTC)`
            : "—"}
        </span>
      </button>
      <div className="flex items-center gap-2">
        <Badge tone={STATUS_TONE[campaign.status]}>
          {displayLabel(campaign.status)}
        </Badge>
        {next && (
          <Button
            size="sm"
            disabled={!canManage || setStatus.isPending}
            onClick={() => setStatus.mutate({ id: campaign.id, status: next })}
          >
            Mark {next}
          </Button>
        )}
      </div>
      {setStatus.error && (
        <p role="alert" className="w-full text-sm text-danger">
          {setStatus.error.message}
        </p>
      )}
    </div>
  );
}

function CampaignDetail({ campaignId }: { campaignId: string }) {
  const identity = useAuthWhoami();
  const humanReviewer = ["session:oidc", "session:saml"].includes(
    identity.data?.auth_method ?? "",
  );
  const canManage = identity.data?.scopes.includes("control_manage") === true;
  const detail = useAccessReview(campaignId);
  const items = useAccessReviewItems(campaignId);
  const seed = useSeedAccessReviewMutation();
  const decide = useDecideAccessReviewItemMutation(campaignId);
  const progress = detail.data?.progress;
  const canSeed =
    canManage && ["draft", "active"].includes(detail.data?.status ?? "");
  const active = detail.data?.status === "active";
  const terminal = ["completed", "cancelled"].includes(
    detail.data?.status ?? "",
  );

  return (
    <Card className="p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <CardHeader className="p-0">
          <CardTitle>{detail.data?.name ?? "Campaign"}</CardTitle>
        </CardHeader>
        <Button
          size="sm"
          disabled={!canSeed || seed.isPending}
          onClick={() => seed.mutate(campaignId)}
        >
          {seed.isPending ? "Seeding…" : "Seed from evidence"}
        </Button>
      </div>

      {terminal ? (
        <p className="mt-3 text-sm text-muted">
          This campaign is closed; its subjects and decisions cannot be changed.
        </p>
      ) : !active && detail.data ? (
        <p className="mt-3 text-sm text-muted">
          Decisions require an active campaign.
        </p>
      ) : null}
      {!humanReviewer && (
        <p className="mt-3 text-sm text-muted">
          Sign in with OIDC or SAML to record human review decisions.
        </p>
      )}
      {[seed.error, decide.error].filter(Boolean).map((error, index) => (
        <p key={index} role="alert" className="mt-3 text-sm text-danger">
          {error?.message}
        </p>
      ))}
      {progress && (
        <div className="mt-3 flex flex-wrap gap-2 text-xs">
          <Badge tone="default">{progress.total} subjects</Badge>
          <Badge tone="ready">{progress.certified} certified</Badge>
          <Badge tone="critical">{progress.revoked} revoked</Badge>
          <Badge tone="attention">{progress.flagged} flagged</Badge>
          <Badge tone="info">{progress.pending} pending</Badge>
        </div>
      )}

      <QueryState queries={items} label="review items">
        <div className="mt-4 space-y-2">
          {items.data?.length ? (
            items.data.map((item) => (
              <div
                key={item.id}
                className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-line px-3 py-2"
              >
                <div className="min-w-0">
                  <div className="truncate text-sm text-ink">
                    {item.subject_name || item.subject_id}
                  </div>
                  <div className="truncate text-xs text-muted">
                    {item.source} · {item.access_summary || "—"}
                  </div>
                  {item.decision !== "pending" && (
                    <p className="text-xs text-muted">
                      Recorded decisions cannot be changed.
                    </p>
                  )}
                </div>
                <div className="flex items-center gap-1.5">
                  <Badge tone={DECISION_TONE[item.decision]}>
                    {displayLabel(item.decision)}
                  </Badge>
                  {DECISIONS.map((d) => (
                    <Button
                      key={d}
                      size="sm"
                      variant={item.decision === d ? "dark" : "ghost"}
                      disabled={
                        decide.isPending ||
                        !canManage ||
                        !humanReviewer ||
                        !active ||
                        item.decision !== "pending"
                      }
                      title={
                        !humanReviewer
                          ? "Human SSO sign-in is required to record a decision"
                          : undefined
                      }
                      onClick={() => {
                        if (
                          d !== "revoked" ||
                          window.confirm(
                            `Record revoked access for ${item.subject_name}? This records the review decision and does not revoke access at the provider.`,
                          )
                        )
                          decide.mutate({ itemId: item.id, decision: d });
                      }}
                    >
                      {d}
                    </Button>
                  ))}
                </div>
              </div>
            ))
          ) : (
            <p className="text-sm text-muted">
              No items yet. Use “Seed from evidence” to pull the identities in
              the lake into this review.
            </p>
          )}
        </div>
      </QueryState>
    </Card>
  );
}

function CoveragePanel() {
  const coverage = useAccessReviewCoverage();
  if (!coverage.data?.length) return null;
  return (
    <Card className="p-5">
      <CardHeader className="p-0">
        <CardTitle>Control coverage</CardTitle>
      </CardHeader>
      <div className="mt-3 space-y-2">
        {coverage.data.map((row) => (
          <div
            key={row.control_id}
            className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-line px-3 py-2 text-sm"
          >
            <div>
              <span className="font-medium text-ink">{row.control_id}</span>{" "}
              <span className="text-xs text-muted">
                {row.framework ?? ""} · last reviewed{" "}
                {fmtDate(row.last_completed_at)}
              </span>
            </div>
            <Badge tone={row.current ? "ready" : "attention"}>
              {row.current ? "current" : "needs review"}
            </Badge>
          </div>
        ))}
      </div>
    </Card>
  );
}

export default function AccessReviewsPage() {
  const campaigns = useAccessReviews();
  const canManage =
    useAuthWhoami().data?.scopes.includes("control_manage") === true;
  const [selectedId, setSelectedId] = useState<string | null>(null);

  return (
    <div className="page-shell space-y-6">
      <PageHeader
        title={ROUTE_LABELS["/access-reviews"]}
        description="Run periodic user-access certification campaigns: seed the identities in your lake, certify or revoke each one, and prove each access control is under a current review."
      />

      {!canManage && (
        <p className="text-sm text-muted">
          Your role can view access reviews. Managing campaigns and decisions
          requires control management permission.
        </p>
      )}
      <Card className="p-5">
        <CardHeader className="p-0">
          <CardTitle>New campaign</CardTitle>
        </CardHeader>
        <div className="mt-3">
          <CreateCampaignForm />
        </div>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <QueryState queries={campaigns} label="access review campaigns">
          <div className="space-y-2">
            {campaigns.data?.length ? (
              campaigns.data.map((c) => (
                <CampaignRow
                  key={c.id}
                  campaign={c}
                  selected={c.id === selectedId}
                  onSelect={() => setSelectedId(c.id)}
                />
              ))
            ) : (
              <p className="text-sm text-muted">No campaigns yet.</p>
            )}
          </div>
        </QueryState>
        <div className="space-y-6">
          {selectedId ? (
            <CampaignDetail campaignId={selectedId} />
          ) : (
            <Card className="p-5 text-sm text-muted">
              Select a campaign to review its subjects.
            </Card>
          )}
          <CoveragePanel />
        </div>
      </div>
    </div>
  );
}

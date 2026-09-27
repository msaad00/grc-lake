"use client";

import { useMemo, useRef, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { QueryState } from "@/components/QueryState";
import {
  useAdoptPolicyMutation,
  usePolicies,
  usePolicy,
  usePolicyAcknowledgments,
  usePolicyAttestationSummary,
  usePolicyCoverage,
  usePolicyTemplates,
  usePublishPolicyMutation,
  useRecordPolicyAcknowledgmentMutation,
  useUpdatePolicyMutation,
} from "@/lib/api/hooks";
import type {
  PolicyDocument,
  PolicyDocumentStatus,
  PolicyTemplateSummary,
} from "@/lib/api/types";
import { ROUTE_LABELS } from "@/lib/console-copy";

const inputClass =
  "rounded-lg border border-line bg-surface px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-brand";

const STATUS_TONE: Record<
  PolicyDocumentStatus,
  "default" | "info" | "ready" | "attention"
> = {
  draft: "default",
  published: "ready",
  archived: "attention",
};

function AdoptTemplateForm({
  template,
  onAdopted,
}: {
  template: PolicyTemplateSummary;
  onAdopted: (doc: PolicyDocument) => void;
}) {
  const adopt = useAdoptPolicyMutation();
  const [companyName, setCompanyName] = useState("Acme Corp");
  const [owner, setOwner] = useState("security@company.com");

  return (
    <form
      className="flex flex-wrap items-end gap-3"
      onSubmit={(e) => {
        e.preventDefault();
        const variables: Record<string, string> = {
          company_name: companyName.trim(),
          policy_owner: owner.trim(),
          effective_date: new Date().toISOString().slice(0, 10),
        };
        for (const key of template.variables) {
          if (!(key in variables)) variables[key] = "";
        }
        adopt.mutate(
          {
            template_id: template.template_id,
            variables,
            owner: owner.trim(),
          },
          { onSuccess: onAdopted },
        );
      }}
    >
      <label className="flex flex-col gap-1 text-xs text-muted">
        Company name
        <input
          className={inputClass}
          value={companyName}
          onChange={(e) => setCompanyName(e.target.value)}
        />
      </label>
      <label className="flex flex-col gap-1 text-xs text-muted">
        Policy owner
        <input
          className={inputClass}
          value={owner}
          onChange={(e) => setOwner(e.target.value)}
        />
      </label>
      <Button type="submit" variant="primary" disabled={adopt.isPending}>
        {adopt.isPending ? "Adopting…" : `Adopt ${template.title}`}
      </Button>
    </form>
  );
}

function PolicyDetail({ documentId }: { documentId: string }) {
  const detail = usePolicy(documentId);
  const acknowledgments = usePolicyAcknowledgments(documentId);
  const recordAck = useRecordPolicyAcknowledgmentMutation(documentId);
  const update = useUpdatePolicyMutation(documentId);
  const publish = usePublishPolicyMutation();
  const doc = detail.data;
  const [content, setContent] = useState("");

  const draftContent = content || doc?.content || "";

  if (!doc) {
    return <Card className="p-5 text-sm text-muted">Loading policy…</Card>;
  }

  return (
    <Card className="space-y-4 p-5">
      <CardHeader className="p-0">
        <CardTitle className="flex flex-wrap items-center gap-2">
          {doc.title}
          <Badge tone={STATUS_TONE[doc.status]}>{doc.status}</Badge>
        </CardTitle>
      </CardHeader>
      <p className="text-xs text-muted">
        Template {doc.template_id} · updated{" "}
        {new Date(doc.updated_at).toLocaleDateString()}
      </p>
      <textarea
        className="min-h-64 w-full rounded-lg border border-line bg-surface p-3 font-mono text-xs"
        value={draftContent}
        disabled={doc.status === "published" || update.isPending}
        onChange={(e) => setContent(e.target.value)}
      />
      {doc.status !== "published" ? (
        <div className="flex flex-wrap gap-2">
          <Button
            variant="default"
            disabled={update.isPending || !content}
            onClick={() => update.mutate({ content: draftContent })}
          >
            {update.isPending ? "Saving…" : "Save draft"}
          </Button>
          <Button
            variant="primary"
            disabled={publish.isPending}
            onClick={() => publish.mutate(documentId)}
          >
            {publish.isPending ? "Publishing…" : "Publish"}
          </Button>
        </div>
      ) : (
        <div className="space-y-3 rounded-lg border border-line bg-surfaceMuted p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <p className="text-sm font-bold text-ink">
                Employee acknowledgments
              </p>
              <p className="text-xs text-muted">
                Sign-offs recorded here become attestation evidence for
                auditors.
              </p>
            </div>
            <Button
              variant="primary"
              size="sm"
              disabled={recordAck.isPending}
              onClick={() => recordAck.mutate({})}
            >
              {recordAck.isPending ? "Recording…" : "Record my acknowledgment"}
            </Button>
          </div>
          {acknowledgments.data && acknowledgments.data.length > 0 ? (
            <ul className="grid gap-2 text-sm">
              {acknowledgments.data.map((row) => (
                <li
                  key={row.id}
                  className="flex flex-wrap items-center justify-between gap-2 rounded border border-line bg-surface px-3 py-2"
                >
                  <span className="font-medium text-ink">{row.user_email}</span>
                  <span className="text-xs text-muted">
                    {new Date(row.acknowledged_at).toLocaleString()}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-muted">
              No acknowledgments recorded yet.
            </p>
          )}
        </div>
      )}
    </Card>
  );
}

function PolicyRow({
  policy,
  selected,
  onSelect,
}: {
  policy: PolicyDocument;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={`w-full rounded-lg border px-3 py-3 text-left text-sm transition ${
        selected
          ? "border-brand bg-brand/5"
          : "border-line hover:border-brand/30"
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-medium text-ink">{policy.title}</span>
        <Badge tone={STATUS_TONE[policy.status]}>{policy.status}</Badge>
      </div>
      <p className="mt-1 text-xs text-muted">Owner {policy.owner || "—"}</p>
    </button>
  );
}

export default function PoliciesPage() {
  const templates = usePolicyTemplates();
  const policies = usePolicies();
  const coverage = usePolicyCoverage();
  const attestation = usePolicyAttestationSummary();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [templateId, setTemplateId] = useState<string | null>(null);
  const adoptRef = useRef<HTMLDivElement>(null);
  const selectedTemplate =
    templates.data?.find((t) => t.template_id === templateId) ??
    templates.data?.[0];
  const templateIds = useMemo(
    () => new Set((templates.data ?? []).map((t) => t.template_id)),
    [templates.data],
  );

  const gaps = useMemo(
    () => (coverage.data ?? []).filter((row) => !row.published).slice(0, 8),
    [coverage.data],
  );

  const chooseTemplate = (id: string, scroll = false) => {
    setTemplateId(id);
    if (scroll) {
      adoptRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  };

  return (
    <div className="page-shell space-y-6">
      <PageHeader
        eyebrow="Governance"
        title={ROUTE_LABELS["/policies"]}
        description="Browse bundled SOC 2 and ISO-aligned policy templates, adopt them for your tenant, edit markdown drafts, and publish to prove control coverage."
      />

      <QueryState
        queries={[templates, policies, coverage, attestation]}
        label="policy library"
      >
        {attestation.data && attestation.data.published > 0 && (
          <Card className="grid gap-2 p-5 sm:grid-cols-4">
            <div>
              <p className="text-xs text-muted">Published policies</p>
              <p className="text-lg font-bold text-ink">
                {attestation.data.published}
              </p>
            </div>
            <div>
              <p className="text-xs text-muted">With acknowledgments</p>
              <p className="text-lg font-bold text-ink">
                {attestation.data.acknowledged}
              </p>
            </div>
            <div>
              <p className="text-xs text-muted">Unattested</p>
              <p className="text-lg font-bold text-ink">
                {attestation.data.unattested}
              </p>
            </div>
            <div>
              <p className="text-xs text-muted">Total attestations</p>
              <p className="text-lg font-bold text-ink">
                {attestation.data.total_acknowledgments}
              </p>
            </div>
          </Card>
        )}

        <Card className="p-5">
          <CardHeader className="p-0">
            <CardTitle>Templates</CardTitle>
          </CardHeader>
          <p className="mt-1 text-xs text-muted">
            Choose a template to adopt it for your workspace.
          </p>
          <div
            role="group"
            aria-label="Policy templates"
            className="mt-3 grid gap-2 sm:grid-cols-2"
          >
            {templates.data?.map((template) => {
              const selected =
                template.template_id === selectedTemplate?.template_id;
              return (
                <button
                  key={template.template_id}
                  type="button"
                  aria-pressed={selected}
                  onClick={() => chooseTemplate(template.template_id)}
                  className={`min-w-0 rounded-lg border px-3 py-2 text-left text-sm transition focus:outline-none focus-visible:ring-2 focus-visible:ring-brand ${
                    selected
                      ? "border-brand bg-brand/5 ring-1 ring-brand"
                      : "border-line hover:border-brand/40"
                  }`}
                >
                  <span className="block font-medium text-ink">
                    {template.title}
                  </span>
                  <span className="block text-xs text-muted">
                    {template.category?.replaceAll("_", " ")} ·{" "}
                    {template.related_control_ids.length}{" "}
                    {template.related_control_ids.length === 1
                      ? "control"
                      : "controls"}
                  </span>
                  <span className="mt-1 block text-xs text-muted">
                    {template.summary}
                  </span>
                </button>
              );
            }) ?? <p className="text-sm text-muted">Loading templates…</p>}
          </div>
        </Card>

        {selectedTemplate ? (
          <div ref={adoptRef}>
            <Card className="p-5">
              <CardHeader className="p-0">
                <CardTitle>Adopt {selectedTemplate.title}</CardTitle>
              </CardHeader>
              <div className="mt-3">
                <AdoptTemplateForm
                  template={selectedTemplate}
                  onAdopted={(doc) => setSelectedId(doc.id)}
                />
              </div>
            </Card>
          </div>
        ) : null}

        <div className="grid gap-6 lg:grid-cols-2">
          <div className="space-y-2">
            {policies.data?.length ? (
              policies.data.map((row) => (
                <PolicyRow
                  key={row.id}
                  policy={row}
                  selected={row.id === selectedId}
                  onSelect={() => setSelectedId(row.id)}
                />
              ))
            ) : (
              <p className="text-sm text-muted">No adopted policies yet.</p>
            )}
          </div>
          <div className="space-y-6">
            {selectedId ? (
              <PolicyDetail key={selectedId} documentId={selectedId} />
            ) : (
              <Card className="p-5 text-sm text-muted">
                Select a policy to edit or publish.
              </Card>
            )}
            <Card className="p-5">
              <CardHeader className="p-0">
                <CardTitle>Control coverage gaps</CardTitle>
              </CardHeader>
              <div className="mt-3 space-y-2">
                {gaps.length ? (
                  gaps.map((row) => {
                    const covering = row.template_ids.find((id) =>
                      templateIds.has(id),
                    );
                    return (
                      <div
                        key={row.control_id}
                        className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-line px-3 py-2 text-sm"
                      >
                        <div className="min-w-0">
                          <span className="font-medium text-ink">
                            {row.control_id}
                          </span>
                          <span className="ml-2 text-xs text-muted">
                            {row.title}
                          </span>
                        </div>
                        {covering ? (
                          <Button
                            size="sm"
                            variant="default"
                            onClick={() => chooseTemplate(covering, true)}
                          >
                            Adopt a covering policy
                          </Button>
                        ) : null}
                      </div>
                    );
                  })
                ) : (
                  <p className="text-sm text-muted">
                    No policy coverage gaps detected.
                  </p>
                )}
              </div>
            </Card>
          </div>
        </div>
      </QueryState>
    </div>
  );
}

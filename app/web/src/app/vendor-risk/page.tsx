"use client";

import { useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { QueryState } from "@/components/QueryState";
import {
  useCreateVendorAssessmentMutation,
  useSubmitVendorAssessmentMutation,
  useUpdateVendorAssessmentMutation,
  useVendorAssessment,
  useVendorAssessments,
  useVendorQuestionnaires,
} from "@/lib/api/hooks";
import type {
  VendorAnswer,
  VendorAssessment,
  VendorAssessmentStatus,
  VendorQuestionnaireQuestion,
  VendorQuestionnaireTemplateSummary,
  VendorRiskLevel,
} from "@/lib/api/types";
import { ROUTE_LABELS } from "@/lib/console-copy";
import { displayLabel } from "@/lib/display";

const inputClass =
  "rounded-lg border border-line bg-surface px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-brand";

const STATUS_TONE: Record<
  VendorAssessmentStatus,
  "default" | "info" | "ready" | "attention" | "critical"
> = {
  draft: "default",
  in_review: "info",
  completed: "ready",
  rejected: "critical",
};

const RISK_TONE: Record<
  VendorRiskLevel,
  "default" | "ready" | "attention" | "critical"
> = {
  low: "ready",
  medium: "attention",
  high: "attention",
  critical: "critical",
};

const ANSWERS: VendorAnswer[] = ["yes", "partial", "no", "na"];

function fmtDate(value: string | null): string {
  if (!value) return "—";
  return new Date(value).toLocaleDateString();
}

function responseAnswer(
  responses: VendorAssessment["responses"],
  questionId: string,
): VendorAnswer | "" {
  const raw = responses[questionId];
  if (typeof raw === "string") return raw as VendorAnswer;
  if (raw && typeof raw === "object" && "answer" in raw) {
    return (raw.answer as VendorAnswer) || "";
  }
  return "";
}

const VENDOR_NAME_INPUT_ID = "vendor-name";

function CreateAssessmentForm({
  templates,
  defaultTemplateId,
}: {
  templates: VendorQuestionnaireTemplateSummary[];
  defaultTemplateId: string;
}) {
  const create = useCreateVendorAssessmentMutation();
  const [vendorName, setVendorName] = useState("");
  const [templateId, setTemplateId] = useState(defaultTemplateId);
  const [owner, setOwner] = useState("");
  const [nameError, setNameError] = useState(false);
  const selectedTemplateId = templateId || defaultTemplateId;

  return (
    <form
      noValidate
      className="flex flex-wrap items-start gap-3"
      onSubmit={(e) => {
        e.preventDefault();
        if (!vendorName.trim()) {
          setNameError(true);
          document.getElementById(VENDOR_NAME_INPUT_ID)?.focus();
          return;
        }
        if (!selectedTemplateId) return;
        create.mutate(
          {
            vendor_name: vendorName.trim(),
            template_id: selectedTemplateId,
            owner: owner.trim(),
          },
          {
            onSuccess: () => {
              setVendorName("");
              setOwner("");
            },
          },
        );
      }}
    >
      <div className="flex flex-col gap-1 text-xs text-muted">
        <label htmlFor={VENDOR_NAME_INPUT_ID}>Vendor name</label>
        <input
          id={VENDOR_NAME_INPUT_ID}
          className={`${inputClass} ${nameError ? "border-critical" : ""}`}
          value={vendorName}
          aria-invalid={nameError}
          aria-describedby={nameError ? "vendor-name-error" : undefined}
          onChange={(e) => {
            setVendorName(e.target.value);
            if (e.target.value.trim()) setNameError(false);
          }}
          placeholder="Acme SaaS"
        />
        {nameError && (
          <span
            id="vendor-name-error"
            role="alert"
            className="font-semibold text-critical"
          >
            Enter a vendor name.
          </span>
        )}
      </div>
      <label className="flex flex-col gap-1 text-xs text-muted">
        Template
        <select
          className={inputClass}
          value={selectedTemplateId}
          onChange={(e) => setTemplateId(e.target.value)}
        >
          {templates.map((template) => (
            <option key={template.template_id} value={template.template_id}>
              {template.name}
            </option>
          ))}
        </select>
      </label>
      <label className="flex flex-col gap-1 text-xs text-muted">
        Owner (optional)
        <input
          className={inputClass}
          value={owner}
          onChange={(e) => setOwner(e.target.value)}
          placeholder="security@company.com"
        />
      </label>
      <Button
        type="submit"
        variant="primary"
        className="mt-5"
        disabled={create.isPending || templates.length === 0}
      >
        {create.isPending ? "Creating…" : "New assessment"}
      </Button>
    </form>
  );
}

function QuestionRow({
  question,
  value,
  disabled,
  onChange,
}: {
  question: VendorQuestionnaireQuestion;
  value: VendorAnswer | "";
  disabled: boolean;
  onChange: (answer: VendorAnswer) => void;
}) {
  return (
    <div className="space-y-2 rounded-lg border border-line px-3 py-3 text-sm">
      <p className="font-medium text-ink">
        {question.prompt}
        {question.required ? (
          <span className="ml-1 text-critical">*</span>
        ) : null}
      </p>
      <p className="text-xs text-muted">
        {question.risk_domains.join(" · ")} ·{" "}
        {question.safeguard_ids.join(", ")} · {question.mapping_status}
      </p>
      <div className="flex flex-wrap gap-2">
        {ANSWERS.map((answer) => {
          if (answer === "na" && question.required) return null;
          const selected = value === answer;
          return (
            <button
              key={answer}
              type="button"
              disabled={disabled}
              onClick={() => onChange(answer)}
              className={`rounded-full border px-3 py-1 text-xs capitalize transition ${
                selected
                  ? "border-brand bg-brand/10 text-brand"
                  : "border-line text-muted hover:border-brand/40"
              }`}
            >
              {answer}
            </button>
          );
        })}
      </div>
    </div>
  );
}

function AssessmentDetail({
  assessmentId,
  templateName,
}: {
  assessmentId: string;
  templateName: (id: string) => string;
}) {
  const detail = useVendorAssessment(assessmentId);
  const update = useUpdateVendorAssessmentMutation(assessmentId);
  const submit = useSubmitVendorAssessmentMutation();
  const assessment = detail.data;
  const [draftResponses, setDraftResponses] = useState<
    Record<string, VendorAnswer>
  >({});

  const questions = useMemo(() => {
    const sections = assessment?.template?.sections ?? [];
    return sections.flatMap((section) =>
      (section.questions ?? []).map((q) => ({
        ...q,
        section_title: section.title,
      })),
    );
  }, [assessment?.template?.sections]);

  if (!assessment) {
    return <Card className="p-5 text-sm text-muted">Loading assessment…</Card>;
  }

  const locked = assessment.status === "completed";
  const responses = { ...assessment.responses };
  for (const [qid, answer] of Object.entries(draftResponses)) {
    responses[qid] = { answer };
  }

  return (
    <Card className="space-y-4 p-5">
      <CardHeader className="p-0">
        <CardTitle className="flex flex-wrap items-center gap-2">
          {assessment.vendor_name}
          <Badge tone={STATUS_TONE[assessment.status]}>
            {displayLabel(assessment.status)}
          </Badge>
          {assessment.risk_level ? (
            <Badge tone={RISK_TONE[assessment.risk_level]}>
              {assessment.risk_level} risk
            </Badge>
          ) : null}
          {assessment.score != null ? (
            <span className="text-sm font-normal text-muted">
              Score {assessment.score}
            </span>
          ) : null}
        </CardTitle>
      </CardHeader>
      <p className="text-xs text-muted">
        {templateName(assessment.template_id)} · due{" "}
        {fmtDate(assessment.due_at)} · updated {fmtDate(assessment.updated_at)}
      </p>

      {questions.length ? (
        <div className="space-y-3">
          {questions.map((question) => (
            <QuestionRow
              key={question.question_id}
              question={question}
              value={
                draftResponses[question.question_id] ??
                responseAnswer(responses, question.question_id)
              }
              disabled={locked || update.isPending}
              onChange={(answer) =>
                setDraftResponses((prev) => ({
                  ...prev,
                  [question.question_id]: answer,
                }))
              }
            />
          ))}
        </div>
      ) : (
        <p className="text-sm text-muted">Questionnaire template not loaded.</p>
      )}

      {!locked ? (
        <div className="flex flex-wrap gap-2">
          <Button
            variant="default"
            disabled={update.isPending || !Object.keys(draftResponses).length}
            onClick={() => {
              const payload: Record<string, { answer: string }> = {};
              for (const [qid, answer] of Object.entries(draftResponses)) {
                payload[qid] = { answer };
              }
              update.mutate(
                { responses: payload, status: "in_review" },
                { onSuccess: () => setDraftResponses({}) },
              );
            }}
          >
            {update.isPending ? "Saving…" : "Save responses"}
          </Button>
          <Button
            variant="primary"
            disabled={submit.isPending}
            onClick={() => submit.mutate(assessmentId)}
          >
            {submit.isPending ? "Scoring…" : "Submit & score"}
          </Button>
        </div>
      ) : null}
    </Card>
  );
}

function AssessmentRow({
  assessment,
  templateName,
  selected,
  onSelect,
}: {
  assessment: VendorAssessment;
  templateName: string;
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
        <span className="font-medium text-ink">{assessment.vendor_name}</span>
        <div className="flex flex-wrap gap-2">
          <Badge tone={STATUS_TONE[assessment.status]}>
            {displayLabel(assessment.status)}
          </Badge>
          {assessment.risk_level ? (
            <Badge tone={RISK_TONE[assessment.risk_level]}>
              {displayLabel(assessment.risk_level)}
            </Badge>
          ) : null}
        </div>
      </div>
      <p className="mt-1 text-xs text-muted">
        {templateName}
        {assessment.score != null ? ` · score ${assessment.score}` : ""}
      </p>
    </button>
  );
}

export default function VendorRiskPage() {
  const templates = useVendorQuestionnaires();
  const assessments = useVendorAssessments();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const defaultTemplateId = templates.data?.[0]?.template_id ?? "";
  const templateName = (id: string) =>
    templates.data?.find((t) => t.template_id === id)?.name ?? id;

  return (
    <div className="page-shell space-y-6">
      <PageHeader
        title={ROUTE_LABELS["/vendor-risk"]}
        description="Run standardized vendor diligence questionnaires, capture yes/partial/no answers, and score third-party readiness against SOC 2 vendor-risk controls."
      />

      <QueryState queries={[templates, assessments]} label="vendor risk">
        <Card className="p-5">
          <CardHeader className="p-0">
            <CardTitle>Questionnaire templates</CardTitle>
          </CardHeader>
          <div className="mt-3 grid gap-2 sm:grid-cols-2">
            {templates.data?.map((template) => (
              <div
                key={template.template_id}
                className="rounded-lg border border-line px-3 py-2 text-sm"
              >
                <p className="font-medium text-ink">{template.name}</p>
                <p className="text-xs text-muted">
                  {template.question_count} questions
                </p>
                <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-muted">
                  <Badge
                    tone={
                      template.mapping_status === "reviewed"
                        ? "ready"
                        : "attention"
                    }
                  >
                    {displayLabel(template.mapping_status)}
                  </Badge>
                  <span>
                    {template.mapped_question_count}/{template.question_count}{" "}
                    mapped · {template.safeguard_ids.length} safeguards ·{" "}
                    {template.framework_ids.length} frameworks ·{" "}
                    {template.risk_domains.length} risk domains
                  </span>
                </div>
              </div>
            )) ?? <p className="text-sm text-muted">Loading templates…</p>}
          </div>
        </Card>

        <Card className="p-5">
          <CardHeader className="p-0">
            <CardTitle>New vendor assessment</CardTitle>
          </CardHeader>
          <div className="mt-3">
            <CreateAssessmentForm
              templates={templates.data ?? []}
              defaultTemplateId={defaultTemplateId}
            />
          </div>
        </Card>

        <div className="grid gap-6 lg:grid-cols-2">
          <div className="space-y-2">
            {assessments.data?.length ? (
              assessments.data.map((row) => (
                <AssessmentRow
                  key={row.id}
                  assessment={row}
                  templateName={templateName(row.template_id)}
                  selected={row.id === selectedId}
                  onSelect={() => setSelectedId(row.id)}
                />
              ))
            ) : (
              <Card className="grid gap-3 border-dashed p-5">
                <p className="text-sm font-semibold text-ink">
                  Start your first vendor review
                </p>
                <p className="text-sm leading-6 text-muted">
                  Add a vendor above, pick a questionnaire, then answer or send
                  the questions. Submitting scores the vendor&apos;s risk
                  against your third-party controls.
                </p>
                <div>
                  <Button
                    variant="primary"
                    size="sm"
                    onClick={() =>
                      document.getElementById(VENDOR_NAME_INPUT_ID)?.focus()
                    }
                  >
                    Start a vendor review
                  </Button>
                </div>
              </Card>
            )}
          </div>
          <div>
            {selectedId ? (
              <AssessmentDetail
                key={selectedId}
                assessmentId={selectedId}
                templateName={templateName}
              />
            ) : (
              <Card className="p-5 text-sm text-muted">
                Select an assessment to answer its questionnaire.
              </Card>
            )}
          </div>
        </div>
      </QueryState>
    </div>
  );
}

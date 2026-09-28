"use client";

import { Badge } from "@/components/ui/badge";
import { useControlRemediation } from "@/lib/api/hooks";

export function RemediationGuidance({
  controlId,
}: {
  controlId: string | null;
}) {
  const remediation = useControlRemediation(controlId);
  if (!remediation.data) return null;
  const { matched, summary, steps, references } = remediation.data;
  return (
    <section
      aria-label="Suggested remediation"
      className="rounded-lg border border-line bg-surfaceMuted p-3"
    >
      <div className="mb-1 text-xs font-medium text-muted">
        Suggested remediation
        {!matched && (
          <Badge tone="default" className="ml-2 normal-case">
            general guidance
          </Badge>
        )}
      </div>
      <p className="text-sm text-ink">{summary}</p>
      {steps.length > 0 && (
        <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm text-ink">
          {steps.map((step, i) => (
            <li key={i}>{step}</li>
          ))}
        </ol>
      )}
      {references.length > 0 && (
        <div className="mt-2 text-xs text-muted">{references.join(" · ")}</div>
      )}
    </section>
  );
}

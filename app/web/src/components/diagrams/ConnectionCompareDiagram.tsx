"use client";

import { BRAND } from "@/lib/brand";

function evidenceSteps(name: string) {
  return [
    "Read-only IAM roles, OAuth apps, or API tokens",
    `The ${name} scheduler syncs each source`,
    "Raw evidence lands in your lake or warehouse",
    "Deterministic control tests score posture",
  ] as const;
}

/** Where evidence travels: from read-only sources into the customer's lake. */
export function ConnectionCompareDiagram() {
  const steps = evidenceSteps(BRAND.name);
  return (
    <div className="grid min-w-0 gap-3 overflow-hidden">
      <div className="overflow-hidden rounded-xl border border-line bg-surface p-4">
        <div className="mb-3 overflow-hidden rounded-lg border border-success/40 bg-success-bg px-3 py-2 text-success-fg">
          <div className="truncate text-[11px] font-semibold uppercase tracking-wide opacity-80">
            {BRAND.name}
          </div>
          <div className="truncate text-sm font-semibold">
            Customer-owned lake
          </div>
        </div>
        <ol className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {steps.map((step, index) => (
            <li
              key={step}
              className="grid grid-cols-[auto_minmax(0,1fr)] items-start gap-2 overflow-hidden text-xs leading-5 text-muted"
            >
              <span className="grid h-6 w-6 shrink-0 place-items-center rounded-md bg-panel text-[10px] font-semibold text-ink ring-1 ring-line">
                {index + 1}
              </span>
              <span className="min-w-0">{step}</span>
            </li>
          ))}
        </ol>
      </div>
      <p className="line-clamp-3 text-xs leading-5 text-muted">
        AWS cross-account IAM, GitHub App tokens, and Okta/Google read-only
        scopes use the same connection patterns — {BRAND.name} stores raw events
        in your boundary.
      </p>
    </div>
  );
}

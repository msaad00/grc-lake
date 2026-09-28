"use client";

import { ArrowRight } from "lucide-react";
import { BRAND } from "@/lib/brand";

const SAAS_STEPS = [
  "Read-only IAM role / OAuth / API token",
  "Vendor SaaS pulls on schedule",
  "Evidence in vendor database",
  "Automated control tests",
] as const;

function customerSteps(name: string) {
  return [
    "Same read-only roles & tokens",
    `Your ${name} scheduler syncs`,
    "Evidence in your /lake or warehouse",
    "Deterministic control tests",
  ] as const;
}

function Column({
  title,
  eyebrow,
  steps,
  accent,
}: {
  title: string;
  eyebrow: string;
  steps: readonly string[];
  accent: "vendor" | "customer";
}) {
  const header =
    accent === "vendor"
      ? "border-danger/40 bg-danger-bg text-danger-fg"
      : "border-success/40 bg-success-bg text-success-fg";
  return (
    <div className="grid min-w-0 gap-2 overflow-hidden rounded-xl border border-line bg-surface p-4">
      <div className={`overflow-hidden rounded-lg border px-3 py-2 ${header}`}>
        <div className="truncate text-[11px] font-semibold uppercase tracking-wide opacity-80">
          {eyebrow}
        </div>
        <div className="truncate text-sm font-semibold">{title}</div>
      </div>
      <ol className="grid gap-2">
        {steps.map((step, index) => (
          <li
            key={step}
            className="grid grid-cols-[auto_minmax(0,1fr)] items-start gap-2 overflow-hidden text-xs leading-5 text-muted"
          >
            <span className="grid h-6 w-6 shrink-0 place-items-center rounded-md bg-panel text-[10px] font-semibold text-ink ring-1 ring-line">
              {index + 1}
            </span>
            <span className="line-clamp-2 min-w-0">{step}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}

export function ConnectionCompareDiagram() {
  const steps = customerSteps(BRAND.name);
  return (
    <div className="grid min-w-0 gap-3 overflow-hidden">
      <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] lg:items-stretch">
        <Column
          eyebrow="Managed GRC SaaS"
          title="Vendor-hosted evidence"
          steps={SAAS_STEPS}
          accent="vendor"
        />
        <ArrowRight
          className="mx-auto hidden h-5 w-5 shrink-0 self-center text-muted lg:block"
          aria-hidden
        />
        <Column
          eyebrow={BRAND.name}
          title="Customer-owned lake"
          steps={steps}
          accent="customer"
        />
      </div>
      <p className="line-clamp-3 text-xs leading-5 text-muted">
        AWS cross-account IAM, GitHub App tokens, and Okta/Google read-only
        scopes use the same connection patterns — {BRAND.name} stores raw events
        in your boundary.
      </p>
    </div>
  );
}

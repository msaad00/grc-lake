"use client";

import Link from "next/link";
import { X } from "lucide-react";

interface Props {
  step: number;
  total?: number;
  title: string;
  detail: string;
  dismissHref?: string;
}

/** Guided setup banner when ?onboarding=1 is present. */
export function OnboardingGuideBanner({
  step,
  total = 4,
  title,
  detail,
  dismissHref = "/onboarding",
}: Props) {
  return (
    <div className="flex items-start gap-3 rounded-xl border border-brand/25 bg-info-bg px-4 py-3">
      <span className="shrink-0 rounded-full border border-brand/30 bg-surface px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-brand">
        Step {step}/{total}
      </span>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-semibold text-ink">{title}</div>
        <p className="mt-0.5 text-xs leading-5 text-muted">{detail}</p>
      </div>
      <Link
        href={dismissHref}
        className="grid h-7 w-7 shrink-0 place-items-center rounded-md text-muted hover:bg-surface hover:text-ink"
        aria-label="Dismiss setup guide"
      >
        <X className="h-4 w-4" />
      </Link>
    </div>
  );
}

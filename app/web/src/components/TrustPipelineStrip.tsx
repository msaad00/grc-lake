"use client";

import Link from "next/link";
import {
  ChevronRight,
  ClipboardCheck,
  Database,
  FileCheck2,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import { cn } from "@/lib/utils";

type StageId = "frameworks" | "evidence" | "controls" | "findings" | "proof";

const stages = [
  {
    id: "frameworks",
    label: "Map",
    title: "Framework map",
    href: "/frameworks",
    Icon: ClipboardCheck,
  },
  {
    id: "evidence",
    label: "Collect",
    title: "Evidence facts",
    href: "/evidence",
    Icon: Database,
  },
  {
    id: "controls",
    label: "Evaluate",
    title: "Control eval",
    href: "/controls",
    Icon: ShieldCheck,
  },
  {
    id: "findings",
    label: "Triage",
    title: "Findings",
    href: "/violations",
    Icon: TriangleAlert,
  },
  {
    id: "proof",
    label: "Prove",
    title: "Proof export",
    href: "/audit-room",
    Icon: FileCheck2,
  },
] as const;

/** A slim stepper: where this page sits in map → collect → evaluate → triage → prove. */
export function TrustPipelineStrip({
  activeStage,
  className,
}: {
  activeStage: StageId;
  className?: string;
}) {
  return (
    <nav
      aria-label="Trust pipeline"
      className={cn("-mx-1 overflow-x-auto", className)}
    >
      <ol className="flex min-w-max items-center gap-1 px-1 text-[13px]">
        {stages.map(({ id, title, href, Icon }, index) => {
          const active = id === activeStage;
          return (
            <li key={id} className="flex items-center gap-1">
              {index > 0 ? (
                <ChevronRight
                  aria-hidden="true"
                  className="h-3.5 w-3.5 text-line-strong"
                />
              ) : null}
              <Link
                href={href}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-md px-2 py-1 transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-brand",
                  active
                    ? "bg-surface font-medium text-ink shadow-card ring-1 ring-line"
                    : "text-muted hover:text-ink",
                )}
              >
                <Icon aria-hidden="true" className="h-3.5 w-3.5" />
                {title}
              </Link>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

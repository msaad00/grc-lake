"use client";

import type { ReactNode } from "react";
import { BookText, MessageCircleQuestion } from "lucide-react";
import { BRAND } from "@/lib/brand";

const VERSION = BRAND.version;

const LINK_FOCUS =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-rail";

interface Props {
  collapsed: boolean;
  toggle?: ReactNode;
}

export function SidebarFooter({ collapsed, toggle }: Props) {
  return (
    <div className="mt-auto grid gap-1 border-t border-rail-line px-3 py-1.5 text-[11px] text-muted">
      {!collapsed ? (
        // One row keeps the footer short enough for the whole rail to fit at
        // 900px tall.
        <div className="flex min-h-7 items-center gap-0.5">
          <a
            href={BRAND.repoUrl}
            target="_blank"
            rel="noreferrer"
            className={`inline-flex items-center gap-1.5 rounded-md px-2 py-1.5 hover:bg-rail-hover ${LINK_FOCUS}`}
          >
            <BookText aria-hidden="true" className="h-3.5 w-3.5" /> Docs
            <span className="sr-only">(opens in a new tab)</span>
          </a>
          <a
            href={`${BRAND.repoUrl}/issues`}
            target="_blank"
            rel="noreferrer"
            className={`inline-flex items-center gap-1.5 rounded-md px-2 py-1.5 hover:bg-rail-hover ${LINK_FOCUS}`}
          >
            <MessageCircleQuestion aria-hidden="true" className="h-3.5 w-3.5" />
            Feedback
            <span className="sr-only">(opens in a new tab)</span>
          </a>
          <span className="ml-auto pl-1 text-[10px] text-muted">
            v{VERSION}
          </span>
          {toggle}
        </div>
      ) : (
        <div className="flex flex-col items-center gap-1">
          <a
            href={BRAND.repoUrl}
            target="_blank"
            rel="noreferrer"
            aria-label="Docs"
            title="Docs"
            className={`grid h-7 w-7 place-items-center rounded-md hover:bg-rail-hover ${LINK_FOCUS}`}
          >
            <BookText aria-hidden="true" className="h-3.5 w-3.5" />
          </a>
          <div className="text-[9px] text-muted">v{VERSION}</div>
          {toggle}
        </div>
      )}
    </div>
  );
}

"use client";

import type { ReactNode } from "react";
import { BookText, ExternalLink, MessageCircleQuestion } from "lucide-react";
import { BRAND } from "@/lib/brand";

const VERSION = BRAND.version;

const LINK_FOCUS =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-cyan focus-visible:ring-offset-2 focus-visible:ring-offset-rail";

interface Props {
  collapsed: boolean;
  toggle?: ReactNode;
}

export function SidebarFooter({ collapsed, toggle }: Props) {
  return (
    <div className="mt-auto grid gap-1 border-t border-rail-line p-3 text-[11px] text-slate-300">
      {!collapsed ? (
        <>
          <a
            href={BRAND.repoUrl}
            target="_blank"
            rel="noreferrer"
            className={`inline-flex items-center justify-between gap-2 rounded-md px-2 py-1.5 hover:bg-rail-hover ${LINK_FOCUS}`}
          >
            <span className="inline-flex items-center gap-2">
              <BookText aria-hidden="true" className="h-3.5 w-3.5" /> Docs
            </span>
            <ExternalLink aria-hidden="true" className="h-3 w-3 opacity-60" />
          </a>
          <a
            href={`${BRAND.repoUrl}/issues`}
            target="_blank"
            rel="noreferrer"
            className={`inline-flex items-center justify-between gap-2 rounded-md px-2 py-1.5 hover:bg-rail-hover ${LINK_FOCUS}`}
          >
            <span className="inline-flex items-center gap-2">
              <MessageCircleQuestion
                aria-hidden="true"
                className="h-3.5 w-3.5"
              />{" "}
              Feedback
            </span>
            <ExternalLink aria-hidden="true" className="h-3 w-3 opacity-60" />
          </a>
          <div className="mt-1 flex min-h-7 items-center justify-between pl-2 text-[10px] text-slate-400">
            <span>v{VERSION}</span>
            {toggle}
          </div>
        </>
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
          <div className="text-[9px] text-slate-400">v{VERSION}</div>
          {toggle}
        </div>
      )}
    </div>
  );
}

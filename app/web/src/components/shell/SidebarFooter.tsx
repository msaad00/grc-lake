"use client";

import type { ReactNode } from "react";
import { BookText, ExternalLink, MessageCircleQuestion } from "lucide-react";
import { BRAND } from "@/lib/brand";

const VERSION = BRAND.version;

interface Props {
  collapsed: boolean;
  toggle: ReactNode;
}

export function SidebarFooter({ collapsed, toggle }: Props) {
  return (
    <div className="mt-auto grid gap-1 border-t border-railLine p-3 text-[11px] text-[#9aa9bc]">
      {!collapsed ? (
        <>
          <a
            href="https://github.com/msaad00/trustops-security-data-lake"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center justify-between gap-2 rounded-md px-2 py-1.5 hover:bg-[#152030]"
          >
            <span className="inline-flex items-center gap-2">
              <BookText className="h-3.5 w-3.5" /> Docs
            </span>
            <ExternalLink className="h-3 w-3 opacity-60" />
          </a>
          <a
            href="https://github.com/msaad00/trustops-security-data-lake/issues"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center justify-between gap-2 rounded-md px-2 py-1.5 hover:bg-[#152030]"
          >
            <span className="inline-flex items-center gap-2">
              <MessageCircleQuestion className="h-3.5 w-3.5" /> Feedback
            </span>
            <ExternalLink className="h-3 w-3 opacity-60" />
          </a>
          <div className="mt-1 flex items-center justify-between pl-2 text-[10px] text-[#5b6a7e]">
            <span>v{VERSION}</span>
            {toggle}
          </div>
        </>
      ) : (
        <div className="flex flex-col items-center gap-1">
          <a
            href="https://github.com/msaad00/trustops-security-data-lake"
            target="_blank"
            rel="noreferrer"
            className="grid h-7 w-7 place-items-center rounded-md hover:bg-[#152030]"
            title="Docs"
          >
            <BookText className="h-3.5 w-3.5" />
          </a>
          <div className="text-[9px] text-[#5b6a7e]">v{VERSION}</div>
          {toggle}
        </div>
      )}
    </div>
  );
}

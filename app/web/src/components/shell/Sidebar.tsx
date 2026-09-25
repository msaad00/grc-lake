"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ActivityIcon,
  AlertOctagon,
  BookOpen,
  Bot,
  BrainCircuit,
  ChevronLeft,
  ChevronRight,
  ClipboardCheck,
  FileSearch,
  Layers,
  LayoutDashboard,
  Plug,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Users,
  Zap,
} from "lucide-react";
import { SidebarFooter } from "./SidebarFooter";
import { cn } from "@/lib/utils";
import { usePersistentState } from "@/lib/state/preferences";

interface RailItem {
  href: string;
  label: string;
  Icon: typeof LayoutDashboard;
  group: "Overview" | "Collect" | "Evaluate" | "Resolve" | "Review & export";
}

const ITEMS: RailItem[] = [
  // ── Overview ──
  {
    href: "/dashboard",
    label: "Overview",
    Icon: LayoutDashboard,
    group: "Overview",
  },
  {
    href: "/insights",
    label: "Insights",
    Icon: ActivityIcon,
    group: "Overview",
  },

  // ── Collect ──
  { href: "/connectors", label: "Connections", Icon: Plug, group: "Collect" },
  { href: "/evidence", label: "Evidence", Icon: FileSearch, group: "Collect" },
  {
    href: "/access-reviews",
    label: "Access reviews",
    Icon: Users,
    group: "Collect",
  },
  {
    href: "/vendor-risk",
    label: "Vendor risk",
    Icon: ShieldAlert,
    group: "Collect",
  },

  // ── Evaluate ──
  {
    href: "/controls",
    label: "Controls",
    Icon: ShieldCheck,
    group: "Evaluate",
  },
  {
    href: "/frameworks",
    label: "Frameworks",
    Icon: BookOpen,
    group: "Evaluate",
  },
  {
    href: "/violations",
    label: "Findings",
    Icon: AlertOctagon,
    group: "Evaluate",
  },
  {
    href: "/risks",
    label: "Risk register",
    Icon: ShieldAlert,
    group: "Evaluate",
  },
  { href: "/policies", label: "Policies", Icon: BookOpen, group: "Evaluate" },
  {
    href: "/ai-governance",
    label: "AI governance",
    Icon: BrainCircuit,
    group: "Evaluate",
  },
  { href: "/crosswalk", label: "Crosswalk", Icon: Layers, group: "Evaluate" },

  // ── Resolve ──
  {
    href: "/remediation",
    label: "Remediation",
    Icon: ShieldCheck,
    group: "Resolve",
  },
  { href: "/automation", label: "Workflows", Icon: Zap, group: "Resolve" },
  { href: "/agents", label: "Agents", Icon: Bot, group: "Resolve" },

  // ── Review & export ──
  {
    href: "/audit-room",
    label: "Audit room",
    Icon: ClipboardCheck,
    group: "Review & export",
  },
  {
    href: "/trust-center",
    label: "Trust center",
    Icon: Sparkles,
    group: "Review & export",
  },
  {
    href: "/audit-log",
    label: "Audit log",
    Icon: ActivityIcon,
    group: "Review & export",
  },
];

const GROUPS: RailItem["group"][] = [
  "Overview",
  "Collect",
  "Evaluate",
  "Resolve",
  "Review & export",
];

function isGroupClosed(
  group: RailItem["group"],
  closedGroups: Record<string, boolean>,
) {
  if (closedGroups[group] !== undefined) return closedGroups[group];
  return false;
}

export function Sidebar() {
  const pathname = usePathname() ?? "/dashboard";
  const [collapsed, setCollapsed] = usePersistentState(
    "trustops:sidebar:collapsed",
    false,
  );
  const [compactViewport, setCompactViewport] = useState(false);
  const [closedGroups, setClosedGroups] = usePersistentState<
    Record<string, boolean>
  >("trustops:sidebar:closed-groups", {});
  const effectiveCollapsed = collapsed || compactViewport;
  useEffect(() => {
    const query = window.matchMedia("(max-width: 767px)");
    const update = () => setCompactViewport(query.matches);
    update();
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);

  const toggleGroup = (group: RailItem["group"]) => {
    setClosedGroups({
      ...closedGroups,
      [group]: !isGroupClosed(group, closedGroups),
    });
  };

  return (
    <aside
      className={cn(
        "sticky top-[52px] grid h-[calc(100dvh-52px)] grid-rows-[1fr_auto] self-start border-r border-railLine bg-rail text-slate-300 transition-[width]",
        effectiveCollapsed ? "w-[64px]" : "w-[248px]",
      )}
    >
      <div className="overflow-y-auto p-2.5">
        {GROUPS.map((group) => {
          const isClosed =
            isGroupClosed(group, closedGroups) && !effectiveCollapsed;
          const groupItems = ITEMS.filter((i) => i.group === group);
          return (
            <div key={group} className="mb-3">
              {!effectiveCollapsed ? (
                <button
                  type="button"
                  onClick={() => toggleGroup(group)}
                  aria-expanded={!isClosed}
                  className="flex w-full items-center justify-between px-2.5 py-1.5 text-[10px] font-black uppercase tracking-[0.08em] text-[#708198] hover:text-[#bcc8d8]"
                >
                  <span>{group}</span>
                  {isClosed ? (
                    <ChevronRight className="h-3 w-3" />
                  ) : (
                    <ChevronLeft className="h-3 w-3 rotate-180" />
                  )}
                </button>
              ) : (
                <div
                  aria-hidden="true"
                  className="mx-3 mb-2 border-t border-railLine"
                />
              )}
              {!isClosed && (
                <div className="grid gap-1">
                  {groupItems.map(({ href, label, Icon }) => {
                    const active =
                      pathname === href || pathname.startsWith(href + "/");
                    return (
                      <Link
                        key={href}
                        href={href}
                        title={effectiveCollapsed ? label : undefined}
                        className={cn(
                          "flex items-center gap-2 rounded-lg border px-2.5 text-[13px] font-extrabold transition-colors",
                          effectiveCollapsed
                            ? "h-9 justify-center px-0"
                            : "h-9 justify-between",
                          active
                            ? "border-[#31435c] bg-[#172436] text-white"
                            : "border-transparent text-[#c6d1df] hover:bg-[#152030]",
                        )}
                      >
                        <span
                          className={cn(
                            "flex items-center gap-2.5",
                            effectiveCollapsed ? "justify-center" : "",
                          )}
                        >
                          <span
                            className={cn(
                              "grid place-items-center rounded-lg",
                              effectiveCollapsed ? "h-7 w-7" : "h-6 w-6",
                              active
                                ? "bg-[#eff6ff] text-[#1d4ed8]"
                                : "bg-[#1d2b3d] text-[#9cc2ff]",
                            )}
                          >
                            <Icon className="h-4 w-4" />
                          </span>
                          {!effectiveCollapsed && label}
                        </span>
                      </Link>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>

      <SidebarFooter
        collapsed={effectiveCollapsed}
        toggle={
          <button
            type="button"
            onClick={() => {
              if (!compactViewport) setCollapsed(!collapsed);
            }}
            aria-label={
              compactViewport
                ? "Sidebar is compact on small screens"
                : effectiveCollapsed
                  ? "Expand sidebar"
                  : "Collapse sidebar"
            }
            className="ml-auto grid h-7 w-7 place-items-center rounded-md text-[#9aa9bc] hover:bg-[#152030]"
          >
            {effectiveCollapsed ? (
              <ChevronRight className="h-4 w-4" />
            ) : (
              <ChevronLeft className="h-4 w-4" />
            )}
          </button>
        }
      />
    </aside>
  );
}

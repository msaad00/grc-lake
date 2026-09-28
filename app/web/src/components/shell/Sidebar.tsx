"use client";

import { useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import * as Dialog from "@radix-ui/react-dialog";
import { ChevronDown, ChevronLeft, ChevronRight, X } from "lucide-react";
import { SidebarFooter } from "./SidebarFooter";
import { cn } from "@/lib/utils";
import { usePersistentState } from "@/lib/state/preferences";
import { NAV_GROUPS, NAV_ITEMS, isActiveRoute, type NavGroup } from "@/lib/nav";

const FOCUS_RING =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-rail";

function NavLinks({
  collapsed,
  onNavigate,
}: {
  collapsed: boolean;
  onNavigate?: () => void;
}) {
  const pathname = usePathname() ?? "/dashboard";
  const [closedGroups, setClosedGroups] = usePersistentState<
    Record<string, boolean>
  >("trustops:sidebar:closed-groups", {});

  const toggleGroup = (group: NavGroup) => {
    setClosedGroups({ ...closedGroups, [group]: !closedGroups[group] });
  };

  return (
    <nav aria-label="Primary" className="overflow-y-auto p-2.5">
      {NAV_GROUPS.map((group) => {
        const isClosed = Boolean(closedGroups[group]) && !collapsed;
        const groupId = `nav-group-${group.replace(/\W+/g, "-").toLowerCase()}`;
        return (
          <div key={group} className="mb-3">
            {!collapsed ? (
              <button
                type="button"
                onClick={() => toggleGroup(group)}
                aria-expanded={!isClosed}
                aria-controls={groupId}
                className={cn(
                  "flex w-full items-center justify-between rounded-md px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide text-rail-heading hover:text-ink",
                  FOCUS_RING,
                )}
              >
                <span>{group}</span>
                {isClosed ? (
                  <ChevronRight aria-hidden="true" className="h-3 w-3" />
                ) : (
                  <ChevronDown aria-hidden="true" className="h-3 w-3" />
                )}
              </button>
            ) : (
              <div
                aria-hidden="true"
                className="mx-3 mb-2 border-t border-rail-line"
              />
            )}
            {!isClosed && (
              <ul id={groupId} className="grid gap-0.5">
                {NAV_ITEMS.filter((item) => item.group === group).map(
                  ({ href, label, Icon }) => {
                    const active = isActiveRoute(pathname, href);
                    return (
                      <li key={href}>
                        <Link
                          href={href}
                          onClick={onNavigate}
                          aria-current={active ? "page" : undefined}
                          aria-label={collapsed ? label : undefined}
                          title={collapsed ? label : undefined}
                          className={cn(
                            "flex h-8 items-center gap-2.5 rounded-md px-2.5 text-[13px] font-medium transition-colors",
                            FOCUS_RING,
                            collapsed && "justify-center px-0",
                            active
                              ? "bg-rail-active font-semibold text-brand"
                              : "text-rail-text hover:bg-rail-hover hover:text-ink",
                          )}
                        >
                          <span
                            aria-hidden="true"
                            className={cn(
                              "grid shrink-0 place-items-center",
                              collapsed ? "h-7 w-7" : "h-5 w-5",
                              active ? "text-brand" : "text-rail-heading",
                            )}
                          >
                            <Icon className="h-4 w-4" strokeWidth={1.75} />
                          </span>
                          {!collapsed && label}
                        </Link>
                      </li>
                    );
                  },
                )}
              </ul>
            )}
          </div>
        );
      })}
    </nav>
  );
}

/** Persistent rail from `md` up; below that the TopBar opens `MobileNav`. */
export function Sidebar() {
  const [collapsed, setCollapsed] = usePersistentState(
    "trustops:sidebar:collapsed",
    false,
  );

  return (
    <aside
      className={cn(
        "sticky top-[var(--topbar-h)] h-[calc(100dvh-var(--topbar-h))] grid-rows-[1fr_auto] self-start border-r border-rail-line bg-rail text-muted transition-[width] hidden md:grid",
        collapsed ? "w-[64px]" : "w-[248px]",
      )}
    >
      <NavLinks collapsed={collapsed} />
      <SidebarFooter
        collapsed={collapsed}
        toggle={
          <button
            type="button"
            onClick={() => setCollapsed(!collapsed)}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            className={cn(
              "ml-auto grid h-7 w-7 place-items-center rounded-md text-muted hover:bg-rail-hover hover:text-ink",
              FOCUS_RING,
            )}
          >
            {collapsed ? (
              <ChevronRight aria-hidden="true" className="h-4 w-4" />
            ) : (
              <ChevronLeft aria-hidden="true" className="h-4 w-4" />
            )}
          </button>
        }
      />
    </aside>
  );
}

export function MobileNav({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  // The drawer only exists below md; never leave a hidden modal trapping focus.
  useEffect(() => {
    if (!open) return;
    const query = window.matchMedia("(min-width: 768px)");
    const close = () => {
      if (query.matches) onOpenChange(false);
    };
    close();
    query.addEventListener("change", close);
    return () => query.removeEventListener("change", close);
  }, [open, onOpenChange]);

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm md:hidden" />
        <Dialog.Content className="fixed inset-y-0 left-0 z-50 grid w-[min(288px,calc(100vw-48px))] grid-rows-[auto_1fr_auto] border-r border-rail-line bg-rail text-muted shadow-hero md:hidden">
          <div className="flex h-[var(--topbar-h)] items-center justify-between border-b border-rail-line px-4">
            <Dialog.Title className="text-sm font-semibold text-ink">
              Navigation
            </Dialog.Title>
            <Dialog.Description className="sr-only">
              Console sections
            </Dialog.Description>
            <Dialog.Close
              aria-label="Close navigation"
              className={cn(
                "grid h-8 w-8 place-items-center rounded-md text-muted hover:bg-rail-hover hover:text-ink",
                FOCUS_RING,
              )}
            >
              <X aria-hidden="true" className="h-4 w-4" />
            </Dialog.Close>
          </div>
          <NavLinks collapsed={false} onNavigate={() => onOpenChange(false)} />
          <SidebarFooter collapsed={false} />
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

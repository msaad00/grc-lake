"use client";

import { useCallback, useEffect, useRef, useState } from "react";
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
    setClosedGroups((prev) => ({ ...prev, [group]: !prev[group] }));
  };

  // Keep the current page in view, and fade whichever edge has more links
  // past it so a scrolled rail never hides items without a hint.
  const navRef = useRef<HTMLElement>(null);
  const [edges, setEdges] = useState({ top: false, bottom: false });
  const measure = useCallback(() => {
    const el = navRef.current;
    if (!el) return;
    const top = el.scrollTop > 1;
    const bottom = el.scrollTop + el.clientHeight < el.scrollHeight - 1;
    setEdges((prev) =>
      prev.top === top && prev.bottom === bottom ? prev : { top, bottom },
    );
  }, []);
  useEffect(() => {
    navRef.current
      ?.querySelector<HTMLElement>('a[aria-current="page"]')
      ?.scrollIntoView({ block: "nearest" });
    measure();
  }, [pathname, measure]);
  useEffect(() => {
    const el = navRef.current;
    if (!el) return;
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    return () => observer.disconnect();
  }, [measure]);

  return (
    <div className="relative min-h-0">
      <div
        aria-hidden="true"
        data-testid="nav-fade-top"
        className={cn(
          "pointer-events-none absolute inset-x-0 top-0 z-10 h-6 bg-gradient-to-b from-rail to-transparent transition-opacity",
          edges.top ? "opacity-100" : "opacity-0",
        )}
      />
      <nav
        ref={navRef}
        aria-label="Primary"
        onScroll={measure}
        className="h-full overflow-y-auto px-2 py-1.5"
      >
        {NAV_GROUPS.map((group) => {
          const isClosed = Boolean(closedGroups[group]) && !collapsed;
          const groupId = `nav-group-${group.replace(/\W+/g, "-").toLowerCase()}`;
          return (
            <div key={group} className="mb-1 last:mb-0">
              {!collapsed ? (
                <button
                  type="button"
                  onClick={() => toggleGroup(group)}
                  aria-expanded={!isClosed}
                  aria-controls={groupId}
                  className={cn(
                    "flex w-full items-center justify-between rounded-md px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-rail-heading hover:text-ink",
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
                <ul id={groupId} className="grid">
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
                              "flex h-7 items-center gap-2.5 rounded-md px-2.5 text-[13px] font-medium transition-colors",
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
      <div
        aria-hidden="true"
        data-testid="nav-fade-bottom"
        className={cn(
          "pointer-events-none absolute inset-x-0 bottom-0 z-10 h-8 bg-gradient-to-t from-rail to-transparent transition-opacity",
          edges.bottom ? "opacity-100" : "opacity-0",
        )}
      />
    </div>
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
      aria-label="Console sidebar"
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
              "grid h-7 w-7 place-items-center rounded-md text-muted hover:bg-rail-hover hover:text-ink",
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

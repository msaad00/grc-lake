"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import * as Dialog from "@radix-ui/react-dialog";
import {
  AlertOctagon,
  Camera,
  FileSearch,
  PlayCircle,
  RefreshCw,
  Rocket,
  Search,
  ShieldCheck,
  Sparkles,
  Workflow,
  type LucideIcon,
} from "lucide-react";
import { ROUTE_LABELS } from "@/lib/console-copy";
import { NAV_ITEMS } from "@/lib/nav";
import { api } from "@/lib/api/client";
import type {
  ControlPosture,
  NormalizedEvent,
  Violation,
  Workflow as WorkflowRow,
} from "@/lib/api/types";
import { assetLabel } from "@/lib/format";

interface PaletteItem {
  id: string;
  group:
    | "Actions"
    | "Routes"
    | "Controls"
    | "Findings"
    | "Evidence"
    | "Workflows";
  label: string;
  subtitle?: string;
  href?: string;
  run?: () => void;
  Icon: LucideIcon;
}

const EXTRA_ROUTES = [
  { href: "/onboarding", Icon: Rocket },
  { href: "/poc", Icon: Sparkles },
  { href: "/demo", Icon: PlayCircle },
] as const;

const ROUTE_ITEMS: PaletteItem[] = [
  ...NAV_ITEMS.map(({ href, label, Icon }) => ({ href, label, Icon })),
  ...EXTRA_ROUTES.map(({ href, Icon }) => ({
    href,
    label: ROUTE_LABELS[href],
    Icon,
  })),
].map(({ href, label, Icon }) => ({
  id: `r:${href}`,
  group: "Routes",
  label,
  href,
  Icon,
}));

const LISTBOX_ID = "command-palette-results";
const optionId = (index: number) => `${LISTBOX_ID}-option-${index}`;

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSnapshot?: () => void;
  onRefresh?: () => void;
}

export function CommandPalette({
  open,
  onOpenChange,
  onSnapshot,
  onRefresh,
}: Props) {
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [controls, setControls] = useState<ControlPosture[]>([]);
  const [violations, setViolations] = useState<Violation[]>([]);
  const [evidence, setEvidence] = useState<NormalizedEvent[]>([]);
  const [workflows, setWorkflows] = useState<WorkflowRow[]>([]);
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  // Lazy-load the searchable indexes when first opened.
  useEffect(() => {
    if (!open) return;
    setQuery("");
    setActiveIndex(0);
    Promise.allSettled([
      api.controls().then((r) => setControls(r.controls ?? [])),
      api.violations().then((r) => setViolations(r.violations ?? [])),
      api.evidence().then((r) => setEvidence(r.evidence ?? [])),
      api.listWorkflows().then((r) => setWorkflows(r.workflows ?? [])),
    ]).catch(() => undefined);
  }, [open]);

  // Focus the input every time the dialog opens.
  useEffect(() => {
    if (open) {
      const handle = window.setTimeout(() => inputRef.current?.focus(), 50);
      return () => window.clearTimeout(handle);
    }
  }, [open]);

  const items = useMemo<PaletteItem[]>(() => {
    const actions: PaletteItem[] = [];
    if (onSnapshot) {
      actions.push({
        id: "a:snapshot",
        group: "Actions",
        label: "Create assessment snapshot",
        subtitle: "Freeze current posture for audit / JIT review",
        run: onSnapshot,
        Icon: Camera,
      });
    }
    if (onRefresh) {
      actions.push({
        id: "a:refresh",
        group: "Actions",
        label: "Refresh data",
        subtitle: "Re-read posture from the assessment lake",
        run: onRefresh,
        Icon: RefreshCw,
      });
    }
    const dynamic: PaletteItem[] = [
      ...controls.map<PaletteItem>((c) => ({
        id: `c:${c.control_id}`,
        group: "Controls",
        label: c.control_id,
        subtitle: c.title,
        href: `/controls?id=${encodeURIComponent(c.control_id)}`,
        Icon: ShieldCheck,
      })),
      ...violations.map<PaletteItem>((v) => ({
        id: `v:${v.violation_id}`,
        group: "Findings",
        label: v.violation_id,
        subtitle: `${v.severity} · ${assetLabel(v)}`,
        href: `/violations?id=${encodeURIComponent(v.violation_id)}`,
        Icon: AlertOctagon,
      })),
      ...evidence.map<PaletteItem>((e) => ({
        id: `e:${e.event_id}`,
        group: "Evidence",
        label: e.event_id,
        subtitle: `${e.source} · ${assetLabel(e)}`,
        href: `/evidence?id=${encodeURIComponent(e.event_id)}`,
        Icon: FileSearch,
      })),
      ...workflows.map<PaletteItem>((w) => ({
        id: `w:${w.workflow_id}`,
        group: "Workflows",
        label: w.name,
        subtitle: `${w.workflow_id} · v${w.version}`,
        href: `/automation?id=${encodeURIComponent(w.workflow_id)}`,
        Icon: Workflow,
      })),
    ];
    const all = [...actions, ...ROUTE_ITEMS, ...dynamic];
    if (!query) return all.slice(0, 60);
    const lower = query.toLowerCase();
    return all
      .filter((item) =>
        `${item.label} ${item.subtitle ?? ""} ${item.group}`
          .toLowerCase()
          .includes(lower),
      )
      .sort((a, b) => {
        const rank = (item: PaletteItem) => {
          const label = item.label.toLowerCase();
          if (label === lower) return 0;
          if (label.startsWith(lower)) return 1;
          if (label.includes(lower)) return 2;
          return 3;
        };
        return rank(a) - rank(b);
      })
      .slice(0, 60);
  }, [controls, violations, evidence, workflows, query, onSnapshot, onRefresh]);

  // Reset active index when filter changes.
  useEffect(() => {
    setActiveIndex(0);
  }, [query]);

  const grouped = useMemo(() => {
    const out = new Map<PaletteItem["group"], PaletteItem[]>();
    for (const item of items) {
      const list = out.get(item.group) ?? [];
      list.push(item);
      out.set(item.group, list);
    }
    return out;
  }, [items]);

  const activeId = items[activeIndex] ? optionId(activeIndex) : undefined;

  useEffect(() => {
    if (!activeId) return;
    document.getElementById(activeId)?.scrollIntoView({ block: "nearest" });
  }, [activeId]);

  const go = (item: PaletteItem) => {
    onOpenChange(false);
    if (item.run) {
      item.run();
    } else if (item.href) {
      router.push(item.href);
    }
  };

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-slate-950/40 backdrop-blur-sm" />
        <Dialog.Content className="fixed left-1/2 top-[14%] z-50 w-[min(640px,calc(100vw-32px))] -translate-x-1/2 overflow-hidden rounded-2xl bg-surface shadow-hero">
          <Dialog.Title className="sr-only">Search</Dialog.Title>
          <Dialog.Description className="sr-only">
            Search controls, findings, evidence, workflows, and pages.
          </Dialog.Description>
          <div className="flex items-center gap-3 border-b border-line px-4 py-3">
            <Search aria-hidden="true" className="h-4 w-4 text-muted" />
            <input
              ref={inputRef}
              role="combobox"
              aria-label="Search the console"
              aria-expanded={items.length > 0}
              aria-controls={LISTBOX_ID}
              aria-autocomplete="list"
              aria-activedescendant={activeId}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "ArrowDown") {
                  e.preventDefault();
                  setActiveIndex((i) => Math.min(i + 1, items.length - 1));
                } else if (e.key === "ArrowUp") {
                  e.preventDefault();
                  setActiveIndex((i) => Math.max(i - 1, 0));
                } else if (e.key === "Enter") {
                  e.preventDefault();
                  const target = items[activeIndex];
                  if (target) go(target);
                }
              }}
              placeholder="Search controls, findings, evidence, workflows, pages…"
              className="flex-1 bg-transparent text-sm text-ink placeholder:text-muted focus:outline-none"
            />
            <kbd className="rounded border border-line bg-surfaceMuted px-1.5 py-0.5 text-[10px] font-semibold text-muted">
              esc
            </kbd>
          </div>
          <div
            id={LISTBOX_ID}
            role="listbox"
            aria-label="Search results"
            className="max-h-[60vh] overflow-auto p-2"
          >
            {items.length === 0 && (
              <div
                role="presentation"
                className="px-3 py-8 text-center text-sm text-muted"
              >
                No matches.
              </div>
            )}
            {Array.from(grouped.entries()).map(([group, list]) => (
              <div
                key={group}
                role="group"
                aria-labelledby={`${LISTBOX_ID}-${group}`}
                className="grid gap-0.5 px-1 pb-2"
              >
                <div
                  id={`${LISTBOX_ID}-${group}`}
                  role="presentation"
                  className="px-2 pb-1 pt-3 text-[11px] font-semibold uppercase tracking-wider text-muted"
                >
                  {group}
                </div>
                {list.map((item) => {
                  const idx = items.indexOf(item);
                  const active = idx === activeIndex;
                  return (
                    <div
                      key={item.id}
                      id={optionId(idx)}
                      role="option"
                      aria-selected={active}
                      tabIndex={-1}
                      onMouseEnter={() => setActiveIndex(idx)}
                      onMouseDown={(e) => e.preventDefault()}
                      onClick={() => go(item)}
                      className={[
                        "grid w-full cursor-pointer grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3 rounded-lg px-2.5 py-2 text-left text-sm text-ink",
                        active ? "bg-brand/15" : "hover:bg-surfaceMuted",
                      ].join(" ")}
                    >
                      <item.Icon
                        aria-hidden="true"
                        className={
                          active ? "h-4 w-4 text-brand" : "h-4 w-4 text-muted"
                        }
                      />
                      <span className="min-w-0">
                        <span className="block truncate font-semibold">
                          {item.label}
                        </span>
                        {item.subtitle && (
                          <span
                            className={[
                              "block truncate text-[11px]",
                              "text-muted",
                            ].join(" ")}
                          >
                            {item.subtitle}
                          </span>
                        )}
                      </span>
                      <kbd
                        aria-hidden="true"
                        className={[
                          "rounded border border-line bg-surface px-1.5 py-0.5 text-[10px] font-semibold text-muted",
                          active ? "visible" : "invisible",
                        ].join(" ")}
                      >
                        ↵
                      </kbd>
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
          <div className="flex items-center justify-between gap-3 border-t border-line bg-surfaceMuted px-4 py-2 text-[11px] text-muted">
            <span>
              <kbd className="rounded border border-line bg-surface px-1.5 py-0.5 font-semibold">
                ↑↓
              </kbd>{" "}
              navigate{" "}
              <kbd className="rounded border border-line bg-surface px-1.5 py-0.5 font-semibold">
                ↵
              </kbd>{" "}
              open{" "}
              <kbd className="rounded border border-line bg-surface px-1.5 py-0.5 font-semibold">
                esc
              </kbd>{" "}
              close
            </span>
            <span>{items.length} matches</span>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

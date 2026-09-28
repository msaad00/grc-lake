import {
  AlertOctagon,
  BadgeCheck,
  Bot,
  BrainCircuit,
  ChartLine,
  ClipboardCheck,
  FileSearch,
  Handshake,
  History,
  KeyRound,
  Layers,
  LayoutDashboard,
  Library,
  ListChecks,
  Network,
  Plug,
  Scale,
  ScrollText,
  Server,
  ShieldCheck,
  Users,
  Wrench,
  Zap,
  type LucideIcon,
} from "lucide-react";
import { ROUTE_LABELS, type RouteHref } from "@/lib/console-copy";

export const NAV_GROUPS = [
  "Overview",
  "Collect",
  "Evaluate",
  "Resolve",
  "Review & export",
  "Settings",
] as const;

export type NavGroup = (typeof NAV_GROUPS)[number];

export interface NavItem {
  href: RouteHref;
  label: string;
  Icon: LucideIcon;
  group: NavGroup;
}

export const NAV_ITEMS: NavItem[] = [
  {
    href: "/dashboard",
    label: ROUTE_LABELS["/dashboard"],
    Icon: LayoutDashboard,
    group: "Overview",
  },
  {
    href: "/insights",
    label: ROUTE_LABELS["/insights"],
    Icon: ChartLine,
    group: "Overview",
  },
  {
    href: "/connectors",
    label: ROUTE_LABELS["/connectors"],
    Icon: Plug,
    group: "Collect",
  },
  {
    href: "/evidence",
    label: ROUTE_LABELS["/evidence"],
    Icon: FileSearch,
    group: "Collect",
  },
  {
    href: "/access-reviews",
    label: ROUTE_LABELS["/access-reviews"],
    Icon: Users,
    group: "Collect",
  },
  {
    href: "/vendor-risk",
    label: ROUTE_LABELS["/vendor-risk"],
    Icon: Handshake,
    group: "Collect",
  },
  {
    href: "/controls",
    label: ROUTE_LABELS["/controls"],
    Icon: ShieldCheck,
    group: "Evaluate",
  },
  {
    href: "/frameworks",
    label: ROUTE_LABELS["/frameworks"],
    Icon: Library,
    group: "Evaluate",
  },
  {
    href: "/mapping-review",
    label: ROUTE_LABELS["/mapping-review"],
    Icon: ListChecks,
    group: "Evaluate",
  },
  {
    href: "/violations",
    label: ROUTE_LABELS["/violations"],
    Icon: AlertOctagon,
    group: "Evaluate",
  },
  {
    href: "/risks",
    label: ROUTE_LABELS["/risks"],
    Icon: Scale,
    group: "Evaluate",
  },
  {
    href: "/policies",
    label: ROUTE_LABELS["/policies"],
    Icon: ScrollText,
    group: "Evaluate",
  },
  {
    href: "/ai-governance",
    label: ROUTE_LABELS["/ai-governance"],
    Icon: BrainCircuit,
    group: "Evaluate",
  },
  {
    href: "/crosswalk",
    label: ROUTE_LABELS["/crosswalk"],
    Icon: Layers,
    group: "Evaluate",
  },
  {
    href: "/graph",
    label: ROUTE_LABELS["/graph"],
    Icon: Network,
    group: "Evaluate",
  },
  {
    href: "/remediation",
    label: ROUTE_LABELS["/remediation"],
    Icon: Wrench,
    group: "Resolve",
  },
  {
    href: "/automation",
    label: ROUTE_LABELS["/automation"],
    Icon: Zap,
    group: "Resolve",
  },
  {
    href: "/agents",
    label: ROUTE_LABELS["/agents"],
    Icon: Bot,
    group: "Resolve",
  },
  {
    href: "/audit-room",
    label: ROUTE_LABELS["/audit-room"],
    Icon: ClipboardCheck,
    group: "Review & export",
  },
  {
    href: "/trust-center",
    label: ROUTE_LABELS["/trust-center"],
    Icon: BadgeCheck,
    group: "Review & export",
  },
  {
    href: "/audit-log",
    label: ROUTE_LABELS["/audit-log"],
    Icon: History,
    group: "Review & export",
  },
  {
    href: "/auth",
    label: ROUTE_LABELS["/auth"],
    Icon: KeyRound,
    group: "Settings",
  },
  {
    href: "/deploy",
    label: ROUTE_LABELS["/deploy"],
    Icon: Server,
    group: "Settings",
  },
];

export function isActiveRoute(pathname: string, href: string): boolean {
  const path = pathname.replace(/\/$/, "") || "/";
  return path === href || path.startsWith(href + "/");
}

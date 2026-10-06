"use client";

import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Bell,
  Building2,
  ChevronDown,
  LogOut,
  Monitor,
  Moon,
  Rocket,
  Settings,
  Sun,
  User,
} from "lucide-react";
import { api } from "@/lib/api/client";
import { useAuthWhoami } from "@/lib/api/hooks";
import { useAuditorMode } from "@/lib/state/auditor";
import { useTheme, type ThemeMode } from "@/components/theme/ThemeProvider";
import { workspaceIdentity } from "@/lib/workspace";
import { ROUTE_LABELS } from "@/lib/console-copy";

export function UserMenu({ compact = false }: { compact?: boolean }) {
  const router = useRouter();
  const auditor = useAuditorMode();
  const whoami = useAuthWhoami();
  const { theme, setTheme } = useTheme();

  const sessionLabel =
    (whoami.data?.auth_method === "insecure"
      ? "Local demo"
      : whoami.data?.email) ??
    (auditor
      ? `${workspaceIdentity.orgName} · auditor`
      : workspaceIdentity.primaryLabel);
  const avatar = (
    whoami.data?.email?.[0] ?? workspaceIdentity.avatar
  ).toUpperCase();

  const signOut = async () => {
    try {
      await api.authLogout();
    } catch {
      // Still clear the browser session cookie client-side when possible.
    }
    router.push("/login");
    router.refresh();
  };

  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button
          type="button"
          aria-label={`${sessionLabel} — account menu`}
          className={`${compact ? "h-8 justify-center !border-transparent !bg-transparent !px-0" : ""} inline-flex items-center gap-2 rounded-md border border-line bg-surface px-3 py-2 text-sm font-semibold text-ink hover:bg-rail-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-rail`}
        >
          <span className="grid h-6 w-6 place-items-center rounded-full bg-brand text-[11px] text-onBrand">
            {avatar}
          </span>
          <span
            className={
              compact
                ? "hidden max-w-[140px] truncate lg:inline"
                : "hidden max-w-[190px] truncate sm:inline"
            }
          >
            {sessionLabel}
          </span>
          {!compact && <ChevronDown className="h-3.5 w-3.5 opacity-60" />}
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          align="end"
          sideOffset={6}
          className="z-[60] grid min-w-[240px] gap-0.5 rounded-xl border border-line bg-surface p-1.5 shadow-hero"
        >
          {whoami.data && (
            <>
              <DropdownMenu.Label className="px-2 py-2 text-[11px] font-semibold uppercase tracking-wider text-muted">
                Signed in
              </DropdownMenu.Label>
              <DropdownMenu.Item className="grid cursor-default grid-cols-[auto_minmax(0,1fr)] items-center gap-2 rounded-md px-2 py-1.5 text-sm outline-none">
                <User className="h-4 w-4 text-muted" />
                <span className="min-w-0 truncate text-ink">
                  {whoami.data.email}
                  <span className="block text-[10px] font-semibold text-muted">
                    {whoami.data.role} ·{" "}
                    {whoami.data.auth_method === "insecure"
                      ? "Local demo"
                      : whoami.data.auth_method?.startsWith("session:")
                        ? "Signed-in session"
                        : "API identity"}
                  </span>
                </span>
              </DropdownMenu.Item>
              <DropdownMenu.Separator className="my-1 h-px bg-line" />
            </>
          )}
          <DropdownMenu.Label className="px-2 py-2 text-[11px] font-semibold uppercase tracking-wider text-muted">
            Organization
          </DropdownMenu.Label>
          <DropdownMenu.Item className="grid cursor-pointer grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-2 rounded-md px-2 py-1.5 text-sm outline-none data-[highlighted]:bg-surfaceMuted">
            <Building2 className="h-4 w-4 text-muted" />
            <span className="truncate text-ink">
              {workspaceIdentity.orgName}
              {workspaceIdentity.environmentName
                ? ` — ${workspaceIdentity.environmentName}`
                : ""}
            </span>
            <span className="rounded-full bg-success-bg px-1.5 py-0.5 text-[10px] font-semibold text-success-fg">
              active
            </span>
          </DropdownMenu.Item>
          <DropdownMenu.Separator className="my-1 h-px bg-line" />
          <DropdownMenu.Label className="px-2 py-1 text-[11px] font-semibold uppercase tracking-wider text-muted">
            Theme
          </DropdownMenu.Label>
          <div className="grid grid-cols-3 gap-1 px-1.5 pb-1.5">
            {(["light", "dark", "system"] as const).map((mode) => (
              <button
                key={mode}
                type="button"
                onClick={() => setTheme(mode as ThemeMode)}
                className={[
                  "inline-flex items-center justify-center gap-1 rounded-md border px-2 py-1.5 text-[11px] font-semibold",
                  theme === mode
                    ? "border-ink bg-ink text-panel"
                    : "border-line bg-surface text-muted hover:bg-surfaceMuted",
                ].join(" ")}
              >
                {mode === "light" && <Sun className="h-3 w-3" />}
                {mode === "dark" && <Moon className="h-3 w-3" />}
                {mode === "system" && <Monitor className="h-3 w-3" />}
                {mode}
              </button>
            ))}
          </div>
          <DropdownMenu.Separator className="my-1 h-px bg-line" />
          <DropdownMenu.Label className="px-2 py-1 text-[11px] font-semibold uppercase tracking-wider text-muted">
            You
          </DropdownMenu.Label>
          <DropdownMenu.Item asChild>
            <Link
              href="/auth"
              className="grid cursor-pointer grid-cols-[auto_minmax(0,1fr)] items-center gap-2 rounded-md px-2 py-1.5 text-sm text-ink outline-none data-[highlighted]:bg-surfaceMuted"
            >
              <User className="h-4 w-4 text-muted" />
              {ROUTE_LABELS["/auth"]}
            </Link>
          </DropdownMenu.Item>
          <DropdownMenu.Item asChild>
            <Link
              href="/audit-log"
              className="grid cursor-pointer grid-cols-[auto_minmax(0,1fr)] items-center gap-2 rounded-md px-2 py-1.5 text-sm text-ink outline-none data-[highlighted]:bg-surfaceMuted sm:hidden"
            >
              <Bell className="h-4 w-4 text-muted" />
              Notifications
            </Link>
          </DropdownMenu.Item>
          <DropdownMenu.Item asChild>
            <Link
              href="/poc"
              className="grid cursor-pointer grid-cols-[auto_minmax(0,1fr)] items-center gap-2 rounded-md px-2 py-1.5 text-sm text-ink outline-none data-[highlighted]:bg-surfaceMuted"
            >
              <Rocket className="h-4 w-4 text-muted" />
              POC readiness
            </Link>
          </DropdownMenu.Item>
          <DropdownMenu.Item className="grid cursor-pointer grid-cols-[auto_minmax(0,1fr)] items-center gap-2 rounded-md px-2 py-1.5 text-sm text-ink outline-none data-[highlighted]:bg-surfaceMuted">
            <Settings className="h-4 w-4 text-muted" />
            Settings
          </DropdownMenu.Item>
          <DropdownMenu.Item
            className="grid cursor-pointer grid-cols-[auto_minmax(0,1fr)] items-center gap-2 rounded-md px-2 py-1.5 text-sm text-ink outline-none data-[highlighted]:bg-surfaceMuted"
            onSelect={() => void signOut()}
          >
            <LogOut className="h-4 w-4 text-muted" />
            Sign out
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

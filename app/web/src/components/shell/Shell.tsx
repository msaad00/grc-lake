"use client";

import { useCallback, useState, type ReactNode } from "react";
import { MotionConfig, motion } from "framer-motion";
import { useQueryClient } from "@tanstack/react-query";
import { usePathname } from "next/navigation";
import { CommandPalette } from "./CommandPalette";
import { PlatformStreamLiveRegion } from "./PlatformStreamLiveRegion";
import { MobileNav, Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";
import { ApiHealthBanner } from "@/components/ApiHealthBanner";
import { AuditorBanner } from "@/components/AuditorBanner";
import { SnapshotModal } from "@/components/modals/SnapshotModal";
import { api } from "@/lib/api/client";
import { ROUTE_LABELS } from "@/lib/console-copy";
import { notify } from "@/lib/toast";

export function Shell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const normalizedPathname = pathname.replace(/\/$/, "");
  const isLoginRoute =
    normalizedPathname === "/login" ||
    normalizedPathname.endsWith("/login") ||
    normalizedPathname === "/signup" ||
    normalizedPathname.endsWith("/signup") ||
    normalizedPathname === "/invite" ||
    normalizedPathname.endsWith("/invite");
  // The public trust center is rendered for unauthenticated external reviewers
  // holding a token; it must bypass the authed Shell (nav, auditor banner,
  // API-health probes) entirely, the same way /login does.
  const isPublicTrustRoute = /(^|\/)trust\/[^/]+$/.test(normalizedPathname);
  const route = normalizedPathname.replace(/^\/console/, "");
  const pageTitle = `${ROUTE_LABELS[route as keyof typeof ROUTE_LABELS] ?? (isPublicTrustRoute ? "Shared trust report" : isLoginRoute ? "Sign in" : "Page not found")} · TrustOps`;
  const qc = useQueryClient();
  const [snapshotOpen, setSnapshotOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [navOpen, setNavOpen] = useState(false);

  const flash = useCallback((msg: string) => notify.success(msg), []);

  const onRefresh = useCallback(async () => {
    await qc.invalidateQueries();
    flash("Posture refreshed from assessment data");
  }, [qc, flash]);

  const onSnapshot = useCallback(async () => {
    setSnapshotOpen(true);
    // Pre-warm the snapshot list so the modal already has the latest record.
    try {
      await api.listSnapshots();
    } catch {
      /* non-blocking */
    }
  }, []);

  if (isLoginRoute || isPublicTrustRoute) {
    return (
      <main id="main-content" className="min-h-screen bg-panel">
        <title>{pageTitle}</title>
        {children}
      </main>
    );
  }

  return (
    <MotionConfig reducedMotion="user">
      <title>{pageTitle}</title>
      <div className="flex min-h-dvh w-full min-w-0 max-w-none flex-col bg-rail">
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-[100] focus:rounded-lg focus:bg-surface focus:px-3 focus:py-2 focus:text-sm focus:font-semibold focus:text-ink focus:shadow-hero"
        >
          Skip to main content
        </a>
        <PlatformStreamLiveRegion />
        <TopBar
          onRefresh={onRefresh}
          onSnapshot={onSnapshot}
          onOpenPalette={() => setPaletteOpen(true)}
          onOpenNav={() => setNavOpen(true)}
        />
        <MobileNav open={navOpen} onOpenChange={setNavOpen} />
        <AuditorBanner />
        <div className="grid min-w-0 flex-1 grid-cols-1 bg-panel md:grid-cols-[auto_minmax(0,1fr)]">
          <Sidebar />
          <div className="min-w-0 overflow-x-hidden">
            <main
              id="main-content"
              className="min-w-0 max-w-full overflow-x-hidden bg-panel"
            >
              <ApiHealthBanner />
              {/* Entry animation only. An exit phase would render the next page
                inside the outgoing wrapper and then mount it again, throwing
                away anything typed in between. */}
              <motion.div
                key={normalizedPathname}
                className="min-w-0"
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.16, ease: "easeOut" }}
              >
                {children}
              </motion.div>
            </main>
          </div>
        </div>
        <CommandPalette
          open={paletteOpen}
          onOpenChange={setPaletteOpen}
          onSnapshot={onSnapshot}
          onRefresh={onRefresh}
        />
        <SnapshotModal
          open={snapshotOpen}
          onClose={() => setSnapshotOpen(false)}
          onToast={flash}
        />
      </div>
    </MotionConfig>
  );
}

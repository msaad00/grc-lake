"use client";

import { useSyncExternalStore } from "react";

/** Tailwind's `sm` breakpoint: below it, dense tables become cards. */
export const SM_UP = "(min-width: 640px)";

/**
 * Live `matchMedia` result. The static export prerenders without a window, so
 * the server snapshot is `serverDefault` (desktop) and the client corrects it
 * on hydration.
 */
export function useMediaQuery(query: string, serverDefault = true): boolean {
  return useSyncExternalStore(
    (onChange) => {
      const list = window.matchMedia(query);
      list.addEventListener("change", onChange);
      return () => list.removeEventListener("change", onChange);
    },
    () => window.matchMedia(query).matches,
    () => serverDefault,
  );
}

"use client";

import { useCallback, useEffect, useState } from "react";

/**
 * Tiny localStorage-backed hook so sidebar collapse + read-notification state
 * survive reloads. Falls back to defaults during SSR / hydration.
 */
export function usePersistentState<T>(
  key: string,
  initial: T,
): [T, (next: T | ((prev: T) => T)) => void] {
  const [value, setValue] = useState<T>(initial);

  useEffect(() => {
    if (typeof window === "undefined") return;
    try {
      const raw = window.localStorage.getItem(key);
      if (raw !== null) setValue(JSON.parse(raw) as T);
    } catch {
      /* ignore */
    }
    // intentionally only on mount per key
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const update = useCallback(
    (next: T | ((prev: T) => T)) => {
      // Functional updates read the latest committed value, so two quick
      // toggles never overwrite each other with a stale snapshot.
      setValue((prev) => {
        const resolved =
          typeof next === "function" ? (next as (prev: T) => T)(prev) : next;
        if (typeof window !== "undefined") {
          try {
            window.localStorage.setItem(key, JSON.stringify(resolved));
          } catch {
            /* storage full or disabled */
          }
        }
        return resolved;
      });
    },
    [key],
  );

  return [value, update];
}

"use client";

import { useEffect, useState } from "react";

let auditorMode = false;
const listeners = new Set<(value: boolean) => void>();

export function setAuditorMode(value: boolean) {
  if (typeof window !== "undefined") {
    try {
      window.sessionStorage.setItem("trustops-auditor-view", String(value));
    } catch {
      /* Storage can be unavailable. */
    }
  }
  if (auditorMode === value) return;
  auditorMode = value;
  listeners.forEach((cb) => cb(value));
}

export function isAuditorMode(): boolean {
  return typeof window === "undefined" ? auditorMode : readFromUrl();
}

function readFromUrl(): boolean {
  if (typeof window === "undefined") return false;
  const params = new URLSearchParams(window.location.search);
  if (params.has("role"))
    return params.get("role")?.toLowerCase() === "auditor";
  try {
    return (
      window.sessionStorage.getItem("trustops-auditor-view") === "true" ||
      auditorMode
    );
  } catch {
    return auditorMode;
  }
}

export function useAuditorMode(): boolean {
  const [value, setValue] = useState(() => auditorMode || readFromUrl());

  useEffect(() => {
    const initial = readFromUrl();
    if (initial !== auditorMode) {
      setAuditorMode(initial);
    }
    setValue(auditorMode);
    const cb = (v: boolean) => setValue(v);
    listeners.add(cb);
    return () => {
      listeners.delete(cb);
    };
  }, []);

  return value;
}

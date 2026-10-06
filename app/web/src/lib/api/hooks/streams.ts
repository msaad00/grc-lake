"use client";

import { useAuditorMode } from "@/lib/state/auditor";

import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type {
  AiGovernance,
  Assessment,
  AuditReadiness,
  EvidenceFreshnessSummary,
} from "../types";

export function usePlatformStream(): { connected: boolean } {
  const auditor = useAuditorMode();
  const qc = useQueryClient();
  const [connected, setConnected] = useState(false);
  useEffect(() => {
    if (typeof window === "undefined" || typeof EventSource === "undefined")
      return;
    const es = new EventSource(
      auditor ? "/api/v1/stream?role=auditor" : "/api/v1/stream",
      { withCredentials: true },
    );
    es.addEventListener("posture", (event) => {
      try {
        const data = JSON.parse((event as MessageEvent).data) as Assessment;
        qc.setQueryData(["posture", "current"], data);
      } catch {
        /* ignore malformed frame */
      }
    });
    es.addEventListener("freshness", (event) => {
      try {
        const data = JSON.parse(
          (event as MessageEvent).data,
        ) as EvidenceFreshnessSummary;
        qc.setQueryData(["evidence", "freshness", "summary"], data);
      } catch {
        /* ignore malformed frame */
      }
    });
    es.addEventListener("audit-readiness", (event) => {
      try {
        const data = JSON.parse((event as MessageEvent).data) as AuditReadiness;
        qc.setQueryData(["platform", "audit-readiness"], data);
      } catch {
        /* ignore malformed frame */
      }
    });
    es.addEventListener("ai-governance", (event) => {
      try {
        const data = JSON.parse((event as MessageEvent).data) as AiGovernance;
        qc.setQueryData(["platform", "ai-governance"], data);
        qc.invalidateQueries({
          queryKey: ["platform", "ai-governance", "inventory"],
        });
      } catch {
        /* ignore malformed frame */
      }
    });
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    return () => es.close();
  }, [qc, auditor]);
  return { connected };
}

export function usePostureStream(): { connected: boolean } {
  return usePlatformStream();
}

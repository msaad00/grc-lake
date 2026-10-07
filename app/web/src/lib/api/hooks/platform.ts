"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, bootstrapAssessment } from "../client";
import { LIVE, STALE, type Opts } from "./shared";
import type {
  AiGovernance,
  AiInventoryItem,
  Assessment,
  AuditReadiness,
  IngestionStatus,
  LakeEvalRun,
  PlatformJobsFeed,
  PlatformUsage,
  PoamItem,
  PocReadiness,
  SprsReport,
} from "../types";

export function useHealth(opts?: Opts<{ ok: boolean }>) {
  return useQuery({
    queryKey: ["health"],
    queryFn: async () => {
      try {
        const h = await api.health();
        return { ok: Boolean(h.ok) };
      } catch {
        return { ok: false };
      }
    },
    staleTime: STALE,
    retry: false,
    ...opts,
  });
}

export function usePosture(opts?: Opts<Assessment>) {
  const initialData =
    typeof window !== "undefined"
      ? (bootstrapAssessment() ?? undefined)
      : undefined;
  return useQuery({
    queryKey: ["posture", "current"],
    queryFn: api.posture,
    staleTime: STALE,
    refetchInterval: LIVE,
    refetchOnWindowFocus: true,
    initialData,
    ...opts,
  });
}

export function useIngestionStatus(opts?: Opts<IngestionStatus>) {
  return useQuery({
    queryKey: ["ingestion", "status"],
    queryFn: api.ingestionStatus,
    staleTime: STALE,
    refetchInterval: LIVE,
    refetchOnWindowFocus: true,
    ...opts,
  });
}

export function usePlatformJobs(limit = 8, opts?: Opts<PlatformJobsFeed>) {
  return useQuery({
    queryKey: ["platform", "jobs", limit],
    queryFn: () => api.platformJobs(`?limit=${limit}`),
    staleTime: 5_000,
    refetchInterval: LIVE,
    refetchOnWindowFocus: true,
    ...opts,
  });
}

export function useEvalRuns(limit = 10, opts?: Opts<LakeEvalRun[]>) {
  return useQuery({
    queryKey: ["ingestion", "eval-runs", limit],
    queryFn: () => api.listEvalRuns(limit),
    staleTime: STALE,
    refetchInterval: LIVE,
    refetchOnWindowFocus: true,
    ...opts,
  });
}

export function usePocReadiness(opts?: Opts<PocReadiness>) {
  return useQuery({
    queryKey: ["platform", "poc-readiness"],
    queryFn: api.pocReadiness,
    staleTime: STALE,
    refetchInterval: LIVE,
    retry: false,
    ...opts,
  });
}

export function useAuditReadiness(opts?: Opts<AuditReadiness>) {
  return useQuery({
    queryKey: ["platform", "audit-readiness"],
    queryFn: api.auditReadiness,
    staleTime: STALE,
    refetchInterval: LIVE,
    retry: false,
    ...opts,
  });
}

export function useAiGovernance(opts?: Opts<AiGovernance>) {
  return useQuery({
    queryKey: ["platform", "ai-governance"],
    queryFn: api.aiGovernance,
    staleTime: STALE,
    refetchInterval: LIVE,
    retry: false,
    ...opts,
  });
}

export function useAiInventory(limit = 8, opts?: Opts<AiInventoryItem[]>) {
  return useQuery({
    queryKey: ["platform", "ai-governance", "inventory", limit],
    queryFn: () => api.aiInventory(`?limit=${limit}`),
    staleTime: STALE,
    retry: false,
    ...opts,
  });
}

export function useSprsScore(opts?: Opts<SprsReport>) {
  return useQuery({
    queryKey: ["gov-compliance", "sprs"],
    queryFn: api.sprsScore,
    staleTime: STALE,
    retry: false,
    ...opts,
  });
}

export function useOpenPoamItems(
  frameworkId = "cmmc-2-level2",
  opts?: Opts<PoamItem[]>,
) {
  return usePoamItems({ framework_id: frameworkId, status: "open" }, opts);
}

export function usePoamItems(
  params?: { framework_id?: string; status?: string },
  opts?: Opts<PoamItem[]>,
) {
  const frameworkId = params?.framework_id ?? "cmmc-2-level2";
  const status = params?.status ?? "";
  return useQuery({
    queryKey: ["gov-compliance", "poam", frameworkId, status || "all"],
    queryFn: () => api.poamItems(params),
    staleTime: STALE,
    retry: false,
    ...opts,
  });
}

export function useUpdatePoamItemMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      payload,
    }: {
      id: string;
      payload: Record<string, unknown>;
    }) => api.updatePoamItem(id, payload),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["gov-compliance"] });
    },
  });
}

export function useSyncPoamMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.syncPoam,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["gov-compliance"] });
    },
  });
}

export function usePlatformUsage(enabled = true, opts?: Opts<PlatformUsage>) {
  return useQuery({
    queryKey: ["platform", "usage"],
    queryFn: api.platformUsage,
    staleTime: STALE,
    retry: false,
    enabled,
    ...opts,
  });
}

export function useCancelOperationMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.cancelOperation,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["platform", "jobs"] });
    },
  });
}

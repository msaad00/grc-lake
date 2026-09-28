"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import { STALE } from "./shared";
import type { VerifyResult, TrackingEvent } from "../types";

export function useTrustShares() {
  return useQuery({
    queryKey: ["trust-shares"],
    queryFn: async () => (await api.listTrustShares()).shares ?? [],
    staleTime: 5_000,
  });
}

export function useCreateTrustShare() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.createTrustShare,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["trust-shares"] }),
  });
}

export function useRevokeTrustShare() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.revokeTrustShare,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["trust-shares"] }),
  });
}

export function useComplianceGraph() {
  return useQuery({
    queryKey: ["graph"],
    queryFn: api.graph,
    staleTime: STALE,
  });
}

export function useRepositoryGraph() {
  return useQuery({
    queryKey: ["repo-graph"],
    queryFn: api.repoGraph,
    staleTime: STALE,
  });
}

export function useCrosswalk() {
  return useQuery({
    queryKey: ["crosswalk"],
    queryFn: api.crosswalk,
    staleTime: 60_000,
  });
}

export function useReviewedCrosswalk() {
  return useQuery({
    queryKey: ["crosswalk", "reviewed"],
    queryFn: api.reviewedCrosswalk,
    staleTime: 60_000,
  });
}

export function useCcfCoverage() {
  return useQuery({
    queryKey: ["ccf", "coverage"],
    queryFn: api.ccfCoverage,
    staleTime: 60_000,
  });
}

export function useFrameworkEquivalence() {
  return useQuery({
    queryKey: ["mappings", "equivalence"],
    queryFn: api.frameworkEquivalence,
    staleTime: 60_000,
  });
}

export function useMappings() {
  return useQuery({
    queryKey: ["mappings"],
    queryFn: async () => (await api.mappings()).mappings ?? [],
    staleTime: 60_000,
  });
}

export function useReadiness() {
  return useQuery({
    queryKey: ["readiness"],
    queryFn: async () => (await api.readiness()).frameworks ?? [],
    staleTime: 30_000,
  });
}

export function useAuditLog(opts?: {
  category?: string;
  actor?: string;
  limit?: number;
}) {
  return useQuery({
    queryKey: [
      "audit-log",
      opts?.category ?? null,
      opts?.actor ?? null,
      opts?.limit ?? null,
    ],
    queryFn: async () => (await api.auditLog(opts ?? {})).entries ?? [],
    staleTime: 5_000,
  });
}

export type { VerifyResult, TrackingEvent };

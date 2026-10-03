"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "../client";
import { STALE, type Opts } from "./shared";
import type {
  FrameworkCoveragePayload,
  FrameworkDetail,
  FrameworkView,
} from "../types";

export function useFrameworks(opts?: Opts<FrameworkView[]>) {
  return useQuery({
    queryKey: ["frameworks"],
    queryFn: async () => (await api.listFrameworks()).frameworks ?? [],
    staleTime: STALE,
    ...opts,
  });
}

export function useFrameworkDetail(id: string | null) {
  return useQuery<FrameworkDetail>({
    queryKey: ["framework-detail", id],
    queryFn: () =>
      id ? api.frameworkDetail(id) : Promise.reject(new Error("no id")),
    enabled: Boolean(id),
    staleTime: STALE,
  });
}

export function useFrameworkCoverage() {
  return useQuery<FrameworkCoveragePayload>({
    queryKey: ["frameworks", "coverage"],
    queryFn: api.frameworkCoverage,
    staleTime: STALE,
  });
}

export function useCcfAssessment() {
  return useQuery({
    queryKey: ["ccf", "assessment"],
    queryFn: api.ccfAssessment,
    staleTime: STALE,
  });
}

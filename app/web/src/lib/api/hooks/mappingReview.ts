"use client";

import {
  keepPreviousData,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { api } from "../client";
import { STALE } from "./shared";
import type {
  MappingReviewDecisionRequest,
  MappingReviewQueueParams,
} from "../types";

export function useMappingReviewQueue(params: MappingReviewQueueParams) {
  return useQuery({
    queryKey: ["mapping-review", "queue", params],
    queryFn: () => api.mappingReviewQueue(params),
    staleTime: STALE,
    placeholderData: keepPreviousData,
  });
}

export function useMappingReviewSummary() {
  return useQuery({
    queryKey: ["mapping-review", "summary"],
    queryFn: api.mappingReviewSummary,
    staleTime: STALE,
  });
}

export function useMappingReviewHistory(
  mapping: { safeguard_id: string; control_id: string } | null,
) {
  return useQuery({
    queryKey: [
      "mapping-review",
      "history",
      mapping?.safeguard_id,
      mapping?.control_id,
    ],
    queryFn: () =>
      mapping
        ? api.mappingReviewHistory(mapping.safeguard_id, mapping.control_id)
        : Promise.resolve([]),
    enabled: Boolean(mapping),
  });
}

export function useRecordMappingReviewMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: MappingReviewDecisionRequest) =>
      api.recordMappingReview(payload),
    onSuccess: () => {
      // Decisions change coverage everywhere it is shown.
      void qc.invalidateQueries({ queryKey: ["mapping-review"] });
      void qc.invalidateQueries({ queryKey: ["frameworks"] });
    },
  });
}

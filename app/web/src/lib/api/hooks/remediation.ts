"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import { LIVE, STALE, type Opts } from "./shared";
import type {
  ControlExceptionItem,
  EvidenceRequestItem,
  RemediationTask,
} from "../types";

export function useRemediationTasks(
  query = "",
  opts?: Opts<RemediationTask[]>,
) {
  return useQuery({
    queryKey: ["remediation", "tasks", query],
    queryFn: () => api.remediationTasks(query),
    staleTime: STALE,
    refetchInterval: LIVE,
    refetchOnWindowFocus: true,
    ...opts,
  });
}

export function useCreateTaskMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: Partial<RemediationTask> & { title: string }) =>
      api.createRemediationTask(payload),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["remediation", "tasks"] }),
  });
}

export function useUpdateTaskMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      payload,
    }: {
      id: string;
      payload: Record<string, unknown>;
    }) => api.updateRemediationTask(id, payload),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["remediation", "tasks"] }),
  });
}

export function useEvidenceRequests(opts?: Opts<EvidenceRequestItem[]>) {
  return useQuery({
    queryKey: ["remediation", "evidence-requests"],
    queryFn: api.evidenceRequests,
    staleTime: STALE,
    refetchInterval: LIVE,
    ...opts,
  });
}

export function useCreateEvidenceRequestMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: {
      control_id: string;
      requested_from?: string;
      note?: string;
    }) => api.createEvidenceRequest(payload),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["remediation", "evidence-requests"] }),
  });
}

export function useSetEvidenceRequestStatusMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      api.setEvidenceRequestStatus(id, status),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["remediation", "evidence-requests"] }),
  });
}

export function useControlExceptions(opts?: Opts<ControlExceptionItem[]>) {
  return useQuery({
    queryKey: ["remediation", "exceptions"],
    queryFn: api.controlExceptions,
    staleTime: STALE,
    refetchInterval: LIVE,
    ...opts,
  });
}

export function useCreateControlExceptionMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: {
      control_id: string;
      reason?: string;
      expires_at?: string | null;
    }) => api.createControlException(payload),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["remediation", "exceptions"] }),
  });
}

export function useRevokeControlExceptionMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.revokeControlException(id),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["remediation", "exceptions"] }),
  });
}

export function useApproveControlExceptionMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.approveControlException,
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["remediation", "exceptions"] }),
  });
}

export function useVerifyTaskMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, note }: { id: string; note: string }) =>
      api.verifyRemediationTask(id, note),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["remediation", "tasks"] }),
  });
}

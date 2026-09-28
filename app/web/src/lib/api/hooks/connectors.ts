"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import { LIVE, STALE, type Opts } from "./shared";
import type {
  ConfigurePayload,
  ConnectorRun,
  ConnectorView,
  DiscoverPayload,
  ProbePayload,
} from "../types";

export function useConnectors(opts?: Opts<ConnectorView[]>) {
  return useQuery({
    queryKey: ["connectors"],
    queryFn: async () => (await api.listConnectors()).connectors ?? [],
    staleTime: STALE,
    refetchInterval: LIVE,
    refetchOnWindowFocus: true,
    ...opts,
  });
}

export function useConnectorRuns(id: string | null) {
  return useQuery({
    queryKey: ["connector-runs", id],
    queryFn: async () => {
      if (!id) return [] as ConnectorRun[];
      return (await api.connectorRuns(id)).runs ?? [];
    },
    enabled: Boolean(id),
    staleTime: 5_000,
  });
}

export function useConfigureMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: ConfigurePayload }) =>
      api.configureConnector(id, payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["connectors"] }),
  });
}

export function useCloudLinkStartMutation() {
  return useMutation({
    mutationFn: ({
      id,
      publicUrl,
      tenantId,
    }: {
      id: string;
      publicUrl?: string;
      tenantId?: string;
    }) =>
      api.startCloudLink(id, {
        public_url: publicUrl,
        tenant_id: tenantId,
      }),
  });
}

export function useCloudLinkCompleteMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      sessionId,
      roleArn,
      subscriptionId,
      projectId,
      delegation,
    }: {
      id: string;
      sessionId: string;
      roleArn?: string;
      subscriptionId?: string;
      projectId?: string;
      delegation?: Record<string, string>;
    }) =>
      api.completeCloudLink(id, {
        session_id: sessionId,
        role_arn: roleArn,
        subscription_id: subscriptionId,
        project_id: projectId,
        delegation,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["connectors"] }),
  });
}

export function useProbeMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      payload = {},
    }: {
      id: string;
      payload?: ProbePayload;
    }) => api.probeConnector(id, payload),
    onSuccess: (_data, { id }) => {
      qc.invalidateQueries({ queryKey: ["connectors"] });
      qc.invalidateQueries({ queryKey: ["connector-runs", id] });
    },
  });
}

export function useSyncMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      payload = {},
    }: {
      id: string;
      payload?: { actor?: string; materialize?: boolean };
    }) => api.syncConnector(id, payload),
    onSuccess: (_data, { id }) => {
      // A sync lands evidence: refresh the connector, its runs, and the posture
      // surfaces so the UI reflects the new state immediately.
      qc.invalidateQueries({ queryKey: ["connectors"] });
      qc.invalidateQueries({ queryKey: ["connector-runs", id] });
      qc.invalidateQueries({ queryKey: ["posture", "current"] });
      qc.invalidateQueries({ queryKey: ["ingestion", "status"] });
      qc.invalidateQueries({ queryKey: ["violations"] });
    },
  });
}

export function useRunLakeEvalMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: { actor?: string } = {}) => api.runLakeEval(payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ingestion", "status"] });
      qc.invalidateQueries({ queryKey: ["ingestion", "eval-runs"] });
      qc.invalidateQueries({ queryKey: ["posture", "current"] });
      qc.invalidateQueries({ queryKey: ["violations"] });
      qc.invalidateQueries({ queryKey: ["controls"] });
    },
  });
}

export function useRunSchedulerTickMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.runSchedulerTick(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ingestion", "status"] });
      qc.invalidateQueries({ queryKey: ["connectors"] });
      qc.invalidateQueries({ queryKey: ["posture", "current"] });
      qc.invalidateQueries({ queryKey: ["violations"] });
    },
  });
}

export function useDiscoverMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      payload = {},
    }: {
      id: string;
      payload?: DiscoverPayload;
    }) => api.discoverConnector(id, payload),
    onSuccess: (_data, { id }) => {
      qc.invalidateQueries({ queryKey: ["connectors"] });
      qc.invalidateQueries({ queryKey: ["connector-runs", id] });
    },
  });
}
